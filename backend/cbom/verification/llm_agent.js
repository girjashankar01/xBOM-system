// verification/llm_agent.js — Phase 6
//
// Gated LLM verification. "Gated" = this only ever runs on candidates that
// DIDN'T already get DIRECT evidence from scanner/ (semgrep/AST) — if a
// detector already confidently identified the algorithm, sending it to an
// LLM anyway wastes a call and adds a second, lower-quality opinion on
// something already settled. shouldVerify() below is the gate; call it
// before invoking verifySpan(), not after.
//
// Talks to a plain local HTTP endpoint (Ollama-compatible /api/chat by
// default) — no hosted API, per the privacy call already made for Phase 5
// embeddings: full code spans are more sensitive than embeddings, so
// keeping this offline matters MORE here, not less. If you're running
// LM Studio / text-generation-webui instead of Ollama, only callLLM()
// below needs to change — everything else (gating, prompt, parsing) is
// endpoint-agnostic.
//
// Output here is a raw CryptoFinding with INTERPRETIVE evidence, same
// shape scanner/ and retrieval/ produce — analysis/evidence.js aggregates
// all three phases' findings together, it doesn't know or care which
// detector produced which one.

const { CryptoFinding, Evidence, EvidenceClass } = require('../core/models');
const { Primitive } = require('../core/taxonomy');
const registry = require('./registry_snapshot.json');

const OFFLINE_LLM_URL = process.env.OFFLINE_LLM_URL || 'http://localhost:11434/api/chat';
const OFFLINE_LLM_MODEL = process.env.OFFLINE_LLM_MODEL || 'qwen2.5-coder:1.5b';

const VALID_PRIMITIVES = new Set(Object.values(Primitive));
const VALID_FAMILIES_MAP = new Map(registry.algorithmFamilies.map((f) => [f.toLowerCase(), f]));

// Standard naming aliases mapped to canonical CycloneDX registry families
VALID_FAMILIES_MAP.set('chacha', 'ChaCha');
VALID_FAMILIES_MAP.set('chacha20-poly1305', 'ChaCha20');
VALID_FAMILIES_MAP.set('salsa20', 'Salsa20');
VALID_FAMILIES_MAP.set('aes-gcm', 'AES');
VALID_FAMILIES_MAP.set('aes-cbc', 'AES');
VALID_FAMILIES_MAP.set('sha256', 'SHA-2');
VALID_FAMILIES_MAP.set('sha-256', 'SHA-2');
VALID_FAMILIES_MAP.set('sha512', 'SHA-2');
VALID_FAMILIES_MAP.set('sha-512', 'SHA-2');
VALID_FAMILIES_MAP.set('sha1', 'SHA-1');
VALID_FAMILIES_MAP.set('sha-1', 'SHA-1');

/**
 * Validates and canonicalizes raw LLM output against the CycloneDX algorithm registry
 * and primitive enums. Discards malformed guesses (e.g. primitives in the family field).
 */
function validateLlmResponse(parsed) {
  if (!parsed || typeof parsed !== 'object') return null;

  const rawFamily = (parsed.algorithmFamily || '').trim();
  if (!rawFamily || rawFamily === 'null' || rawFamily.toLowerCase() === 'unknown') {
    return null;
  }

  // Reject if the model mistakenly placed a primitive type in the algorithmFamily field
  if (VALID_PRIMITIVES.has(rawFamily.toLowerCase())) {
    console.warn(`[llm_agent] rejected malformed LLM response: algorithmFamily="${rawFamily}" is a primitive enum value, not an algorithm family`);
    return null;
  }

  // Validate against canonical registry families
  const canonicalFamily = VALID_FAMILIES_MAP.get(rawFamily.toLowerCase());
  if (!canonicalFamily) {
    console.warn(`[llm_agent] rejected invalid algorithmFamily "${rawFamily}" — not catalogued in CycloneDX algorithm registry snapshot`);
    return null;
  }

  // Validate primitive: must be in VALID_PRIMITIVES enum or coerced to null
  const rawPrimitive = (parsed.primitive || '').trim().toLowerCase();
  const canonicalPrimitive = VALID_PRIMITIVES.has(rawPrimitive) ? rawPrimitive : null;

  const rawConfidence = Math.max(0, Math.min(1, Number(parsed.confidence) || 0));
  if (rawConfidence <= 0) return null;

  return {
    algorithmFamily: canonicalFamily,
    primitive: canonicalPrimitive,
    parameterSet: parsed.parameterSet || null,
    confidence: rawConfidence,
    reasoning: parsed.reasoning || '',
  };
}

/**
 * Gate: only verify a span if nothing has already produced DIRECT
 * evidence for it. `existingEvidenceClasses` is whatever
 * analysis/evidence.js's shouldMerge-adjacent findings already carry —
 * pass an empty Set for a brand-new candidate with no prior evidence.
 */
function shouldVerify(existingEvidenceClasses = new Set()) {
  return !existingEvidenceClasses.has(EvidenceClass.DIRECT);
}

function buildPrompt({ codeText, filePath, candidates }) {
  const candidateBlock = (candidates || [])
    .map((c) => `- ${c.entry.algorithmFamily} (${c.entry.primitive}), similarity ${c.score.toFixed(2)}`)
    .join('\n') || '(no close matches from the retrieval corpus)';

  return [
    {
      role: 'system',
      content:
        'You are a static-analysis assistant identifying cryptographic algorithm usage in source code. ' +
        'Respond with ONLY a JSON object, no markdown fences, no prose. ' +
        `Valid "primitive" values: ${Array.from(VALID_PRIMITIVES).join(', ')}. ` +
        `"algorithmFamily" MUST be a specific named algorithm from this list if it matches: ${registry.algorithmFamilies.join(', ')}. ` +
        'CRITICAL: Do NOT set "algorithmFamily" to a primitive type (like "stream-cipher", "block-cipher", or "hash"). ' +
        'If the specific algorithm is not in the list or the code does not use cryptography, set "algorithmFamily" to null. ' +
        'Schema: {"algorithmFamily": string|null, "primitive": string|null, "parameterSet": string|null, ' +
        '"confidence": number (0-1), "reasoning": string (max 2 sentences)}',
    },
    {
      role: 'user',
      content:
        `File: ${filePath}\n\nCode:\n\`\`\`\n${codeText}\n\`\`\`\n\n` +
        `Similar known crypto usages from a labeled corpus (candidate hints, may be irrelevant):\n${candidateBlock}`,
    },
  ];
}

/** Ollama /api/chat shape. Swap this function's body for another endpoint. */
async function callLLM(messages) {
  console.log(`[llm_agent] Requesting Ollama endpoint ${OFFLINE_LLM_URL} (model: ${OFFLINE_LLM_MODEL})`);
  console.log('[llm_agent] Raw Prompt Messages:\n', JSON.stringify(messages, null, 2));
  const res = await fetch(OFFLINE_LLM_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: OFFLINE_LLM_MODEL, messages, stream: false, format: 'json' }),
  });
  if (!res.ok) {
    throw new Error(`Offline LLM endpoint ${OFFLINE_LLM_URL} returned ${res.status}`);
  }
  const data = await res.json();
  const content = data.message?.content ?? '';
  console.log('[llm_agent] Raw LLM Response Content:\n', content);
  return content;
}

function parseModelJson(raw) {
  const cleaned = raw.trim().replace(/^```json\s*|^```\s*|```$/g, '');
  try {
    return JSON.parse(cleaned);
  } catch {
    return null;
  }
}

/**
 * Verifies one candidate span. Returns a CryptoFinding with a single
 * INTERPRETIVE Evidence entry, or null if the model found nothing / the
 * call failed / the response didn't parse / validation failed.
 */
async function verifySpan({ filePath, line, codeText, candidates = [], contextCategory = 'unknown' }) {
  let validated;
  try {
    const raw = await callLLM(buildPrompt({ codeText, filePath, candidates }));
    const parsed = parseModelJson(raw);
    validated = validateLlmResponse(parsed);
  } catch (err) {
    console.warn(`[llm_agent] verification failed for ${filePath}:${line} — ${err.message}`);
    return null;
  }

  if (!validated || !validated.algorithmFamily) return null;

  const finding = new CryptoFinding({
    assetType: 'algorithm',
    name: validated.algorithmFamily,
    algorithmFamily: validated.algorithmFamily,
    primitive: validated.primitive,
    parameterSet: validated.parameterSet,
    filePath,
    line,
    contextCategory,
  });

  finding.addEvidence(new Evidence({
    source: 'llm',
    evidenceClass: EvidenceClass.INTERPRETIVE,
    detail: validated.reasoning || '',
    rawConfidence: validated.confidence,
    filePath,
    line,
  }));

  return finding;
}

module.exports = { shouldVerify, verifySpan, validateLlmResponse };

if (require.main === module) {
  verifySpan({
    filePath: process.argv[2],
    line: Number(process.argv[3]) || 0,
    codeText: require('node:fs').readFileSync(process.argv[2], 'utf-8'),
  }).then((f) => console.log(f ? f.toJSON() : 'no finding'));
}