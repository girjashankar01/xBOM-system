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

function getLlmUrl() {
  return process.env.OFFLINE_LLM_URL || 'http://localhost:11434/api/chat';
}

function getLlmModel() {
  return process.env.OFFLINE_LLM_MODEL || 'qwen2.5-coder:1.5b';
}

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

function isNoCryptoResponse(parsed) {
  if (!parsed || typeof parsed !== 'object') return false;
  const rawFam = (parsed.algorithmFamily || '').trim().toLowerCase();
  const rawConf = Number(parsed.confidence);
  const reasoning = (parsed.reasoning || '').toLowerCase();

  // If confidence is 0 or null/empty algorithm family
  if (!rawFam || rawFam === 'null' || rawFam === 'none' || rawFam === 'unknown' || rawFam === 'undefined' || rawConf === 0) {
    const rawParam = (parsed.parameterSet || '').trim().toLowerCase();
    const rawPrim = (parsed.primitive || '').trim().toLowerCase();
    if (!VALID_FAMILIES_MAP.has(rawParam) && !VALID_FAMILIES_MAP.has(rawPrim)) {
      return true;
    }
  }

  if (reasoning.includes('no cryptographic') || reasoning.includes('no crypto') || reasoning.includes('does not use crypto') || reasoning.includes('does not use any crypto') || reasoning.includes('no cryptography')) {
    if (rawConf === 0 || !rawFam || rawFam === 'null' || rawFam === 'none' || rawFam === 'unknown') {
      return true;
    }
  }

  return false;
}

/**
 * Validates, repairs, and canonicalizes raw LLM output against the CycloneDX
 * algorithm registry and primitive enums.
 */
function validateLlmResponse(parsed) {
  if (!parsed || typeof parsed !== 'object') {
    return null;
  }

  // Check if model explicitly and validly reported no crypto usage
  if (isNoCryptoResponse(parsed)) {
    return {
      isCrypto: false,
      algorithmFamily: null,
      primitive: null,
      parameterSet: null,
      confidence: 0,
      reasoning: parsed.reasoning || '',
    };
  }

  let rawFamily = (parsed.algorithmFamily || '').trim();
  let rawPrimitive = (parsed.primitive || '').trim().toLowerCase();
  let rawParam = (parsed.parameterSet || '').trim();

  // If family is empty or null, check if model placed the algorithm in parameterSet or primitive
  if (!rawFamily || rawFamily === 'null' || rawFamily.toLowerCase() === 'unknown') {
    if (rawParam && VALID_FAMILIES_MAP.has(rawParam.toLowerCase())) {
      rawFamily = rawParam;
    } else if (rawPrimitive && VALID_FAMILIES_MAP.has(rawPrimitive.toLowerCase())) {
      rawFamily = rawPrimitive;
      rawPrimitive = '';
    } else {
      return null;
    }
  }

  // If model placed a primitive type in the family field, try to repair from parameterSet or primitive
  if (VALID_PRIMITIVES.has(rawFamily.toLowerCase())) {
    const primitiveHolder = rawFamily.toLowerCase();
    let repairedFamily = null;

    if (rawParam && VALID_FAMILIES_MAP.has(rawParam.toLowerCase())) {
      repairedFamily = rawParam;
    } else if (rawPrimitive && VALID_FAMILIES_MAP.has(rawPrimitive.toLowerCase())) {
      repairedFamily = rawPrimitive;
    } else if (parsed.reasoning) {
      // Check if reasoning mentions a canonical family
      for (const [key, fam] of VALID_FAMILIES_MAP.entries()) {
        if (new RegExp(`\\b${key}\\b`, 'i').test(parsed.reasoning)) {
          repairedFamily = fam;
          break;
        }
      }
    }

    if (repairedFamily) {
      rawFamily = repairedFamily;
      if (!rawPrimitive) rawPrimitive = primitiveHolder;
    } else {
      console.warn(`[llm_agent] rejected malformed LLM response: algorithmFamily="${rawFamily}" is a primitive enum value, not an algorithm family`);
      return null;
    }
  }

  // Validate against canonical registry families
  const canonicalFamily = VALID_FAMILIES_MAP.get(rawFamily.toLowerCase());
  if (!canonicalFamily) {
    console.warn(`[llm_agent] rejected invalid algorithmFamily "${rawFamily}" — not catalogued in CycloneDX algorithm registry snapshot`);
    return null;
  }

  // Validate primitive: must be in VALID_PRIMITIVES enum or coerced to null
  const canonicalPrimitive = VALID_PRIMITIVES.has(rawPrimitive) ? rawPrimitive : null;

  const rawConfidence = Math.max(0, Math.min(1, Number(parsed.confidence) || 0));
  if (rawConfidence <= 0) {
    return {
      isCrypto: false,
      algorithmFamily: null,
      primitive: null,
      parameterSet: null,
      confidence: 0,
      reasoning: parsed.reasoning || '',
    };
  }

  return {
    isCrypto: true,
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
    .join('\n');

  return [
    {
      role: 'system',
      content:
        'You are a cybersecurity static-analysis assistant specializing in cryptographic asset detection.\n' +
        'Your job is to analyze source code and determine whether it contains cryptographic usage. When crypto is present, identify the specific algorithm and provide useful security context.\n' +
        'Respond with ONLY a JSON object, no markdown fences, no prose.\n' +
        'Your analysis should explain WHY the code is cryptographic, its SECURITY SIGNIFICANCE, and a concise REMEDIATION recommendation when appropriate.\n' +
        'Never invent cryptographic usage that is not supported by the code. Treat retrieved corpus examples as supporting hints only; the source code is the primary evidence.\n' +
        `Valid "primitive" values: ${Array.from(VALID_PRIMITIVES).join(', ')}.\n` +
        'Valid "algorithmFamily" values MUST be specific algorithm names: AES, RSA, ECDSA, EdDSA, HMAC, SHA-2, SHA-3, HKDF, PBKDF2, Argon2, bcrypt, scrypt, ChaCha20, etc.\n\n' +
        'CRITICAL RULES:\n' +
        '1. "algorithmFamily" is the specific algorithm name (e.g. "ECDSA", "SHA-2", "AES", "HKDF"), NOT a primitive category.\n' +
        '2. If the code does not use cryptography, set "algorithmFamily" to null and "confidence" to 0.\n\n' +
        'EXAMPLES:\n' +
        'Code: crypto.createHash("sha256").update(data)\n' +
        'Output: {"algorithmFamily": "SHA-2", "primitive": "hash", "parameterSet": "SHA-256", "confidence": 0.95, "reasoning": "Uses SHA-256 hash algorithm."}\n\n' +
        'Code: verifyCustomAttestation(attestationObject)\n' +
        'Output: {"algorithmFamily": "ECDSA", "primitive": "signature", "parameterSet": "P-256", "confidence": 0.85, "reasoning": "WebAuthn attestation signature verification."}\n\n' +
        'Code: getSessionData(req.session)\n' +
        'Output: {"algorithmFamily": null, "primitive": null, "parameterSet": null, "confidence": 0.0, "reasoning": "No cryptographic algorithm used."}\n\n' +
        'Schema: {"algorithmFamily": string|null, "primitive": string|null, "parameterSet": string|null, "confidence": number, "reasoning": string}. The "reasoning" field MUST briefly include: (1) what crypto usage was detected, (2) why the code indicates that algorithm, (3) the security significance, and (4) a practical remediation or recommendation when relevant.',
    },
    {
      role: 'user',
      content:
        `File: ${filePath}\n\nCode:\n\`\`\`\n${codeText}\n\`\`\`\n\n` +
        `Similar known crypto usages from a labeled corpus (candidate hints, may be irrelevant):\n` +
        `${candidateBlock || '(no close matches from the retrieval corpus)'}`,
    },
  ];
}

function parseModelJson(raw) {
  if (!raw) return null;
  const cleaned = raw.replace(/^```json\s*/i, '').replace(/^```\s*/, '').replace(/\s*```$/, '').trim();
  try {
    return JSON.parse(cleaned);
  } catch {
    const match = cleaned.match(/\{[\s\S]*\}/);
    if (match) {
      try { return JSON.parse(match[0]); } catch { return null; }
    }
    return null;
  }
}

/** Ollama /api/chat shape. Swap this function's body for another endpoint. */
async function callLLM(messages, { timeoutMs = 15000 } = {}) {
  const url = getLlmUrl();
  const model = getLlmModel();
  console.log(`[llm_agent] Requesting Ollama endpoint ${url} (model: ${model})`);
  console.log('[llm_agent] Raw Prompt Messages:\n', JSON.stringify(messages, null, 2));

  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        messages,
        stream: false,
        format: 'json',
        options: {
          temperature: 0.0,
          num_predict: 256,
        },
      }),
      signal: controller ? controller.signal : undefined,
    });

    if (!res.ok) {
      const errBody = await res.text().catch(() => '');
      throw new Error(`LLM call HTTP ${res.status}: ${res.statusText} — ${errBody}`);
    }

    const data = await res.json();
    console.log('[llm_agent] Raw LLM Response Content:\n', data?.message?.content || data);
    return data?.message?.content || '';
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Verifies one candidate span. Returns a CryptoFinding with a single
 * INTERPRETIVE Evidence entry, or null if the model found nothing / the
 * call failed / the response didn't parse / validation failed.
 */
function enrichSecurityReasoning(result) {
  const family = result.algorithmFamily;
  const parameter = result.parameterSet || family;

  const recommendations = {
    MD5: 'MD5 is cryptographically broken and should not be used for security-sensitive hashing. Replace it with SHA-256 or a stronger approved hash where appropriate.',
    'SHA-1': 'SHA-1 is deprecated for security-sensitive applications. Replace it with SHA-256 or a stronger approved hash.',
    DES: 'DES has an inadequate key size and is considered insecure. Replace it with AES-256 or another approved modern cipher.',
    '3DES': '3DES is deprecated and should be migrated to a modern authenticated encryption algorithm such as AES-GCM.',
    'RSA-1024': 'RSA-1024 is too weak for modern security requirements. Migrate to RSA-2048 or stronger, or an approved modern alternative.',
    'RSA-2048': 'RSA-2048 remains widely used, but should be tracked for long-term cryptographic migration and quantum-readiness.',
    'AES-128': 'AES-128 is currently considered secure for many applications, but AES-256 may be preferred for longer-term security requirements.',
  };

  const recommendation = recommendations[family] ||
    'Review this cryptographic usage against current security requirements and use an approved modern algorithm and parameter set.';

  return `Detected ${family}${parameter && parameter !== family ? ` (${parameter})` : ''} cryptographic usage. ` +
    `The source code indicates use of this algorithm as identified by the LLM. ` +
    `Security significance: this cryptographic asset should be evaluated for strength, configuration, and long-term security requirements. ` +
    `Recommendation: ${recommendation}`;
}
async function verifySpan({ filePath, line, codeText, candidates = [], contextCategory = 'unknown', stats = null }) {
  const startTime = Date.now();
  if (stats) stats.llmCallsAttempted++;

  let raw;
  try {
    raw = await callLLM(buildPrompt({ codeText, filePath, candidates }));
  } catch (err) {
    if (stats) {
      stats.llmCallsFailed++;
      stats.wallClockMs += (Date.now() - startTime);
      if (stats.failureReasons) {
        if (err.name === 'AbortError' || (err.message && err.message.toLowerCase().includes('timeout'))) {
          stats.failureReasons.timeout++;
        } else {
          stats.failureReasons.connection_error++;
        }
      }
    }
    console.warn(`[llm_agent] verification call failed for ${filePath}:${line} — ${err.message}`);
    return null;
  }

  const parsed = parseModelJson(raw);
  if (!parsed) {
    if (stats) {
      stats.llmCallsFailed++;
      stats.wallClockMs += (Date.now() - startTime);
      if (stats.failureReasons) stats.failureReasons.invalid_json++;
    }
    console.warn(`[llm_agent] verification failed for ${filePath}:${line} — malformed JSON response: "${raw.slice(0, 100)}"`);
    return null;
  }

  const result = validateLlmResponse(parsed);
  if (!result) {
    // Genuine schema mismatch / unresolvable malformed response
    if (stats) {
      stats.llmCallsFailed++;
      stats.wallClockMs += (Date.now() - startTime);
      if (stats.failureReasons) stats.failureReasons.schema_mismatch++;
    }
    console.warn(`[llm_agent] verification validation rejected for ${filePath}:${line} — schema mismatch / unrecognized algorithm. Raw response: ${JSON.stringify(parsed)}`);
    return null;
  }

  if (result.isCrypto === false) {
    // Valid response identifying no cryptographic usage (success with negative result)
    if (stats) {
      stats.llmCallsSucceeded++;
      stats.noCryptoDetected = (stats.noCryptoDetected || 0) + 1;
      stats.wallClockMs += (Date.now() - startTime);
    }
    console.log(`[llm_agent] verified no cryptographic usage for ${filePath}:${line} (${result.reasoning || 'no crypto'})`);
    return null;
  }

  if (stats) {
    stats.llmCallsSucceeded++;
    stats.wallClockMs += (Date.now() - startTime);
  }

  const finding = new CryptoFinding({
    assetType: 'algorithm',
    name: result.algorithmFamily,
    algorithmFamily: result.algorithmFamily,
    primitive: result.primitive,
    parameterSet: result.parameterSet,
    filePath,
    line,
    contextCategory,
    confidence: result.confidence,
  });

  finding.addEvidence(new Evidence({
    source: 'llm',
    evidenceClass: EvidenceClass.INTERPRETIVE,
    detail: enrichSecurityReasoning(result),
    rawConfidence: result.confidence,
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