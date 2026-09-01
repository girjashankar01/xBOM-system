// scanner/astExtract.js — Phase 2
//
// Runs Semgrep against the target repo and converts each match into a
// CryptoFinding using ONLY deterministic data already present in the match
// (metavariable bindings, rule metadata). No LLM call here — if the
// metavariable already gives us $MODE / $BITS, we never pay for an LLM to
// restate it.
//
// Requires the `semgrep` binary on PATH: `brew install semgrep` (macOS,
// self-contained, no Python needed at runtime) or `pip install semgrep`.
// This is an external CLI dependency regardless of host language — porting
// the engine to Node doesn't remove it.

const { execFileSync } = require('node:child_process');
const path = require('node:path');

const { CryptoFinding, Evidence, EvidenceClass } = require('../core/models');

function runSemgrep(targetDir, rulesDir) {
  let stdout;
  try {
    stdout = execFileSync(
      'semgrep',
      ['--config', rulesDir, '--json', '--quiet', targetDir],
      { encoding: 'utf-8', maxBuffer: 1024 * 1024 * 64 }
    );
  } catch (err) {
    // semgrep exits non-zero when it finds matches with certain severities
    // — that's not a real error for us. Only stdout absence is fatal.
    if (err.stdout) {
      stdout = err.stdout;
    } else {
      throw new Error(`semgrep failed to run: ${err.message}`);
    }
  }
  const payload = JSON.parse(stdout);
  if (payload.errors && payload.errors.length) {
    // don't silently swallow rule-syntax errors — a broken YAML rule means
    // zero findings for that pattern and you won't notice until the demo
    for (const e of payload.errors) {
      console.error(`[semgrep error] ${e.message || JSON.stringify(e)}`);
    }
  }
  return payload.results || [];
}

function extractMetavar(result, name) {
  if (!name) return null;
  const metavars = result.extra?.metavars || {};
  return metavars[name]?.abstract_content ?? null;
}

// ---------------------------------------------------------------------------
// Deterministic parsing of a literal identifier bound to a metavariable
// named by `cbom-algorithm-source` in rule metadata (see semgrep_rules/).
// Some APIs pack family+mode+keySize into one string argument instead of
// giving each its own metavariable — e.g. crypto.createCipheriv("aes-256-gcm",
// ...) or a JWT `alg: "RS256"`. This is pure string-pattern matching against
// known, documented naming conventions (OpenSSL cipher names, JWA alg codes,
// WebCrypto algorithm objects, Node keypair "type" strings) — never a guess.
// Anything that doesn't match a known convention is passed through as-is in
// `family` with mode/keySize left null, rather than fabricated.
// ---------------------------------------------------------------------------
const CIPHER_MODE_TOKENS = new Set([
  'cbc', 'ecb', 'cfb', 'cfb1', 'cfb8', 'ofb', 'ctr', 'gcm', 'ccm', 'ocb', 'xts', 'wrap', 'poly1305',
]);

const JWA_FAMILY_BY_PREFIX = { hs: 'HMAC', rs: 'RSA', es: 'ECDSA', ps: 'RSA-PSS' };

function parseAlgorithmIdentifier(raw) {
  if (raw == null) return null;
  const trimmed = String(raw).trim();
  if (!trimmed) return null;

  // WebCrypto-style algorithm object literal source text, e.g.
  // "{ name: 'AES-GCM', length: 256 }" or "{ name: 'RSA-OAEP', hash: 'SHA-256' }"
  const nameMatch = trimmed.match(/name\s*:\s*['"]([\w.-]+)['"]/i);
  if (nameMatch) {
    const lengthMatch = trimmed.match(/length\s*:\s*(\d+)/i);
    const hashMatch = trimmed.match(/hash\s*:\s*['"]?([\w-]+)['"]?/i);
    return {
      family: nameMatch[1].toUpperCase(),
      mode: null,
      keySize: lengthMatch ? lengthMatch[1] : hashMatch ? hashMatch[1].toUpperCase() : null,
    };
  }

  const lower = trimmed.replace(/^['"]|['"]$/g, '').toLowerCase();

  // JWA alg codes: HS256/RS384/ES512/PS256, plus EdDSA and the explicit
  // "none" (unsigned) case — worth surfacing distinctly, not silently.
  const jwaMatch = lower.match(/^(hs|rs|es|ps)(256|384|512)$/);
  if (jwaMatch) {
    return { family: JWA_FAMILY_BY_PREFIX[jwaMatch[1]], mode: `SHA-${jwaMatch[2]}`, keySize: null };
  }
  if (lower === 'eddsa') return { family: 'EdDSA', mode: null, keySize: null };
  if (lower === 'none') return { family: 'none', mode: null, keySize: null, insecure: true };

  // OpenSSL-style cipher strings: aes-256-gcm, des-ede3-cbc, chacha20-poly1305
  if (lower.includes('-')) {
    const tokens = lower.split('-');
    let keySize = null;
    let mode = null;
    const famTokens = [];
    for (const t of tokens) {
      if (/^\d{2,3}$/.test(t)) { keySize = t; continue; }
      if (CIPHER_MODE_TOKENS.has(t)) { mode = t.toUpperCase(); continue; }
      famTokens.push(t);
    }
    if (famTokens.length) {
      return { family: famTokens.join('-').toUpperCase(), mode, keySize };
    }
  }

  // Bare hash names: sha256, sha512, md5, ripemd160
  const shaMatch = lower.match(/^sha(\d{3})$/);
  if (shaMatch) return { family: `SHA-${shaMatch[1]}`, mode: null, keySize: null };
  if (lower === 'md5') return { family: 'MD5', mode: null, keySize: null };
  if (lower === 'ripemd160') return { family: 'RIPEMD-160', mode: null, keySize: null };

  // Node generateKeyPair "type" strings / EC curve names (rsa, ec, ed25519,
  // x25519, secp256k1, prime256v1, ...) — no further decomposition possible
  // from the literal alone; pass through uppercased rather than guess.
  return { family: trimmed.toUpperCase(), mode: null, keySize: null };
}

function toFinding(result) {
  const meta = result.extra.metadata;

  const assetType = meta['cbom-asset-type'] || 'algorithm';
  const primitive = meta['cbom-primitive'] || null;
  const materialType = meta['cbom-material-type'] || null;

  let mode = meta['cbom-mode'] || extractMetavar(result, '$MODE');
  let algoFamily = meta['cbom-algorithm-family'] || null;

  // deterministic parameter extraction — extend per-rule as you add more
  // Semgrep patterns; this is intentionally a flat lookup, not inference.
  let parameterSet = extractMetavar(result, '$BITS');
  const hashName = extractMetavar(result, '$DIGESTMOD') || extractMetavar(result, '$HASH_NAME');

  // cbom-algorithm-source: metadata points at a metavariable whose bound
  // literal packs family/mode/keySize together (e.g. createCipheriv's
  // "aes-256-gcm", or a JWT "HS256") rather than exposing them as separate
  // metavariables. Parse it instead of leaving the finding as "unknown".
  const sourceMetavarName = meta['cbom-algorithm-source'];
  if (sourceMetavarName) {
    const raw = extractMetavar(result, sourceMetavarName) ?? meta['cbom-algorithm-default-if-missing'] ?? null;
    if (raw != null) {
      if (meta['cbom-parameter-role']) {
        // the bound value is a parameter (bcrypt cost factor, EC curve
        // name, ...), not an algorithm identifier to decompose
        parameterSet = parameterSet || raw;
      } else {
        const parsed = parseAlgorithmIdentifier(raw);
        if (parsed) {
          algoFamily = algoFamily || parsed.family;
          mode = mode || parsed.mode;
          parameterSet = parameterSet || parsed.keySize;
        }
      }
    }
  }

  algoFamily = algoFamily || 'unknown';

  const finding = new CryptoFinding({
    assetType,
    name: algoFamily,
    algorithmFamily: algoFamily,
    primitive,
    materialType,
    parameterSet,
    mode,
    filePath: result.path,
    line: result.start.line,
  });

  finding.addEvidence(
    new Evidence({
      source: 'semgrep',
      evidenceClass: EvidenceClass.DIRECT,
      detail: result.check_id,
      rawConfidence: 0.95,
      filePath: result.path,
      line: result.start.line,
    })
  );

  // a Semgrep API match plus a successfully-bound metavariable is stronger
  // than the API match alone — record as its own supporting evidence entry
  // rather than inflating rawConfidence, so the Phase 7 confidence engine
  // can reason about it explicitly.
  if (mode || parameterSet || hashName || sourceMetavarName) {
    finding.addEvidence(
      new Evidence({
        source: 'ast',
        evidenceClass: EvidenceClass.SUPPORTING,
        detail: `metavariable bindings: mode=${mode} params=${parameterSet} hash=${hashName}`,
        rawConfidence: 0.9,
        filePath: result.path,
        line: result.start.line,
      })
    );
  }

  // rule-level review/deprecation annotations (cbom-deprecated-api,
  // cbom-review-flag) — recorded as their own low-weight supporting
  // evidence entry so Phase 7 can surface "flag for manual review" without
  // a separate side-channel field on CryptoFinding.
  const annotations = [];
  if (meta['cbom-deprecated-api'] === 'true') annotations.push('deprecated API');
  if (meta['cbom-review-flag'] === 'true') annotations.push('flagged for manual review');
  if (annotations.length) {
    finding.addEvidence(
      new Evidence({
        source: 'semgrep',
        evidenceClass: EvidenceClass.SUPPORTING,
        detail: annotations.join('; '),
        rawConfidence: 0.5,
        filePath: result.path,
        line: result.start.line,
      })
    );
  }

  return finding;
}

function scan(targetDir, rulesDir = null) {
  const dir = rulesDir || path.join(__dirname, 'semgrep_rules');
  const results = runSemgrep(targetDir, dir);
  return results.map(toFinding);
}

module.exports = { scan, runSemgrep, toFinding, parseAlgorithmIdentifier };

if (require.main === module) {
  const findings = scan(process.argv[2]);
  findings.forEach((f) => console.log(f.toJSON()));
}
