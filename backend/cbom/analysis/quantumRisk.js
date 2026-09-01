// analysis/quantumRisk.js — Phase 8
//
// Priority buckets, NOT a break-date prediction (build guide §7 Phase 8 /
// §9 Limitations). Mosca's inequality (shelf_life + migration_time >
// years_to_CRQC) is the right mental model to EXPLAIN this with in a demo,
// but nobody can put a real number on years_to_CRQC, so this module never
// computes or emits one — only CRITICAL/HIGH/MEDIUM/LOW plus the numeric
// nistQuantumLevel (0-5, from core/taxonomy.js) that fed the bucket.
//
// ADDITION vs. the guide's pseudocode: the guide's classify_risk() takes
// nist_quantum_level and data_sensitivity as already-given inputs and
// doesn't say where either comes from. Both need a source, so this module
// supplies them:
//
//   - nistQuantumLevelFor(finding): a hand-built algorithm-family -> NIST
//     quantum level table. Asymmetric primitives broken outright by
//     Shor's algorithm (RSA, DH, ECDSA/ECDH/EdDSA family, etc.) -> L0
//     regardless of key size. Symmetric ciphers and hashes are bucketed by
//     key/digest size against Grover's/BHT's quadratic speedup (roughly:
//     halve the bit strength), following NIST CNSA 2.0's treatment of
//     AES-256/ChaCha20 as acceptable and AES-128/SHA-1/MD5 as not. This is
//     a defensible heuristic, not a vendored NIST table — flag it as such
//     if asked in a demo/review.
//
//   - inferDataSensitivity(finding): a heuristic off contextCategory and
//     assetType, since CryptoFinding carries no explicit sensitivity label
//     today (the guide doesn't add one either). This is a placeholder
//     until the project has a real data-classification pass — documented
//     here and in the top-level summary, not hidden.

const { AssetType, Primitive, NistQuantumLevel } = require('../core/taxonomy');

// Broken outright by Shor's algorithm, independent of key size.
const SHOR_BROKEN_FAMILIES = new Set([
  'RSA', 'RSA-OAEP', 'RSA-PSS', 'RSASSA-PKCS1', 'DSA', 'DH', 'DHE',
  'ECDSA', 'ECDH', 'ECDHE', 'EDDSA', 'ED25519', 'ED448', 'X25519', 'X448',
  'EC', 'ECC', 'SECP256K1', 'PRIME256V1',
]);

// Broken classically already (pre-quantum) — still bucketed at L0 since
// "worse than broken" isn't a lower number than "broken".
const CLASSICALLY_BROKEN_FAMILIES = new Set(['MD5', 'DES', '3DES', 'RC4']);

// key-size (bits) -> NIST quantum level, thresholds checked high-to-low.
const SYMMETRIC_QUANTUM_LEVEL_BY_KEYSIZE = [
  [256, NistQuantumLevel.L5_PQC_NATIVE],
  [192, NistQuantumLevel.L3],
  [128, NistQuantumLevel.L1],
];

// digest-size (bits) -> NIST quantum level.
const HASH_QUANTUM_LEVEL_BY_DIGEST_BITS = [
  [512, NistQuantumLevel.L5_PQC_NATIVE],
  [384, NistQuantumLevel.L4],
  [256, NistQuantumLevel.L3],
  [160, NistQuantumLevel.L1], // SHA-1: not classically broken like MD5, but weak
];

function keySizeOf(finding) {
  const raw = finding.parameterSet;
  const n = raw ? parseInt(String(raw).replace(/[^\d]/g, ''), 10) : NaN;
  return Number.isFinite(n) ? n : null;
}

function bucketBySize(size, table) {
  if (size == null) return NistQuantumLevel.L1;
  for (const [threshold, level] of table) {
    if (size >= threshold) return level;
  }
  return NistQuantumLevel.L0_BROKEN;
}

/** Returns a NistQuantumLevel (0-5) for a finding. Falls back to L1
 * ("not yet known-safe") rather than guessing a worse or better level when
 * the family/primitive/parameterSet don't resolve to anything in the
 * tables above. */
function nistQuantumLevelFor(finding) {
  const family = (finding.algorithmFamily || finding.name || '').toUpperCase();

  if (
    (finding.assetType === AssetType.RELATED_CRYPTO_MATERIAL || finding.assetType === AssetType.CERTIFICATE) &&
    finding.parameterSet && /rsa|ec|dsa/i.test(finding.parameterSet)
  ) {
    // keysCerts.js stores the cert's signature algorithm in parameterSet —
    // a key/cert secured by a Shor-broken signature scheme is itself L0.
    return NistQuantumLevel.L0_BROKEN;
  }

  if (SHOR_BROKEN_FAMILIES.has(family)) return NistQuantumLevel.L0_BROKEN;
  if (CLASSICALLY_BROKEN_FAMILIES.has(family)) return NistQuantumLevel.L0_BROKEN;

  if (finding.primitive === Primitive.BLOCK_CIPHER || finding.primitive === Primitive.STREAM_CIPHER || finding.primitive === Primitive.AE) {
    return bucketBySize(keySizeOf(finding), SYMMETRIC_QUANTUM_LEVEL_BY_KEYSIZE);
  }
  if (finding.primitive === Primitive.HASH || finding.primitive === Primitive.MAC) {
    const m = family.match(/(\d{3})/);
    const digestBits = m ? parseInt(m[1], 10) : keySizeOf(finding);
    return bucketBySize(digestBits, HASH_QUANTUM_LEVEL_BY_DIGEST_BITS);
  }

  // KDF/DRBG/unresolved primitive: no established quantum-level convention
  // to bucket against — L1 is the safe default (assume unproven, don't
  // fabricate a specific level).
  return NistQuantumLevel.L1;
}

/**
 * Heuristic sensitivity label, used only as classify_risk()'s third input.
 * NOT a real data-classification engine. Keys/certs and asymmetric
 * signature/key-agreement material in production default to "high";
 * anything in test/vendor context is downgraded regardless of asset type,
 * mirroring the non-punitive-but-lower-weight treatment
 * analysis/confidence.js already applies via CONTEXT_CAP.
 */
function inferDataSensitivity(finding) {
  if (finding.contextCategory === 'test' || finding.contextCategory === 'vendor') return 'low';
  if (finding.assetType === AssetType.RELATED_CRYPTO_MATERIAL || finding.assetType === AssetType.CERTIFICATE) return 'high';
  if (
    finding.primitive === Primitive.PKE ||
    finding.primitive === Primitive.KEM ||
    finding.primitive === Primitive.SIGNATURE ||
    finding.primitive === Primitive.KEY_AGREE
  ) {
    return 'high';
  }
  return 'medium';
}

/** Direct port of the guide's classify_risk() pseudocode — buckets only,
 * never a year. */
function classifyRisk(nistQuantumLevel, dataSensitivity) {
  if (nistQuantumLevel === NistQuantumLevel.L0_BROKEN && dataSensitivity === 'high') return 'CRITICAL';
  if (nistQuantumLevel === NistQuantumLevel.L0_BROKEN) return 'HIGH';
  if (nistQuantumLevel <= NistQuantumLevel.L2) return 'MEDIUM';
  return 'LOW';
}

/**
 * Mutates and returns findings with `.nistQuantumLevel` and `.quantumRisk`
 * set. Run AFTER context_classifier/classify.js (Phase 4) and
 * analysis/confidence.js (Phase 7) — inferDataSensitivity() reads
 * contextCategory, which must already be final.
 */
function classifyFindings(findings) {
  for (const f of findings) {
    f.nistQuantumLevel = nistQuantumLevelFor(f);
    f.quantumRisk = classifyRisk(f.nistQuantumLevel, inferDataSensitivity(f));
  }
  return findings;
}

module.exports = { classifyRisk, nistQuantumLevelFor, inferDataSensitivity, classifyFindings };

if (require.main === module) {
  console.log('RSA-2048, production, high sensitivity ->', classifyRisk(NistQuantumLevel.L0_BROKEN, 'high'));
  console.log('AES-256, production, medium sensitivity ->', classifyRisk(NistQuantumLevel.L5_PQC_NATIVE, 'medium'));
  console.log('SHA-1, production, medium sensitivity   ->', classifyRisk(NistQuantumLevel.L1, 'medium'));
}
