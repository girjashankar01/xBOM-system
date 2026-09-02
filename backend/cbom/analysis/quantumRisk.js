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

const { AssetType, Primitive, MaterialType, NistQuantumLevel } = require('../core/taxonomy');

// Broken outright by Shor's algorithm, independent of key size.
const SHOR_BROKEN_FAMILIES = new Set([
  'RSA', 'RSA-OAEP', 'RSA-PSS', 'RSASSA-PKCS1', 'DSA', 'DH', 'DHE',
  'ECDSA', 'ECDH', 'ECDHE', 'EDDSA', 'ED25519', 'ED448', 'X25519', 'X448',
  'EC', 'ECC', 'SECP256K1', 'PRIME256V1',
]);

// Broken classically already (pre-quantum) — still bucketed at L0 since
// "worse than broken" isn't a lower number than "broken".
const CLASSICALLY_BROKEN_FAMILIES = new Set(['MD5', 'DES', '3DES', 'TRIPLEDES', 'RC4', 'NONE']);

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

/** Returns a NistQuantumLevel (0-5) for a finding. */
function nistQuantumLevelFor(finding) {
  const family = (finding.algorithmFamily || finding.name || '').toUpperCase();

  // Algorithm finding with no cryptographic primitive (e.g. comparison, utility)
  if (finding.assetType === AssetType.ALGORITHM && !finding.primitive) {
    return NistQuantumLevel.L5_PQC_NATIVE;
  }

  // CSPRNG and salts are not algorithmically quantum-vulnerable
  if (
    finding.primitive === Primitive.DRBG ||
    finding.materialType === MaterialType.SALT ||
    finding.materialType === 'salt' ||
    family === 'CSPRNG'
  ) {
    return NistQuantumLevel.L5_PQC_NATIVE;
  }

  // Key/cert material or certificates
  if (
    (finding.assetType === AssetType.RELATED_CRYPTO_MATERIAL || finding.assetType === AssetType.CERTIFICATE) &&
    finding.parameterSet && /rsa|ec|dsa|sha256withrsa/i.test(finding.parameterSet)
  ) {
    return NistQuantumLevel.L0_BROKEN;
  }

  // Asymmetric families broken by Shor's algorithm
  if (SHOR_BROKEN_FAMILIES.has(family)) return NistQuantumLevel.L0_BROKEN;
  if (CLASSICALLY_BROKEN_FAMILIES.has(family)) return NistQuantumLevel.L0_BROKEN;

  // Modern symmetric-based password KDFs (bcrypt, PBKDF2 with SHA-256/512, scrypt, Argon2)
  if (finding.primitive === Primitive.KDF || (finding.primitive && /^(BCRYPT|PBKDF2|SCRYPT|ARGON2)$/i.test(family))) {
    if (finding.parameterSet && /md5|sha1/i.test(finding.parameterSet)) {
      return NistQuantumLevel.L1; // weak underlying hash
    }
    return NistQuantumLevel.L5_PQC_NATIVE;
  }

  // Symmetric block/stream ciphers and authenticated encryption
  if (finding.primitive === Primitive.BLOCK_CIPHER || finding.primitive === Primitive.STREAM_CIPHER || finding.primitive === Primitive.AE) {
    const size = keySizeOf(finding);
    return bucketBySize(size, SYMMETRIC_QUANTUM_LEVEL_BY_KEYSIZE);
  }

  // Hashes and MACs
  if (finding.primitive === Primitive.HASH || finding.primitive === Primitive.MAC) {
    const m = family.match(/(\d{3})/);
    const digestBits = m ? parseInt(m[1], 10) : keySizeOf(finding);
    return bucketBySize(digestBits, HASH_QUANTUM_LEVEL_BY_DIGEST_BITS);
  }

  // Default fallback for unrecognized algorithms
  return NistQuantumLevel.L1;
}

/**
 * Heuristic sensitivity label, used only as classify_risk()'s third input.
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

/** Direct port of classify_risk() with explicit non-quantum handling for non-primitives / CSPRNGs / salts */
function classifyRisk(nistQuantumLevel, dataSensitivity, isNonApplicable = false) {
  if (isNonApplicable) return 'NONE';
  if (nistQuantumLevel === NistQuantumLevel.L0_BROKEN && dataSensitivity === 'high') return 'CRITICAL';
  if (nistQuantumLevel === NistQuantumLevel.L0_BROKEN) return 'HIGH';
  if (nistQuantumLevel <= NistQuantumLevel.L2) return 'MEDIUM';
  return 'LOW';
}

/**
 * Resolves the exposureRisk severity dimension.
 * Independent of quantumRisk: a private key committed to a repository
 * is a CRITICAL secret-exposure issue regardless of algorithm quantum vulnerability.
 * In-memory runtime generated key pairs (e.g. generateKeyPairSync in JS source)
 * do not represent committed static key material on disk and resolve to NONE exposureRisk.
 */
function classifyExposureRisk(finding) {
  const filePath = finding.filePath || '';
  const isKeyFileOnDisk = /\.(key|pem|p8|pkcs8)$/i.test(filePath) ||
    finding.evidence.some(e => e.source === 'keysCerts' || /PEM header|file match|fs\.read/i.test(e.detail || ''));

  const isPrivateKey =
    (finding.assetType === AssetType.RELATED_CRYPTO_MATERIAL &&
      (finding.materialType === MaterialType.PRIVATE_KEY ||
       finding.materialType === 'private-key' ||
       finding.name === 'private-key' ||
       /private-key/i.test(finding.materialType || '') ||
       /private-key/i.test(finding.name || ''))) ||
    /\.(key|pem|p8|pkcs8)$/i.test(filePath);

  // 1. Static committed private key file on disk -> CRITICAL
  if ((isPrivateKey && isKeyFileOnDisk) || /\.(key|pem|p8|pkcs8)$/i.test(filePath)) {
    return 'CRITICAL';
  }

  // 2. In-memory runtime generated key pair (e.g. generateKeyPairSync in JS/TS source file)
  const isRuntimeGeneratedKey = isPrivateKey && !isKeyFileOnDisk &&
    (finding.evidence.some(e => /generateKeyPair/i.test(e.detail || '')) || /\.(js|jsx|ts|tsx|mjs|cjs)$/i.test(filePath));

  if (isRuntimeGeneratedKey) {
    return 'NONE';
  }

  // 3. Symmetric secret keys committed in files
  if (
    finding.assetType === AssetType.RELATED_CRYPTO_MATERIAL &&
    (finding.materialType === MaterialType.SECRET_KEY || finding.materialType === 'secret-key')
  ) {
    return isKeyFileOnDisk ? 'HIGH' : 'LOW';
  }

  // Explicit weak/hardcoded secret flags
  if (finding.parameterSet && typeof finding.parameterSet === 'string' && finding.parameterSet.includes('weak-secret')) {
    return 'HIGH';
  }

  // Certificates are public material
  if (finding.assetType === AssetType.CERTIFICATE) {
    return 'LOW';
  }

  // Salts and entropy
  if (finding.materialType === MaterialType.SALT || finding.primitive === Primitive.DRBG) {
    return 'NONE';
  }

  return 'NONE';
}

/**
 * Mutates and returns findings with `.nistQuantumLevel`, `.quantumRisk`, and `.exposureRisk` set.
 */
function classifyFindings(findings) {
  for (const f of findings) {
    const family = (f.algorithmFamily || f.name || '').toUpperCase();
    const isNonApplicable =
      (f.assetType === AssetType.ALGORITHM && !f.primitive) ||
      f.primitive === Primitive.DRBG ||
      f.materialType === MaterialType.SALT ||
      f.materialType === 'salt' ||
      family === 'CSPRNG';
    f.nistQuantumLevel = nistQuantumLevelFor(f);
    f.quantumRisk = classifyRisk(f.nistQuantumLevel, inferDataSensitivity(f), isNonApplicable);
    f.exposureRisk = classifyExposureRisk(f);
  }
  return findings;
}

module.exports = {
  classifyRisk,
  classifyExposureRisk,
  nistQuantumLevelFor,
  inferDataSensitivity,
  classifyFindings,
};

if (require.main === module) {
  console.log('RSA-2048, production, high sensitivity ->', classifyRisk(NistQuantumLevel.L0_BROKEN, 'high'));
  console.log('AES-256, production, medium sensitivity ->', classifyRisk(NistQuantumLevel.L5_PQC_NATIVE, 'medium'));
  console.log('SHA-1, production, medium sensitivity   ->', classifyRisk(NistQuantumLevel.L1, 'medium'));
}
