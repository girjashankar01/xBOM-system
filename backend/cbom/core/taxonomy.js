// core/taxonomy.js — Phase 0
//
// Canonical enum module. Every detector, classifier and serializer requires
// from here. Nothing hardcodes category strings inline anywhere else — grep
// for raw strings like "symmetric" outside this file during review.
//
// Maps 1:1 onto CycloneDX 1.7 cryptographic-asset enums.

const AssetType = Object.freeze({
  ALGORITHM: 'algorithm',
  PROTOCOL: 'protocol',
  CERTIFICATE: 'certificate',
  RELATED_CRYPTO_MATERIAL: 'related-crypto-material',
});

const Primitive = Object.freeze({
  AE: 'ae',
  BLOCK_CIPHER: 'block-cipher',
  COMBINER: 'combiner',
  DRBG: 'drbg',
  HASH: 'hash',
  KDF: 'kdf',
  KEM: 'kem',
  KEY_AGREE: 'key-agree',
  MAC: 'mac',
  PKE: 'pke',
  SIGNATURE: 'signature',
  STREAM_CIPHER: 'stream-cipher',
  XOF: 'xof',
  OTHER: 'other',
  UNKNOWN: 'unknown',
});

const MaterialType = Object.freeze({
  PRIVATE_KEY: 'private-key',
  PUBLIC_KEY: 'public-key',
  SECRET_KEY: 'secret-key',
  TOKEN: 'token',
  CREDENTIAL: 'credential',
  PASSWORD: 'password',
  DIGEST: 'digest',
  SALT: 'salt',
  SHARED_SECRET: 'shared-secret',
  CIPHERTEXT: 'ciphertext',
  SIGNATURE: 'signature',
  SEED: 'seed',
  INITIALIZATION_VECTOR: 'initialization-vector',
  TAG: 'tag',
  ADDITIONAL_DATA: 'additional-data',
  NONCE: 'nonce',
  OTHER: 'other',
});

const ProtocolType = Object.freeze({
  TLS: 'tls',
  SSH: 'ssh',
  JWT: 'jwt',
  IPSEC: 'ipsec',
  OTHER: 'other',
});

// Phase 4 — where in the target repo a finding lives.
const ContextCategory = Object.freeze({
  PRODUCTION: 'production',
  TEST: 'test',
  VENDOR: 'vendor',
  UNKNOWN: 'unknown',
});

// Phase 2+ — which detector produced a piece of evidence.
const EvidenceSource = Object.freeze({
  SEMGREP: 'semgrep',
  AST: 'ast',
  SCA: 'sca',
  KEYS_CERTS: 'keys_certs',
  CONSTANT: 'constant',
  EMBEDDING: 'embedding',
  LLM: 'llm',
});

// Source context: live executable code vs. code comments / tutorial snippets
const SourceContext = Object.freeze({
  LIVE: 'live',
  COMMENT: 'comment',
});

// Exposure risk: independent of quantum risk — committed private keys are CRITICAL
const ExposureRisk = Object.freeze({
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  NONE: 'NONE',
});

// NIST PQC posture, 0 (broken today) through 5 (PQC-native). Priority
// signal for analysis/quantumRisk.js, not a date prediction.
const NistQuantumLevel = Object.freeze({
  L0_BROKEN: 0,
  L1: 1,
  L2: 2,
  L3: 3,
  L4: 4,
  L5_PQC_NATIVE: 5,
});

module.exports = {
  AssetType,
  Primitive,
  MaterialType,
  ProtocolType,
  ContextCategory,
  EvidenceSource,
  SourceContext,
  ExposureRisk,
  NistQuantumLevel,
};
