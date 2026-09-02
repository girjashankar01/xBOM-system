// cbom/cli/main.test.js
//
// End-to-end pipeline integration tests using Jest (the project's declared test
// runner in package.json). Equivalent assertions to the original node:test
// version — same fixture, same checks, same coverage.

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');

const { runPipeline } = require('./main');

function makeFixtureDir() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-fixture-'));

  // scanner/constants.js matches raw bytes, so write the actual hex bytes,
  // not a JS string containing the hex text.
  fs.writeFileSync(path.join(dir, 'legacy-hash.bin'), Buffer.from('0123456789abcdeffedcba9876543210', 'hex'));

  // A throwaway RSA private key, generated fresh per test run — never a
  // real key, exists only to exercise scanner/keysCerts.js's PEM matcher.
  const { privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 1024,
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
  });
  fs.writeFileSync(path.join(dir, 'test-key.pem'), privateKey);
  return dir;
}

describe('runPipeline', () => {
  test('detects a known-constant hash match and a PEM private key', async () => {
    const dir = makeFixtureDir();
    try {
      const result = await runPipeline(dir, { skipLlm: true }); // no corpus

      expect(result.findings.length).toBeGreaterThanOrEqual(2);
      expect(result.validation.errors.length).toBe(0);

      const md5Finding = result.findings.find((f) => f.algorithmFamily === 'MD5');
      expect(md5Finding).toBeDefined();
      expect(['HIGH', 'CRITICAL']).toContain(md5Finding.quantumRisk);

      const keyFinding = result.findings.find((f) => f.materialType === 'private-key');
      expect(keyFinding).toBeDefined();

      expect(result.cbom.bomFormat).toBe('CycloneDX');
      expect(result.cbom.components.length).toBe(result.findings.length);
      expect(result.cbom.components.every((c) => c.type === 'cryptographic-asset')).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('detects code-level crypto API calls (crypto, bcrypt, jwt)', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-code-fixture-'));
    try {
      const code = `
        const crypto = require('crypto');
        const bcrypt = require('bcryptjs');
        const jwt = require('jsonwebtoken');

        function auth(password, key, iv) {
          const salt = bcrypt.genSaltSync(10);
          const hash = bcrypt.hashSync(password, salt);
          const valid = bcrypt.compareSync(password, hash);
          const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
          const derived = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512');
          const token = jwt.sign({ sub: 'user1' }, 'secret', { algorithm: 'HS256' });
          const verified = jwt.verify(token, 'secret');
          return { hash, valid, token };
        }
      `;
      fs.writeFileSync(path.join(dir, 'auth.js'), code);

      const result = await runPipeline(dir, { skipLlm: true });
      expect(result.validation.errors.length).toBe(0);

      const families = result.findings.map(f => f.algorithmFamily);
      expect(families).toContain('bcrypt');
      expect(families).toContain('AES');
      expect(families).toContain('PBKDF2');
      expect(families.some(f => f === 'JWT' || f === 'HMAC')).toBe(true);

      const bcryptFinding = result.findings.find(f => f.algorithmFamily === 'bcrypt' && f.primitive === 'kdf');
      expect(bcryptFinding).toBeDefined();

      const aesFinding = result.findings.find(f => f.algorithmFamily === 'AES');
      expect(aesFinding).toBeDefined();
      expect(aesFinding.primitive).toBe('block-cipher');
      expect(aesFinding.mode).toBe('GCM');

      const saltFinding = result.findings.find(f => f.materialType === 'salt');
      expect(saltFinding).toBeDefined();
      expect(saltFinding.assetType).toBe('related-crypto-material');
      expect(saltFinding.primitive).toBeNull();

      const compareFinding = result.findings.find(f => f.algorithmFamily === 'bcrypt' && f.evidence.some(e => e.detail.includes('compare')));
      expect(compareFinding).toBeDefined();
      expect(compareFinding.assetType).toBe('algorithm');
      expect(compareFinding.primitive).toBeNull();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('rejects a non-existent target directory', async () => {
    await expect(runPipeline('/definitely/not/a/real/path')).rejects.toThrow(/not a directory/);
  });
});

describe('CBOM Correctness & Schema Verification', () => {
  const { validateFinding, validateFindings } = require('../verification/validator');
  const { CryptoFinding, Evidence, EvidenceClass } = require('../core/models');
  const { AssetType, Primitive, MaterialType, NistQuantumLevel } = require('../core/taxonomy');
  const { nistQuantumLevelFor, classifyRisk } = require('../analysis/quantumRisk');
  const { score } = require('../analysis/confidence');

  test('enforces schema separation: primitive rejected on related-crypto-material and certificate', () => {
    const invalidMaterial = new CryptoFinding({
      assetType: AssetType.RELATED_CRYPTO_MATERIAL,
      materialType: MaterialType.SALT,
      primitive: Primitive.DRBG, // invalid on related-crypto-material!
    });
    const issues1 = validateFinding(invalidMaterial);
    expect(issues1.some(i => i.level === 'error' && i.field === 'primitive')).toBe(true);

    const invalidCert = new CryptoFinding({
      assetType: AssetType.CERTIFICATE,
      primitive: Primitive.SIGNATURE, // invalid on certificate!
    });
    const issues2 = validateFinding(invalidCert);
    expect(issues2.some(i => i.level === 'error' && i.field === 'primitive')).toBe(true);
  });

  test('enforces schema separation: materialType rejected on algorithm', () => {
    const invalidAlgorithm = new CryptoFinding({
      assetType: AssetType.ALGORITHM,
      algorithmFamily: 'AES',
      primitive: Primitive.BLOCK_CIPHER,
      materialType: MaterialType.SECRET_KEY, // invalid on algorithm!
    });
    const issues = validateFinding(invalidAlgorithm);
    expect(issues.some(i => i.level === 'error' && i.field === 'materialType')).toBe(true);
  });

  test('distinguishes bcrypt hash vs. compare vs. genSalt primitive treatment', () => {
    const saltFinding = new CryptoFinding({
      assetType: AssetType.RELATED_CRYPTO_MATERIAL,
      materialType: MaterialType.SALT,
      algorithmFamily: 'bcrypt',
    });
    expect(validateFinding(saltFinding).filter(i => i.level === 'error')).toHaveLength(0);
    expect(saltFinding.primitive).toBeFalsy();

    const hashFinding = new CryptoFinding({
      assetType: AssetType.ALGORITHM,
      algorithmFamily: 'bcrypt',
      primitive: Primitive.KDF,
    });
    expect(validateFinding(hashFinding).filter(i => i.level === 'error')).toHaveLength(0);
    expect(hashFinding.primitive).toBe(Primitive.KDF);

    const compareFinding = new CryptoFinding({
      assetType: AssetType.ALGORITHM,
      algorithmFamily: 'bcrypt',
    });
    expect(validateFinding(compareFinding).filter(i => i.level === 'error')).toHaveLength(0);
    expect(compareFinding.primitive).toBeFalsy();
  });

  test('quantum-risk severity varies correctly across algorithm families', () => {
    // 1. RSA / Shor-vulnerable -> L0_BROKEN, CRITICAL/HIGH
    const rsaFinding = new CryptoFinding({
      assetType: AssetType.ALGORITHM,
      algorithmFamily: 'RSA',
      primitive: Primitive.SIGNATURE,
    });
    expect(nistQuantumLevelFor(rsaFinding)).toBe(NistQuantumLevel.L0_BROKEN);
    expect(classifyRisk(NistQuantumLevel.L0_BROKEN, 'high')).toBe('CRITICAL');

    // 2. AES-256 / SHA-512 / PBKDF2 -> L5_PQC_NATIVE / LOW
    const aes256Finding = new CryptoFinding({
      assetType: AssetType.ALGORITHM,
      algorithmFamily: 'AES',
      primitive: Primitive.BLOCK_CIPHER,
      parameterSet: '256',
    });
    expect(nistQuantumLevelFor(aes256Finding)).toBe(NistQuantumLevel.L5_PQC_NATIVE);
    expect(classifyRisk(NistQuantumLevel.L5_PQC_NATIVE, 'medium')).toBe('LOW');

    // 3. AES-128 -> L1 / MEDIUM
    const aes128Finding = new CryptoFinding({
      assetType: AssetType.ALGORITHM,
      algorithmFamily: 'AES',
      primitive: Primitive.BLOCK_CIPHER,
      parameterSet: '128',
    });
    expect(nistQuantumLevelFor(aes128Finding)).toBe(NistQuantumLevel.L1);
    expect(classifyRisk(NistQuantumLevel.L1, 'medium')).toBe('MEDIUM');

    // 4. CSPRNG & salts -> not quantum vulnerable -> NONE
    const csprngFinding = new CryptoFinding({
      assetType: AssetType.ALGORITHM,
      algorithmFamily: 'CSPRNG',
      primitive: Primitive.DRBG,
    });
    expect(classifyRisk(nistQuantumLevelFor(csprngFinding), 'medium', true)).toBe('NONE');
  });

  test('confidence varies dynamically based on evidence resolution quality and context', () => {
    // High-quality direct literal AST match in production
    const explicitEvidence = [
      new Evidence({ source: 'ast', evidenceClass: EvidenceClass.DIRECT, rawConfidence: 0.95 }),
      new Evidence({ source: 'ast', evidenceClass: EvidenceClass.SUPPORTING, rawConfidence: 0.90 }),
    ];
    const scoreExplicit = score(explicitEvidence, 'production');
    expect(scoreExplicit).toBe(0.99);

    // Single direct inferred AST match in production
    const inferredEvidence = [
      new Evidence({ source: 'ast', evidenceClass: EvidenceClass.DIRECT, rawConfidence: 0.80 }),
    ];
    const scoreInferred = score(inferredEvidence, 'production');
    expect(scoreInferred).toBe(0.80);

    // Commented / tutorial AST match in production
    const commentEvidence = [
      new Evidence({ source: 'ast', evidenceClass: EvidenceClass.DIRECT, rawConfidence: 0.65 }),
    ];
    const scoreComment = score(commentEvidence, 'production');
    expect(scoreComment).toBe(0.65);

    // Regex fallback match in production
    const regexEvidence = [
      new Evidence({ source: 'ast', evidenceClass: EvidenceClass.DIRECT, rawConfidence: 0.55 }),
    ];
    const scoreRegex = score(regexEvidence, 'production');
    expect(scoreRegex).toBe(0.55);

    // All distinct resolution levels produce strictly decreasing confidence
    expect(scoreExplicit).toBeGreaterThan(scoreInferred);
    expect(scoreInferred).toBeGreaterThan(scoreComment);
    expect(scoreComment).toBeGreaterThan(scoreRegex);

    // Unknown context downweights correctly
    expect(score(explicitEvidence, 'unknown')).toBe(0.693);
  });
});