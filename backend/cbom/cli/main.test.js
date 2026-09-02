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

  test('validates sourceContext requirement and distinguishes live vs. comment nodes', () => {
    const liveFinding = new CryptoFinding({
      assetType: AssetType.ALGORITHM,
      algorithmFamily: 'AES',
      primitive: Primitive.BLOCK_CIPHER,
      sourceContext: 'live',
    });
    expect(validateFinding(liveFinding).filter(i => i.level === 'error')).toHaveLength(0);

    const commentFinding = new CryptoFinding({
      assetType: AssetType.ALGORITHM,
      algorithmFamily: 'AES',
      primitive: Primitive.BLOCK_CIPHER,
      sourceContext: 'comment',
    });
    expect(validateFinding(commentFinding).filter(i => i.level === 'error')).toHaveLength(0);

    const invalidContext = new CryptoFinding({
      assetType: AssetType.ALGORITHM,
      algorithmFamily: 'AES',
      primitive: Primitive.BLOCK_CIPHER,
      sourceContext: 'invalid-source-context',
    });
    const issues = validateFinding(invalidContext);
    expect(issues.some(i => i.level === 'error' && i.field === 'sourceContext')).toBe(true);
  });

  test('detects jsonwebtoken / jose JWA algorithms (RS256, ES256, HS256, and insecure none)', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-jwt-fixture-'));
    try {
      const code = `
        const jwt = require('jsonwebtoken');
        const token1 = jwt.sign({ sub: 'user1' }, 'secret', { algorithm: 'HS256' });
        const token2 = jwt.sign({ sub: 'user2' }, key, { algorithm: 'RS256' });
        const token3 = jwt.sign({ sub: 'user3' }, key, { algorithm: 'ES256' });
        const token4 = jwt.sign({ sub: 'user4' }, '', { algorithm: 'none' });
        const verified = jwt.verify(token1, 'secret', { algorithms: ['RS256', 'none'] });
      `;
      fs.writeFileSync(path.join(dir, 'jwt-test.js'), code);

      const result = await runPipeline(dir, { skipLlm: true });
      expect(result.validation.errors).toHaveLength(0);

      const families = result.findings.map(f => f.algorithmFamily);
      expect(families).toContain('HMAC');
      expect(families).toContain('RSA');
      expect(families).toContain('ECDSA');
      expect(families).toContain('none');

      // Check all have signature primitive
      const jwtFindings = result.findings.filter(f => f.filePath.endsWith('jwt-test.js'));
      expect(jwtFindings.every(f => f.primitive === 'signature')).toBe(true);
      expect(jwtFindings.every(f => f.sourceContext === 'live')).toBe(true);

      // Check that "none" algorithm is flagged as insecure / L0_BROKEN
      const noneFinding = jwtFindings.find(f => f.algorithmFamily === 'none');
      expect(noneFinding).toBeDefined();
      expect(noneFinding.parameterSet).toContain('none');
      expect(noneFinding.nistQuantumLevel).toBe(NistQuantumLevel.L0_BROKEN);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('detects CryptoJS algorithms (modern AES/SHA512/PBKDF2 vs. legacy DES/3DES/RC4/MD5 with elevated risk)', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-cryptojs-fixture-'));
    try {
      const code = `
        const CryptoJS = require('crypto-js');
        const aes = CryptoJS.AES.encrypt('msg', 'pass');
        const des = CryptoJS.DES.encrypt('msg', 'pass');
        const tripleDes = CryptoJS.TripleDES.encrypt('msg', 'pass');
        const rc4 = CryptoJS.RC4.encrypt('msg', 'pass');
        const md5 = CryptoJS.MD5('msg');
        const sha512 = CryptoJS.SHA512('msg');
        const hmac = CryptoJS.HmacSHA256('msg', 'secret');
        const kdf = CryptoJS.PBKDF2('pass', 'salt');
      `;
      fs.writeFileSync(path.join(dir, 'cryptojs-test.js'), code);

      const result = await runPipeline(dir, { skipLlm: true });
      expect(result.validation.errors).toHaveLength(0);

      const findings = result.findings.filter(f => f.filePath.endsWith('cryptojs-test.js'));
      expect(findings.every(f => f.sourceContext === 'live')).toBe(true);

      const findFamily = fam => findings.find(f => f.algorithmFamily === fam);

      // Modern algorithms -> LOW risk
      const aesFinding = findFamily('AES');
      expect(aesFinding).toBeDefined();
      expect(aesFinding.primitive).toBe('block-cipher');

      const sha512Finding = findFamily('SHA-512');
      expect(sha512Finding).toBeDefined();
      expect(sha512Finding.primitive).toBe('hash');
      expect(sha512Finding.quantumRisk).toBe('LOW');

      const pbkdf2Finding = findFamily('PBKDF2');
      expect(pbkdf2Finding).toBeDefined();
      expect(pbkdf2Finding.primitive).toBe('kdf');
      expect(pbkdf2Finding.quantumRisk).toBe('LOW');

      // Legacy/broken algorithms -> L0_BROKEN / elevated severity
      const desFinding = findFamily('DES');
      expect(desFinding).toBeDefined();
      expect(desFinding.primitive).toBe('block-cipher');
      expect(desFinding.nistQuantumLevel).toBe(NistQuantumLevel.L0_BROKEN);
      expect(['CRITICAL', 'HIGH']).toContain(desFinding.quantumRisk);

      const rc4Finding = findFamily('RC4');
      expect(rc4Finding).toBeDefined();
      expect(rc4Finding.primitive).toBe('stream-cipher');
      expect(rc4Finding.nistQuantumLevel).toBe(NistQuantumLevel.L0_BROKEN);
      expect(['CRITICAL', 'HIGH']).toContain(rc4Finding.quantumRisk);

      const md5Finding = findFamily('MD5');
      expect(md5Finding).toBeDefined();
      expect(md5Finding.primitive).toBe('hash');
      expect(md5Finding.nistQuantumLevel).toBe(NistQuantumLevel.L0_BROKEN);
      expect(['CRITICAL', 'HIGH']).toContain(md5Finding.quantumRisk);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('scores exposureRisk as CRITICAL on committed private key files independent of quantumRisk', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-exposure-fixture-'));
    try {
      const privateKeyContent = [
        '-----BEGIN RSA PRIVATE KEY-----',
        'MIIEowIBAAKCAQEA0Y3wZ...',
        '-----END RSA PRIVATE KEY-----',
      ].join('\n');
      fs.writeFileSync(path.join(dir, 'server.key'), privateKeyContent);

      const result = await runPipeline(dir, { skipLlm: true });
      expect(result.validation.errors).toHaveLength(0);

      const keyFinding = result.findings.find(f => f.filePath.endsWith('server.key'));
      expect(keyFinding).toBeDefined();
      expect(keyFinding.assetType).toBe(AssetType.RELATED_CRYPTO_MATERIAL);
      expect(keyFinding.materialType).toBe('private-key');
      // Independent dimensions:
      expect(keyFinding.exposureRisk).toBe('CRITICAL');
      expect(keyFinding.quantumRisk).toBe('MEDIUM');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('scores exposureRisk as NONE / LOW on standard code algorithms and certificates', () => {
    const { classifyFindings } = require('../analysis/quantumRisk');

    const algoFinding = new CryptoFinding({
      assetType: AssetType.ALGORITHM,
      name: 'AES-256-GCM',
      algorithmFamily: 'AES',
      primitive: Primitive.BLOCK_CIPHER,
      parameterSet: '256',
      filePath: 'src/crypto.js',
      line: 12,
    });

    const certFinding = new CryptoFinding({
      assetType: AssetType.CERTIFICATE,
      name: 'X.509 Certificate',
      filePath: 'certs/ca.crt',
      line: 1,
    });

    classifyFindings([algoFinding, certFinding]);

    // Algo: quantumRisk is LOW, exposureRisk is NONE
    expect(algoFinding.quantumRisk).toBe('LOW');
    expect(algoFinding.exposureRisk).toBe('NONE');

    // Cert: quantumRisk is HIGH/CRITICAL (asymmetric), exposureRisk is LOW (public metadata)
    expect(certFinding.exposureRisk).toBe('LOW');
  });

  test('attributes crypto dependencies to packages via SbomAdapter and correlation', async () => {
    const { SbomAdapter } = require('../context/sbomAdapter');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-pkg-attribution-'));
    try {
      const mockSbom = {
        components: [
          { name: 'bcrypt-nodejs', version: '0.0.3', purl: 'pkg:npm/bcrypt-nodejs@0.0.3' },
          { name: 'jsonwebtoken', version: '9.0.0', purl: 'pkg:npm/jsonwebtoken@9.0.0' },
          { name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' },
        ],
      };

      const result = await runPipeline(dir, { sbom: mockSbom, skipLlm: true });
      expect(result.correlation).toBeDefined();
      expect(result.correlation.summary.attributedToPackage).toBeGreaterThan(0);

      const correlatedPkgs = result.correlation.correlated
        .filter(c => c.packageContext)
        .map(c => c.packageContext.name);

      expect(correlatedPkgs).toContain('bcrypt-nodejs');
      expect(correlatedPkgs).toContain('jsonwebtoken');
      expect(correlatedPkgs).not.toContain('lodash');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('resolves quantumRisk as NONE for null-primitive algorithm findings and salt material', () => {
    const { classifyFindings } = require('../analysis/quantumRisk');

    const compareFinding = new CryptoFinding({
      assetType: AssetType.ALGORITHM,
      name: 'bcrypt',
      algorithmFamily: 'bcrypt',
      primitive: null, // compare operation has no primitive
      filePath: 'app/data/user-dao.js',
      line: 65,
    });

    const saltFinding = new CryptoFinding({
      assetType: AssetType.RELATED_CRYPTO_MATERIAL,
      name: 'bcrypt-salt',
      materialType: MaterialType.SALT,
      primitive: null,
      filePath: 'app/data/user-dao.js',
      line: 29,
    });

    classifyFindings([compareFinding, saltFinding]);

    expect(compareFinding.quantumRisk).toBe('NONE');
    expect(saltFinding.quantumRisk).toBe('NONE');
  });

  test('scores real cryptographic primitives correctly per per-algorithm rules', () => {
    const { classifyFindings } = require('../analysis/quantumRisk');

    const hashFinding = new CryptoFinding({
      assetType: AssetType.ALGORITHM,
      name: 'bcrypt',
      algorithmFamily: 'bcrypt',
      primitive: Primitive.KDF,
      filePath: 'app/data/user-dao.js',
      line: 29,
    });

    const aesFinding = new CryptoFinding({
      assetType: AssetType.ALGORITHM,
      name: 'AES-256',
      algorithmFamily: 'AES',
      primitive: Primitive.BLOCK_CIPHER,
      parameterSet: '256',
      filePath: 'src/crypto.js',
      line: 10,
    });

    classifyFindings([hashFinding, aesFinding]);

    expect(hashFinding.quantumRisk).toBe('LOW');
    expect(aesFinding.quantumRisk).toBe('LOW');
  });

  test('buildCombinedRiskSummary accurately aggregates 30+ findings across all severity buckets and counts', () => {
    const { buildCombinedRiskSummary } = require('../output/correlation');

    const syntheticFindings = [];
    const syntheticCorrelated = [];

    const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'];
    const exposureSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'];
    const primitives = [Primitive.HASH, Primitive.MAC, Primitive.BLOCK_CIPHER, Primitive.KDF, Primitive.DRBG, null];

    let expectedCritical = 0, expectedHigh = 0, expectedMedium = 0, expectedLow = 0, expectedNone = 0;
    let expectedExpCrit = 0, expectedExpHigh = 0, expectedExpMed = 0, expectedExpLow = 0, expectedExpNone = 0;
    const expectedByPrimitive = {};
    let expectedAttributed = 0;
    let expectedFirstParty = 0;

    for (let i = 0; i < 35; i++) {
      const qRisk = severities[i % severities.length];
      const eRisk = exposureSeverities[i % exposureSeverities.length];
      const prim = primitives[i % primitives.length];
      const isAttributed = i % 3 === 0;

      if (qRisk === 'CRITICAL') expectedCritical++;
      else if (qRisk === 'HIGH') expectedHigh++;
      else if (qRisk === 'MEDIUM') expectedMedium++;
      else if (qRisk === 'LOW') expectedLow++;
      else expectedNone++;

      if (eRisk === 'CRITICAL') expectedExpCrit++;
      else if (eRisk === 'HIGH') expectedExpHigh++;
      else if (eRisk === 'MEDIUM') expectedExpMed++;
      else if (eRisk === 'LOW') expectedExpLow++;
      else expectedExpNone++;

      if (prim) expectedByPrimitive[prim] = (expectedByPrimitive[prim] || 0) + 1;
      if (isAttributed) expectedAttributed++;
      else expectedFirstParty++;

      const f = new CryptoFinding({
        assetType: AssetType.ALGORITHM,
        name: `Algo-${i}`,
        primitive: prim,
        filePath: isAttributed ? `node_modules/pkg-${i}/index.js` : `src/file-${i}.js`,
        line: i + 1,
      });
      f.quantumRisk = qRisk;
      f.exposureRisk = eRisk;

      syntheticFindings.push(f);
      syntheticCorrelated.push({
        findingId: f.findingId,
        name: f.name,
        packageContext: isAttributed ? { name: `pkg-${i}`, version: '1.0.0', purl: `pkg:npm/pkg-${i}@1.0.0` } : null,
      });
    }

    const summary = buildCombinedRiskSummary(syntheticFindings, syntheticCorrelated, { compounding: [] });

    expect(summary.totalFindings).toBe(35);
    expect(summary.quantumRisk.critical).toBe(expectedCritical);
    expect(summary.quantumRisk.high).toBe(expectedHigh);
    expect(summary.quantumRisk.medium).toBe(expectedMedium);
    expect(summary.quantumRisk.low).toBe(expectedLow);
    expect(summary.quantumRisk.none).toBe(expectedNone);

    expect(summary.exposureRisk.critical).toBe(expectedExpCrit);
    expect(summary.exposureRisk.high).toBe(expectedExpHigh);
    expect(summary.exposureRisk.medium).toBe(expectedExpMed);
    expect(summary.exposureRisk.low).toBe(expectedExpLow);
    expect(summary.exposureRisk.none).toBe(expectedExpNone);

    expect(summary.attributedToPackage).toBe(expectedAttributed);
    expect(summary.firstPartySource).toBe(expectedFirstParty);
    expect(summary.byPrimitive).toEqual(expectedByPrimitive);
  });

  test('scores committed private key files as exposureRisk: CRITICAL', () => {
    const { classifyFindings } = require('../analysis/quantumRisk');

    const fileKeyFinding = new CryptoFinding({
      assetType: AssetType.RELATED_CRYPTO_MATERIAL,
      name: 'private-key',
      materialType: MaterialType.PRIVATE_KEY,
      filePath: 'artifacts/cert/server.key',
      line: 1,
    });
    fileKeyFinding.addEvidence(new Evidence({
      source: 'keysCerts',
      evidenceClass: EvidenceClass.DIRECT,
      detail: 'PEM header match (private-key)',
      filePath: 'artifacts/cert/server.key',
      line: 1,
    }));

    classifyFindings([fileKeyFinding]);
    expect(fileKeyFinding.exposureRisk).toBe('CRITICAL');
  });

  test('scores in-memory runtime generated private keys as exposureRisk: NONE while preserving quantumRisk', () => {
    const { classifyFindings } = require('../analysis/quantumRisk');

    const runtimeKeyFinding = new CryptoFinding({
      assetType: AssetType.RELATED_CRYPTO_MATERIAL,
      algorithmFamily: 'EC',
      name: 'private-key',
      materialType: MaterialType.PRIVATE_KEY,
      parameterSet: 'P-256',
      filePath: 'controllers/webauthn.js',
      line: 7,
    });
    runtimeKeyFinding.addEvidence(new Evidence({
      source: 'ast',
      evidenceClass: EvidenceClass.DIRECT,
      detail: 'crypto.generateKeyPairSync("ec")',
      filePath: 'controllers/webauthn.js',
      line: 7,
    }));

    classifyFindings([runtimeKeyFinding]);
    // In-memory key pair generation is not a committed file leak
    expect(runtimeKeyFinding.exposureRisk).toBe('NONE');
    // Algorithmic quantum risk remains CRITICAL for EC
    expect(runtimeKeyFinding.quantumRisk).toBe('CRITICAL');
  });

  test('detects multiple distinct PEM blocks (EC private key + RSA public key) in the same file', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-multi-pem-fixture-'));
    try {
      const multiPemContent = [
        '-----BEGIN EC PRIVATE KEY-----',
        'MHcCAQEEI...',
        '-----END EC PRIVATE KEY-----',
        '',
        '// Some other code in between',
        '',
        '-----BEGIN PUBLIC KEY-----',
        'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Y3wZ...',
        '-----END PUBLIC KEY-----',
      ].join('\n');
      fs.writeFileSync(path.join(dir, 'keys.js'), multiPemContent);

      const result = await runPipeline(dir, { skipLlm: true });
      expect(result.validation.errors).toHaveLength(0);

      const pemFindings = result.findings.filter(f => f.filePath.endsWith('keys.js'));
      expect(pemFindings).toHaveLength(2);

      const privateKey = pemFindings.find(f => f.materialType === 'private-key');
      const publicKey = pemFindings.find(f => f.materialType === 'public-key');
      expect(privateKey).toBeDefined();
      expect(publicKey).toBeDefined();
      expect(privateKey.line).toBe(1);
      expect(publicKey.line).toBe(7);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('classifies hardcoded private key in a .js file as exposureRisk CRITICAL', () => {
    const { classifyFindings } = require('../analysis/quantumRisk');

    const jsKeyFinding = new CryptoFinding({
      assetType: AssetType.RELATED_CRYPTO_MATERIAL,
      name: 'private-key',
      materialType: MaterialType.PRIVATE_KEY,
      filePath: 'controllers/webauthn.js',
      line: 4,
    });
    jsKeyFinding.addEvidence(new Evidence({
      source: 'keys_certs',
      evidenceClass: EvidenceClass.DIRECT,
      detail: 'PEM header match (private-key)',
      filePath: 'controllers/webauthn.js',
      line: 4,
    }));

    classifyFindings([jsKeyFinding]);
    expect(jsKeyFinding.exposureRisk).toBe('CRITICAL');
  });

  test('LLM verification runs on non-DIRECT supporting findings and handles unreachable endpoints gracefully', async () => {
    const { shouldVerify, verifySpan } = require('../verification/llm_agent');

    // 1. Gating check: DIRECT evidence is not verified, SUPPORTING-only is verified
    expect(shouldVerify(new Set([EvidenceClass.DIRECT]))).toBe(false);
    expect(shouldVerify(new Set([EvidenceClass.SUPPORTING]))).toBe(true);
    expect(shouldVerify(new Set())).toBe(true);

    // 2. Unreachable endpoint test: returns null without throwing or crashing
    const unreachableResult = await verifySpan({
      filePath: 'customCipher.js',
      line: 1,
      codeText: 'function customCipher() { return "test"; }',
      candidates: [],
    });
    // With unreachable or unconfigured model, gracefully returns null
    expect(unreachableResult === null || unreachableResult instanceof CryptoFinding).toBe(true);
  }, 15000);

  test('validateLlmResponse rejects invalid enum values and malformed primitive-in-family guesses', () => {
    const { validateLlmResponse } = require('../verification/llm_agent');

    // 1. Malformed primitive placed in algorithmFamily field -> rejected
    expect(validateLlmResponse({
      algorithmFamily: 'stream-cipher',
      primitive: 'xor',
      confidence: 0.9,
    })).toBeNull();

    // 2. Unknown algorithm family not in CycloneDX registry snapshot -> rejected
    expect(validateLlmResponse({
      algorithmFamily: 'unrecognized-homebrew-crypto',
      primitive: 'block-cipher',
      confidence: 0.8,
    })).toBeNull();

    // 3. Valid algorithm family and invalid primitive -> family canonicalized, primitive coerced to null
    const res = validateLlmResponse({
      algorithmFamily: 'chacha20',
      primitive: 'xor',
      confidence: 0.95,
      reasoning: 'uses ChaCha20 constant',
    });
    expect(res).not.toBeNull();
    expect(res.algorithmFamily).toBe('ChaCha20');
    expect(res.primitive).toBeNull();
    expect(res.confidence).toBe(0.95);
  });

  test('valid static classification is preserved and outranks lower-quality or malformed LLM guesses', () => {
    const { aggregate } = require('../analysis/evidence');

    const staticFinding = new CryptoFinding({
      assetType: AssetType.ALGORITHM,
      name: 'ChaCha20',
      algorithmFamily: 'ChaCha20',
      primitive: Primitive.STREAM_CIPHER,
      filePath: 'customStream.js',
      line: 3,
    });
    staticFinding.addEvidence(new Evidence({
      source: 'constant',
      evidenceClass: EvidenceClass.SUPPORTING,
      detail: 'known-constant byte match for ChaCha20',
      rawConfidence: 0.5,
    }));

    const malformedLlmFinding = new CryptoFinding({
      assetType: AssetType.ALGORITHM,
      name: 'stream-cipher',
      algorithmFamily: 'stream-cipher',
      primitive: null,
      filePath: 'customStream.js',
      line: 3,
    });
    malformedLlmFinding.addEvidence(new Evidence({
      source: 'llm',
      evidenceClass: EvidenceClass.INTERPRETIVE,
      detail: 'xor loop',
      rawConfidence: 0.9,
    }));

    // If a malformed LLM finding were somehow produced, it must never overwrite the static finding's canonical fields
    const merged = aggregate([staticFinding, malformedLlmFinding]);
    const chacha = merged.find(f => f.algorithmFamily === 'ChaCha20');
    expect(chacha).toBeDefined();
    expect(chacha.algorithmFamily).toBe('ChaCha20');
    expect(chacha.primitive).toBe(Primitive.STREAM_CIPHER);
  });
});