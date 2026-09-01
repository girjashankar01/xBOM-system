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

  test('rejects a non-existent target directory', async () => {
    await expect(runPipeline('/definitely/not/a/real/path')).rejects.toThrow(/not a directory/);
  });
});