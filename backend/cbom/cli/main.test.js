const test = require('node:test');
const assert = require('node:assert/strict');
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

test('runPipeline detects a known-constant hash match and a PEM private key', async () => {
  const dir = makeFixtureDir();
  try {
    const result = await runPipeline(dir, { skipLlm: true }); // no corpus set up yet

    assert.ok(result.findings.length >= 2, `expected >=2 findings, got ${result.findings.length}`);
    assert.equal(result.validation.errors.length, 0, 'validator should not reject either fixture finding');

    const md5Finding = result.findings.find((f) => f.algorithmFamily === 'MD5');
    assert.ok(md5Finding, 'expected an MD5 finding from the known-constant match');
    assert.ok(['HIGH', 'CRITICAL'].includes(md5Finding.quantumRisk), `MD5 should be HIGH or CRITICAL, got ${md5Finding.quantumRisk}`);

    const keyFinding = result.findings.find((f) => f.materialType === 'private-key');
    assert.ok(keyFinding, 'expected a private-key finding from the PEM matcher');

    assert.equal(result.cbom.bomFormat, 'CycloneDX');
    assert.equal(result.cbom.components.length, result.findings.length);
    assert.ok(result.cbom.components.every((c) => c.type === 'cryptographic-asset'));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('runPipeline rejects a non-existent target directory', async () => {
  await assert.rejects(() => runPipeline('/definitely/not/a/real/path'), /not a directory/);
});