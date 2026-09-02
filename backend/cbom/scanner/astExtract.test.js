// cbom/scanner/astExtract.test.js
//
// Unit tests for AST crypto scanner (COSE identifiers, WebCrypto, and Node crypto API).

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const { scan } = require('./astExtract');
const { runPipeline } = require('../cli/main');

describe('astExtract scanner extensions', () => {
  test('detects pubKeyCredParams array with multiple COSE algorithm entries', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-cose-fixture-'));
    try {
      const code = `
        const registrationOptions = {
          rp: { name: 'Demo RP', id: 'example.com' },
          user: { id: '123', name: 'alice', displayName: 'Alice' },
          challenge: Buffer.from('random-challenge'),
          pubKeyCredParams: [
            { type: 'public-key', alg: -7 },   // ES256 (ECDSA P-256)
            { type: 'public-key', alg: -257 }, // RS256 (RSA PKCS#1 v1.5)
            { type: 'public-key', alg: -8 },   // EdDSA
            { type: 'public-key', alg: -37 },  // PS256 (RSA-PSS)
            { type: 'public-key', alg: -35 },  // ES384 (ECDSA P-384)
            { type: 'public-key', alg: -36 },  // ES512 (ECDSA P-521)
          ],
          timeout: 60000,
        };
      `;
      fs.writeFileSync(path.join(dir, 'webauthn-options.js'), code);

      const findings = scan(dir);
      const families = findings.map((f) => f.algorithmFamily);

      expect(families).toContain('ECDSA');
      expect(families).toContain('RSA');
      expect(families).toContain('EdDSA');
      expect(families).toContain('RSA-PSS');

      // Verify each finding has DIRECT evidence and signature primitive
      expect(findings.length).toBe(6);
      expect(findings.every((f) => f.primitive === 'signature')).toBe(true);
      expect(findings.every((f) => f.evidence[0].evidenceClass === 'direct')).toBe(true);

      const es256 = findings.find((f) => f.parameterSet === 'P-256 / ES256');
      expect(es256).toBeDefined();
      expect(es256.name).toBe('ECDSA');

      const rs256 = findings.find((f) => f.parameterSet === 'RS256');
      expect(rs256).toBeDefined();
      expect(rs256.name).toBe('RSA');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('detects crypto.subtle.verify with ECDSA/P-256 parameters', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-webcrypto-verify-'));
    try {
      const code = `
        async function verifyAssertion(publicKey, signature, clientDataJSON) {
          const isValid = await crypto.subtle.verify(
            { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } },
            publicKey,
            signature,
            clientDataJSON
          );
          return isValid;
        }
      `;
      fs.writeFileSync(path.join(dir, 'verifier.js'), code);

      const findings = scan(dir);
      expect(findings.length).toBeGreaterThanOrEqual(1);

      const ecdsaFinding = findings.find((f) => f.algorithmFamily === 'ECDSA');
      expect(ecdsaFinding).toBeDefined();
      expect(ecdsaFinding.primitive).toBe('signature');
      expect(ecdsaFinding.parameterSet).toContain('P-256');
      expect(ecdsaFinding.evidence[0].evidenceClass).toBe('direct');
      expect(ecdsaFinding.evidence[0].detail).toContain('crypto.subtle.verify');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('detects crypto.subtle.importKey for an EC public key', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-webcrypto-import-'));
    try {
      const code = `
        async function loadKey(keyBuffer) {
          const key = await crypto.subtle.importKey(
            'spki',
            keyBuffer,
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['verify']
          );
          return key;
        }
      `;
      fs.writeFileSync(path.join(dir, 'keyLoader.js'), code);

      const findings = scan(dir);
      expect(findings.length).toBeGreaterThanOrEqual(1);

      const keyFinding = findings.find((f) => f.algorithmFamily === 'ECDSA');
      expect(keyFinding).toBeDefined();
      expect(keyFinding.materialType).toBe('public-key');
      expect(keyFinding.parameterSet).toContain('P-256');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('detects Node crypto.verify and crypto.sign calls with require("crypto")', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-node-crypto-'));
    try {
      const code = `
        const crypto = require('crypto');

        function verifyToken(data, pubKey, sig) {
          const ok = crypto.verify('SHA256', data, pubKey, sig);
          const signature = crypto.sign('SHA256', data, privateKey);
          const pub = crypto.createPublicKey(pubKey);
          const priv = crypto.createPrivateKey(privateKey);
          return { ok, signature };
        }
      `;
      fs.writeFileSync(path.join(dir, 'signer.js'), code);

      const findings = scan(dir);
      const details = findings.map((f) => f.evidence[0].detail);

      expect(details.some((d) => d.includes('crypto.verify'))).toBe(true);
      expect(details.some((d) => d.includes('crypto.sign'))).toBe(true);
      expect(details.some((d) => d.includes('crypto.createPublicKey'))).toBe(true);
      expect(details.some((d) => d.includes('crypto.createPrivateKey'))).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('detects Node crypto.hkdf and crypto.pbkdf2Sync with require("node:crypto")', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-node-prefix-'));
    try {
      const code = `
        const crypto = require('node:crypto');

        function deriveSessionKeys(masterKey, salt, info) {
          const hkdfKey = crypto.hkdfSync('sha256', masterKey, salt, info, 32);
          const pbkdf2Key = crypto.pbkdf2Sync(masterKey, salt, 10000, 32, 'sha256');
          return { hkdfKey, pbkdf2Key };
        }
      `;
      fs.writeFileSync(path.join(dir, 'kdf.js'), code);

      const findings = scan(dir);
      const families = findings.map((f) => f.algorithmFamily);

      expect(families).toContain('HKDF');
      expect(families).toContain('PBKDF2');

      const hkdfFinding = findings.find((f) => f.algorithmFamily === 'HKDF');
      expect(hkdfFinding).toBeDefined();
      expect(hkdfFinding.primitive).toBe('kdf');
      expect(hkdfFinding.parameterSet).toBe('sha256');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('detects destructured imports from require("crypto") and require("node:crypto")', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-destructured-'));
    try {
      const code = `
        const { verify, sign, hkdf, timingSafeEqual } = require('node:crypto');

        function check(a, b, key, sig) {
          const validSig = verify('SHA256', a, key, sig);
          const newSig = sign('SHA256', a, key);
          const equal = timingSafeEqual(Buffer.from(a), Buffer.from(b));
          hkdf('sha384', key, 'salt', 'info', 32, () => {});
          return { validSig, newSig, equal };
        }
      `;
      fs.writeFileSync(path.join(dir, 'destructured.js'), code);

      const findings = scan(dir);
      const details = findings.map((f) => f.evidence[0].detail);

      expect(details.some((d) => d.includes('crypto.verify'))).toBe(true);
      expect(details.some((d) => d.includes('crypto.sign'))).toBe(true);
      expect(details.some((d) => d.includes('crypto.timingSafeEqual'))).toBe(true);
      expect(details.some((d) => d.includes('crypto.hkdf'))).toBe(true);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('scans a comprehensive WebAuthn controller fixture and detects rich cryptographic findings', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-webauthn-full-fixture-'));
    try {
      const webauthnController = `
        const crypto = require('node:crypto');

        // Static PEM private key for attestation / testing
        const ATTESTATION_KEY = [
          '-----BEGIN EC PRIVATE KEY-----',
          'MHcCAQEEILeK3oQv7W2...',
          '-----END EC PRIVATE KEY-----',
        ].join('\\n');

        // WebAuthn Registration Options (COSE identifiers)
        function generateRegistrationOptions() {
          const challenge = crypto.randomBytes(32);
          return {
            challenge: challenge.toString('base64url'),
            rp: { name: 'CBOM Secure App', id: 'localhost' },
            pubKeyCredParams: [
              { type: 'public-key', alg: -7 },   // ES256
              { type: 'public-key', alg: -257 }, // RS256
              { type: 'public-key', alg: -8 },   // EdDSA
            ],
            authenticatorSelection: {
              residentKey: 'preferred',
              userVerification: 'preferred',
            },
          };
        }

        // WebAuthn Verification Handler
        async function verifyAuthenticationResponse(credential, expectedChallenge, userPublicKey) {
          const clientData = JSON.parse(Buffer.from(credential.response.clientDataJSON, 'base64url').toString());
          
          // Verify signature using WebCrypto subtle API
          const isValid = await crypto.subtle.verify(
            { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } },
            userPublicKey,
            Buffer.from(credential.response.signature, 'base64url'),
            Buffer.from(credential.response.authenticatorData, 'base64url')
          );

          // Derive session key using HKDF
          const sessionKey = crypto.hkdfSync('sha256', userPublicKey, 'session-salt', 'auth-info', 32);

          return { isValid, sessionKey };
        }
      `;
      fs.writeFileSync(path.join(dir, 'webauthn.js'), webauthnController);

      const result = await runPipeline(dir, { skipLlm: true });
      expect(result.validation.errors).toHaveLength(0);

      // Previously, this file would only detect 1 finding (the EC private key from keysCerts.js)
      // Now it must detect:
      // 1. EC Private Key (keys_certs) with exposureRisk CRITICAL
      // 2. CSPRNG randomBytes (32 bytes / 256 bits)
      // 3. COSE ES256 (-7) (ECDSA P-256)
      // 4. COSE RS256 (-257) (RSA)
      // 5. COSE EdDSA (-8) (EdDSA)
      // 6. WebCrypto crypto.subtle.verify (ECDSA P-256 / SHA-256)
      // 7. HKDF (sha256)
      expect(result.findings.length).toBeGreaterThanOrEqual(6);

      const privateKey = result.findings.find((f) => f.materialType === 'private-key');
      expect(privateKey).toBeDefined();
      expect(privateKey.exposureRisk).toBe('CRITICAL');

      const coseFindings = result.findings.filter((f) => f.evidence.some((e) => e.detail.includes('COSE')));
      expect(coseFindings.length).toBe(3);

      const subtleFinding = result.findings.find((f) => f.evidence.some((e) => e.detail.includes('crypto.subtle.verify')));
      expect(subtleFinding).toBeDefined();
      expect(subtleFinding.algorithmFamily).toBe('ECDSA');

      const hkdfFinding = result.findings.find((f) => f.algorithmFamily === 'HKDF');
      expect(hkdfFinding).toBeDefined();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
