// scanner/candidateExtractor.test.js — Tests for crypto candidate span extraction & LLM tier integration

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { scanCandidates, sanitizeLine, matchesCryptoCall, tokenizeIdentifier, isTestPath } = require('./candidateExtractor');
const { CryptoFinding, Evidence, EvidenceClass } = require('../core/models');
const { AssetType } = require('../core/taxonomy');
const { runPipeline } = require('../cli/main');

describe('candidateExtractor unit tests', () => {
  test('matches crypto function/method calls on the invoked method or bare call, but not on receiver names', () => {
    const positiveCases = [
      'const isValid = verifySignature(token);',
      'if (crypto.verify(pub, sig, data)) { ... }',
      'await crypto.subtle.sign(key, data);',
      'someObj.hashPassword(pw);',
      'const result = authUser(credentials);',
      'const derived = kdf(secret, salt);',
      'const enc = encryptData(data, key);',
      'const dec = decryptMessage(ciphertext);',
      'const s = customSealPayload(data);',
    ];

    for (const code of positiveCases) {
      const clean = sanitizeLine(code);
      expect(matchesCryptoCall(clean)).toBe(true);
    }

    // Calls where only receiver variable had crypto-sounding word, but invoked method is unrelated
    const receiverOnlyCases = [
      'const upper = rawHash.toUpperCase();',
      'const trimmed = authToken.trim();',
      'const len = cipherConfig.length;',
      'const str = hashVal.toString();',
      'const lower = signatureBuffer.toLowerCase();',
      'const m = keyStr.match(/regex/);',
    ];

    for (const code of receiverOnlyCases) {
      const clean = sanitizeLine(code);
      expect(matchesCryptoCall(clean)).toBe(false);
    }
  });

  test('correctly rejects false positives where keywords are accidental substrings inside non-crypto words', () => {
    const nonCryptoCases = [
      'const parsed = parseAlgorithmIdentifier(raw);', // parSE ALgorithm -> seal
      'const sealed = resealArchive(archive);',         // reseal -> not a segment
      'const model = machineLearning(data);',           // mac in machine
      'const author = getAuthorName(book);',            // auth in author
      'const calculated = calculateTotal(a, b);',
      'const item = findOrCreateItem(id);',
      'const user = getAuthenticatedUserSession(req);', // session getter
    ];

    for (const code of nonCryptoCases) {
      const clean = sanitizeLine(code);
      expect(matchesCryptoCall(clean)).toBe(false);
    }
  });

  test('correctly ignores comments and string literals', () => {
    const ignoredCases = [
      '// TODO: add signature verification',
      '/* multiline comment verify(token) */',
      '* verify(token) in jsdoc',
      'const msg = "please verify your email";',
      "const note = 'sign up today';",
      'const log = `encrypt passwords before storing`;',
      'function calculateTotal(a, b) { return a + b; }',
    ];

    for (const code of ignoredCases) {
      const clean = sanitizeLine(code);
      const isComment = code.trim().startsWith('//') || code.trim().startsWith('/*') || code.trim().startsWith('*');
      if (!isComment) {
        expect(matchesCryptoCall(clean)).toBe(false);
      }
    }
  });

  test('excludes test files (including hyphenated crypto-test.js and foo-spec.js) and test directories', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-test-filter-'));
    try {
      const testDir = path.join(dir, 'test');
      fs.mkdirSync(testDir, { recursive: true });

      // Code in test directory
      fs.writeFileSync(path.join(testDir, 'helper.js'), 'const v = verifySignature(token);');
      // Dotted test file
      fs.writeFileSync(path.join(dir, 'app.test.js'), 'const v = verifySignature(token);');
      // Hyphenated test files
      fs.writeFileSync(path.join(dir, 'crypto-test.js'), 'const v = verifySignature(token);');
      fs.writeFileSync(path.join(dir, 'foo-spec.js'), 'const v = verifySignature(token);');
      // Real application file
      fs.writeFileSync(path.join(dir, 'app.js'), 'const v = verifySignature(token);');

      const candidates = scanCandidates(dir, []);
      expect(candidates.length).toBe(1);
      expect(candidates[0].filePath).toBe('app.js');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('extracts UNCLASSIFIED candidate findings from file', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-candidate-test-'));
    try {
      const code = `
        const jose = require('jose');
        // TODO: add signature verification
        const msg = "please verify your email";

        async function authenticateUser(token, key) {
          const isValid = verifySignature(token);
          const hashed = someObj.hashPassword('secret');
          return { isValid, hashed };
        }
      `;
      fs.writeFileSync(path.join(dir, 'authHelper.js'), code);

      const candidates = scanCandidates(dir, []);
      expect(candidates.length).toBeGreaterThanOrEqual(3);

      const importCandidate = candidates.find((c) => c.line === 2);
      expect(importCandidate).toBeDefined();
      expect(importCandidate.evidence[0].evidenceClass).toBe(EvidenceClass.UNCLASSIFIED);
      expect(importCandidate.evidence[0].detail).toContain('jose');

      const verifyCandidate = candidates.find((c) => c.line === 7);
      expect(verifyCandidate).toBeDefined();
      expect(verifyCandidate.evidence[0].evidenceClass).toBe(EvidenceClass.UNCLASSIFIED);

      const hashCandidate = candidates.find((c) => c.line === 8);
      expect(hashCandidate).toBeDefined();
      expect(hashCandidate.evidence[0].evidenceClass).toBe(EvidenceClass.UNCLASSIFIED);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('skips lines that already have DIRECT evidence from static scanners', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-candidate-skip-'));
    try {
      const code = `
        const crypto = require('crypto');
        function verify(pub, sig, data) {
          return crypto.verify('SHA256', data, pub, sig);
        }
      `;
      fs.writeFileSync(path.join(dir, 'verify.js'), code);

      const existingDirectFinding = new CryptoFinding({
        assetType: AssetType.ALGORITHM,
        name: 'RSA',
        algorithmFamily: 'RSA',
        filePath: 'verify.js',
        line: 4,
      });
      existingDirectFinding.addEvidence(new Evidence({
        source: 'ast',
        evidenceClass: EvidenceClass.DIRECT,
        detail: 'crypto.verify',
        rawConfidence: 0.95,
        filePath: 'verify.js',
        line: 4,
      }));

      const candidates = scanCandidates(dir, [existingDirectFinding]);
      // Line 4 is skipped because it has direct evidence
      expect(candidates.some((c) => c.line === 4)).toBe(false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('LLM verification tier integration & scanSummary telemetry', () => {
  test('gracefully handles unreachable LLM endpoint and records failures in scanSummary', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-llm-telemetry-'));
    try {
      const code = `
        async function checkToken(token) {
          const isValid = customVerifyFunction(token);
          return isValid;
        }
      `;
      fs.writeFileSync(path.join(dir, 'service.js'), code);

      // Mock fetch to reject (simulate unreachable endpoint)
      const originalFetch = global.fetch;
      global.fetch = jest.fn().mockRejectedValue(new Error('ECONNREFUSED 127.0.0.1:59999'));

      try {
        const result = await runPipeline(dir, {
          corpusDir: path.join(__dirname, '../retrieval/corpus'),
          skipLlm: false,
        });

        expect(result.scanSummary).toBeDefined();
        expect(result.scanSummary.candidateFindings).toBeGreaterThanOrEqual(1);
        expect(result.scanSummary.llmVerification.candidatesConsidered).toBeGreaterThanOrEqual(1);
        expect(result.scanSummary.llmVerification.llmCallsAttempted).toBeGreaterThanOrEqual(1);
        expect(result.scanSummary.llmVerification.llmCallsFailed).toBeGreaterThanOrEqual(1);
        expect(result.scanSummary.llmVerification.llmCallsSucceeded).toBe(0);
        expect(result.scanSummary.llmVerification.wallClockMs).toBeGreaterThanOrEqual(0);
      } finally {
        global.fetch = originalFetch;
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('successfully verifies a candidate when LLM endpoint responds with valid classification', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-llm-mock-'));
    try {
      const code = `
        async function runCrypto(data, key) {
          const cipher = customEncryptCall(data, key);
          return cipher;
        }
      `;
      fs.writeFileSync(path.join(dir, 'cryptoHelper.js'), code);

      // Mock global fetch to return a valid LLM response
      const originalFetch = global.fetch;
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          message: {
            content: JSON.stringify({
              algorithmFamily: 'AES',
              primitive: 'block-cipher',
              parameterSet: '256 bits',
              confidence: 0.9,
              reasoning: 'customEncryptCall performs AES block cipher encryption.',
            }),
          },
        }),
      });

      try {
        const result = await runPipeline(dir, {
          corpusDir: path.join(__dirname, '../retrieval/corpus'),
          skipLlm: false,
        });

        expect(result.scanSummary.llmVerification.candidatesConsidered).toBeGreaterThanOrEqual(1);
        expect(result.scanSummary.llmVerification.llmCallsSucceeded).toBeGreaterThanOrEqual(1);
        expect(result.scanSummary.llmVerification.llmCallsFailed).toBe(0);

        const aesFinding = result.findings.find((f) => f.algorithmFamily === 'AES');
        expect(aesFinding).toBeDefined();
        expect(aesFinding.evidence.some((e) => e.evidenceClass === EvidenceClass.INTERPRETIVE)).toBe(true);
      } finally {
        global.fetch = originalFetch;
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('enforces MAX_LLM_CANDIDATES safety cap and skips excess candidates when 100+ candidates exist', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-cap-test-'));
    try {
      // Generate 120 lines of candidate crypto calls
      const lines = [];
      for (let i = 1; i <= 120; i++) {
        lines.push(`const val_${i} = verifyCustomToken_${i}(token);`);
      }
      fs.writeFileSync(path.join(dir, 'manyCandidates.js'), lines.join('\n'));

      const originalFetch = global.fetch;
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          message: {
            content: JSON.stringify({
              algorithmFamily: 'ECDSA',
              primitive: 'signature',
              confidence: 0.9,
              reasoning: 'Verified token',
            }),
          },
        }),
      });

      try {
        const result = await runPipeline(dir, {
          corpusDir: path.join(__dirname, '../retrieval/corpus'),
          skipLlm: false,
          maxLlmCandidates: 50,
          concurrency: 4,
        });

        expect(result.scanSummary).toBeDefined();
        expect(result.scanSummary.candidateFindings).toBe(120);
        expect(result.scanSummary.llmVerification.candidatesConsidered).toBe(120);
        expect(result.scanSummary.llmVerification.candidatesSkippedDueToLimit).toBe(70);
        expect(result.scanSummary.llmVerification.llmCallsAttempted).toBe(50);
        expect(result.scanSummary.llmVerification.llmCallsSucceeded).toBe(50);
      } finally {
        global.fetch = originalFetch;
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('correctly counts well-formed negative no_crypto_detected responses as success without adding findings', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-nocrypto-test-'));
    try {
      const code = `
        function checkStatus(token) {
          const auth = verifyPlainSession(token);
          return auth;
        }
      `;
      fs.writeFileSync(path.join(dir, 'session.js'), code);

      const originalFetch = global.fetch;
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          message: {
            content: JSON.stringify({
              algorithmFamily: null,
              primitive: null,
              parameterSet: null,
              confidence: 0.0,
              reasoning: 'Plain session token check, no cryptography used.',
            }),
          },
        }),
      });

      try {
        const result = await runPipeline(dir, {
          corpusDir: path.join(__dirname, '../retrieval/corpus'),
          skipLlm: false,
        });

        expect(result.scanSummary.llmVerification.llmCallsAttempted).toBe(1);
        expect(result.scanSummary.llmVerification.llmCallsSucceeded).toBe(1);
        expect(result.scanSummary.llmVerification.noCryptoDetected).toBe(1);
        expect(result.scanSummary.llmVerification.llmCallsFailed).toBe(0);
        expect(result.scanSummary.llmVerification.failureReasons.schema_mismatch).toBe(0);

        // No findings added to clean findings
        const interpretiveFindings = result.findings.filter(f => f.evidence.some(e => e.evidenceClass === EvidenceClass.INTERPRETIVE));
        expect(interpretiveFindings).toHaveLength(0);
      } finally {
        global.fetch = originalFetch;
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('records schema_mismatch in failureReasons when LLM returns unresolvable invalid algorithm', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbom-mismatch-test-'));
    try {
      const code = `
        function checkStatus(token) {
          const auth = verifyPlainSession(token);
          return auth;
        }
      `;
      fs.writeFileSync(path.join(dir, 'session.js'), code);

      const originalFetch = global.fetch;
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          message: {
            content: JSON.stringify({
              algorithmFamily: 'completely-invalid-homebrew-cipher',
              primitive: 'stream-cipher',
              parameterSet: 'custom',
              confidence: 0.9,
              reasoning: 'Uses invalid homebrew cipher',
            }),
          },
        }),
      });

      try {
        const result = await runPipeline(dir, {
          corpusDir: path.join(__dirname, '../retrieval/corpus'),
          skipLlm: false,
        });

        expect(result.scanSummary.llmVerification.llmCallsAttempted).toBe(1);
        expect(result.scanSummary.llmVerification.llmCallsSucceeded).toBe(0);
        expect(result.scanSummary.llmVerification.llmCallsFailed).toBe(1);
        expect(result.scanSummary.llmVerification.failureReasons.schema_mismatch).toBe(1);
      } finally {
        global.fetch = originalFetch;
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
