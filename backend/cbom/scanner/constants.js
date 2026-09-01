// scanner/constants.js — Phase 3
//
// A match here is SUPPORTING evidence, NEVER DIRECT — test fixtures and
// educational/reference code also contain these literal constants, so a
// bare match can't confirm a real finding on its own. The confidence
// engine (Phase 7) only reaches HIGH confidence when this combines with
// DIRECT evidence (Semgrep/AST), or flags manual review when it's the only
// signal.
//
// Trivially defeated by obfuscation/byte-splitting — documented limitation.
// This layer exists to catch hand-rolled/vendored crypto that never goes
// through a recognized library API (so Semgrep's rules never fire), not to
// be unbeatable.

const fs = require('node:fs');
const path = require('node:path');

const { CryptoFinding, Evidence, EvidenceClass } = require('../core/models');
const { AssetType, Primitive } = require('../core/taxonomy');

// Each entry: constant bytes -> [algorithmFamily, primitive]. Extend as you
// profile real target repos in Phase 11 benchmarking.
// scanner/constants.js — KNOWN_CONSTANTS table, corrected
const KNOWN_CONSTANTS = [
  [Buffer.from('637c777bf26b6fc53001672bfed7ab7', 'hex'), ['AES', Primitive.BLOCK_CIPHER]],
  [Buffer.from('6a09e667bb67ae853c6ef372a54ff53', 'hex'), ['SHA-256', Primitive.HASH]],
  [Buffer.from('67452301efcdab8998badcfe10325476', 'hex'), ['SHA-1', Primitive.HASH]],
  [Buffer.from('0123456789abcdeffedcba9876543210', 'hex'), ['MD5', Primitive.HASH]],
  [Buffer.from('3a343d3937333f383a34', 'hex'), ['DES', Primitive.BLOCK_CIPHER]],
  [Buffer.from('expand 32-byte k', 'ascii'), ['ChaCha20', Primitive.STREAM_CIPHER]],
  [Buffer.from('ffffffffffffffffc90fdaa22168c234', 'hex'), ['FFDH', Primitive.KEY_AGREE]],
];
const SKIP_DIR_NAMES = new Set(['node_modules', '.git']);
const MAX_FILE_BYTES = 2_000_000;

function* iterFiles(targetDir) {
  const stack = [targetDir];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (SKIP_DIR_NAMES.has(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else if (entry.isFile()) yield full;
    }
  }
}

function scan(targetDir) {
  const findings = [];

  for (const filePath of iterFiles(targetDir)) {
    let stat;
    try {
      stat = fs.statSync(filePath);
      if (stat.size > MAX_FILE_BYTES) continue;
    } catch {
      continue;
    }

    let content;
    try {
      content = fs.readFileSync(filePath);
    } catch {
      continue;
    }

    for (const [constBytes, [family, primitive]] of KNOWN_CONSTANTS) {
      const idx = content.indexOf(constBytes);
      if (idx === -1) continue;

      const line = content.slice(0, idx).toString('latin1').split('\n').length;
      const finding = new CryptoFinding({
        assetType: AssetType.ALGORITHM,
        name: family,
        algorithmFamily: family,
        primitive,
        filePath,
        line,
      });
      finding.addEvidence(
        new Evidence({
          source: 'constant',
          evidenceClass: EvidenceClass.SUPPORTING, // never DIRECT — see module docstring
          detail: `known-constant byte match for ${family}`,
          rawConfidence: 0.5,
          filePath,
          line,
        })
      );
      findings.push(finding);
    }
  }

  return findings;
}

module.exports = { scan, KNOWN_CONSTANTS };

if (require.main === module) {
  scan(process.argv[2]).forEach((f) => console.log(f.toJSON()));
}
