// scanner/candidateExtractor.js — Extracts crypto-adjacent code spans for LLM verification
//
// Identifies code spans that are crypto-adjacent but didn't match any static DIRECT rule:
// 1. Imports of crypto-related packages (jose, jsonwebtoken, node-forge, @simplewebauthn/*,
//    tweetnacl, elliptic, @peculiar/webcrypto, crypto-js, bcrypt, sodium-native, libsodium, etc.)
// 2. Function/method calls matching crypto segments at identifier boundaries (e.g. verifySignature,
//    hashPassword, crypto.subtle.verify, etc.), while avoiding false-positive substring matches
//    (e.g. parseAlgorithmIdentifier, resealArchive, machineLearning).
//
// Skips test files (*.test.*, *.spec.*, test/, __tests__/) and lines that already received
// DIRECT evidence from astExtract.js, keysCerts.js, or constants.js.
// Tags candidates as EvidenceClass.UNCLASSIFIED with confidence ~0.35.

const fs = require('node:fs');
const path = require('node:path');
const { CryptoFinding, Evidence, EvidenceClass } = require('../core/models');
const { AssetType } = require('../core/taxonomy');

const CRYPTO_MODULE_PATTERN = /^(jose|jsonwebtoken|node-forge|forge|@simplewebauthn\/.*|tweetnacl|elliptic|@peculiar\/webcrypto|crypto-js|bcrypt.*|sodium-native|libsodium.*|noble-curves|noble-hashes|argon2|scrypt.*|jwa|jws|node-jose|webcrypto)$/i;

const CRYPTO_SEGMENTS = new Set([
  'verify', 'sign', 'encrypt', 'decrypt', 'hash', 'derive', 'auth', 'cipher',
  'mac', 'hmac', 'signature', 'kdf', 'digest', 'keygen', 'attestation',
  'assertion', 'generatekey', 'importkey', 'exportkey', 'seal', 'unseal',
  'box', 'secretbox',
]);

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'coverage', '.next',
  '__tests__', '__mocks__', 'test', 'tests', 'fixtures',
]);

function isTestPath(filename, relPath = '') {
  if (/[._-](test|spec)\.[a-zA-Z0-9]+$/i.test(filename)) return true;
  const normalized = relPath.replace(/\\/g, '/');
  if (/(?:^|\/)(?:__tests__|__mocks__|test|tests)\//i.test(normalized)) return true;
  return false;
}

function sanitizeLine(line) {
  let clean = line.replace(/\/\/.*$/, '');
  clean = clean.replace(/(["'`])(?:(?=(\\?))\2.)*?\1/g, '""');
  return clean;
}

function tokenizeIdentifier(ident) {
  const parts = ident.split(/[._]+/);
  const segments = [];
  for (const part of parts) {
    const words = part
      .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
      .replace(/([A-Z]+)([A-Z][a-z0-9])/g, '$1 $2')
      .toLowerCase()
      .split(/\s+/);
    segments.push(...words.filter(Boolean));
  }
  return segments;
}

function matchesCryptoCall(cleanLine) {
  const matches = cleanLine.match(/[a-zA-Z_$][a-zA-Z0-9_$.]*\s*(?=\()/g);
  if (!matches) return false;
  for (const callToken of matches) {
    const trimmed = callToken.trim();
    // Only inspect the invoked method/function name (the last part of a dotted chain)
    const dotParts = trimmed.split('.');
    const methodName = dotParts[dotParts.length - 1];
    const segments = tokenizeIdentifier(methodName);
    if (segments.some((s) => CRYPTO_SEGMENTS.has(s))) {
      return true;
    }
  }
  return false;
}

function walkDirectory(dir, targetDir = dir, fileList = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return fileList;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    const relPath = path.relative(targetDir, fullPath).replace(/\\/g, '/');

    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) {
        walkDirectory(fullPath, targetDir, fileList);
      }
    } else if (/\.(js|jsx|ts|tsx|mjs|cjs)$/i.test(entry.name) && !entry.name.endsWith('.d.ts')) {
      if (!isTestPath(entry.name, relPath)) {
        fileList.push(fullPath);
      }
    }
  }
  return fileList;
}

function scanCandidates(targetDir, staticFindings = []) {
  const directLines = new Set();
  for (const f of staticFindings) {
    if (f.evidenceClasses && f.evidenceClasses().has(EvidenceClass.DIRECT) && f.filePath && f.line) {
      directLines.add(`${f.filePath.replace(/\\/g, '/')}:${f.line}`);
    }
  }

  const files = walkDirectory(targetDir);
  const candidates = [];

  for (const file of files) {
    const relPath = path.relative(targetDir, file).replace(/\\/g, '/');
    let content = '';
    try {
      content = fs.readFileSync(file, 'utf-8');
    } catch {
      continue;
    }

    const lines = content.split('\n');
    const seenLinesInFile = new Set();
    let inBlockComment = false;

    lines.forEach((lineText, idx) => {
      const lineNum = idx + 1;
      const locKey = `${relPath}:${lineNum}`;
      if (directLines.has(locKey) || seenLinesInFile.has(lineNum)) return;

      let trimmed = lineText.trim();
      if (!trimmed) return;

      if (inBlockComment) {
        if (trimmed.includes('*/')) {
          inBlockComment = false;
          trimmed = trimmed.substring(trimmed.indexOf('*/') + 2).trim();
        } else {
          return;
        }
      }

      if (trimmed.startsWith('/*')) {
        if (trimmed.includes('*/')) {
          trimmed = trimmed.replace(/\/\*[\s\S]*?\*\//g, '').trim();
        } else {
          inBlockComment = true;
          return;
        }
      }

      if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;

      let isCandidate = false;
      let reason = '';

      // 1. Imports of crypto-related modules
      const reqMatch = trimmed.match(/(?:require\(|from\s+)['"]([^'"]+)['"]/);
      if (reqMatch && CRYPTO_MODULE_PATTERN.test(reqMatch[1])) {
        isCandidate = true;
        reason = `Import of crypto library "${reqMatch[1]}"`;
      }

      // 2. Crypto-adjacent function calls (segment-aware matching)
      if (!isCandidate) {
        const clean = sanitizeLine(trimmed);
        if (matchesCryptoCall(clean)) {
          isCandidate = true;
          reason = `Function/method invocation matching crypto pattern: ${trimmed.slice(0, 60)}`;
        }
      }

      if (isCandidate) {
        seenLinesInFile.add(lineNum);
        const finding = new CryptoFinding({
          assetType: AssetType.ALGORITHM,
          name: 'UNKNOWN',
          algorithmFamily: null,
          primitive: null,
          filePath: relPath,
          line: lineNum,
          sourceContext: 'live',
        });

        finding.addEvidence(new Evidence({
          source: 'ast',
          evidenceClass: EvidenceClass.UNCLASSIFIED,
          detail: reason,
          rawConfidence: 0.35,
          filePath: relPath,
          line: lineNum,
        }));

        candidates.push(finding);
      }
    });
  }

  return candidates;
}

module.exports = {
  scanCandidates,
  sanitizeLine,
  tokenizeIdentifier,
  matchesCryptoCall,
  isTestPath,
  CRYPTO_SEGMENTS,
};
