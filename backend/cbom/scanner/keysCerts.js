// scanner/keysCerts.js — Phase 2.5
//
// SECURITY BOUNDARY: this module NEVER returns, logs, or stores raw key or
// certificate bytes. Only a truncated SHA-256 fingerprint, the detected
// type, and file location leave this module. Do not "temporarily" add the
// raw material for debugging — grep this file in review for any use of
// `content` outside `fingerprint()` before merging.
//
// Uses Node's BUILT-IN crypto.X509Certificate for cert metadata — no extra
// dependency needed (this is a real advantage over the Python port, which
// needed the `cryptography` package for the same thing).

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const { CryptoFinding, Evidence, EvidenceClass } = require('../core/models');
const { AssetType, MaterialType } = require('../core/taxonomy');

const PATTERNS = [
  { label: MaterialType.PRIVATE_KEY, regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { label: 'certificate', regex: /-----BEGIN CERTIFICATE-----/g },
  { label: MaterialType.PUBLIC_KEY, regex: /-----BEGIN PUBLIC KEY-----/g },
];

const KEY_FILE_EXTENSIONS = new Set(['.pem', '.key', '.crt', '.cer', '.p12', '.pfx', '.jks', '.keystore']);
const SKIP_DIR_NAMES = new Set([
  'node_modules', '.git', 'dist', 'build', 'coverage', '.next',
  '__tests__', '__mocks__', 'test', 'tests', 'fixtures',
]);
const SIZE_GUARD_BYTES = 20_000; // read-full-content threshold for extensionless/misnamed key files

function isTestPath(filename, relPath = '') {
  if (/[._-](test|spec)\.[a-zA-Z0-9]+$/i.test(filename)) return true;
  const normalized = relPath.replace(/\\/g, '/');
  if (/(?:^|\/)(?:__tests__|__mocks__|test|tests)\//i.test(normalized)) return true;
  return false;
}

function fingerprint(buf) {
  // Never store or emit the actual key/cert bytes — hash only.
  return crypto.createHash('sha256').update(buf).digest('hex').slice(0, 16);
}

function* iterCandidateFiles(targetDir) {
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
      if (entry.isDirectory()) {
        stack.push(full);
      } else if (entry.isFile()) {
        const relPath = path.relative(targetDir, full).replace(/\\/g, '/');
        if (isTestPath(entry.name, relPath)) continue;
        const ext = path.extname(full).toLowerCase();
        const size = fs.statSync(full).size;
        if (KEY_FILE_EXTENSIONS.has(ext) || size < SIZE_GUARD_BYTES) {
          yield full;
        }
      }
    }
  }
}

function parseCertMetadata(pemBuffer) {
  try {
    const cert = new crypto.X509Certificate(pemBuffer);
    return {
      subject: cert.subject,
      validTo: cert.validTo,
      signatureAlgorithm: cert.publicKey?.asymmetricKeyType || null,
    };
  } catch {
    return {};
  }
}

function scan(targetDir) {
  const findings = [];

  for (const filePath of iterCandidateFiles(targetDir)) {
    let content;
    try {
      content = fs.readFileSync(filePath);
    } catch {
      continue;
    }
    const contentStr = content.toString('latin1');
    const seenLocations = new Set();

    for (const { label, regex } of PATTERNS) {
      const matcher = new RegExp(regex.source, regex.flags);
      let match;
      while ((match = matcher.exec(contentStr)) !== null) {
        const upToMatch = contentStr.slice(0, match.index);
        const line = (upToMatch.match(/\n/g) || []).length + 1;
        const locKey = `${filePath}:${line}:${label}`;
        if (seenLocations.has(locKey)) continue;
        seenLocations.add(locKey);

        const rest = contentStr.slice(match.index);
        const endIdx = rest.indexOf('-----END ');
        let blockStr;
        if (endIdx !== -1) {
          const endLineEnd = rest.indexOf('\n', endIdx);
          blockStr = endLineEnd !== -1 ? rest.slice(0, endLineEnd + 1) : rest.slice(0, endIdx + 30);
        } else {
          blockStr = rest;
        }
        const blockBuf = Buffer.from(blockStr, 'latin1');
        const fp = fingerprint(blockBuf);

        const isCert = label === 'certificate';

        const finding = new CryptoFinding({
          assetType: isCert ? AssetType.CERTIFICATE : AssetType.RELATED_CRYPTO_MATERIAL,
          name: isCert ? 'X.509 Certificate' : label,
          materialType: isCert ? null : label,
          filePath,
          line,
        });
        const ext = path.extname(filePath).toLowerCase();
        finding.fingerprint = fp;
        finding.keyExtension = ext;

        const hasStdExt = KEY_FILE_EXTENSIONS.has(ext);
        const baseRawConf = hasStdExt ? 0.95 : 0.80;

        finding.addEvidence(
          new Evidence({
            source: 'keys_certs',
            evidenceClass: EvidenceClass.DIRECT,
            detail: `PEM header match (${label}), fingerprint=${fp}${hasStdExt ? '' : ' (non-standard extension)'}`,
            rawConfidence: baseRawConf,
            filePath,
            line,
          })
        );

        if (isCert) {
          const meta = parseCertMetadata(blockBuf);
          if (meta.signatureAlgorithm) finding.parameterSet = meta.signatureAlgorithm;
          if (meta.subject || meta.validTo) {
            finding.callContext = { subject: meta.subject, validTo: meta.validTo };
            finding.addEvidence(
              new Evidence({
                source: 'keys_certs',
                evidenceClass: EvidenceClass.SUPPORTING,
                detail: `Parsed X.509 certificate metadata (subject=${meta.subject || 'unknown'})`,
                rawConfidence: 0.90,
                filePath,
                line,
              })
            );
          }
        }

        findings.push(finding);
      }
    }
  }

  return findings;
}

module.exports = { scan, fingerprint };

if (require.main === module) {
  scan(process.argv[2]).forEach((f) => console.log(f.toJSON()));
}
