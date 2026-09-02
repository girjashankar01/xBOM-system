// context/sbomAdapter.js — Phase 1
//
// Reads YOUR EXISTING SBOM TOOL'S CycloneDX JSON output (the object your own
// buildCycloneDX() produces). Does not re-parse package-lock.json
// independently — that duplicates work your SBOM tool already does.
//
// Same process, same codebase, same language now — you can literally
// `require('../serialize/cyclonedx')` output directly instead of reading a
// file round-trip, if you're calling this from within the same backend
// process. from Bom() / fromFile() below still work if the CBOM engine runs
// as a separate process/service and only sees the JSON file.

const fs = require('node:fs');

const cryptoLibMap = require('./crypto_library_map.json');
const { CryptoFinding, Evidence, EvidenceClass } = require('../core/models');
const { AssetType, Primitive, ContextCategory } = require('../core/taxonomy');

const PRIMITIVE_MAP = {
  kdf: Primitive.KDF,
  signature: Primitive.SIGNATURE,
  mac: Primitive.MAC,
  symmetric: Primitive.BLOCK_CIPHER,
  hash: Primitive.HASH,
  drbg: Primitive.DRBG,
  asymmetric: Primitive.PKE,
  'key-agreement': Primitive.KEY_AGREE,
  ae: Primitive.AE,
};

class SbomAdapter {
  constructor(componentsByKey) {
    this._componentsByKey = componentsByKey; // Map<"name@version", PackageContext>
  }

  // ---- construction -------------------------------------------------

  static fromFile(path) {
    const data = JSON.parse(fs.readFileSync(path, 'utf-8'));
    return SbomAdapter.fromCycloneDxJson(data);
  }

  /**
   * Parses a CycloneDX BOM (1.4-1.7 — component shape for `library`
   * components hasn't changed in ways that break this). Adjust the
   * OSV/vulnerability extraction if your SBOM tool stores CVEs somewhere
   * other than `vulnerabilities[]`.
   */
  static fromCycloneDxJson(bom, { targetDir = null } = {}) {
    const byKey = new Map();
    let directNames = new Set();

    if (targetDir) {
      try {
        const pkgJsonPath = require('node:path').join(targetDir, 'package.json');
        if (fs.existsSync(pkgJsonPath)) {
          const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
          directNames = new Set([
            ...Object.keys(pkg.dependencies || {}),
            ...Object.keys(pkg.devDependencies || {}),
          ]);
        }
      } catch {}
    }

    // index vulnerabilities by the bom-refs they affect, once
    const vulnsByRef = new Map();
    for (const vuln of bom.vulnerabilities || []) {
      const vulnId = vuln.id || '';
      for (const affected of vuln.affects || []) {
        const ref = affected.ref;
        if (!ref) continue;
        if (!vulnsByRef.has(ref)) vulnsByRef.set(ref, []);
        vulnsByRef.get(ref).push(vulnId);
      }
    }

    for (const comp of bom.components || []) {
      const name = comp.name;
      const version = comp.version || '';
      if (!name) continue;
      const bomRef = comp['bom-ref'] || '';
      const isDirect = directNames.has(name) || comp.scope === 'required' || comp.direct === true;
      const key = SbomAdapter._key(name, version);
      byKey.set(key, {
        name,
        version,
        ecosystem: SbomAdapter._ecosystemFromPurl(comp.purl || ''),
        devDependency: SbomAdapter._isDev(comp),
        isDirect,
        osvCves: vulnsByRef.get(bomRef) || [],
        purl: comp.purl || null,
        filePaths: [],
      });
    }
    return new SbomAdapter(byKey);
  }

  // ---- lookup ---------------------------------------------------------

  getContext(packageName, version = null) {
    if (version) {
      const hit = this._componentsByKey.get(SbomAdapter._key(packageName, version));
      if (hit) return hit;
    }
    // fall back to name-only match (first version found)
    for (const [key, ctx] of this._componentsByKey) {
      if (key.startsWith(`${packageName}@`)) return ctx;
    }
    return null;
  }

  /**
   * Matches `node_modules/<pkg>/...` paths to a known component.
   */
  getContextForFile(filePath) {
    const norm = (filePath || '').replace(/\\/g, '/');
    if (!norm.includes('node_modules/')) return null;
    const parts = norm.split('node_modules/').pop().split('/');
    if (!parts.length || !parts[0]) return null;
    const pkgName = parts[0].startsWith('@') ? `${parts[0]}/${parts[1]}` : parts[0];
    return this.getContext(pkgName);
  }

  /**
   * Checks a package name against known crypto libraries map and keywords.
   */
  static getCryptoPackageInfo(packageName) {
    if (!packageName) return null;
    const lower = packageName.toLowerCase();

    // 1. Direct hit in crypto_library_map.json
    if (cryptoLibMap[lower]) {
      return { ...cryptoLibMap[lower], exactMatch: true };
    }

    // 2. Unscoped / alias match
    const unscoped = lower.includes('/') ? lower.split('/')[1] : lower;
    if (cryptoLibMap[unscoped]) {
      return { ...cryptoLibMap[unscoped], exactMatch: false, unscopedMatch: true };
    }

    // 3. Keyword / stem matching for common crypto package names
    if (/^bcrypt(-nodejs|js)?$/.test(unscoped)) {
      return {
        cryptoCapable: true,
        primitives: ['kdf'],
        algorithmFamilies: ['bcrypt'],
        notes: 'Bcrypt password hashing library',
        exactMatch: false,
      };
    }
    if (/^(jsonwebtoken|jwt-simple|jose|jwa|jws|node-jose)$/.test(unscoped)) {
      return {
        cryptoCapable: true,
        primitives: ['signature', 'mac', 'asymmetric'],
        algorithmFamilies: ['JWT', 'HMAC', 'RSA', 'ECDSA'],
        notes: 'JWT / JWA / JOSE library',
        exactMatch: false,
      };
    }
    if (/^(crypto-js|node-forge|forge|tweetnacl|elliptic|noble-secp256k1)$/.test(unscoped)) {
      return {
        cryptoCapable: true,
        primitives: ['symmetric', 'hash', 'signature', 'asymmetric'],
        algorithmFamilies: ['AES', 'SHA-256', 'RSA', 'ECDSA'],
        notes: 'General crypto library',
        exactMatch: false,
      };
    }

    return null;
  }

  /**
   * Evaluates all packages in the SBOM against the crypto capability library map.
   * Emits debug logging per component as requested.
   */
  findCryptoDependencies() {
    const cryptoDeps = [];
    for (const [key, ctx] of this._componentsByKey) {
      const info = SbomAdapter.getCryptoPackageInfo(ctx.name);
      const isMatch = info && info.cryptoCapable !== false;
      console.log(`[sbomAdapter] component check: "${ctx.name}@${ctx.version}" against crypto_library_map.json -> ${isMatch ? `MATCH (${info.algorithmFamilies.join(', ')})` : 'no match'}`);
      if (isMatch) {
        cryptoDeps.push({
          ...ctx,
          cryptoInfo: info,
        });
      }
    }
    return cryptoDeps;
  }

  /**
   * Generates SCA-level CryptoFindings for crypto packages declared in the SBOM.
   * Computes dynamic confidence based on direct vs transitive status, exact vs fuzzy match,
   * and live AST code usage in the target repository.
   */
  generateScaFindings({ astFindings = [] } = {}) {
    const cryptoDeps = this.findCryptoDependencies();
    const findings = [];

    for (const dep of cryptoDeps) {
      const info = dep.cryptoInfo;
      const primaryFamily = (info.algorithmFamilies && info.algorithmFamilies[0]) || dep.name;
      const primaryPrim = (info.primitives && info.primitives[0]) ? PRIMITIVE_MAP[info.primitives[0]] : null;
      const filePath = `node_modules/${dep.name}/package.json`;

      // 1. Base match quality
      let rawConfidence = info.exactMatch ? 0.70 : 0.50;

      // 2. Direct vs. Transitive
      if (dep.isDirect) {
        rawConfidence += 0.15;
      } else {
        rawConfidence -= 0.10;
      }

      // 3. Dev dependency adjustment
      if (dep.devDependency) {
        rawConfidence -= 0.10;
      }

      // 4. Code usage corroboration: check if target repo has AST findings referencing this algorithm/package
      const hasCodeCorroboration = astFindings.some((af) => {
        const matchesFamily = af.algorithmFamily && info.algorithmFamilies && info.algorithmFamilies.includes(af.algorithmFamily);
        const matchesName = af.evidence && af.evidence.some((e) => e.detail && (e.detail.includes(dep.name) || (dep.name.includes('/') && e.detail.includes(dep.name.split('/')[1]))));
        return matchesFamily || matchesName;
      });

      if (hasCodeCorroboration) {
        rawConfidence += 0.20;
      }

      rawConfidence = Math.max(0.15, Math.min(0.98, Math.round(rawConfidence * 100) / 100));

      const isHighConfidenceDirect = dep.isDirect && hasCodeCorroboration;
      const contextCategory = isHighConfidenceDirect ? ContextCategory.PRODUCTION : ContextCategory.VENDOR;

      const f = new CryptoFinding({
        assetType: AssetType.ALGORITHM,
        name: primaryFamily,
        algorithmFamily: primaryFamily,
        primitive: primaryPrim,
        filePath,
        line: 1,
        contextCategory,
        sourceContext: 'live',
      });

      f.addEvidence(
        new Evidence({
          source: 'sca',
          evidenceClass: isHighConfidenceDirect ? EvidenceClass.DIRECT : EvidenceClass.SUPPORTING,
          detail: `known crypto-capable package in dependency tree: ${dep.name}@${dep.version} (${info.notes || 'crypto library'}) [${dep.isDirect ? 'direct' : 'transitive'}${hasCodeCorroboration ? ', active code usage' : ''}]`,
          rawConfidence,
          filePath,
          line: 1,
        })
      );

      findings.push(f);
    }

    return findings;
  }

  // ---- internals --------------------------------------------------------

  static _key(name, version) {
    return `${name}@${version}`;
  }

  static _isDev(comp) {
    for (const prop of comp.properties || []) {
      if ((prop.name || '').endsWith('development') && prop.value === 'true') return true;
    }
    return false;
  }

  static _ecosystemFromPurl(purl) {
    if (purl.startsWith('pkg:npm/')) return 'npm';
    if (purl.startsWith('pkg:pypi/')) return 'pypi';
    return 'unknown';
  }
}

module.exports = { SbomAdapter };

if (require.main === module) {
  const adapter = SbomAdapter.fromFile(process.argv[2]);
  console.log(JSON.stringify(adapter.getContext(process.argv[3]), null, 2));
}
