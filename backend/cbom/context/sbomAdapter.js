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
  static fromCycloneDxJson(bom) {
    const byKey = new Map();

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
      const key = SbomAdapter._key(name, version);
      byKey.set(key, {
        name,
        version,
        ecosystem: SbomAdapter._ecosystemFromPurl(comp.purl || ''),
        devDependency: SbomAdapter._isDev(comp),
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
    // fall back to name-only match (first version found) — version pins in
    // the target repo's manifest may not exactly match what the SBOM tool
    // resolved if this runs before a fresh SBOM pass
    for (const [key, ctx] of this._componentsByKey) {
      if (key.startsWith(`${packageName}@`)) return ctx;
    }
    return null;
  }

  /**
   * Best-effort: matches `node_modules/<pkg>/...` paths to a known
   * component. Extend with your own import-resolution logic if you need
   * this to work for non-node_modules source files too.
   */
  getContextForFile(filePath) {
    if (!filePath.includes('node_modules')) return null;
    const parts = filePath.split('node_modules/').pop().split('/');
    if (!parts.length) return null;
    const pkgName = parts[0].startsWith('@') ? `${parts[0]}/${parts[1]}` : parts[0];
    return this.getContext(pkgName);
  }

  // ---- internals --------------------------------------------------------

  static _key(name, version) {
    return `${name}@${version}`;
  }

  static _isDev(comp) {
    // CycloneDX doesn't have a canonical "is dev dependency" field on
    // Component itself. If your generator stashes this in properties[]
    // (e.g. `sbomtool:npm:development`), match it here — adjust the
    // property name to match what YOUR src/modules generator actually
    // writes.
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
