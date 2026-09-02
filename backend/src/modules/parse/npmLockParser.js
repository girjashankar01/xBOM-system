//npmLockParser.js

const fs = require('fs');

function parseLockfile(lockPath) {
  const lockData = JSON.parse(fs.readFileSync(lockPath, 'utf-8'));

  if (!lockData.lockfileVersion || lockData.lockfileVersion < 2 || !lockData.packages) {
    throw new Error('lockfileVersion < 2 not supported — regenerate with npm 7+');
  }

  const components = [];

  for (const [pkgPath, pkgInfo] of Object.entries(lockData.packages)) {
    if (pkgPath === '') continue;
    if (!pkgInfo.version) continue;

    // pkgPath is "node_modules/foo" or, for a nested duplicate version,
    // "node_modules/bar/node_modules/foo". The real npm package name is only the
    // segment after the LAST "node_modules/" — registry lookups and declaredRanges
    // matching both need the bare name, not the full nested tree path.
    const segments = pkgPath.split('node_modules/');
    const name = segments[segments.length - 1];

    components.push({
      name,
      lockfilePath: pkgPath, // keep the full path too, useful for debugging/tree display later
      version: pkgInfo.version,
      purl: `pkg:npm/${encodeURIComponent(name)}@${pkgInfo.version}`,
      resolved: pkgInfo.resolved || null,
      integrity: pkgInfo.integrity || null,
      dev: pkgInfo.dev || false,
      optional: pkgInfo.optional || false,
      hasInstallScript: pkgInfo.hasInstallScript || false,
      declaredRanges: findDeclaredRanges(lockData.packages, name),
    });
  }

  return components;
}

function findDeclaredRanges(packages, targetName) {
  const ranges = [];
  for (const [, pkgInfo] of Object.entries(packages)) {
    if (pkgInfo.dependencies && pkgInfo.dependencies[targetName]) {
      ranges.push(pkgInfo.dependencies[targetName]);
    }
  }
  return ranges;
}

module.exports = { parseLockfile };