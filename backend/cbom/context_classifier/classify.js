// contextClassifier/classify.js — Phase 4
//
// 4 categories, not 8 — expand only if Phase 11 benchmarking shows real
// value in splitting further. Findings tagged test/vendor are NOT dropped —
// they're reduced-weight in the confidence engine (Phase 7) and shown in a
// separate report section. Silent exclusion hides real findings from a
// reviewer who specifically wants "is there a vulnerable crypto call even
// in a vendored file."

const { ContextCategory } = require('../core/taxonomy');

const CATEGORY_PATTERNS = {
  [ContextCategory.TEST]: ['test/', 'tests/', 'spec/', '__tests__/', '__mocks__/', '.test.', '.spec.', 'mock', 'fixture'],
  [ContextCategory.VENDOR]: ['vendor/', 'node_modules/', 'third_party/', 'third-party/', 'dist/', 'build/'],
};

function classify(filePath) {
  const normalized = filePath.replace(/\\/g, '/').toLowerCase();

  for (const [category, patterns] of Object.entries(CATEGORY_PATTERNS)) {
    if (patterns.some((p) => normalized.includes(p))) return category;
  }

  // default: production if inside a conventional source directory, unknown
  // otherwise — "unknown" deliberately does NOT get production-level
  // confidence weight in Phase 7.
  const srcMarkers = ['src/', 'lib/', 'app/', 'backend/', 'server/'];
  if (srcMarkers.some((m) => normalized.includes(m)) || !normalized.replace(/^\/+|\/+$/g, '').includes('/')) {
    return ContextCategory.PRODUCTION;
  }

  return ContextCategory.UNKNOWN;
}

/** Mutates and returns findings with contextCategory set. */
function classifyFindings(findings) {
  for (const f of findings) {
    f.contextCategory = classify(f.filePath);
  }
  return findings;
}

module.exports = { classify, classifyFindings };

if (require.main === module) {
  for (const p of process.argv.slice(2)) {
    console.log(`${p} -> ${classify(p)}`);
  }
}
