// analysis/confidence.js — Phase 7 (scoring half)
//
// Evidence-class scoring table (build guide §3.3 / §7 Phase 7) — NOT a
// weighted sum. Direct and supporting evidence on the same finding are
// correlated (they're usually the same underlying code fact observed
// twice, e.g. a Semgrep API match plus its own metavariable-bound param),
// so summing independent raw_confidence values would double-count one real
// signal. This table is hand-designed and intentionally coarse — calibrate
// it against a real benchmark (guide Phase 11) once you have one; these
// numbers are the guide's own starting values, not derived from data.
//
// ADDITION vs. the guide's pseudocode: the guide's score() only looks at
// evidence classes. context_classifier/classify.js's own module docstring
// already commits to more than that though — it says test/vendor findings
// are "reduced-weight in the confidence engine (Phase 7)", not silently
// dropped. That downweighting has to live somewhere, and this is the
// module the classify.js docstring names, so CONTEXT_CAP below is what
// makes good on that comment. It multiplies the evidence-class base score;
// it never drops a finding outright, and "unknown" context is capped
// tighter than "production" but looser than test/vendor since it's
// unresolved, not confirmed-safe-to-ignore.

const { EvidenceClass } = require('../core/models');

const SCORE_DIRECT_AND_SUPPORTING = 0.99;
const SCORE_DIRECT_ONLY = 0.95;
const SCORE_SUPPORTING_AND_INTERPRETIVE = 0.70;
const SCORE_INTERPRETIVE_ONLY = 0.30; // LLM-only: flag for manual review, don't silently include
const SCORE_SUPPORTING_ONLY = 0.10;   // e.g. bare constant match: weak, review needed
const SCORE_NO_EVIDENCE = 0.0;

const CONTEXT_CAP = {
  production: 1.0,
  test: 0.4,
  vendor: 0.4,
  unknown: 0.7,
};

function baseScore(evidence) {
  if (!evidence || !evidence.length) return 0.0;

  const directEv = evidence.filter((e) => e.evidenceClass === EvidenceClass.DIRECT);
  const supportingEv = evidence.filter((e) => e.evidenceClass === EvidenceClass.SUPPORTING);
  const interpretiveEv = evidence.filter((e) => e.evidenceClass === EvidenceClass.INTERPRETIVE);

  if (directEv.length) {
    const maxDirect = Math.max(...directEv.map((e) => e.rawConfidence));
    if (supportingEv.length) {
      return Math.min(0.99, Math.round((maxDirect + 0.04) * 100) / 100);
    }
    return maxDirect;
  }

  if (supportingEv.length && interpretiveEv.length) {
    const maxSupp = Math.max(...supportingEv.map((e) => e.rawConfidence));
    const maxInterp = Math.max(...interpretiveEv.map((e) => e.rawConfidence));
    return Math.min(0.85, (maxSupp + maxInterp) / 2);
  }

  if (interpretiveEv.length) {
    return Math.max(...interpretiveEv.map((e) => e.rawConfidence)) * 0.5;
  }

  if (supportingEv.length) {
    return Math.max(...supportingEv.map((e) => e.rawConfidence)) * 0.25;
  }

  return 0.0;
}

function score(evidence, contextCategory = 'unknown') {
  const base = baseScore(evidence);
  const cap = CONTEXT_CAP[contextCategory] ?? CONTEXT_CAP.unknown;
  return Math.round(base * cap * 1000) / 1000;
}

/**
 * Mutates and returns findings with `.confidence` set. Run AFTER
 * analysis/evidence.js aggregation (so the full merged evidence set is
 * present) and AFTER context_classifier/classify.js (so contextCategory
 * is final) — running this before either produces an artificially low
 * score for findings whose evidence/context is still split across
 * multiple objects.
 */
function scoreFindings(findings) {
  for (const f of findings) {
    f.confidence = score(f.evidence, f.contextCategory);
  }
  return findings;
}

module.exports = { score, scoreFindings, CONTEXT_CAP };

if (require.main === module) {
  const { Evidence, EvidenceClass: EC } = require('../core/models');
  const directPlusSupporting = [
    new Evidence({ source: 'semgrep', evidenceClass: EC.DIRECT, detail: 'demo', rawConfidence: 0.95 }),
    new Evidence({ source: 'ast', evidenceClass: EC.SUPPORTING, detail: 'demo', rawConfidence: 0.9 }),
  ];
  console.log('direct+supporting, production ->', score(directPlusSupporting, 'production'));
  console.log('direct+supporting, vendor     ->', score(directPlusSupporting, 'vendor'));
  console.log('direct+supporting, unknown    ->', score(directPlusSupporting, 'unknown'));

  const interpretiveOnly = [new Evidence({ source: 'llm', evidenceClass: EC.INTERPRETIVE, detail: 'demo', rawConfidence: 0.6 })];
  console.log('llm-only, production          ->', score(interpretiveOnly, 'production'));
}
