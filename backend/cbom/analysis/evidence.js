// analysis/evidence.js — Phase 7 (aggregation half)
//
// Merges raw per-detector CryptoFinding[] (Phase 2 semgrep/AST, Phase 2.5
// keys/certs, Phase 3 known-constants, Phase 5-6 embedding+LLM) into one
// finding per real-world crypto usage site. Without this step, four
// detectors hitting the same `crypto.createCipheriv('aes-256-gcm', ...)`
// line produce four separate CryptoFinding objects, each carrying only its
// own evidence — analysis/confidence.js would then score each one alone
// (e.g. semgrep's DIRECT-only finding at 0.95, the constant match's
// SUPPORTING-only finding at 0.10) instead of seeing DIRECT+SUPPORTING
// together on one finding (0.99). Aggregation has to run before scoring,
// not after.
//
// Merge key: same file, same assetType, line within `lineWindow`, and
// compatible algorithm identity (equal, or either side is null/'unknown').
// Deliberately does NOT merge across assetType — a certificate detection
// and an algorithm detection landing on the same line are two distinct
// assets, not duplicates of one finding.

const DEFAULT_LINE_WINDOW = 2;

function algoIdentityCompatible(a, b) {
  const an = (a || '').toLowerCase();
  const bn = (b || '').toLowerCase();
  if (!an || !bn || an === 'unknown' || bn === 'unknown') return true;
  return an === bn;
}

function normalizedPath(p) {
  return (p || '').replace(/\\/g, '/');
}

function shouldMerge(a, b, lineWindow) {
  if (a.assetType !== b.assetType) return false;
  if (normalizedPath(a.filePath) !== normalizedPath(b.filePath)) return false;
  if (Math.abs(a.line - b.line) > lineWindow) return false;
  return algoIdentityCompatible(a.algorithmFamily || a.name, b.algorithmFamily || b.name);
}

/** Copies scalar fields from `src` onto `dst` wherever `dst` is missing
 * them. Never overwrites a value `dst` already has — the earlier detector
 * in scan order (semgrep/AST, which is DIRECT evidence) keeps priority
 * over a later, lower-confidence signal filling the same field. */
function fillMissing(dst, src) {
  const fields = [
    'primitive', 'algorithmFamily', 'parameterSet', 'mode', 'materialType',
    'fingerprint', 'keyExtension', 'callContext',
  ];
  for (const f of fields) {
    if ((dst[f] === null || dst[f] === undefined) && src[f] != null) dst[f] = src[f];
  }
  if ((!dst.name || dst.name === 'unknown') && src.name && src.name !== 'unknown') {
    dst.name = src.name;
  }
  return dst;
}

/**
 * Merges raw findings from every detector phase into one finding per real
 * usage site. Does not mutate the input array; the returned findings ARE
 * (a subset of) the original objects, mutated in place via addEvidence/
 * fillMissing — callers should treat `findings` as consumed after this
 * call. Run this AFTER Phases 2, 2.5, 3, 5-6 have all produced their raw
 * finding lists and BEFORE context_classifier/classify.js and
 * analysis/confidence.js.
 */
function aggregate(findings, { lineWindow = DEFAULT_LINE_WINDOW } = {}) {
  const merged = [];

  for (const finding of findings) {
    const target = merged.find((m) => shouldMerge(m, finding, lineWindow));
    if (!target) {
      merged.push(finding);
      continue;
    }
    fillMissing(target, finding);
    for (const ev of finding.evidence) target.addEvidence(ev);
  }

  return merged;
}

module.exports = { aggregate, shouldMerge, algoIdentityCompatible };

if (require.main === module) {
  console.log(
    'analysis/evidence.js exports aggregate(findings). Wire it into your ' +
    'pipeline glue as: aggregate([...semgrepFindings, ...constantFindings, ' +
    '...keysCertsFindings, ...llmVerifiedFindings]) — run before classify() ' +
    'and score().'
  );
}
