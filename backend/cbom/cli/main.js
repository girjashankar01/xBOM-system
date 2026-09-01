// cli/main.js — pipeline glue
//
// Wires every phase built so far:
//   Phase 2.5  scanner/keysCerts.js
//   Phase 3    scanner/constants.js
//   Phase 4    context_classifier/classify.js
//   Phase 5/6  retrieval + verification/llm_agent.js (skipped gracefully
//              if no corpus dir or no offline LLM server is reachable)
//   Phase 7    analysis/evidence.js + analysis/confidence.js
//   Phase 8    analysis/quantumRisk.js
//   Phase 7    verification/validator.js (enum-conformance gate)
//   Phase 10   output/cyclonedx_serializer.js
//   Phase 11   output/correlation.js (only if --sbom is passed)
//
// NOT wired: Phase 2 (scanner/astExtract.js + semgrep_rules/*.yaml) —
// doesn't exist yet. That's the detector that recognizes actual library
// API calls (crypto.createCipheriv(...), require('crypto-js'), etc.) —
// by far the most common real-world crypto usage. This pipeline runs
// end-to-end today, but until Phase 2 exists it only catches (a) PEM
// keys/certs on disk and (b) raw known-algorithm byte constants. Don't
// read a demo run's finding count as representative until that's in.

const fs = require('node:fs');

const { classifyFindings } = require('../context_classifier/classify');
const { extractEnclosingSpan } = require('../retrieval/embedder');
const { CandidateRetriever } = require('../retrieval/vectorSearch');
const { shouldVerify, verifySpan } = require('../verification/llm_agent');
const { validateFindings } = require('../verification/validator');
const { aggregate } = require('../analysis/evidence');
const { scoreFindings } = require('../analysis/confidence');
const { classifyFindings: classifyQuantumRisk } = require('../analysis/quantumRisk');
const { buildCBOM } = require('../output/cyclonedx_serializer');
const { correlateFindings, findCompoundingRisk, buildCombinedRiskSummary } = require('../output/correlation');
const { SbomAdapter } = require('../context/sbomAdapter');
const { scan: scanKeysCerts } = require('../scanner/keysCerts');
const { scan: scanConstants } = require('../scanner/constants');

const { scan: scanAstExtract } = require('../scanner/astExtract');


async function runVerification(findings, { corpusDir }) {
  if (!corpusDir) {
    console.warn('[main] no corpusDir provided — skipping Phase 6 LLM verification.');
    return [];
  }
  let retriever;
  try {
    retriever = await new CandidateRetriever(corpusDir).init();
  } catch (err) {
    console.warn(`[main] retrieval corpus unavailable (${err.message}) — skipping Phase 6 LLM verification.`);
    return [];
  }

  const llmFindings = [];
  for (const finding of findings) {
    if (!shouldVerify(finding.evidenceClasses())) continue; // already has DIRECT evidence
    if (!finding.filePath || !finding.line) continue;

    let span;
    try { span = extractEnclosingSpan(finding.filePath, finding.line); } catch { continue; }

    let candidates = [];
    try { candidates = await retriever.candidates(span.text); } catch (err) {
      console.warn(`[main] candidate retrieval failed for ${finding.filePath}:${finding.line} — ${err.message}`);
    }

    const verified = await verifySpan({
      filePath: finding.filePath, line: finding.line, codeText: span.text,
      candidates, contextCategory: finding.contextCategory,
    });
    if (verified) llmFindings.push(verified);
  }
  return llmFindings;
}

/**
 * Runs the full pipeline against targetDir. No file I/O beyond reading the
 * scanned tree and (optionally) an SBOM json — writing output is the CLI
 * wrapper's job, so tests can call this directly.
 */
async function runPipeline(targetDir, options = {}) {
  const { corpusDir = null, sbomPath = null, skipLlm = false } = options;

  if (!fs.existsSync(targetDir) || !fs.statSync(targetDir).isDirectory()) {
    throw new Error(`targetDir "${targetDir}" is not a directory`);
  }

  // Phase 2: Semgrep/AST detector. Degrades gracefully when semgrep is not
  // on PATH (e.g. dev environments without semgrep installed) — warns and
  // returns [] so the rest of the pipeline still runs on Phase 2.5/3 findings.
  let astFindings = [];
  try {
    astFindings = scanAstExtract(targetDir);
  } catch (err) {
    console.warn(`[main] scanner/astExtract.js (Phase 2) skipped — ${err.message}`);
  }
  const rawFindings = [...astFindings, ...scanKeysCerts(targetDir), ...scanConstants(targetDir)];

  classifyFindings(rawFindings); // Phase 4, before verification so llm_agent gets real context

  const llmFindings = skipLlm ? [] : await runVerification(rawFindings, { corpusDir });
  classifyFindings(llmFindings);

  const merged = aggregate([...rawFindings, ...llmFindings]); // Phase 7a
  scoreFindings(merged);        // Phase 7b
  classifyQuantumRisk(merged);  // Phase 8

  const validation = validateFindings(merged); // Phase 7 (validator)
  for (const w of validation.warnings) console.warn(`[validator] warning: ${w.message} (${w.findingId})`);
  for (const e of validation.errors) console.error(`[validator] error: ${e.message} (${e.findingId})`);

  let sbomAdapter = null;
  let correlation = null;
  if (sbomPath) {
    try { sbomAdapter = SbomAdapter.fromFile(sbomPath); } catch (err) {
      console.warn(`[main] could not load SBOM at ${sbomPath} — skipping correlation. ${err.message}`);
    }
  }

  const cbom = buildCBOM(validation.clean, { sbomAdapter }); // Phase 10

  if (sbomAdapter) { // Phase 11
    const correlated = correlateFindings(validation.clean, sbomAdapter);
    const compounding = findCompoundingRisk(correlated);
    correlation = { correlated, compounding: compounding.compounding, summary: buildCombinedRiskSummary(validation.clean, correlated, compounding) };
  }

  return { cbom, validation, correlation, findings: validation.clean };
}

// ---- CLI wrapper -----------------------------------------------------

function parseArgs(argv) {
  const args = { targetDir: null, corpusDir: null, sbomPath: null, out: 'cbom-output.json', skipLlm: false };
  const positional = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--corpus') args.corpusDir = argv[++i];
    else if (a === '--sbom') args.sbomPath = argv[++i];
    else if (a === '--out') args.out = argv[++i];
    else if (a === '--no-llm') args.skipLlm = true;
    else positional.push(a);
  }
  args.targetDir = positional[0];
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.targetDir) {
    console.error('Usage: node cli/main.js <targetDir> [--corpus <dir>] [--sbom <sbom.json>] [--out <file>] [--no-llm]');
    process.exitCode = 1;
    return;
  }

  const result = await runPipeline(args.targetDir, { corpusDir: args.corpusDir, sbomPath: args.sbomPath, skipLlm: args.skipLlm });

  fs.writeFileSync(args.out, JSON.stringify(result.cbom, null, 2));
  console.log(`Wrote ${result.cbom.components.length} crypto-asset components to ${args.out}`);

  if (result.correlation) {
    const corrOut = args.out.replace(/\.json$/, '') + '.correlation.json';
    fs.writeFileSync(corrOut, JSON.stringify(result.correlation, null, 2));
    console.log(`Wrote correlation report to ${corrOut}`);
  }

  console.log(`Findings: ${result.findings.length} clean, ${result.validation.errors.length} rejected, ${result.validation.warnings.length} warnings.`);
}

module.exports = { runPipeline, parseArgs };

if (require.main === module) {
  main().catch((err) => { console.error(err); process.exitCode = 1; });
}