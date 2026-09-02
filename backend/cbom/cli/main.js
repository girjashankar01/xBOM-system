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
const path = require('node:path');

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
const { scanCandidates } = require('../scanner/candidateExtractor');
const { EvidenceClass } = require('../core/models');

const DEFAULT_MAX_LLM_CANDIDATES = 50;
const DEFAULT_LLM_CONCURRENCY = 4;

async function runVerification(findings, {
  corpusDir,
  targetDir,
  maxLlmCandidates = DEFAULT_MAX_LLM_CANDIDATES,
  concurrency = DEFAULT_LLM_CONCURRENCY,
} = {}) {
  const eligible = [];
  for (const finding of findings) {
    if (!shouldVerify(finding.evidenceClasses())) continue; // already has DIRECT evidence
    if (!finding.filePath || !finding.line) continue;
    eligible.push(finding);
  }

  const totalEligible = eligible.length;
  let candidatesToProcess = eligible;
  let skippedCount = 0;

  if (totalEligible > maxLlmCandidates) {
    skippedCount = totalEligible - maxLlmCandidates;
    console.warn(`[main] LLM candidate count (${totalEligible}) exceeded safety cap (${maxLlmCandidates}) — truncating and skipping ${skippedCount} candidates.`);
    candidatesToProcess = eligible.slice(0, maxLlmCandidates);
  }

  const stats = {
    candidatesConsidered: totalEligible,
    candidatesSkippedDueToLimit: skippedCount,
    llmCallsAttempted: 0,
    llmCallsSucceeded: 0,
    noCryptoDetected: 0,
    llmCallsFailed: 0,
    wallClockMs: 0,
    failureReasons: {
      connection_error: 0,
      timeout: 0,
      invalid_json: 0,
      schema_mismatch: 0,
    },
  };

  let retriever = null;
  if (corpusDir) {
    const tRetriever = Date.now();
    try {
      retriever = await new CandidateRetriever(corpusDir).init();
      console.log(`[main] CandidateRetriever (Phase 5) initialized in ${Date.now() - tRetriever} ms`);
    } catch (err) {
      console.warn(`[main] retrieval corpus unavailable (${err.message}) — proceeding with Phase 6 LLM verification without vector candidate hints.`);
    }
  }

  const llmFindings = [];

  // Parallel pool worker over candidatesToProcess with concurrency limit
  let idx = 0;
  const poolLimit = Math.max(1, Math.min(concurrency, candidatesToProcess.length || 1));
  const workers = Array.from({ length: poolLimit }, async () => {
    while (idx < candidatesToProcess.length) {
      const currentIdx = idx++;
      const finding = candidatesToProcess[currentIdx];

      let span;
      try {
        const fullPath = targetDir ? path.resolve(targetDir, finding.filePath) : finding.filePath;
        span = extractEnclosingSpan(fullPath, finding.line);
      } catch {
        continue;
      }

      let candidates = [];
      if (retriever) {
        try {
          candidates = await retriever.candidates(span.text);
        } catch (err) {
          console.warn(`[main] candidate retrieval failed for ${finding.filePath}:${finding.line} — ${err.message}`);
        }
      }

      const verified = await verifySpan({
        filePath: finding.filePath,
        line: finding.line,
        codeText: span.text,
        candidates,
        contextCategory: finding.contextCategory,
        stats,
      });

      if (verified) {
        llmFindings.push(verified);
      }
    }
  });

  await Promise.all(workers);
  return { llmFindings, stats };
}

/**
 * Runs the full pipeline against targetDir. No file I/O beyond reading the
 * scanned tree and (optionally) an SBOM json — writing output is the CLI
 * wrapper's job, so tests can call this directly.
 */
async function runPipeline(targetDir, options = {}) {
  const totalStart = Date.now();
  const phaseTimingsMs = {};

  const {
    corpusDir = null,
    sbomPath = null,
    sbomJson = null,
    sbom = null,
    sbomAdapter: passedAdapter = null,
    skipLlm = false,
    maxLlmCandidates = DEFAULT_MAX_LLM_CANDIDATES,
    concurrency = DEFAULT_LLM_CONCURRENCY,
  } = options;

  if (!fs.existsSync(targetDir) || !fs.statSync(targetDir).isDirectory()) {
    throw new Error(`targetDir "${targetDir}" is not a directory`);
  }

  const defaultCorpusDir = require('node:path').join(__dirname, '../retrieval/corpus');
  const resolvedCorpusDir = corpusDir || (fs.existsSync(defaultCorpusDir) ? defaultCorpusDir : null);

  const tSbom = Date.now();
  let sbomAdapter = passedAdapter;
  let correlation = null;
  const inMemorySbom = sbomJson || sbom;
  if (!sbomAdapter && inMemorySbom) {
    try {
      sbomAdapter = SbomAdapter.fromCycloneDxJson(inMemorySbom, { targetDir });
    } catch (err) {
      console.warn(`[main] could not load in-memory SBOM — skipping correlation. ${err.message}`);
    }
  } else if (!sbomAdapter && sbomPath) {
    try { sbomAdapter = SbomAdapter.fromFile(sbomPath); } catch (err) {
      console.warn(`[main] could not load SBOM at ${sbomPath} — skipping correlation. ${err.message}`);
    }
  }
  phaseTimingsMs.sbomSetup = Date.now() - tSbom;

  // Phase 2: AST detector
  const tAst = Date.now();
  let astFindings = [];
  try {
    astFindings = scanAstExtract(targetDir);
  } catch (err) {
    console.warn(`[main] scanner/astExtract.js (Phase 2) skipped — ${err.message}`);
  }
  phaseTimingsMs.astExtract = Date.now() - tAst;

  // Phase 2.5: Keys & Certs Scanner
  const tKeys = Date.now();
  const keysFindings = scanKeysCerts(targetDir);
  phaseTimingsMs.keysCerts = Date.now() - tKeys;

  // Phase 2.5: Constants Scanner
  const tConst = Date.now();
  const constFindings = scanConstants(targetDir);
  phaseTimingsMs.constants = Date.now() - tConst;

  // Phase 1 / 3: SCA package-level crypto detection from SBOM
  const tSca = Date.now();
  const scaFindings = sbomAdapter ? sbomAdapter.generateScaFindings({ astFindings }) : [];
  phaseTimingsMs.sca = Date.now() - tSca;

  const staticFindings = [
    ...astFindings,
    ...keysFindings,
    ...constFindings,
    ...scaFindings,
  ];

  // Phase 2.9: Candidate Extractor
  const tCand = Date.now();
  const candidateFindings = scanCandidates(targetDir, staticFindings);
  phaseTimingsMs.candidateExtractor = Date.now() - tCand;
  console.log(`[main] scanCandidates extracted ${candidateFindings.length} candidate findings (static direct findings: ${staticFindings.length})`);

  // Phase 4: Context Classification
  const tClassify = Date.now();
  const rawFindings = [...staticFindings];
  classifyFindings(rawFindings);
  phaseTimingsMs.contextClassification = Date.now() - tClassify;

  // Phase 5 & 6: LLM Verification Tier
  const tLlm = Date.now();
  const candidatesToVerify = [...rawFindings, ...candidateFindings];
  const defaultStats = {
    candidatesConsidered: candidateFindings.length,
    candidatesSkippedDueToLimit: 0,
    llmCallsAttempted: 0,
    llmCallsSucceeded: 0,
    noCryptoDetected: 0,
    llmCallsFailed: 0,
    wallClockMs: 0,
    failureReasons: {
      connection_error: 0,
      timeout: 0,
      invalid_json: 0,
      schema_mismatch: 0,
    },
  };

  const { llmFindings, stats } = skipLlm
    ? { llmFindings: [], stats: defaultStats }
    : await runVerification(candidatesToVerify, {
        corpusDir: resolvedCorpusDir,
        targetDir,
        maxLlmCandidates,
        concurrency,
      });

  classifyFindings(llmFindings);
  phaseTimingsMs.llmVerificationTier = Date.now() - tLlm;

  // Phase 7a, 7b, 8, 7: Aggregation, Scoring, Quantum Risk, Validator
  const tAnalysis = Date.now();
  const merged = aggregate([...rawFindings, ...llmFindings]); // Phase 7a
  scoreFindings(merged);        // Phase 7b
  classifyQuantumRisk(merged);  // Phase 8

  const validation = validateFindings(merged); // Phase 7 (validator)
  for (const w of validation.warnings) console.warn(`[validator] warning: ${w.message} (${w.findingId})`);
  for (const e of validation.errors) console.error(`[validator] error: ${e.message} (${e.findingId})`);
  phaseTimingsMs.analysisAndValidation = Date.now() - tAnalysis;

  // Phase 10 & 11: Output Serialization & Correlation
  const tOutput = Date.now();
  const cbom = buildCBOM(validation.clean, { sbomAdapter }); // Phase 10

  if (sbomAdapter) { // Phase 11
    const correlated = correlateFindings(validation.clean, sbomAdapter);
    const compounding = findCompoundingRisk(correlated);
    correlation = { correlated, compounding: compounding.compounding, summary: buildCombinedRiskSummary(validation.clean, correlated, compounding) };
  }
  phaseTimingsMs.serializationAndCorrelation = Date.now() - tOutput;
  phaseTimingsMs.totalPipelineMs = Date.now() - totalStart;

  console.log('\n[main] Pipeline Phase Timing Breakdown:');
  console.log(`  - AST Extraction:               ${phaseTimingsMs.astExtract} ms`);
  console.log(`  - Keys & Certs Scanner:         ${phaseTimingsMs.keysCerts} ms`);
  console.log(`  - Constants Scanner:            ${phaseTimingsMs.constants} ms`);
  console.log(`  - SCA / SBOM Setup:             ${phaseTimingsMs.sbomSetup + phaseTimingsMs.sca} ms`);
  console.log(`  - Candidate Extractor:          ${phaseTimingsMs.candidateExtractor} ms`);
  console.log(`  - Context Classification:       ${phaseTimingsMs.contextClassification} ms`);
  console.log(`  - LLM Verification Tier:        ${phaseTimingsMs.llmVerificationTier} ms`);
  console.log(`  - Analysis & Validation:        ${phaseTimingsMs.analysisAndValidation} ms`);
  console.log(`  - CBOM Build & Serialization:   ${phaseTimingsMs.serializationAndCorrelation} ms`);
  console.log(`  => Total Pipeline Duration:     ${phaseTimingsMs.totalPipelineMs} ms\n`);

  const scanSummary = {
    totalFindings: validation.clean.length,
    directFindings: validation.clean.filter((f) => f.evidence.some((e) => e.evidenceClass === EvidenceClass.DIRECT)).length,
    candidateFindings: candidateFindings.length,
    llmVerification: {
      candidatesConsidered: stats.candidatesConsidered,
      candidatesSkippedDueToLimit: stats.candidatesSkippedDueToLimit || 0,
      llmCallsAttempted: stats.llmCallsAttempted,
      llmCallsSucceeded: stats.llmCallsSucceeded,
      noCryptoDetected: stats.noCryptoDetected || 0,
      llmCallsFailed: stats.llmCallsFailed,
      failureReasons: stats.failureReasons || {
        connection_error: 0,
        timeout: 0,
        invalid_json: 0,
        schema_mismatch: 0,
      },
      wallClockMs: stats.wallClockMs,
    },
    phaseTimingsMs,
  };

  return { cbom, validation, correlation, findings: validation.clean, scanSummary };
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
  console.log(`[scanSummary] Total Findings: ${result.scanSummary.totalFindings} (Direct: ${result.scanSummary.directFindings}) | LLM Verification: ${result.scanSummary.llmVerification.candidatesConsidered} candidates considered, ${result.scanSummary.llmVerification.llmCallsAttempted} attempted, ${result.scanSummary.llmVerification.llmCallsSucceeded} succeeded, ${result.scanSummary.llmVerification.llmCallsFailed} failed (${result.scanSummary.llmVerification.wallClockMs}ms)`);
}

module.exports = { runPipeline, parseArgs };

if (require.main === module) {
  main().catch((err) => { console.error(err); process.exitCode = 1; });
}