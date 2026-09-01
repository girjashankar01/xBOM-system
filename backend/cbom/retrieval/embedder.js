// retrieval/embedder.js — Phase 5
//
// Embeds AST-BOUNDED code spans, not raw line ranges (signal dilution from
// unrelated surrounding lines is the #1 cause of poor embedding recall).
//
// Uses @xenova/transformers (ONNX Runtime under the hood, same class of
// engine PyTorch/sentence-transformers uses in the Python version) — runs
// entirely in Node, no Python process required. This was the actual
// blocker that made me recommend Python originally; it isn't one.
//
// Span extraction here is JS/TS-specific (via @babel/parser), which is the
// right default since your target repos are npm/JS projects — the Python
// port's `ast`-module approach only worked for Python source files anyway.
//
// npm i @xenova/transformers @babel/parser @babel/traverse

const fs = require('node:fs');

let _pipelinePromise = null;
const MODEL_NAME = 'Xenova/all-MiniLM-L6-v2'; // ONNX-converted port of the same model the Python guide references

async function getEmbedder() {
  if (!_pipelinePromise) {
    const { pipeline } = await import('@xenova/transformers');
    _pipelinePromise = pipeline('feature-extraction', MODEL_NAME);
  }
  return _pipelinePromise;
}

/**
 * Python-source lookback fallback (fixed line window) — used for any file
 * a JS/TS parser can't parse. For JS/TS files (the expected case), see
 * extractEnclosingSpan below.
 */
function fixedWindowSpan(filePath, targetLine, lookback = 40) {
  const lines = fs.readFileSync(filePath, 'utf-8').split('\n');
  const start = Math.max(0, targetLine - lookback);
  const end = Math.min(lines.length, targetLine + 5);
  return { filePath, startLine: start + 1, endLine: end, text: lines.slice(start, end).join('\n') };
}

/**
 * Walks the Babel AST to find the smallest enclosing function/class
 * containing targetLine. Falls back to a fixed lookback window if the file
 * isn't parseable JS/TS (e.g. it's actually Python — wire in a Python-aware
 * fallback there if your target repos are mixed-language).
 */
function extractEnclosingSpan(filePath, targetLine, lookback = 40) {
  const source = fs.readFileSync(filePath, 'utf-8');

  let parser, traverse;
  try {
    parser = require('@babel/parser');
    traverse = require('@babel/traverse').default;
  } catch {
    return fixedWindowSpan(filePath, targetLine, lookback);
  }

  let ast;
  try {
    ast = parser.parse(source, {
      sourceType: 'unambiguous',
      plugins: ['typescript', 'jsx', 'classProperties', 'decorators-legacy'],
      errorRecovery: true,
    });
  } catch {
    return fixedWindowSpan(filePath, targetLine, lookback);
  }

  let best = null;
  const consider = (path) => {
    const { start: startLine } = path.node.loc.start;
    const { line: endLine } = path.node.loc.end;
    if (startLine <= targetLine && targetLine <= endLine) {
      const span = endLine - startLine;
      if (!best || span < best.span) best = { startLine, endLine, span };
    }
  };

  traverse(ast, {
    FunctionDeclaration: consider,
    FunctionExpression: consider,
    ArrowFunctionExpression: consider,
    ClassMethod: consider,
    ClassDeclaration: consider,
  });

  if (!best) return fixedWindowSpan(filePath, targetLine, lookback);

  const lines = source.split('\n');
  const text = lines.slice(best.startLine - 1, best.endLine).join('\n');
  return { filePath, startLine: best.startLine, endLine: best.endLine, text };
}

async function embed(texts) {
  const embedder = await getEmbedder();
  const output = await embedder(texts, { pooling: 'mean', normalize: false });
  // output.data is a flat Float32Array; output.dims = [batch, seqOrPooled, hidden] depending on pooling.
  // With mean pooling, dims = [batch, hidden].
  const [batch, hidden] = output.dims;
  const vectors = [];
  for (let i = 0; i < batch; i++) {
    vectors.push(Array.from(output.data.slice(i * hidden, (i + 1) * hidden)));
  }
  return vectors;
}

module.exports = { extractEnclosingSpan, embed };

if (require.main === module) {
  const span = extractEnclosingSpan(process.argv[2], Number(process.argv[3]));
  console.log(span.text);
  embed([span.text]).then((v) => console.log(`embedding length: ${v[0].length}`));
}
