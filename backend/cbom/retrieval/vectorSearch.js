// retrieval/vectorSearch.js — Phase 5
//
// Treat retrieval as CANDIDATE GENERATION ONLY — nothing here confirms a
// finding. A high similarity score decides what gets sent to the Phase 6
// LLM gate, nothing more.
//
// No FAISS/hnswlib here on purpose: the guide's own corpus target is
// 200-500 entries. Brute-force cosine over a few hundred 384-dim vectors is
// low-single-digit milliseconds in plain JS — FAISS exists for
// million-scale corpora. If you ever actually get there, reach for a
// hosted vector DB (Qdrant/pgvector), not an in-process index either way.

const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');

const { embed } = require('./embedder');

function dot(a, b) {
  let s = 0;
  for (let i = 0; i < a.length; i++) s += a[i] * b[i];
  return s;
}

function norm(a) {
  return Math.sqrt(dot(a, a));
}

function cosine(a, b) {
  const denom = norm(a) * norm(b);
  return denom === 0 ? 0 : dot(a, b) / denom;
}

async function loadJsonlCorpus(corpusDir) {
  const entries = [];
  const files = fs.readdirSync(corpusDir).filter((f) => f.endsWith('.jsonl'));
  for (const file of files) {
    const rl = readline.createInterface({ input: fs.createReadStream(path.join(corpusDir, file)) });
    for await (const line of rl) {
      if (!line.trim()) continue;
      const row = JSON.parse(line);
      entries.push({
        text: row.text,
        algorithmFamily: row.algorithm_family,
        primitive: row.primitive,
        sourceRepo: row.source_repo || '',
      });
    }
  }
  return entries;
}

/**
 * Loads a labeled corpus (retrieval/corpus/*.jsonl — see corpus/README.md),
 * embeds it once at construction, and exposes nearest-neighbor lookup for a
 * query span. Construct this ONCE per process and reuse it — re-embedding
 * the corpus per request is the expensive part, not the search itself. Run
 * the CBOM engine as a persistent Express route/service from Phase 5
 * onward, not a fresh process per scan.
 */
class CandidateRetriever {
  constructor(corpusDir) {
    this.corpusDir = corpusDir;
    this.entries = null;
    this.vectors = null;
  }

  async init() {
    this.entries = await loadJsonlCorpus(this.corpusDir);
    if (!this.entries.length) {
      throw new Error(
        `No corpus entries found in ${this.corpusDir}. Populate retrieval/corpus/ before running retrieval — see corpus/README.md.`
      );
    }
    this.vectors = await embed(this.entries.map((e) => e.text));
    return this;
  }

  async candidates(queryText, k = 3, minScore = 0.75) {
    const [qvec] = await embed([queryText]);
    const scored = this.entries.map((entry, i) => ({ entry, score: cosine(qvec, this.vectors[i]) }));
    scored.sort((a, b) => b.score - a.score);
    return scored.filter((s) => s.score >= minScore).slice(0, k);
  }
}

module.exports = { CandidateRetriever, cosine };

if (require.main === module) {
  (async () => {
    const retriever = await new CandidateRetriever(process.argv[2]).init();
    const results = await retriever.candidates(process.argv[3]);
    for (const { entry, score } of results) {
      console.log(`${score.toFixed(3)}  ${entry.algorithmFamily} (${entry.primitive})  [${entry.sourceRepo}]`);
    }
  })();
}
