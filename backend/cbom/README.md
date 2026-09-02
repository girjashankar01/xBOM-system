# retrieval/corpus — labeled reference snippets for embedding candidate retrieval

## What this is

`CandidateRetriever` (see `../vectorSearch.js`) loads every `*.jsonl` file in
this directory, embeds each `text` field once at process startup, and uses
cosine similarity to find the nearest labeled examples to a code span the
scanner couldn't confidently classify deterministically. This is **candidate
generation only** — a match here never confirms a finding by itself. It only
decides what gets forwarded to Phase 6's gated LLM verification.

## Format

One JSON object per line:

```json
{"text": "<code snippet>", "algorithm_family": "AES", "primitive": "symmetric", "source_repo": "seed"}
```

- `text` — the code span itself. Keep it AST-bounded (the enclosing
  function/method), not a raw line window — this is what `extractEnclosingSpan`
  in `embedder.js` produces for real scan targets, so curate seed entries at
  the same granularity for the embedding space to be comparable.
- `algorithm_family` — matches the family strings used elsewhere (e.g. `AES`,
  `RSA`, `SHA-256`, `HMAC`, `PBKDF2`) — not a `taxonomy.js` enum, just the
  human-readable family the finding will report.
- `primitive` — one of `taxonomy.js`'s `Primitive` values
  (`symmetric`, `hash`, `mac`, `asymmetric`, `kdf`, `ae`, `signature`,
  `key-agreement`, `drbg`).
- `source_repo` — where the snippet came from (a repo name, or `seed` for the
  hand-written starter entries in this directory). Keep this so you can trace
  a bad candidate back to a mislabeled source example during Phase 11
  benchmarking.

## Curation rules

- **Exclude `test/`, `spec/`, `mock`, `fixture` paths when mining real repos
  for corpus entries.** This is a separate concern from the Phase 4
  scan-time context classifier, which handles the *target* repo being
  scanned — this corpus is *reference* material, and test/mock code tends to
  contain deliberately wrong or oversimplified crypto usage that pollutes the
  embedding neighborhood.
- One file per primitive category keeps entries easy to audit and re-curate
  independently (`symmetric.jsonl`, `hash.jsonl`, etc.) — `CandidateRetriever`
  loads all of them together regardless of filename.
- Target 200-500 entries total once you've mined real repos (per the build
  guide). The files in this directory right now are a **small hand-written
  seed set** (~30 entries) meant to unblock testing `vectorSearch.js` and
  `embedder.js` end-to-end — nowhere near enough for real recall. Treat every
  seed entry as replaceable once you have real mined examples.
- Keep negative/near-miss examples too, not just positive crypto usage (e.g.
  a function that imports `crypto` but only uses `randomUUID()` for a
  non-security ID) — recall on ambiguous cases depends on the corpus having
  contrast, not just clean positives.

## Regenerating the index

There's no persisted index file — `CandidateRetriever.init()` re-embeds
every entry in this directory at process startup. That's the intended
design (see `vectorSearch.js`'s header comment): run the engine as a
persistent service and pay the embedding cost once per process, not once
per scan.
