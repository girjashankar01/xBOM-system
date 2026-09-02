# SIH260077 — Next-Gen SBOM & CBOM Cryptographic Security Platform

An end-to-end Software Bill of Materials (**SBOM**) and Cryptography Bill of Materials (**CBOM**) analysis engine. It ingests any public Git repository, inspects software dependencies, enriches vulnerability feeds, statically traverses ASTs to detect code-level cryptographic primitives, attributes packages to crypto capabilities, scores multi-dimensional post-quantum and secret-exposure risk, verifies ambiguous sites via local in-process vector embeddings + offline LLM verification, and delivers a unified, interactive CycloneDX v1.7 dashboard.

---

## Table of Contents
1. [Architecture Overview](#1-architecture-overview)
2. [End-to-End Request Trace](#2-end-to-end-request-trace)
3. [SBOM Generation Pipeline](#3-sbom-generation-pipeline)
4. [CBOM Detection & Risk Analysis Pipeline](#4-cbom-detection--risk-analysis-pipeline)
5. [In-Process Embedder & Offline LLM Verification (Phases 5 & 6)](#5-in-process-embedder--offline-llm-verification)
6. [Frontend Data Contract & Mapping](#6-frontend-data-contract--mapping)
7. [System Data Flow Architecture](#7-system-data-flow-architecture)
8. [Known Limitations](#8-known-limitations)
9. [Installation & Run Guide](#9-installation--run-guide)

---

## 1. Architecture Overview

```
 ┌────────────────────────────────────────────────────────────────────────┐
 │                           REACT FRONTEND (Vite)                       │
 │  • Software (SBOM) Tab: Vulnerabilities, Anomalies, License Compliance │
 │  • Cryptography (CBOM) Tab: NIST Quantum Levels, Exposure Risk, Trees  │
 └───────────────────────────────────┬────────────────────────────────────┘
                                     │ HTTP (POST /api/scan)
                                     ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │                      EXPRESS BACKEND (Node.js)                         │
 │                                                                        │
 │  ┌──────────────────────────────────────────────────────────────────┐  │
 │  │ 1. INGEST & SBOM ENGINE                                          │  │
 │  │  • Git shallow clone (`repoIngest.js`)                           │  │
 │  │  • Lockfile parser v2/v3 (`npmLockParser.js`)                    │  │
 │  │  • npm registry cache (`npmCache.js`) & OSV client (`osv.js`)   │  │
 │  │  • Anomaly detectors: typosquat, staleness, pinning, scripts     │  │
 │  │  • CycloneDX v1.7 SBOM serializer (`cyclonedx.js`)               │  │
 │  └──────────────────────────────────┬───────────────────────────────┘  │
 │                                     ▼                                  │
 │  ┌──────────────────────────────────────────────────────────────────┐  │
 │  │ 2. CBOM DETECTION ENGINE                                         │  │
 │  │  • AST Visitor (`astExtract.js`): crypto, bcrypt, JWT, CryptoJS │  │
 │  │  • PEM File Scanner (`keysCerts.js`): private keys, X.509 certs  │  │
 │  │  • Constant Matcher (`constants.js`): AES S-box, ChaCha20 sigma │  │
 │  │  • SCA Package Attributor (`sbomAdapter.js` + library map)       │  │
 │  │  • Context Classifier (`classify.js`): prod, test, vendor, live  │  │
 │  └──────────────────────────────────┬───────────────────────────────┘  │
 │                                     ▼                                  │
 │  ┌──────────────────────────────────────────────────────────────────┐  │
 │  │ 3. VECTOR RETRIEVAL & GATED LLM VERIFICATION                     │  │
 │  │  • AST span extractor (`embedder.js`)                            │  │
 │  │  • In-process `@xenova/transformers` (`all-MiniLM-L6-v2` ONNX)   │  │
 │  │  • Cosine candidate retriever (`vectorSearch.js`)                │  │
 │  │  • Gated Ollama client (`llm_agent.js` with `qwen2.5-coder`)     │  │
 │  │  • Strict enum validator (`validateLlmResponse`)                 │  │
 │  └──────────────────────────────────┬───────────────────────────────┘  │
 │                                     ▼                                  │
 │  ┌──────────────────────────────────────────────────────────────────┐  │
 │  │ 4. AGGREGATION, SCORING, VALIDATION & CORRELATION                │  │
 │  │  • Multi-detector evidence aggregator (`evidence.js`)            │  │
 │  │  • Dynamic confidence engine (`confidence.js`)                   │  │
 │  │  • Quantum risk (NIST L0-L5) & exposure risk (`quantumRisk.js`)  │  │
 │  │  • CycloneDX validator & serializer (`cyclonedx_serializer.js`)  │  │
 │  │  • SBOM-CBOM cross-correlation engine (`correlation.js`)         │  │
 │  └──────────────────────────────────────────────────────────────────┘  │
 └────────────────────────────────────────────────────────────────────────┘
```

---

## 2. End-to-End Request Trace

When a user submits a repository URL via `POST /api/scan`, execution proceeds sequentially across modules:

1. **`backend/src/routes/scan.routes.js`**: Receives `{ githubUrl }`.
2. **`backend/src/modules/ingest/repoIngest.js` (`cloneRepo`)**: Executes a shallow `git clone --depth 1` into a unique temporary directory in the OS temp directory.
3. **`backend/src/modules/ingest/repoIngest.js` (`findLockfile`)**: Locates `package-lock.json`.
4. **`backend/src/modules/parse/npmLockParser.js` (`parseLockfile`)**: Parses npm lockfile format v2/v3, extracting all direct and transitive packages, purls, versions, install script flags, and dependency graph relationships.
5. **`backend/src/modules/cache/npmCache.js` & `backend/src/modules/enrich/npmRegistry.js`**: Fetches registry metadata with an in-memory TTL cache and concurrency throttle (10 parallel requests) to avoid registry rate limits.
6. **`backend/src/modules/enrich/osv.js` (`queryOsv`)**: Batches package PURLs into chunks of 500 and queries `https://api.osv.dev/v1/querybatch` to identify known CVEs/GHSAs.
7. **`backend/src/modules/anomaly/*.js` (`detectAnomalies`)**:
   - `typosquat.js`: Checks names against top 500 npm packages using Levenshtein distance $\le 2$.
   - `freshness.js`: Flags unmaintained packages (>2 years without an update).
   - `versionPinning.js`: Flags loose version constraints (`^`, `~`, `*`, `latest`).
   - `installScript.js`: Flags packages executing `preinstall`, `install`, or `postinstall` lifecycle scripts.
8. **`backend/src/modules/serialize/cyclonedx.js` (`buildCycloneDX`)**: Assembles standard CycloneDX v1.7 software BOM components, anomaly annotations, and vulnerability lists.
9. **`backend/cbom/cli/main.js` (`runPipeline`)**:
   - **Phase 1**: `SbomAdapter.fromCycloneDxJson` loads the SBOM and maps package dependencies.
   - **Phase 2**: `scanner/astExtract.js` runs Babel AST parsing across all target `.js`/`.mjs`/`.ts` files.
   - **Phase 2.5**: `scanner/keysCerts.js` parses PEM certificate and private key files on disk.
   - **Phase 3**: `scanner/constants.js` scans file buffers for cryptographic magic byte constants.
   - **Phase 3.5**: `sbomAdapter.generateScaFindings` identifies crypto-capable npm packages from the dependency tree.
   - **Phase 4**: `context_classifier/classify.js` categorizes code context (production, test, vendor).
   - **Phase 5 & 6**: `runVerification` gates non-direct findings, extracts AST function spans, queries local ONNX embeddings, prompts Ollama, and validates responses.
   - **Phase 7a**: `analysis/evidence.js` (`aggregate`) merges per-detector findings within a 2-line window without overwriting static truth.
   - **Phase 7b**: `analysis/confidence.js` (`scoreFindings`) computes dynamic confidence (0.0 to 1.0).
   - **Phase 8**: `analysis/quantumRisk.js` (`classifyFindings`) scores quantum risk (NIST levels) and exposure risk.
   - **Phase 9**: `validator/validate.js` validates CycloneDX v1.7 mutual exclusion rules.
   - **Phase 10**: `output/cyclonedx_serializer.js` formats the CBOM component tree.
   - **Phase 11**: `output/correlation.js` (`correlateCbomWithSbom`) builds cross-layer summaries.
10. **`backend/src/modules/ingest/repoIngest.js` (`cleanup`)**: Recursively deletes the cloned directory.
11. **Express Response**: Returns combined `{ sbom, cbom, correlation }` to the frontend client.

---

## 3. SBOM Generation Pipeline

### Lockfile Parsing & Ecosystem Normalization
- Handled in [`backend/src/modules/parse/npmLockParser.js`](file:///Users/althea/Developer/Projects/sih260077_SBOM/backend/src/modules/parse/npmLockParser.js).
- Supports npm `lockfileVersion: 2` and `3` (nested `packages` structure).
- Extracts standard Package URLs (`pkg:npm/<scope>%2F<name>@<version>`).
- Differentiates direct root dependencies (`lockData.packages[''].dependencies`) from transitive nested dependencies.

### Vulnerability Enrichment (OSV.dev)
- Handled in [`backend/src/modules/enrich/osv.js`](file:///Users/althea/Developer/Projects/sih260077_SBOM/backend/src/modules/enrich/osv.js).
- Batches PURLs into payloads of 500 components per POST request to `https://api.osv.dev/v1/querybatch`.
- Collects CVE, GHSA, severity scores, and affected version ranges.

### Anomaly Detectors
- **Typosquatting** ([`backend/src/modules/anomaly/typosquat.js`](file:///Users/althea/Developer/Projects/sih260077_SBOM/backend/src/modules/anomaly/typosquat.js)): Compares dependency names against a top-500 popular package dictionary. Calculates Levenshtein distance, flagging names with distance $1$ or $2$ (excluding scoped subpackages).
- **Staleness / Freshness** ([`backend/src/modules/anomaly/freshness.js`](file:///Users/althea/Developer/Projects/sih260077_SBOM/backend/src/modules/anomaly/freshness.js)): Checks release timestamps from registry metadata; flags components whose last release was $>730$ days (2 years) ago.
- **Version Pinning** ([`backend/src/modules/anomaly/versionPinning.js`](file:///Users/althea/Developer/Projects/sih260077_SBOM/backend/src/modules/anomaly/versionPinning.js)): Identifies floating version specifiers (`*`, `latest`, `^`, `~`, `>`).
- **Install Scripts** ([`backend/src/modules/anomaly/installScript.js`](file:///Users/althea/Developer/Projects/sih260077_SBOM/backend/src/modules/anomaly/installScript.js)): Flags packages configuring execution hooks (`preinstall`, `install`, `postinstall`).

---

## 4. CBOM Detection & Risk Analysis Pipeline

### 4.1 AST-Based Crypto API Detection (`astExtract.js`)
Uses `@babel/parser` and `@babel/traverse` to scan all JavaScript / TypeScript files:
- **Node.js `crypto` Module**:
  - `crypto.createHash('md5' | 'sha1' | 'sha256' | ...)`
  - `crypto.createCipheriv('aes-256-gcm' | 'des' | ...)` / `createCipher`
  - `crypto.createSign('RSA-SHA256' | ...)` / `createVerify`
  - `crypto.createHmac('sha256', secret)`
  - `crypto.pbkdf2` / `crypto.pbkdf2Sync` / `crypto.scrypt`
  - `crypto.randomBytes` / `crypto.randomUUID` $\rightarrow$ `CSPRNG` (`drbg`)
  - `crypto.generateKeyPairSync('rsa' | 'ec')` $\rightarrow$ In-memory keypair generation
- **Password Hashing**:
  - `bcrypt.hash` / `bcrypt.hashSync` $\rightarrow$ Primitive: `kdf`, Algorithm: `bcrypt`
  - `bcrypt.compare` / `bcrypt.compareSync` $\rightarrow$ Primitive: `null` (verification, not derivation), Quantum Risk: `NONE`
  - `bcrypt.genSalt` / `bcrypt.genSaltSync` $\rightarrow$ Asset Type: `related-crypto-material`, Material Type: `salt`
- **JWT / JWA / JOSE**:
  - `jwt.sign(payload, secret, { algorithm: 'HS256' | 'RS256' | 'none' })`
  - `jwt.verify(token, secret, ...)`
  - Flags weak configurations (e.g. algorithm `none` or weak HMAC secrets).
- **CryptoJS**:
  - `CryptoJS.AES.encrypt`, `CryptoJS.DES.encrypt`, `CryptoJS.TripleDES.encrypt`, `CryptoJS.RC4.encrypt`, `CryptoJS.MD5`, `CryptoJS.SHA256`, `CryptoJS.PBKDF2`.
- **Comment vs. Live Context Tagging**: AST visitors check whether nodes are contained inside comment blocks or unreachable dead code (`sourceContext: 'live' | 'comment'`). Comment findings receive a confidence discount.

### 4.2 Static File Scanning (`keysCerts.js`)
- Recursively walks target directories inspecting files for PEM headers:
  - `-----BEGIN CERTIFICATE-----` $\rightarrow$ Asset Type: `certificate`, Subject, Issuer, Expiry (`notValidAfter`), Algorithm Ref.
  - `-----BEGIN RSA PRIVATE KEY-----` / `-----BEGIN EC PRIVATE KEY-----` / `-----BEGIN PRIVATE KEY-----` $\rightarrow$ Asset Type: `related-crypto-material`, Type: `private-key`.

### 4.3 Package & SCA Attribution (`sbomAdapter.js`)
- Compares dependency tree components against [`crypto_library_map.json`](file:///Users/althea/Developer/Projects/sih260077_SBOM/backend/cbom/context/crypto_library_map.json) (73 curated crypto libraries including `bcrypt`, `jsonwebtoken`, `@noble/hashes`, `crypto-js`, `node-forge`, `tweetnacl`, `elliptic`, etc.).
- Evaluates exact catalog matches vs. keyword/stem fallbacks.

### 4.4 Schema Separation Rules (CycloneDX v1.7)
Enforced in [`backend/cbom/validator/validate.js`](file:///Users/althea/Developer/Projects/sih260077_SBOM/backend/cbom/validator/validate.js):
- **`algorithm`**: Must contain `algorithmProperties` (`primitive`, `algorithmFamily`, `parameterSetIdentifier`). Must **NOT** contain `materialType` or `certificateProperties`.
- **`related-crypto-material`**: Must contain `relatedCryptoMaterialProperties` (`type`: `private-key` | `public-key` | `secret-key` | `salt` | `token` | `iv` | `seed`). Must **NOT** contain `primitive`.
- **`certificate`**: Must contain `certificateProperties` (`subjectName`, `issuerName`, `notValidAfter`, `signatureAlgorithmRef`). Must **NOT** contain `primitive` or `materialType`.

### 4.5 Quantum-Risk Scoring Model (NIST Levels)
Scored in [`backend/cbom/analysis/quantumRisk.js`](file:///Users/althea/Developer/Projects/sih260077_SBOM/backend/cbom/analysis/quantumRisk.js):

| Algorithm Category | Algorithm Family / Primitives | NIST Quantum Level | Severity Label | Justification |
| :--- | :--- | :---: | :---: | :--- |
| **Broken Asymmetric** | RSA, ECDSA, ECDH, DSA, EdDSA | **Level 0** | `CRITICAL` | Vulnerable to Shor's algorithm on Cryptanalytically Relevant Quantum Computers (CRQCs). |
| **Broken Classical** | MD5, SHA-1, DES, 3DES, RC4, algorithm `none` | **Level 0** | `HIGH` | Classically broken (collision/preimage attacks); urgent migration priority. |
| **Grover-Affected Symmetric** | AES-128, ChaCha20, SHA-256, HMAC, SHA-512 | **Level 1–2** | `LOW` / `MEDIUM` | Quantum Grover speedup halves effective security ($2^{128} \rightarrow 2^{64}$); AES-256/SHA-384 provide 128-bit quantum security. |
| **Post-Quantum Crypto** | ML-KEM, ML-DSA, SLH-DSA, Kyber, Dilithium | **Level 3–5** | `NONE` | Quantum-resistant lattice/stateful hash signatures. |
| **Non-Quantum Relevant** | CSPRNG (`drbg`), salts, comparison ops | N/A | `NONE` | Randomness generators and helpers carry no mathematical trapdoor; quantum risk is not applicable. |

### 4.6 Secret Exposure Risk Scoring (Independent Dimension)
Distinct from quantum vulnerability:
- **`exposureRisk: CRITICAL`**: Assigned to `related-crypto-material` findings of type `private-key` found in committed repository files on disk (e.g. `server.key`, `id_rsa`).
- **`exposureRisk: NONE`**: Assigned to in-memory runtime key generation (e.g. `crypto.generateKeyPairSync('ec')`) because ephemeral keys in RAM are not repository secret leaks.

### 4.7 Dynamic Confidence Scoring Engine
Computed in [`backend/cbom/analysis/confidence.js`](file:///Users/althea/Developer/Projects/sih260077_SBOM/backend/cbom/analysis/confidence.js) (no flat constants):
- **AST Code Findings**: Direct string literal algorithm (`0.95` raw) vs. variable/inferred parameter (`0.75` raw). Scaled by context cap: Production (`1.0`), Test (`0.4`), Vendor (`0.7`).
- **File Findings**: Full ASN.1 / X.509 metadata parse (`0.90` raw) vs. plain header regex (`0.65` raw).
- **SCA Package Findings**:
  - Exact catalog match (`0.70` base) vs. stem/fuzzy match (`0.50` base).
  - Direct root dependency (`+0.15`) vs. transitive (`-0.10`).
  - Active AST code corroboration in repo (`+0.20`).
  - Dev-dependency (`-0.10`).

---

## 5. In-Process Embedder & Offline LLM Verification

### 5.1 How Embedder & Ollama Load and Run

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Node.js Process (In-Memory)                     │
│                                                                        │
│  astExtract / constants                                                │
│         │                                                              │
│         ▼                                                              │
│  shouldVerify(evidence) ──► (if no DIRECT evidence)                    │
│         │                                                              │
│         ▼                                                              │
│  extractEnclosingSpan() ──► Babel AST function slice                   │
│         │                                                              │
│         ▼                                                              │
│  @xenova/transformers ────► Xenova/all-MiniLM-L6-v2 (ONNX in-process)  │
│         │                   (auto-cached in ~/.cache/transformers)     │
│         ▼                                                              │
│  vectorSearch.js ─────────► Cosine similarity against corpus/*.jsonl   │
└─────────┬──────────────────────────────────────────────────────────────┘
          │ HTTP JSON POST (offline localhost only)
          ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        Ollama Daemon (localhost:11434)                 │
│                                                                        │
│  qwen2.5-coder:1.5b (or qwen2.5-coder:7b)                              │
│  Returns: { algorithmFamily, primitive, confidence, reasoning }        │
└─────────┬──────────────────────────────────────────────────────────────┘
          │ HTTP Response
          ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        Node.js Process (In-Memory)                     │
│                                                                        │
│  validateLlmResponse() ───► Rejects primitives in family field         │
│         │                   Canonicalizes to CycloneDX registry enum   │
│         ▼                                                              │
│  aggregate() ─────────────► Merges with static evidence                │
└────────────────────────────────────────────────────────────────────────┘
```

1. **In-Process Embedder (`@xenova/transformers`)**:
   - Runs **entirely in-process** inside the Node.js backend using ONNX Runtime.
   - Model: `Xenova/all-MiniLM-L6-v2` (384-dimensional dense embeddings).
   - Automatically downloads the ONNX weight files (~90MB) on first run and caches them locally in `~/.cache/transformers`. No separate server or Python process is required.
2. **Offline LLM Verification (`llm_agent.js`)**:
   - Model: `qwen2.5-coder:1.5b` (default for lightweight local development) or `qwen2.5-coder:7b`.
   - Endpoint: `http://localhost:11434/api/chat`.
   - Setup Requirement: Ollama is an external local daemon. The user can install Ollama and run `ollama pull qwen2.5-coder:1.5b`.
   - Environment Variables:
     - `OFFLINE_LLM_URL`: Custom endpoint URL (default: `http://localhost:11434/api/chat`).
     - `OFFLINE_LLM_MODEL`: Target model tag (default: `qwen2.5-coder:1.5b`). Configured and read in `backend/cbom/verification/llm_agent.js`.
3. **Gating Rule (`shouldVerify`)**:
   - Only triggers on findings that **lack** `EvidenceClass.DIRECT` (e.g. constant byte matches, heuristic code sites, or uncorroborated package matches).
   - High-confidence AST detections (direct literal calls) and PEM certificate matches bypass the LLM entirely, conserving compute.
4. **Graceful Fallback**:
   - If Ollama is offline or unreachable, `llm_agent.js` logs a clean warning and returns `null`.
   - The scan completes normally without failing, preserving all deterministic static and SCA findings.
5. **Strict Response Validation (`validateLlmResponse`)**:
   - Checks `algorithmFamily` against `registry_snapshot.json`.
   - Rejects responses where the LLM places a primitive type (e.g. `"stream-cipher"`) into the `algorithmFamily` field.
   - Coerces invalid primitives (e.g. `"xor"`) to `null`.

### 5.2 Running the LLM Verification Tier

- **Verify Ollama Status**:
  ```bash
  ollama list   # Confirm qwen2.5-coder:1.5b is downloaded
  ollama ps     # Confirm Ollama daemon is active and responsive
  ```
- **Default Execution**:
  LLM verification runs **by default** (`skipLlm: false`) on all `POST /api/scan` requests.
- **Escape Hatch (Fast Mode)**:
  Clients can pass `{"skipLlm": true}` in the JSON body of `POST /api/scan` to completely bypass Phase 5/6 vector search and LLM verification for ultra-fast CI or testing runs.
- **Graceful Fallback Behavior**:
  If the Ollama daemon is not running or unreachable at `http://localhost:11434`, the scan does **not** fail. It logs `[llm_agent] Ollama endpoint unreachable — skipping LLM verification` and completes the scan using static AST and catalog evidence.
- **Latency Impact**:
  Enabling LLM verification adds approximately **~1.8s to 2.5s** total wall-clock duration to an end-to-end repository scan (validated against `sahat/hackathon-starter` and `OWASP/NodeGoat`).

---

## 6. Frontend Data Contract & UI Mapping

The React frontend (`/frontend`) integrates with the backend via a single unified scan response:

### Categorical Confidence Mapping (`cbomTransform.js`)
- $\ge 0.85 \implies$ **Very high** (`bg-accent/15 text-accent`)
- $\ge 0.60 \implies$ **High** (`bg-raised text-muted`)
- $\ge 0.30 \implies$ **Medium** (`bg-medium/15 text-medium`)
- $< 0.30 \implies$ **Low** (`bg-high/15 text-high` $\rightarrow$ triggers *"Needs manual review"* filter)

### Quantum Security Level Mapping
- **Level 0**: Broken by quantum computers (Shor's algorithm) or broken classically $\implies$ Severity: `critical` / `high`
- **Level 1–2**: Grover's quadratic speedup (128-bit symmetric / 256-bit hash) $\implies$ Severity: `high`
- **Level 3–5**: Classical and post-quantum secure (AES-256, SHA-384, ML-KEM, ML-DSA) $\implies$ Severity: `safe`

### Certificate Expiration Window
- Certificates are flagged as **Expiring soon** if `notValidAfter` falls within **90 days** from scan time:
  $$\text{daysUntilExpiry} = \frac{\text{notValidAfter} - \text{now}}{86{,}400{,}000} \le 90$$

---

## 7. System Data Flow Diagram

```mermaid
sequenceDiagram
    autonumber
    actor User as Security Analyst
    participant UI as React Frontend (:5173)
    participant API as Express API (:5050)
    participant Ingest as Repo Ingest & Lock Parser
    participant OSV as OSV.dev REST API
    participant AST as Babel AST & Scanner
    participant Embed as ONNX Embedder (all-MiniLM-L6-v2)
    participant LLM as Ollama (qwen2.5-coder:1.5b)
    participant Cyclone as CycloneDX 1.7 Serializer

    User->>UI: Enter GitHub URL (e.g. sahat/hackathon-starter)
    UI->>API: POST /api/scan { githubUrl, skipLlm: false }
    API->>Ingest: Shallow git clone & parse package-lock.json v3
    Ingest-->>API: 1,222 components parsed
    API->>OSV: Query vulnerabilities (POST /v1/querybatch)
    OSV-->>API: Batch vulnerability records
    API->>API: Anomaly analysis (typosquat, freshness, version pins, install scripts)
    API->>AST: Run CBOM AST crypto detection & PEM scan
    AST-->>API: 29 crypto findings extracted
    loop Ambiguous / Non-Direct Findings
        API->>Embed: Embed enclosing AST function slice
        Embed-->>API: 384-d vector cosine similarity match
        API->>LLM: POST /api/chat { prompt, candidate context }
        LLM-->>API: { algorithmFamily, primitive, confidence }
        API->>API: validateLlmResponse() against registry enum
    end
    User->>UI: cbomTransform.js normalizes and renders dashboard
```

---

## 8. Known Limitations

1. **Language Scope**: AST crypto detection is implemented for **JavaScript and TypeScript** (Node.js and browser JS). Python, Go, Java, and C/C++ crypto calls are not statically extracted.
2. **Curated Library Map**: Package-level crypto capability attribution is bounded by the 73 curated package families in `crypto_library_map.json`. Unlisted third-party wrapper packages fall back to keyword matching.
3. **Threshold Calibration**: Confidence thresholds ($0.85$, $0.60$, $0.30$) and certificate expiry windows ($90$ days) are chosen heuristic thresholds tailored for audit visibility, not empirical ML benchmarks.
4. **LLM Verification Frequency**: Because AST detection and PEM parsing directly classify ground-truth crypto APIs with `DIRECT` evidence, the LLM verification gate triggers only on ambiguous constant matches or custom wrappers.

---

## 9. Installation & Run Guide

### 9.1 Prerequisites
- **Node.js**: v18.0.0 or higher (`node -v`)
- **npm**: v9.0.0 or higher (`npm -v`)
- **git**: Available on system `PATH` (`git --version`)
- **Ollama** (*Optional but Recommended for Phase 6 LLM Verification*):
  - macOS: Download from [ollama.com/download](https://ollama.com/download) or `brew install ollama`
  - Linux: `curl -fsSL https://ollama.com/install.sh | sh`

---

### 9.2 Running the Full Stack (Step-by-Step)

#### Step 1: Clone Repository & Install Dependencies

```bash
# Clone the repository
git clone https://github.com/aresoasis02/sih260077.git
cd sih260077_SBOM

# Install Backend Dependencies (Express, Babel, ONNX Transformers, Axios)
cd backend
npm install

# Install Frontend Dependencies (React 18, Vite, TailwindCSS)
cd ../frontend
npm install
```

#### Step 2: Set Up Ollama & Pull Coding Model (Optional)

1. Start the Ollama background daemon:
   ```bash
   ollama serve
   ```
   *(On macOS, launching the Ollama desktop application starts the daemon automatically).*
2. In a separate terminal, pull the model:
   ```bash
   ollama pull qwen2.5-coder:1.5b
   ```
   *(To use the larger 7B model, pull `ollama pull qwen2.5-coder:7b` and set `OFFLINE_LLM_MODEL=qwen2.5-coder:7b`).*
3. Verify that the model is ready:
   ```bash
   ollama list
   ```

> [!NOTE]
> If Ollama is not installed or running, the scanner gracefully falls back to deterministic AST rules and package catalogs without crashing.

#### Step 3: Configure Environment Variables

- **Backend Configuration** (no external API keys required; OSV.dev and npm registry are public):
  - `PORT`: HTTP port (default: `5000`; recommended: `5050` to avoid conflicts with macOS AirPlay).
  - `OFFLINE_LLM_URL`: Ollama chat endpoint (default: `http://localhost:11434/api/chat`).
  - `OFFLINE_LLM_MODEL`: Ollama model tag (default: `qwen2.5-coder:1.5b`). Configured in `backend/cbom/verification/llm_agent.js`.
- **Frontend Configuration** (`frontend/src/api.js`):
  - `VITE_API_BASE_URL`: Backend API URL (default: `http://localhost:5050/api`).

#### Step 4: Start the Backend Server (Terminal Tab 1)

```bash
cd backend
PORT=5050 npm run dev
```
*Expected log output:* `SBOM backend running on :5050`

#### Step 5: Start the Frontend Client (Terminal Tab 2)

```bash
cd frontend
npm run dev
```
*Expected log output:* `Local: http://localhost:5173/`

#### Step 6: Verify Operation & Run a Scan

1. Open `http://localhost:5173` in your browser.
2. Enter a public GitHub repository URL (e.g. `https://github.com/sahat/hackathon-starter` or `https://github.com/OWASP/NodeGoat`) and click **Scan**.
3. View the **Software (SBOM)** and **Cryptography (CBOM)** tabs side-by-side.
4. Alternatively, execute a scan via cURL:
   ```bash
   curl -X POST http://localhost:5050/api/scan \
     -H "Content-Type: application/json" \
     -d '{"githubUrl":"https://github.com/sahat/hackathon-starter"}' \
     -o scan-output.json
   ```

---

### 9.3 Run Automated Tests

```bash
cd backend

# Run the complete test suite (10 test suites, 59 unit tests)
npm test

# Run CBOM CLI and LLM verification unit tests specifically
npm test -- --testPathPattern="cbom/cli/main.test.js"
```