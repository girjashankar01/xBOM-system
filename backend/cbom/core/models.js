// core/models.js — Phase 0
//
// Internal domain model. CycloneDX is an output format — nothing in
// scanner/, contextClassifier/, retrieval/, verification/ or analysis/
// should import a cyclonedx package. Only your existing
// src/modules/serialize/cyclonedx.js (or its future extension) does.

const crypto = require('node:crypto');

const EvidenceClass = Object.freeze({
  DIRECT: 'direct',             // recognized API + literal algorithm/param
  SUPPORTING: 'supporting',     // dependency present, embedding similarity, constant match
  INTERPRETIVE: 'interpretive', // LLM classification
});

class Evidence {
  constructor({ source, evidenceClass, detail, rawConfidence, filePath = '', line = 0 }) {
    if (rawConfidence < 0 || rawConfidence > 1) {
      throw new RangeError(`rawConfidence must be in [0,1], got ${rawConfidence}`);
    }
    this.source = source;               // "semgrep" | "ast" | "sca" | "embedding" | "llm" | "constant" | "keys_certs"
    this.evidenceClass = evidenceClass;  // EvidenceClass value
    this.detail = detail;                // human-readable: rule id, similarity score, cve id, etc.
    this.rawConfidence = rawConfidence;
    this.filePath = filePath;
    this.line = line;
  }
}

class CryptoFinding {
  constructor({
    assetType,
    name,
    primitive = null,
    algorithmFamily = null,
    parameterSet = null,
    mode = null,
    materialType = null,
    filePath = '',
    line = 0,
    contextCategory = 'unknown',
    sourceContext = 'live',
  }) {
    this.assetType = assetType;
    this.name = name;
    this.primitive = primitive;
    this.algorithmFamily = algorithmFamily;
    this.parameterSet = parameterSet;
    this.mode = mode;
    this.materialType = materialType;

    this.filePath = filePath;
    this.line = line;

    this.callContext = null;             // reserved for future data-flow chain — do not populate yet
    this.contextCategory = contextCategory;
    this.sourceContext = sourceContext;   // "live" | "comment"

    this.nistQuantumLevel = null;        // filled by analysis/quantumRisk.js
    this.quantumRisk = null;             // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"

    this.evidence = [];                  // Evidence[]
    this.confidence = 0.0;               // filled by analysis/confidence.js

    this.findingId = crypto.randomUUID();
    this.bomRef = '';                    // deterministic URN, filled at serialization

    // key/cert-specific, never populated with raw material (Phase 2.5)
    this.fingerprint = null;
    this.keyExtension = null;
  }

  addEvidence(ev) {
    this.evidence.push(ev);
  }

  evidenceClasses() {
    return new Set(this.evidence.map((e) => e.evidenceClass));
  }

  /** Debug/logging helper — NOT the CycloneDX serialization path. */
  toJSON() {
    return {
      findingId: this.findingId,
      assetType: this.assetType,
      name: this.name,
      primitive: this.primitive,
      algorithmFamily: this.algorithmFamily,
      parameterSet: this.parameterSet,
      mode: this.mode,
      materialType: this.materialType,
      filePath: this.filePath,
      line: this.line,
      contextCategory: this.contextCategory,
      sourceContext: this.sourceContext,
      confidence: this.confidence,
      quantumRisk: this.quantumRisk,
      evidence: this.evidence.map((e) => ({
        source: e.source,
        evidenceClass: e.evidenceClass,
        detail: e.detail,
        rawConfidence: e.rawConfidence,
      })),
    };
  }
}

module.exports = { Evidence, EvidenceClass, CryptoFinding };
