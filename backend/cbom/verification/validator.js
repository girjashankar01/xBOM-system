// verification/validator.js — Phase 7
//
// Enum-conformance check, run AFTER analysis/quantumRisk.js and BEFORE
// output/cyclonedx_serializer.js. Two independent checks, because they
// come from two different authorities:
//
//   1. Internal enums (AssetType, Primitive, MaterialType, ProtocolType)
//      checked against core/taxonomy.js — a closed set we control, so a
//      value outside it is a bug in an upstream detector. Hard error.
//
//   2. algorithmFamily checked against registry_snapshot.json's vendored
//      CycloneDX registry — NOT closed the same way. A detector can find a
//      real algorithm the registry hasn't catalogued (new cipher, vendor
//      proprietary KDF). Unknown families are a warning, not an error, and
//      the finding still passes through — CycloneDX's algorithmFamily is
//      SHOULD-match-enum, not MUST.

const { AssetType, Primitive, MaterialType } = require('../core/taxonomy');
const registry = require('./registry_snapshot.json');

const REGISTRY_FAMILY_SET = new Set(registry.algorithmFamilies);
const VALID_ASSET_TYPES = new Set(Object.values(AssetType));
const VALID_PRIMITIVES = new Set(Object.values(Primitive));
const VALID_MATERIAL_TYPES = new Set(Object.values(MaterialType));

class ValidationIssue {
  constructor({ level, field, findingId, message }) {
    this.level = level; // 'error' | 'warning'
    this.field = field;
    this.findingId = findingId;
    this.message = message;
  }
}

function checkEnum(value, validSet, field, findingId, issues, { required = false } = {}) {
  if (value === null || value === undefined || value === '') {
    if (required) {
      issues.push(new ValidationIssue({ level: 'error', field, findingId, message: `${field} is required but missing` }));
    }
    return;
  }
  if (!validSet.has(value)) {
    issues.push(new ValidationIssue({
      level: 'error', field, findingId,
      message: `${field}="${value}" is not a value core/taxonomy.js defines`,
    }));
  }
}

function checkAlgorithmFamily(finding, issues) {
  const family = finding.algorithmFamily;
  if (!family) return; // absence is fine — not every finding resolves a family (e.g. a bare cert)
  if (!REGISTRY_FAMILY_SET.has(family)) {
    issues.push(new ValidationIssue({
      level: 'warning', field: 'algorithmFamily', findingId: finding.findingId,
      message: `algorithmFamily="${family}" isn't in the vendored registry snapshot (dated ${registry.registryLastUpdated}) — still emitted as free text, but won't validate against strict CBOM consumers that enforce the enum`,
    }));
  }
}

/** Validates one CryptoFinding. Returns ValidationIssue[] (empty = clean). Never mutates. */
function validateFinding(finding) {
  const issues = [];
  const id = finding.findingId;

  checkEnum(finding.assetType, VALID_ASSET_TYPES, 'assetType', id, issues, { required: true });
  checkEnum(finding.primitive, VALID_PRIMITIVES, 'primitive', id, issues);
  checkEnum(finding.materialType, VALID_MATERIAL_TYPES, 'materialType', id, issues);

  if (finding.assetType === AssetType.RELATED_CRYPTO_MATERIAL) {
    if (!finding.materialType) {
      issues.push(new ValidationIssue({
        level: 'error', field: 'materialType', findingId: id,
        message: 'assetType is related-crypto-material but materialType is unset — CycloneDX requires relatedCryptoMaterialProperties.type',
      }));
    }
    if (finding.primitive) {
      issues.push(new ValidationIssue({
        level: 'error', field: 'primitive', findingId: id,
        message: `assetType is related-crypto-material but primitive="${finding.primitive}" is set — primitive only belongs under algorithmProperties (asset type algorithm)`,
      }));
    }
  }

  if (finding.assetType === AssetType.ALGORITHM) {
    if (finding.materialType) {
      issues.push(new ValidationIssue({
        level: 'error', field: 'materialType', findingId: id,
        message: `assetType is algorithm but materialType="${finding.materialType}" is set — materialType only belongs under relatedCryptoMaterialProperties`,
      }));
    }
  }

  if (finding.assetType === AssetType.CERTIFICATE) {
    if (finding.primitive) {
      issues.push(new ValidationIssue({
        level: 'error', field: 'primitive', findingId: id,
        message: `assetType is certificate but primitive="${finding.primitive}" is set`,
      }));
    }
    if (finding.materialType) {
      issues.push(new ValidationIssue({
        level: 'error', field: 'materialType', findingId: id,
        message: `assetType is certificate but materialType="${finding.materialType}" is set`,
      }));
    }
  }

  checkAlgorithmFamily(finding, issues);
  return issues;
}

/**
 * Validates a full finding set. `clean` = findings with zero error-level
 * issues (warnings still pass through). Caller (cli/main.js) decides
 * whether to hard-fail on `errors` or just drop those findings from the BOM.
 */
function validateFindings(findings) {
  const errors = [];
  const warnings = [];
  const clean = [];

  for (const finding of findings) {
    const issues = validateFinding(finding);
    const hasError = issues.some((i) => i.level === 'error');
    for (const issue of issues) (issue.level === 'error' ? errors : warnings).push(issue);
    if (!hasError) clean.push(finding);
  }

  return { clean, errors, warnings };
}

module.exports = { validateFinding, validateFindings, ValidationIssue };