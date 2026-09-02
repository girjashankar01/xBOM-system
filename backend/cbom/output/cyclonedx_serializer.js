// output/cyclonedx_serializer.js — Phase 10
//
// Mirrors serializer/cyclonedx.js's shape (bomFormat/specVersion/version/
// metadata/components) so a dashboard consuming both BOMs doesn't need two
// parsers. Component type here is 'cryptographic-asset' (CycloneDX 1.7
// cryptoProperties), not 'library' — genuinely a different schema branch,
// not a stylistic choice.
//
// Custom properties use the `cbomtool:` prefix, deliberately matching
// serializer/cyclonedx.js's `sbomtool:anomaly:${type}` convention — same
// pattern, same tool family, easy to filter for in a combined dashboard.
//
// sbomAdapter is OPTIONAL. Pass it (context/sbomAdapter.js's SbomAdapter
// instance) when you want vendor-context findings linked back to the npm
// package that owns them via CycloneDX's dependsOn/provides relationship
// (see CycloneDX's own cryptographic-algorithm use-case example, which
// links a crypto-asset component back to the library that provides it).
// Without it, you still get a fully valid CBOM — just no cross-links.

const crypto = require('node:crypto');
const { AssetType } = require('../core/taxonomy');

function slugify(s) {
  return String(s || 'unknown').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
}

/**
 * Deterministic bom-ref: same finding (same file/line/name), same run or a
 * rerun on unchanged source, same ref — makes diffing two scans of the
 * same repo meaningful instead of every finding getting a fresh UUID.
 */
function makeBomRef(finding) {
  const kind = finding.assetType === AssetType.RELATED_CRYPTO_MATERIAL ? 'key'
    : finding.assetType === AssetType.CERTIFICATE ? 'cert'
    : finding.assetType === AssetType.PROTOCOL ? 'protocol'
    : 'algorithm';
  const slug = slugify(finding.name || finding.algorithmFamily);
  const loc = finding.filePath
    ? `${slugify(finding.filePath)}-L${finding.line}`
    : crypto.createHash('sha1').update(finding.findingId).digest('hex').slice(0, 8);
  return `crypto/${kind}/${slug}@${loc}`;
}

function buildAlgorithmProperties(f) {
  const props = {};
  if (f.primitive) props.primitive = f.primitive;
  if (f.parameterSet) props.parameterSetIdentifier = String(f.parameterSet);
  if (f.mode) props.mode = f.mode;
  return props;
}

function buildRelatedCryptoMaterialProperties(f) {
  const props = {};
  if (f.materialType) props.type = f.materialType;
  return props;
}

function buildCertificateProperties(f) {
  const props = {};
  if (f.callContext && f.callContext.subject) props.subjectName = f.callContext.subject;
  if (f.callContext && f.callContext.validTo) {
    try {
      props.notValidAfter = new Date(f.callContext.validTo).toISOString();
    } catch {
      props.notValidAfter = String(f.callContext.validTo);
    }
  }
  if (f.signatureAlgorithm || f.parameterSet) {
    props.signatureAlgorithm = f.signatureAlgorithm || f.parameterSet;
  }
  return props;
}

function buildCustomProperties(f) {
  const props = [];
  if (f.quantumRisk) props.push({ name: 'cbomtool:quantumRisk', value: f.quantumRisk });
  if (f.nistQuantumLevel != null) props.push({ name: 'cbomtool:nistQuantumLevel', value: String(f.nistQuantumLevel) });
  if (f.confidence != null) props.push({ name: 'cbomtool:confidence', value: String(f.confidence) });
  if (f.contextCategory) props.push({ name: 'cbomtool:context', value: f.contextCategory });
  if (f.fingerprint) props.push({ name: 'cbomtool:fingerprint', value: f.fingerprint });
  for (const ev of f.evidence || []) {
    props.push({ name: `cbomtool:evidence:${ev.source}`, value: `${ev.evidenceClass} — ${ev.detail}` });
  }
  return props;
}

function buildCryptoComponent(f) {
  const bomRef = f.bomRef || makeBomRef(f);
  f.bomRef = bomRef; // fill the field models.js reserved for this

  const cryptoProperties = { assetType: f.assetType };
  if (f.assetType === AssetType.ALGORITHM) cryptoProperties.algorithmProperties = buildAlgorithmProperties(f);
  if (f.assetType === AssetType.RELATED_CRYPTO_MATERIAL) cryptoProperties.relatedCryptoMaterialProperties = buildRelatedCryptoMaterialProperties(f);
  if (f.assetType === AssetType.CERTIFICATE) cryptoProperties.certificateProperties = buildCertificateProperties(f);
  // protocolProperties intentionally omitted: core/models.js collects no
  // protocol-specific fields yet (version, cipher suites) — emitting an
  // empty object would be worse than omitting it. Add when a detector
  // populates them.

  const component = {
    type: 'cryptographic-asset',
    'bom-ref': bomRef,
    name: f.name,
    cryptoProperties,
  };

  const properties = buildCustomProperties(f);
  if (properties.length) component.properties = properties;

  return component;
}

/**
 * Resolves vendor-context findings to their owning npm package and
 * produces a CycloneDX dependencies[] block (ref: package, provides: [crypto
 * component refs]) — one entry per package, matching how buildCycloneDX's
 * own dependencies work in serializer/cyclonedx.js.
 */
function buildDependencies(findings, components, sbomAdapter) {
  const providesByPackageRef = new Map();

  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    if (f.contextCategory !== 'vendor') continue;
    const pkgCtx = sbomAdapter.getContextForFile(f.filePath);
    if (!pkgCtx || !pkgCtx.purl) continue;
    if (!providesByPackageRef.has(pkgCtx.purl)) providesByPackageRef.set(pkgCtx.purl, []);
    providesByPackageRef.get(pkgCtx.purl).push(components[i]['bom-ref']);
  }

  return Array.from(providesByPackageRef, ([ref, provides]) => ({ ref, provides }));
}

/** Builds a standalone CBOM. findings should already be validator.js-clean. */
function buildCBOM(findings, { sbomAdapter = null } = {}) {
  const components = findings.map(buildCryptoComponent);
  const dependencies = sbomAdapter ? buildDependencies(findings, components, sbomAdapter) : [];

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.7',
    version: 1,
    metadata: { timestamp: new Date().toISOString() },
    components,
    ...(dependencies.length ? { dependencies } : {}),
  };
}

/**
 * Appends a CBOM's components/dependencies into an existing SBOM bom
 * object (e.g. serializer/cyclonedx.js's buildCycloneDX() output) instead
 * of shipping two separate files. Use whichever of buildCBOM /
 * mergeIntoBom fits your dashboard — both are exposed since you hadn't
 * settled which layout you want yet.
 */
function mergeIntoBom(sbomBom, cbom) {
  return {
    ...sbomBom,
    components: [...(sbomBom.components || []), ...cbom.components],
    dependencies: [...(sbomBom.dependencies || []), ...(cbom.dependencies || [])],
  };
}

module.exports = { buildCBOM, mergeIntoBom, buildCryptoComponent, makeBomRef };