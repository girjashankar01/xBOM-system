// Mirrors utils/transform.js's approach: parse whatever shape the backend
// actually sends, enrich into a flat UI-friendly asset, degrade gracefully
// when a field isn't populated yet rather than crashing the tab.
//
// Expected primary shape per asset (agreed contract, see
// cbom-frontend-blueprint.md §3):
//   { bomRef, name, assetType, sourceFile?, sourceLine?, quantumSecurityLevel,
//     classicalSecurityLevel?, confidence, evidenceSources, algorithmProperties?,
//     certificateProperties?, relatedCryptoMaterialProperties?, dependsOn }
//
// Also handles raw CycloneDX cryptographic-asset components (nested
// cryptoProperties) as a fallback, in case the backend hasn't flattened
// the response yet — see cbom-build-guide.md §3.1 for that shape.

export const ASSET_TYPE_ORDER = ['algorithm', 'certificate', 'protocol', 'related-crypto-material']

export const ASSET_TYPE_LABEL = {
  algorithm: 'Algorithm',
  certificate: 'Certificate',
  protocol: 'Protocol',
  'related-crypto-material': 'Key / Material',
}

export const QUANTUM_LEVELS = [0, 1, 2, 3, 4, 5]

export const CONFIDENCE_ORDER = ['very-high', 'high', 'medium', 'low']

export const CONFIDENCE_LABEL = {
  'very-high': 'Very high',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
}

export const EVIDENCE_LABEL = {
  static: 'Static rule match',
  sca: 'Dependency (SCA) match',
  embedding: 'Embedding similarity match',
  llm: 'LLM verification',
}

// Maps a NIST quantum security level to one of the app's existing severity
// colors, per the blueprint's "0=red, 1-2=orange, 3-5=green" scale.
export function quantumRiskTier(level) {
  if (level === 0) return 'critical'
  if (level === 1 || level === 2) return 'high'
  return 'safe'
}

export function quantumRiskLabel(level) {
  if (level === 0) return 'Broken by quantum'
  return `PQC category ${level}`
}

// Extracts a normalized field set whether the raw object is already flat
// (the agreed API contract) or is a raw CycloneDX cryptographic-asset
// component (nested under cryptoProperties).
function normalize(raw) {
  const cp = raw.cryptoProperties
  if (!cp) return raw // already flat

  return {
    bomRef: raw['bom-ref'] || raw.bomRef,
    name: raw.name,
    assetType: cp.assetType,
    sourceFile: raw.sourceFile,
    sourceLine: raw.sourceLine,
    quantumSecurityLevel: cp.algorithmProperties?.nistQuantumSecurityLevel ?? 0,
    classicalSecurityLevel: cp.algorithmProperties?.classicalSecurityLevel,
    confidence: raw.confidence || 'low',
    evidenceSources: raw.evidenceSources || [],
    algorithmProperties: cp.algorithmProperties,
    certificateProperties: cp.certificateProperties,
    relatedCryptoMaterialProperties: cp.relatedCryptoMaterialProperties,
    dependsOn: raw.dependsOn || [],
  }
}

export function enrichCryptoAsset(raw) {
  const a = normalize(raw)
  return {
    ...a,
    quantumSecurityLevel: a.quantumSecurityLevel ?? 0,
    confidence: a.confidence || 'low',
    evidenceSources: a.evidenceSources || [],
    riskTier: quantumRiskTier(a.quantumSecurityLevel ?? 0),
  }
}

// Pulls cryptographic-asset findings out of the shared scan response.
// Tries a few likely shapes so this doesn't break the moment backend
// settles on one — see cbom-frontend-blueprint.md §1 (same scan, filtered
// differently per tab).
export function getCryptoAssetsFromSbom(sbom) {
  if (!sbom) return []
  const raw =
    sbom.cryptoComponents ||
    sbom.cbom?.components ||
    (sbom.components || []).filter((c) => c.type === 'cryptographic-asset')
  return raw.map(enrichCryptoAsset)
}

const MS_PER_DAY = 1000 * 60 * 60 * 24

export function isCertExpiringSoon(asset, withinDays = 90) {
  const notValidAfter = asset.certificateProperties?.notValidAfter
  if (!notValidAfter) return false
  const days = (new Date(notValidAfter).getTime() - Date.now()) / MS_PER_DAY
  return days >= 0 && days <= withinDays
}

export function buildCbomSummary(assets) {
  const byAssetType = Object.fromEntries(ASSET_TYPE_ORDER.map((t) => [t, 0]))
  const byQuantumRisk = Object.fromEntries(QUANTUM_LEVELS.map((l) => [l, 0]))
  const byConfidence = Object.fromEntries(CONFIDENCE_ORDER.map((c) => [c, 0]))
  let flaggedForReview = 0
  let certsExpiringSoon = 0

  for (const a of assets) {
    if (a.assetType in byAssetType) byAssetType[a.assetType] += 1
    if (a.quantumSecurityLevel in byQuantumRisk) byQuantumRisk[a.quantumSecurityLevel] += 1
    if (a.confidence in byConfidence) byConfidence[a.confidence] += 1
    if (a.confidence === 'low') flaggedForReview += 1
    if (isCertExpiringSoon(a)) certsExpiringSoon += 1
  }

  return {
    totalAssets: assets.length,
    byAssetType,
    byQuantumRisk,
    byConfidence,
    flaggedForReview,
    certsExpiringSoon,
  }
}

export function formatPrimitiveLabel(asset) {
  const primitive = asset.algorithmProperties?.primitive
  if (!primitive) return '—'
  const mode = asset.algorithmProperties?.mode
  const size = asset.algorithmProperties?.parameterSetIdentifier
  return [primitive, size, mode].filter(Boolean).join(' / ')
}

export function formatSourceLabel(asset) {
  if (!asset.sourceFile) return 'Location unavailable'
  return asset.sourceLine ? `${asset.sourceFile}:${asset.sourceLine}` : asset.sourceFile
}
