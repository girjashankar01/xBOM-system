// Client-side export. The original blueprint assumed a backend
// GET /api/scan/:scanId/cbom/export endpoint, but the actual backend has no
// scanId concept at all — POST /api/scan is a single synchronous call, no
// per-scan resources to fetch later (see api.js). So instead of hitting a
// route that doesn't exist, this reconstructs a CycloneDX-ish document from
// the data already in the browser and downloads it directly. If backend
// ever adds a real export endpoint, this can be swapped for a plain
// <a href> like the SBOM side's export was originally planned to be.

function toCycloneDxComponent(asset) {
  const cryptoProperties = { assetType: asset.assetType }

  if (asset.algorithmProperties) {
    cryptoProperties.algorithmProperties = {
      ...asset.algorithmProperties,
      nistQuantumSecurityLevel: asset.quantumSecurityLevel,
      ...(asset.classicalSecurityLevel ? { classicalSecurityLevel: asset.classicalSecurityLevel } : {}),
    }
  }
  if (asset.certificateProperties) {
    cryptoProperties.certificateProperties = asset.certificateProperties
  }
  if (asset.relatedCryptoMaterialProperties) {
    cryptoProperties.relatedCryptoMaterialProperties = asset.relatedCryptoMaterialProperties
  }

  const properties = [
    { name: 'cbomtool:confidence', value: asset.confidence },
    { name: 'cbomtool:evidenceSources', value: (asset.evidenceSources || []).join(',') || 'unknown' },
  ]
  if (asset.sourceFile) {
    properties.push({
      name: 'cbomtool:source',
      value: asset.sourceLine ? `${asset.sourceFile}:${asset.sourceLine}` : asset.sourceFile,
    })
  }

  return {
    type: 'cryptographic-asset',
    'bom-ref': asset.bomRef,
    name: asset.name,
    cryptoProperties,
    properties,
  }
}

export function buildCbomDocument(assets, repoUrl) {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    serialNumber: `urn:uuid:cbom-${Date.now()}`,
    metadata: {
      timestamp: new Date().toISOString(),
      ...(repoUrl ? { component: { type: 'application', name: repoUrl } } : {}),
    },
    components: assets.map(toCycloneDxComponent),
    dependencies: assets
      .filter((a) => a.dependsOn && a.dependsOn.length > 0)
      .map((a) => ({ ref: a.bomRef, dependsOn: a.dependsOn })),
  }
}

export function downloadCbomJson(assets, repoUrl, filename = 'cbom.json') {
  const doc = buildCbomDocument(assets, repoUrl)
  const blob = new Blob([JSON.stringify(doc, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}
