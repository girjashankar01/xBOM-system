/**
 * Client-side CycloneDX SBOM export utility.
 * Mirrors cbomExport.js to construct and download a valid CycloneDX v1.7 SBOM JSON.
 */

export function buildSbomDocument(sbom, repoUrl) {
  if (!sbom) return null

  const doc = {
    bomFormat: sbom.bomFormat || 'CycloneDX',
    specVersion: sbom.specVersion || '1.7',
    version: sbom.version || 1,
    serialNumber: sbom.serialNumber || `urn:uuid:sbom-${Date.now()}`,
    metadata: {
      timestamp: sbom.metadata?.timestamp || new Date().toISOString(),
      tools: sbom.metadata?.tools || {
        components: [
          {
            type: 'application',
            name: 'sih260077-sbom-scanner',
            version: '1.0.0',
          },
        ],
      },
      ...(repoUrl
        ? { component: { type: 'application', name: repoUrl } }
        : sbom.metadata?.component
        ? { component: sbom.metadata.component }
        : {}),
    },
    components: (sbom.components || []).filter((c) => c.type !== 'cryptographic-asset'),
    vulnerabilities: sbom.vulnerabilities || [],
  }

  if (sbom.dependencies && sbom.dependencies.length > 0) {
    doc.dependencies = sbom.dependencies
  }

  return doc
}

export function downloadSbomJson(sbom, repoUrl, filename = 'sbom.json') {
  const doc = buildSbomDocument(sbom, repoUrl)
  if (!doc) return
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
