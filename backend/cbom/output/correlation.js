// output/correlation.js — Phase 11
//
// SBOM <-> CBOM join for the dashboard, via context/sbomAdapter.js's
// existing node_modules path matching — reused, not reimplemented, so this
// stays in sync with cyclonedx_serializer.js's dependency linking by
// construction rather than by two copies of the same matching logic.
//
// The real value here isn't the join itself, it's what it makes visible:
// COMPOUNDING risk. A package with an unpatched OSV CVE that ALSO does its
// own broken crypto (e.g. RSA-1024 signing) is a materially different risk
// than either fact alone — that's the reason to run SBOM and CBOM
// together rather than as two unrelated reports, and nothing upstream
// computes it.

function attributePackage(finding, sbomAdapter) {
  if (!sbomAdapter) return null;
  return sbomAdapter.getContextForFile(finding.filePath);
}

/**
 * Joins each CBOM finding to its owning SBOM package where resolvable.
 * `packageContext: null` for first-party source is the correct/expected
 * result, not a failure — most findings won't be inside node_modules.
 */
function correlateFindings(findings, sbomAdapter) {
  return findings.map((f) => ({
    findingId: f.findingId,
    name: f.name,
    assetType: f.assetType,
    quantumRisk: f.quantumRisk,
    exposureRisk: f.exposureRisk,
    confidence: f.confidence,
    filePath: f.filePath,
    line: f.line,
    packageContext: attributePackage(f, sbomAdapter),
  }));
}

/**
 * Groups by package (purl) and flags compounding risk: a package with an
 * SBOM-side flag (OSV CVE from sbomAdapter, or an sbomtool anomaly passed
 * via `anomaliesByPurl` — match serializer/cyclonedx.js's
 * `sbomtool:anomaly:*` property keys if you're pulling this from that
 * output) that ALSO carries a CRITICAL/HIGH quantum-risk or exposure-risk crypto finding.
 */
function findCompoundingRisk(correlated, { anomaliesByPurl = new Map() } = {}) {
  const byPurl = new Map();

  for (const c of correlated) {
    if (!c.packageContext || !c.packageContext.purl) continue;
    const purl = c.packageContext.purl;
    if (!byPurl.has(purl)) {
      byPurl.set(purl, {
        purl,
        name: c.packageContext.name,
        version: c.packageContext.version,
        osvCves: c.packageContext.osvCves || [],
        anomalies: anomaliesByPurl.get(purl) || [],
        cryptoFindings: [],
      });
    }
    byPurl.get(purl).cryptoFindings.push(c);
  }

  const compounding = [];
  for (const pkg of byPurl.values()) {
    const hasSbomFlag = pkg.osvCves.length > 0 || pkg.anomalies.length > 0;
    const hasSevereCrypto = pkg.cryptoFindings.some(
      (f) => f.quantumRisk === 'CRITICAL' || f.quantumRisk === 'HIGH' || f.exposureRisk === 'CRITICAL' || f.exposureRisk === 'HIGH'
    );
    if (hasSbomFlag && hasSevereCrypto) compounding.push(pkg);
  }

  return { byPurl, compounding };
}

/**
 * Aggregates both quantumRisk and exposureRisk dimensions along with package attribution.
 */
function buildCombinedRiskSummary(findings, correlated, compoundingResult) {
  let critical = 0, high = 0, medium = 0, low = 0;
  let exposureCritical = 0, exposureHigh = 0, exposureMedium = 0, exposureLow = 0;
  const byPrimitive = {};

  for (const f of findings) {
    if (f.quantumRisk === 'CRITICAL') critical++;
    else if (f.quantumRisk === 'HIGH') high++;
    else if (f.quantumRisk === 'MEDIUM') medium++;
    else if (f.quantumRisk === 'LOW') low++;

    if (f.exposureRisk === 'CRITICAL') exposureCritical++;
    else if (f.exposureRisk === 'HIGH') exposureHigh++;
    else if (f.exposureRisk === 'MEDIUM') exposureMedium++;
    else if (f.exposureRisk === 'LOW') exposureLow++;

    if (f.primitive) byPrimitive[f.primitive] = (byPrimitive[f.primitive] || 0) + 1;
  }

  return {
    totalFindings: findings.length,
    critical, high, medium, low,
    quantumRisk: { critical, high, medium, low },
    exposureRisk: { critical: exposureCritical, high: exposureHigh, medium: exposureMedium, low: exposureLow },
    byPrimitive,
    attributedToPackage: correlated.filter((c) => c.packageContext).length,
    firstPartySource: correlated.filter((c) => !c.packageContext).length,
    compoundingCount: compoundingResult.compounding.length,
    compoundingPackages: compoundingResult.compounding.map((p) => `${p.name}@${p.version}`),
  };
}

module.exports = { correlateFindings, findCompoundingRisk, buildCombinedRiskSummary };  