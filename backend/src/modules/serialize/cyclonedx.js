//serializer/cyclonedx.js

function buildCycloneDX({ components, vulnMap, anomalies }) {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.7',
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
    },
    components: components.map(c => buildComponent(c, anomalies)),
    vulnerabilities: buildVulnList(components, vulnMap),
  };
}

function buildComponent(c, anomalies) {
  const component = {
    type: 'library',
    'bom-ref': c.purl,   
    name: c.name,
    version: c.version,
    purl: c.purl,
    scope: c.dev ? 'optional' : 'required',
  };

  if (c.license && c.license !== 'UNKNOWN') {
    component.licenses = [{ license: { id: c.license } }];
  }

  const hits = anomalies.get(c.purl) || [];
  if (hits.length > 0) {
    component.properties = hits.map(a => ({
      name: `sbomtool:anomaly:${a.type}`,
      value: `${a.severity} — ${a.reason}`,
    }));
  }

  return component;
}

function buildVulnList(components, vulnMap) {
  const vulns = [];
  for (const c of components) {
    const hits = vulnMap.get(c.purl) || [];
    hits.forEach(v => {
      vulns.push({
        id: v.id,
        affects: [{ ref: c.purl }],
      });
    });
  }
  return vulns;
}

module.exports = { buildCycloneDX };