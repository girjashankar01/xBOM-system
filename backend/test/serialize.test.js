const { buildCycloneDX } = require('../src/modules/serialize/cyclonedx');

describe('buildCycloneDX', () => {
  const components = [
    {
      name: 'express',
      version: '4.18.2',
      purl: 'pkg:npm/express@4.18.2',
      dev: false,
    },
    {
      name: 'nodemon',
      version: '3.1.0',
      purl: 'pkg:npm/nodemon@3.1.0',
      dev: true,
    },
  ];

  const vulnMap = new Map([
    ['pkg:npm/express@4.18.2', [{ id: 'CVE-2024-FAKE-1' }]],
  ]);

  const anomalies = new Map([
    ['pkg:npm/nodemon@3.1.0', [{ type: 'typosquat', severity: 'high', reason: 'test reason' }]],
  ]);

  test('produces required top-level CycloneDX fields', () => {
    const sbom = buildCycloneDX({ components, vulnMap, anomalies });
    expect(sbom.bomFormat).toBe('CycloneDX');
    expect(sbom.specVersion).toBe('1.7');
    expect(sbom.version).toBe(1);
    expect(sbom.metadata.timestamp).toBeDefined();
    expect(() => new Date(sbom.metadata.timestamp).toISOString()).not.toThrow();
  });

  test('maps every component with correct scope', () => {
    const sbom = buildCycloneDX({ components, vulnMap, anomalies });
    expect(sbom.components).toHaveLength(2);

    const express = sbom.components.find(c => c.name === 'express');
    expect(express.scope).toBe('required');
    expect(express.purl).toBe('pkg:npm/express@4.18.2');

    const nodemon = sbom.components.find(c => c.name === 'nodemon');
    expect(nodemon.scope).toBe('optional'); // dev: true maps to optional
  });

  test('vulnerabilities array correctly references purls', () => {
    const sbom = buildCycloneDX({ components, vulnMap, anomalies });
    expect(sbom.vulnerabilities).toHaveLength(1);
    expect(sbom.vulnerabilities[0].id).toBe('CVE-2024-FAKE-1');
    expect(sbom.vulnerabilities[0].affects[0].ref).toBe('pkg:npm/express@4.18.2');
  });

  test('anomaly properties attach directly to the component they describe', () => {
    const sbom = buildCycloneDX({ components, vulnMap, anomalies });

    const nodemon = sbom.components.find(c => c.name === 'nodemon');
    expect(nodemon.properties).toHaveLength(1);
    expect(nodemon.properties[0].name).toBe('sbomtool:anomaly:typosquat');
    expect(nodemon.properties[0].value).toContain('high');
    expect(nodemon.properties[0].value).toContain('test reason');

    // the unaffected component must NOT carry someone else's anomaly
    const express = sbom.components.find(c => c.name === 'express');
    expect(express.properties).toBeUndefined();
  });

  test('a component with no anomalies has no properties key at all', () => {
    const cleanComponents = [
      { name: 'clean-pkg', version: '1.0.0', purl: 'pkg:npm/clean-pkg@1.0.0', dev: false },
    ];
    const sbom = buildCycloneDX({
      components: cleanComponents,
      vulnMap: new Map(),
      anomalies: new Map(),
    });
    expect(sbom.vulnerabilities).toHaveLength(0);
    expect(sbom.components[0].properties).toBeUndefined();
  });

  test('a component can carry multiple anomaly properties at once', () => {
    const multiAnomalyComponents = [
      { name: 'sus-pkg', version: '0.0.1', purl: 'pkg:npm/sus-pkg@0.0.1', dev: false },
    ];
    const multiAnomalies = new Map([
      ['pkg:npm/sus-pkg@0.0.1', [
        { type: 'typosquat', severity: 'high', reason: 'reason A' },
        { type: 'version-pinning', severity: 'low', reason: 'reason B' },
      ]],
    ]);
    const sbom = buildCycloneDX({
      components: multiAnomalyComponents,
      vulnMap: new Map(),
      anomalies: multiAnomalies,
    });
    expect(sbom.components[0].properties).toHaveLength(2);
  });
});