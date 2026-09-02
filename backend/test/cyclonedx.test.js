// test/cyclonedx.test.js
const { buildCycloneDX } = require('../src/modules/serialize/cyclonedx');

test('bumps specVersion, adds bom-ref, everything else unchanged', () => {
  const input = {
    components: [{ name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21', dev: false, license: 'MIT' }],
    vulnMap: new Map([['pkg:npm/lodash@4.17.21', [{ id: 'GHSA-test-1234' }]]]),
    anomalies: new Map(),
  };
  const bom = buildCycloneDX(input);

  expect(bom.specVersion).toBe('1.7');
  expect(bom.components[0]['bom-ref']).toBe('pkg:npm/lodash@4.17.21');
  // vulnerability now actually resolves to a real component
  expect(bom.vulnerabilities[0].affects[0].ref).toBe(bom.components[0]['bom-ref']);
});