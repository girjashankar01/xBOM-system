// scripts/generateSampleBom.js
// Run: node scripts/generateSampleBom.js > /tmp/out.json
const { buildCycloneDX } = require('../src/modules/serialize/cyclonedx');

const testInput = {
  components: [
    { name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21', dev: false, license: 'MIT' },
  ],
  vulnMap: new Map([['pkg:npm/lodash@4.17.21', [{ id: 'GHSA-test-1234' }]]]),
  anomalies: new Map(),
};

process.stdout.write(JSON.stringify(buildCycloneDX(testInput), null, 2));