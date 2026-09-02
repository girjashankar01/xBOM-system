//license/licenseExtract.js

const { fetchPackageMetadata } = require('../cache/npmCache');

async function getPackageMetadata(componentName) {
  try {
    const data = await fetchPackageMetadata(componentName);
    if (!data || data.notFound) return { license: 'UNKNOWN', deprecated: null };

    const license = extractLicense(data);
    const latestVersion = data['dist-tags'] && data['dist-tags'].latest;
    const versionInfo = latestVersion && data.versions ? data.versions[latestVersion] : null;
    const deprecated = (versionInfo && versionInfo.deprecated) || data.deprecated || null;
    return { license, deprecated };
  } catch {
    return { license: 'UNKNOWN', deprecated: null };
  }
}

function extractLicense(data) {
  if (typeof data.license === 'string') return data.license;
  if (data.license && data.license.type) return data.license.type;
  if (Array.isArray(data.licenses) && data.licenses.length > 0) return data.licenses[0].type || 'UNKNOWN';
  return 'UNKNOWN';
}

module.exports = { getPackageMetadata };