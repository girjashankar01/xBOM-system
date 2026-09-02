//anomaly/freshness.js

const { fetchPackageMetadata, fetchWeeklyDownloads } = require('../cache/npmCache');

async function checkFreshness(componentName) {
  try {
    const data = await fetchPackageMetadata(componentName);
    if (!data || data.notFound || !data['dist-tags']) return null;

    const latestVersion = data['dist-tags'].latest;
    if (!latestVersion || !data.time || !data.time[latestVersion]) return null;

    const publishedDate = new Date(data.time[latestVersion]);
    const daysSincePublish = (Date.now() - publishedDate.getTime()) / (1000 * 60 * 60 * 24);

    const weeklyDownloads = await fetchWeeklyDownloads(componentName);

    if (daysSincePublish < 30 && weeklyDownloads < 100) {
      return {
        type: 'freshness',
        severity: 'medium',
        reason: `Published ${Math.round(daysSincePublish)} days ago with only ${weeklyDownloads} weekly downloads`,
      };
    }
    return null;
  } catch {
    return null;
  }
}

module.exports = { checkFreshness };