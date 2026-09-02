const fs = require('node:fs');
const path = require('node:path');
const levenshtein = require('fast-levenshtein');

let npmHighImpact = [];
try {
  const topPath = path.join(__dirname, '../../../node_modules/npm-high-impact/lib/top.js');
  if (fs.existsSync(topPath)) {
    const raw = fs.readFileSync(topPath, 'utf-8');
    npmHighImpact = (raw.match(/'([^']+)'/g) || []).map(s => s.slice(1, -1));
  }
} catch {
  npmHighImpact = [];
}

const SHORT_NAME_LENGTH = 5;
const SHORT_NAME_THRESHOLD = 1;
const DEFAULT_THRESHOLD = 2;
const MIN_NAME_LENGTH_TO_CHECK = 3; // below this, edit-distance comparisons are too noisy to be meaningful

function checkTyposquat(componentName) {
  if (componentName.length < MIN_NAME_LENGTH_TO_CHECK) return null;
  if (npmHighImpact.includes(componentName)) return null; // it IS the popular package

  const threshold =
    componentName.length <= SHORT_NAME_LENGTH ? SHORT_NAME_THRESHOLD : DEFAULT_THRESHOLD;

  let bestMatch = null;
  let bestDistance = Infinity;

  for (const popularName of npmHighImpact) {
    const distance = levenshtein.get(componentName, popularName);
    if (distance > 0 && distance <= threshold && distance < bestDistance) {
      bestDistance = distance;
      bestMatch = popularName;
      if (distance === 1) break; // optimal match found
    }
  }

  if (bestMatch) {
    return {
      type: 'typosquat',
      severity: 'high',
      reason: `Name is ${bestDistance} edit(s) from popular package "${bestMatch}" but is not that package`,
    };
  }

  return null;
}

module.exports = { checkTyposquat };