// cache/npmCache.js
const fs = require('fs');
const path = require('path');
const os = require('os');
const axios = require('axios');

const CACHE_DIR = path.join(os.tmpdir(), 'sbom_npm_registry_cache');
const METADATA_CACHE_FILE = path.join(CACHE_DIR, 'metadata.json');
const DOWNLOADS_CACHE_FILE = path.join(CACHE_DIR, 'downloads.json');

const memoryMetadataCache = new Map();
const memoryDownloadsCache = new Map();

// Initialize persistent disk cache
function initDiskCache() {
  try {
    if (!fs.existsSync(CACHE_DIR)) {
      fs.mkdirSync(CACHE_DIR, { recursive: true });
    }
    if (fs.existsSync(METADATA_CACHE_FILE)) {
      const raw = JSON.parse(fs.readFileSync(METADATA_CACHE_FILE, 'utf-8'));
      for (const [k, v] of Object.entries(raw)) {
        memoryMetadataCache.set(k, v);
      }
    }
    if (fs.existsSync(DOWNLOADS_CACHE_FILE)) {
      const raw = JSON.parse(fs.readFileSync(DOWNLOADS_CACHE_FILE, 'utf-8'));
      for (const [k, v] of Object.entries(raw)) {
        memoryDownloadsCache.set(k, v);
      }
    }
  } catch (err) {
    // Disk cache corruption or permission issues degrade gracefully to in-memory
  }
}

let saveTimeout = null;
function scheduleDiskSave() {
  if (saveTimeout) return;
  saveTimeout = setTimeout(() => {
    saveTimeout = null;
    try {
      if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
      const metaObj = Object.fromEntries(memoryMetadataCache);
      const dlObj = Object.fromEntries(memoryDownloadsCache);
      fs.writeFileSync(METADATA_CACHE_FILE, JSON.stringify(metaObj));
      fs.writeFileSync(DOWNLOADS_CACHE_FILE, JSON.stringify(dlObj));
    } catch {
      // Ignore disk write errors
    }
  }, 500);
}

initDiskCache();

async function getWithRetry(url, attempt = 0) {
  try {
    return await axios.get(url, {
      timeout: 6000,
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'sbom-backend/1.0.0',
      },
    });
  } catch (err) {
    const status = err.response && err.response.status;
    if (status === 429 && attempt < 3) {
      const retryAfter = err.response.headers && err.response.headers['retry-after'];
      const delay = retryAfter ? Number(retryAfter) * 1000 : 400 * 2 ** attempt;
      await new Promise(r => setTimeout(r, delay));
      return getWithRetry(url, attempt + 1);
    }
    throw err;
  }
}

async function fetchPackageMetadata(packageName) {
  if (memoryMetadataCache.has(packageName)) {
    return memoryMetadataCache.get(packageName);
  }

  try {
    const { data } = await getWithRetry(`https://registry.npmjs.org/${encodeURIComponent(packageName)}`);
    memoryMetadataCache.set(packageName, data);
    scheduleDiskSave();
    return data;
  } catch (err) {
    if (err.response && err.response.status === 404) {
      const emptyData = { name: packageName, notFound: true };
      memoryMetadataCache.set(packageName, emptyData);
      scheduleDiskSave();
      return emptyData;
    }
    throw err;
  }
}

async function fetchWeeklyDownloads(packageName) {
  if (memoryDownloadsCache.has(packageName)) {
    return memoryDownloadsCache.get(packageName);
  }

  try {
    const res = await getWithRetry(
      `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(packageName)}`
    );
    const count = (res.data && res.data.downloads) || 0;
    memoryDownloadsCache.set(packageName, count);
    scheduleDiskSave();
    return count;
  } catch {
    memoryDownloadsCache.set(packageName, 0);
    return 0;
  }
}

/**
 * Concurrency-bounded map helper (replaces p-limit / sequential batching)
 */
async function pMap(items, mapper, { concurrency = 20 } = {}) {
  const results = new Array(items.length);
  let index = 0;

  async function worker() {
    while (index < items.length) {
      const current = index++;
      try {
        results[current] = await mapper(items[current], current);
      } catch (err) {
        results[current] = null;
      }
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, items.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

module.exports = {
  fetchPackageMetadata,
  fetchWeeklyDownloads,
  pMap,
  memoryMetadataCache,
  memoryDownloadsCache,
};
