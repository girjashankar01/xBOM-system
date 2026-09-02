//scan.routes.js

const express = require('express');
const router = express.Router();

const { cloneRepo, findLockfile, cleanup } = require('../modules/ingest/repoIngest');
const { parseLockfile } = require('../modules/parse/npmLockParser');
const { queryVulnerabilities } = require('../modules/enrich/osvClient');
const { checkTyposquat } = require('../modules/anomaly/typosquat');
const { checkFreshness } = require('../modules/anomaly/freshness');
const { checkVersionPinning } = require('../modules/anomaly/versionPinning');
const { checkInstallScript } = require('../modules/anomaly/installScript');
const { getPackageMetadata } = require('../modules/license/licenseExtract');
const { classifyLicense, classifyDeprecation } = require('../modules/license/licenseClassify');
const { buildCycloneDX } = require('../modules/serialize/cyclonedx');
const { buildRiskSummary } = require('../modules/serialize/riskSummary');
const { npmHighImpact } = require('npm-high-impact');
const { runPipeline: runCbomPipeline } = require('../../cbom/cli/main');
const { pMap } = require('../modules/cache/npmCache');

const FRESHNESS_CONCURRENCY = 8;  // lowered from 25 — public registry throttles hard past this
const LICENSE_CONCURRENCY = 8;
const BATCH_DELAY_MS = 250;       // small stagger between batches, reduces burstiness

function addAnomalyHit(anomalies, purl, hit) {
  if (!hit) return;
  const existing = anomalies.get(purl) || [];
  existing.push(hit);
  anomalies.set(purl, existing);
}

// Wraps an async fn(name) so identical names share one in-flight/resolved call —
// created fresh per scan (not module-level) so state never leaks across requests.
function memoizeByName(fn) {
  const cache = new Map();
  return (name) => {
    if (!cache.has(name)) {
      cache.set(name, fn(name).catch(err => { cache.delete(name); throw err; }));
    }
    return cache.get(name);
  };
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

router.post('/scan', async (req, res) => {
  const { githubUrl, skipLlm = false } = req.body;
  if (!githubUrl) return res.status(400).json({ error: 'githubUrl is required' });

  let repoDir;
  try {
    repoDir = cloneRepo(githubUrl);
    const lockPath = findLockfile(repoDir);
    const components = parseLockfile(lockPath);

    const vulnMap = await queryVulnerabilities(components);

    const anomalies = new Map();
    const freshnessCandidates = [];

    let typosquatHits = 0;
    for (const c of components) {
      const isKnownPopular = npmHighImpact.includes(c.name);
      const hits = [
        checkTyposquat(c.name),
        checkVersionPinning(c.declaredRanges),
        checkInstallScript(c, isKnownPopular),
      ].filter(Boolean);

      if (hits.some(h => h.type === 'typosquat')) typosquatHits++;
      hits.forEach(hit => addAnomalyHit(anomalies, c.purl, hit));

      if (hits.length === 0) freshnessCandidates.push(c);
    }

    console.log(`[scan] typosquat hits: ${typosquatHits} / ${components.length} components checked`);
    console.log(`[scan] freshness candidates: ${freshnessCandidates.length}`);

    // dedupe: same package name appearing at multiple tree locations shares one network call
    const memoizedFreshness = memoizeByName(name => checkFreshness(name));
    const memoizedMetadata = memoizeByName(name => getPackageMetadata(name));

    let freshnessHits = 0;
    let freshnessErrors = 0;

    const freshnessResults = await pMap(
      freshnessCandidates,
      async (c) => {
        try {
          return await memoizedFreshness(c.name);
        } catch (err) {
          freshnessErrors++;
          return null;
        }
      },
      { concurrency: 20 }
    );

    freshnessResults.forEach((fresh, idx) => {
      if (fresh) {
        freshnessHits++;
        addAnomalyHit(anomalies, freshnessCandidates[idx].purl, fresh);
      }
    });

    console.log(`[scan] freshness hits: ${freshnessHits}, errors/timeouts: ${freshnessErrors}`);

    const metadataResults = await pMap(
      components,
      c => memoizedMetadata(c.name),
      { concurrency: 20 }
    );

    metadataResults.forEach((meta, idx) => {
      const c = components[idx];
      const license = (meta && meta.license) || 'UNKNOWN';
      const deprecated = (meta && meta.deprecated) || null;
      c.license = license;
      addAnomalyHit(anomalies, c.purl, classifyLicense(license));
      addAnomalyHit(anomalies, c.purl, classifyDeprecation(deprecated));
    });

    const sbom = buildCycloneDX({ components, vulnMap, anomalies });
    sbom.riskSummary = buildRiskSummary(components, vulnMap, anomalies);

    try {
      const cbomResult = await runCbomPipeline(repoDir, {
        sbom,
        skipLlm: Boolean(skipLlm),
      });

      if (cbomResult && cbomResult.cbom && Array.isArray(cbomResult.cbom.components)) {
        sbom.cryptoComponents = cbomResult.cbom.components;
      }
      if (cbomResult && cbomResult.correlation) {
        sbom.cbomCorrelation = cbomResult.correlation;
      }
    } catch (cbomErr) {
      console.warn(`[scan] CBOM generation skipped or failed: ${cbomErr.message}`);
    }

    res.json(sbom);
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    if (repoDir) cleanup(repoDir);
  }
});

module.exports = router;