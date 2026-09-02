import { useMemo, useState } from 'react'
import CbomSummaryCards from './CbomSummaryCards'
import QuantumRiskChart from './QuantumRiskChart'
import CbomAssetTable from './CbomAssetTable'
import { buildCbomSummary, enrichCryptoAsset } from '../utils/cbomTransform'
import { MOCK_CBOM_ASSETS } from '../data/mockCbomAssets'
import { downloadCbomJson } from '../utils/cbomExport'

export default function CbomTab({ assets, repoUrl, cbomCorrelation, rawCryptoComponents }) {
  const [showSample, setShowSample] = useState(false)

  const displayAssets = useMemo(() => {
    if (assets.length > 0) return assets
    return showSample ? MOCK_CBOM_ASSETS.map(enrichCryptoAsset) : []
  }, [assets, showSample])

  const summary = useMemo(
    () => buildCbomSummary(displayAssets, cbomCorrelation?.summary),
    [displayAssets, cbomCorrelation]
  )

  if (assets.length === 0 && !showSample) {
    return (
      <div className="rounded-lg border border-border bg-surface px-6 py-10 text-center">
        <p className="text-sm text-muted">
          No cryptographic-asset findings in this scan yet — crypto detection may not be wired up
          for this backend build.
        </p>
        <button
          onClick={() => setShowSample(true)}
          className="mt-4 text-xs text-accent hover:underline underline-offset-2"
        >
          Preview this tab with sample data
        </button>
      </div>
    )
  }

  const isSample = assets.length === 0 && showSample

  return (
    <div className="flex flex-col gap-8 animate-fade-in">
      {isSample && (
        <div className="rounded-md border border-accent/30 bg-accent/10 px-4 py-2.5 text-xs text-accent flex items-center justify-between">
          <span>Showing sample data — not results from an actual scan.</span>
          <button onClick={() => setShowSample(false)} className="underline underline-offset-2">
            Hide
          </button>
        </div>
      )}

      {/* Compounding Supply Chain Risk Banner */}
      {summary.compoundingCount > 0 && (
        <div className="rounded-lg border border-critical/40 bg-critical/10 p-4 animate-fade-in flex flex-col gap-2">
          <div className="flex items-center gap-2 text-critical font-semibold text-sm">
            <span>⚠️ Compounding Supply Chain Risk Detected ({summary.compoundingCount} package{summary.compoundingCount > 1 ? 's' : ''})</span>
          </div>
          <p className="text-xs text-muted leading-relaxed">
            The following dependenc{summary.compoundingCount > 1 ? 'ies carry' : 'y carries'} <strong>both</strong> an active unpatched OSV vulnerability and a severe (Critical/High) cryptographic finding. This joint exposure represents a high-risk supply chain vector:
          </p>
          <div className="flex flex-wrap gap-2 mt-1">
            {summary.compoundingPackages.map((pkg) => (
              <span
                key={pkg}
                className="inline-flex items-center rounded-md border border-critical/40 bg-critical/20 px-2.5 py-1 text-xs font-mono font-medium text-critical"
              >
                {pkg}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="flex items-baseline justify-between">
        <div>
          <h2 className="text-lg font-semibold text-text">Cryptography findings</h2>
          <div className="flex items-center gap-3 mt-0.5">
            <p className="text-xs text-dim font-mono truncate max-w-md">{repoUrl}</p>
            <span className="text-xs text-dim font-mono">•</span>
            <p className="text-xs font-mono text-muted">
              {summary.firstPartySource} First-Party / {summary.attributedToPackage} Third-Party findings
            </p>
          </div>
        </div>
        <button
          onClick={() => downloadCbomJson(rawCryptoComponents || displayAssets, repoUrl, isSample ? 'cbom-sample.json' : 'cbom.json')}
          className="text-xs text-muted hover:text-text border border-border rounded-md px-3 py-1.5 transition-colors whitespace-nowrap"
        >
          Export CBOM (JSON)
        </button>
      </div>

      <CbomSummaryCards summary={summary} />
      <QuantumRiskChart byQuantumRisk={summary.byQuantumRisk} />
      <CbomAssetTable assets={displayAssets} />
    </div>
  )
}
