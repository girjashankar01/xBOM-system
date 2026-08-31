import { useMemo, useState } from 'react'
import CbomSummaryCards from './CbomSummaryCards'
import QuantumRiskChart from './QuantumRiskChart'
import CbomAssetTable from './CbomAssetTable'
import { buildCbomSummary, enrichCryptoAsset } from '../utils/cbomTransform'
import { MOCK_CBOM_ASSETS } from '../data/mockCbomAssets'

export default function CbomTab({ assets }) {
  const [showSample, setShowSample] = useState(false)

  const displayAssets = useMemo(() => {
    if (assets.length > 0) return assets
    return showSample ? MOCK_CBOM_ASSETS.map(enrichCryptoAsset) : []
  }, [assets, showSample])

  const summary = useMemo(() => buildCbomSummary(displayAssets), [displayAssets])

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

  return (
    <div className="flex flex-col gap-8 animate-fade-in">
      {assets.length === 0 && showSample && (
        <div className="rounded-md border border-accent/30 bg-accent/10 px-4 py-2.5 text-xs text-accent flex items-center justify-between">
          <span>Showing sample data — not results from an actual scan.</span>
          <button onClick={() => setShowSample(false)} className="underline underline-offset-2">
            Hide
          </button>
        </div>
      )}

      <CbomSummaryCards summary={summary} />
      <QuantumRiskChart byQuantumRisk={summary.byQuantumRisk} />
      <CbomAssetTable assets={displayAssets} />
    </div>
  )
}
