import { useMemo, useState } from 'react'
import CbomSummaryCards from './CbomSummaryCards'
import QuantumRiskChart from './QuantumRiskChart'
import CbomAssetTable from './CbomAssetTable'
import RemediationChecklist from './RemediationChecklist'
import QuantumRiskGuideModal from './QuantumRiskGuideModal'
import { buildCbomSummary, enrichCryptoAsset } from '../utils/cbomTransform'
import { generateRemediationChecklist } from '../utils/cbomRemediation'
import { MOCK_CBOM_ASSETS } from '../data/mockCbomAssets'
import { downloadCbomJson } from '../utils/cbomExport'

export default function CbomTab({ assets, repoUrl, cbomCorrelation, rawCryptoComponents }) {
  const [showSample, setShowSample] = useState(false)
  const [viewMode, setViewMode] = useState('table') // 'table' | 'checklist'
  const [isGuideOpen, setIsGuideOpen] = useState(false)

  const displayAssets = useMemo(() => {
    if (assets.length > 0) return assets
    return showSample ? MOCK_CBOM_ASSETS.map(enrichCryptoAsset) : []
  }, [assets, showSample])

  const summary = useMemo(
    () => buildCbomSummary(displayAssets, cbomCorrelation?.summary),
    [displayAssets, cbomCorrelation]
  )

  const tasks = useMemo(() => generateRemediationChecklist(displayAssets), [displayAssets])

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
            <span>Compounding Supply Chain Risk Detected ({summary.compoundingCount} package{summary.compoundingCount > 1 ? 's' : ''})</span>
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

      <div className="flex flex-col sm:flex-row sm:items-baseline justify-between gap-3">
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
        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsGuideOpen(true)}
            className="text-xs text-accent hover:text-accent/80 border border-accent/30 bg-accent/5 rounded-md px-3 py-1.5 transition-colors whitespace-nowrap"
          >
            NIST PQC Guide
          </button>
          <button
            onClick={() => downloadCbomJson(rawCryptoComponents || displayAssets, repoUrl, isSample ? 'cbom-sample.json' : 'cbom.json')}
            className="text-xs text-muted hover:text-text border border-border rounded-md px-3 py-1.5 transition-colors whitespace-nowrap"
          >
            Export CBOM (JSON)
          </button>
        </div>
      </div>

      <CbomSummaryCards summary={summary} />
      <QuantumRiskChart byQuantumRisk={summary.byQuantumRisk} onOpenGuide={() => setIsGuideOpen(true)} />

      {/* View Switcher: Findings Table vs Remediation Checklist */}
      <div className="space-y-4">
        <div className="flex items-center gap-2 border-b border-border pb-1">
          <button
            onClick={() => setViewMode('table')}
            className={`px-3 py-2 text-xs font-semibold rounded-t-md transition-colors flex items-center gap-1.5 border-b-2 -mb-px ${
              viewMode === 'table'
                ? 'border-accent text-accent bg-surface/50'
                : 'border-transparent text-muted hover:text-text'
            }`}
          >
            <span>Asset Findings ({displayAssets.length})</span>
          </button>
          <button
            onClick={() => setViewMode('checklist')}
            className={`px-3 py-2 text-xs font-semibold rounded-t-md transition-colors flex items-center gap-1.5 border-b-2 -mb-px ${
              viewMode === 'checklist'
                ? 'border-accent text-accent bg-surface/50'
                : 'border-transparent text-muted hover:text-text'
            }`}
          >
            <span>Remediation Checklist</span>
            {tasks.length > 0 && (
              <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] font-mono bg-critical/20 text-critical border border-critical/30">
                {tasks.length}
              </span>
            )}
          </button>
        </div>

        {viewMode === 'table' ? (
          <CbomAssetTable
            assets={displayAssets}
            repoUrl={repoUrl}
            onOpenGuide={() => setIsGuideOpen(true)}
          />
        ) : (
          <RemediationChecklist assets={displayAssets} repoUrl={repoUrl} />
        )}
      </div>

      {/* Global NIST PQC Guide Modal */}
      <QuantumRiskGuideModal isOpen={isGuideOpen} onClose={() => setIsGuideOpen(false)} />
    </div>
  )
}
