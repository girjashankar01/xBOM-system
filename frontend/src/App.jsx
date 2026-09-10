import { useMemo, useState } from 'react'
import ScanInput from './components/ScanInput'
import LoadingState from './components/LoadingState'
import ErrorBanner from './components/ErrorBanner'
import RiskSummary from './components/RiskSummary'
import ComponentTable from './components/ComponentTable'
import CbomTab from './components/CbomTab'
import { scanRepo } from './api'
import { enrichAllComponents, getAnomalyTypeBreakdown } from './utils/transform'
import { getCryptoAssetsFromSbom } from './utils/cbomTransform'

// idle -> loading -> results | error
export default function App() {
  const [status, setStatus] = useState('idle')
  const [error, setError] = useState(null)
  const [sbom, setSbom] = useState(null)
  const [repoUrl, setRepoUrl] = useState('')
  const [activeTab, setActiveTab] = useState('sbom') // 'sbom' | 'cbom'

  const enrichedComponents = useMemo(
    () => (sbom ? enrichAllComponents(sbom) : []),
    [sbom]
  )

  const typeBreakdown = useMemo(
    () => (sbom ? getAnomalyTypeBreakdown(sbom.riskSummary, enrichedComponents) : {}),
    [sbom, enrichedComponents]
  )

  const cryptoAssets = useMemo(
    () => (sbom ? getCryptoAssetsFromSbom(sbom) : []),
    [sbom]
  )

  async function handleScan(url) {
    setStatus('loading')
    setError(null)
    setRepoUrl(url)
    try {
      const result = await scanRepo(url)
      setSbom(result)
      setStatus('results')
      setActiveTab('sbom')
    } catch (err) {
      setError(err.message || 'Something went wrong.')
      setStatus('error')
    }
  }

  function handleNewScan() {
    setStatus('idle')
    setSbom(null)
    setError(null)
  }

  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b border-border">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <button onClick={handleNewScan} className="flex items-center gap-2">
            <span className="font-mono text-sm text-accent">xBOM://</span>
            <span className="font-mono text-sm text-dim">scan</span>
          </button>
          {status === 'results' && (
            <button
              onClick={handleNewScan}
              className="text-xs text-muted hover:text-text border border-border rounded-md px-3 py-1.5 transition-colors"
            >
              New scan
            </button>
          )}
        </div>
      </header>

      <main className="flex-1 max-w-6xl w-full mx-auto px-6 py-10 flex flex-col gap-8">
        {status !== 'results' && (
          <div className="flex flex-col items-start gap-2 mt-6">
            <h1 className="text-2xl sm:text-3xl font-semibold text-text tracking-tight">
              Know what's in your software &amp; cryptography.
            </h1>
            <p className="text-muted max-w-xl text-sm sm:text-base">
              Point this at a public npm/Node.js repo to generate a unified Software &amp; Cryptography
              Bill of Materials (xBOM) — auditing dependency vulnerabilities, cryptographic primitives,
              keys, and quantum readiness.
            </p>
          </div>
        )}

        <div className="flex flex-col items-start gap-6">
          {status !== 'results' && (
            <ScanInput onSubmit={handleScan} disabled={status === 'loading'} />
          )}

          {status === 'loading' && <LoadingState />}

          {status === 'error' && (
            <ErrorBanner message={error} onDismiss={() => setStatus('idle')} />
          )}
        </div>

        {status === 'results' && sbom && (
          <div className="flex flex-col gap-6">
            <div className="flex items-center gap-1 border-b border-border">
              <TabButton
                label="Software"
                active={activeTab === 'sbom'}
                onClick={() => setActiveTab('sbom')}
              />
              <TabButton
                label="Cryptography"
                active={activeTab === 'cbom'}
                onClick={() => setActiveTab('cbom')}
              />
            </div>

            {activeTab === 'sbom' && (
              <div className="flex flex-col gap-8">
                <RiskSummary
                  riskSummary={sbom.riskSummary}
                  typeBreakdown={typeBreakdown}
                  repoUrl={repoUrl}
                  sbom={sbom}
                />
                <ComponentTable components={enrichedComponents} />
              </div>
            )}

            {activeTab === 'cbom' && (
              <CbomTab
                assets={cryptoAssets}
                repoUrl={repoUrl}
                cbomCorrelation={sbom.cbomCorrelation}
                rawCryptoComponents={sbom.cryptoComponents}
              />
            )}
          </div>
        )}
      </main>

      <footer className="border-t border-border">
        <div className="max-w-6xl mx-auto px-6 py-4 text-xs text-dim">
          Results reflect a single point-in-time scan. No data is stored server-side.
        </div>
      </footer>
    </div>
  )
}

function TabButton({ label, active, onClick }) {
  return (
    <button
      onClick={onClick}
      className={`px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${
        active
          ? 'border-accent text-text'
          : 'border-transparent text-muted hover:text-text'
      }`}
    >
      {label}
    </button>
  )
}
