import { useMemo, useState } from 'react'
import QuantumRiskBadge from './QuantumRiskBadge'
import ConfidenceBadge from './ConfidenceBadge'
import {
  ASSET_TYPE_ORDER,
  ASSET_TYPE_LABEL,
  CONFIDENCE_ORDER,
  CONFIDENCE_LABEL,
  QUANTUM_LEVELS,
  EVIDENCE_LABEL,
  formatPrimitiveLabel,
  formatSourceLabel,
} from '../utils/cbomTransform'

const CONFIDENCE_RANK = { 'very-high': 0, high: 1, medium: 2, low: 3 }

export default function CbomAssetTable({ assets }) {
  const [search, setSearch] = useState('')
  const [sortBy, setSortBy] = useState('quantum')
  const [sortDir, setSortDir] = useState('asc')
  const [typeFilter, setTypeFilter] = useState('all')
  const [confidenceFilter, setConfidenceFilter] = useState('all')
  const [quantumFilter, setQuantumFilter] = useState('all')
  const [onlyReview, setOnlyReview] = useState(false)
  const [expanded, setExpanded] = useState(() => new Set())

  const filtered = useMemo(() => {
    let list = assets

    if (search.trim()) {
      const q = search.trim().toLowerCase()
      list = list.filter(
        (a) => a.name.toLowerCase().includes(q) || (a.sourceFile || '').toLowerCase().includes(q)
      )
    }
    if (typeFilter !== 'all') list = list.filter((a) => a.assetType === typeFilter)
    if (confidenceFilter !== 'all') list = list.filter((a) => a.confidence === confidenceFilter)
    if (quantumFilter !== 'all') list = list.filter((a) => a.quantumSecurityLevel === Number(quantumFilter))
    if (onlyReview) list = list.filter((a) => a.confidence === 'low')

    const sorted = [...list].sort((a, b) => {
      let cmp = 0
      if (sortBy === 'name') cmp = a.name.localeCompare(b.name)
      else if (sortBy === 'type') cmp = a.assetType.localeCompare(b.assetType)
      else if (sortBy === 'confidence') cmp = CONFIDENCE_RANK[a.confidence] - CONFIDENCE_RANK[b.confidence]
      else if (sortBy === 'quantum') cmp = a.quantumSecurityLevel - b.quantumSecurityLevel
      return sortDir === 'asc' ? cmp : -cmp
    })

    return sorted
  }, [assets, search, typeFilter, confidenceFilter, quantumFilter, onlyReview, sortBy, sortDir])

  function toggleSort(col) {
    if (sortBy === col) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortBy(col)
      setSortDir('asc')
    }
  }

  function toggleExpanded(bomRef) {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(bomRef)) next.delete(bomRef)
      else next.add(bomRef)
      return next
    })
  }

  const activeFilterCount =
    (typeFilter !== 'all' ? 1 : 0) +
    (confidenceFilter !== 'all' ? 1 : 0) +
    (quantumFilter !== 'all' ? 1 : 0) +
    (onlyReview ? 1 : 0)

  function clearFilters() {
    setTypeFilter('all')
    setConfidenceFilter('all')
    setQuantumFilter('all')
    setOnlyReview(false)
  }

  return (
    <div className="w-full animate-fade-in">
      <div className="flex flex-col gap-3">
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by name or file path…"
            className="flex-1 bg-surface border border-border rounded-lg px-4 py-2.5 text-sm font-mono placeholder:text-dim focus:border-accent focus:ring-1 focus:ring-accent"
          />
          <span className="self-center text-xs text-dim whitespace-nowrap">
            {filtered.length} of {assets.length} shown
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="bg-surface border border-border rounded-md px-3 py-1.5 text-xs text-muted focus:border-accent"
          >
            <option value="all">All asset types</option>
            {ASSET_TYPE_ORDER.map((t) => (
              <option key={t} value={t}>{ASSET_TYPE_LABEL[t]}</option>
            ))}
          </select>

          <select
            value={quantumFilter}
            onChange={(e) => setQuantumFilter(e.target.value)}
            className="bg-surface border border-border rounded-md px-3 py-1.5 text-xs text-muted focus:border-accent"
          >
            <option value="all">All quantum levels</option>
            {QUANTUM_LEVELS.map((l) => (
              <option key={l} value={l}>Level {l}</option>
            ))}
          </select>

          <select
            value={confidenceFilter}
            onChange={(e) => setConfidenceFilter(e.target.value)}
            className="bg-surface border border-border rounded-md px-3 py-1.5 text-xs text-muted focus:border-accent"
          >
            <option value="all">All confidence</option>
            {CONFIDENCE_ORDER.map((c) => (
              <option key={c} value={c}>{CONFIDENCE_LABEL[c]}</option>
            ))}
          </select>

          <button
            onClick={() => setOnlyReview((v) => !v)}
            className={`rounded-md px-3 py-1.5 text-xs border transition-colors ${
              onlyReview
                ? 'bg-high/15 border-high/30 text-high'
                : 'bg-surface border-border text-muted hover:border-borderLight'
            }`}
          >
            Needs review
          </button>

          {activeFilterCount > 0 && (
            <button
              onClick={clearFilters}
              className="text-xs text-dim hover:text-muted underline underline-offset-2"
            >
              Clear filters ({activeFilterCount})
            </button>
          )}
        </div>
      </div>

      <div className="mt-4 rounded-lg border border-border overflow-x-auto">
        <div className="min-w-[820px]">
          <div className="grid grid-cols-[1fr_120px_150px_70px_100px_170px_28px] gap-2 px-4 py-2.5 bg-raised border-b border-border text-xs text-dim uppercase tracking-wide">
            <SortHeader label="Name" col="name" sortBy={sortBy} sortDir={sortDir} onClick={toggleSort} />
            <SortHeader label="Type" col="type" sortBy={sortBy} sortDir={sortDir} onClick={toggleSort} />
            <span>Primitive</span>
            <SortHeader label="Risk" col="quantum" sortBy={sortBy} sortDir={sortDir} onClick={toggleSort} />
            <SortHeader label="Confidence" col="confidence" sortBy={sortBy} sortDir={sortDir} onClick={toggleSort} />
            <span>Source</span>
            <span />
          </div>

          {filtered.length === 0 ? (
            <div className="px-4 py-10 text-center text-sm text-dim">
              No crypto assets match the current filters.
            </div>
          ) : (
            <div className="divide-y divide-border">
              {filtered.map((a) => (
                <AssetRow
                  key={a.bomRef}
                  asset={a}
                  isExpanded={expanded.has(a.bomRef)}
                  onToggle={() => toggleExpanded(a.bomRef)}
                />
              ))}
            </div>
          )}
        </div>
      </div>
      <p className="mt-1.5 text-[11px] text-dim sm:hidden">Scroll horizontally to see all columns →</p>
    </div>
  )
}

function SortHeader({ label, col, sortBy, sortDir, onClick }) {
  const active = sortBy === col
  return (
    <button
      onClick={() => onClick(col)}
      className={`text-left flex items-center gap-1 hover:text-muted transition-colors ${active ? 'text-accent' : ''}`}
    >
      {label}
      {active && <span className="text-[10px]">{sortDir === 'asc' ? '↑' : '↓'}</span>}
    </button>
  )
}

function AssetRow({ asset: a, isExpanded, onToggle }) {
  const lowConfidence = a.confidence === 'low'
  const [copied, setCopied] = useState(false)

  async function copyFinding(e) {
    e.stopPropagation()
    try {
      await navigator.clipboard.writeText(JSON.stringify(a, null, 2))
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      // Clipboard API can be unavailable (permissions, non-HTTPS context);
      // fail quietly rather than showing a broken "Copied!" state.
    }
  }

  return (
    <div className={lowConfidence ? 'bg-medium/[0.04]' : undefined}>
      <button
        onClick={onToggle}
        className="w-full grid grid-cols-[1fr_120px_150px_70px_100px_170px_28px] gap-2 px-4 py-3 text-left items-center hover:bg-raised/60 transition-colors"
      >
        <div className="flex items-center gap-2 truncate">
          <span className="font-mono text-sm text-text truncate">{a.name}</span>
          {a.sourceContext === 'comment' && (
            <span
              className="inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-mono font-medium bg-dim/20 text-dim border border-dim/30 whitespace-nowrap"
              title="Found in comments or documentation code (inert, non-live execution)"
            >
              Comment
            </span>
          )}
        </div>
        <span className="text-xs text-muted truncate">{ASSET_TYPE_LABEL[a.assetType] || a.assetType}</span>
        <span className="text-xs text-muted truncate">{formatPrimitiveLabel(a)}</span>
        <QuantumRiskBadge level={a.quantumSecurityLevel} />
        <ConfidenceBadge confidence={a.confidence} score={a.confidenceScore} />
        <span className="font-mono text-xs text-dim truncate">{formatSourceLabel(a)}</span>
        <span className={`text-dim text-xs transition-transform ${isExpanded ? 'rotate-180' : ''}`}>
          ▾
        </span>
      </button>

      {isExpanded && (
        <div className="px-4 pb-4 pt-1 bg-bg/40 border-t border-border/60 animate-fade-in">
          <div className="flex items-start justify-between gap-3 mb-3">
            <p className="text-xs text-dim font-mono break-all">{a.bomRef}</p>
            <button
              onClick={copyFinding}
              className="shrink-0 text-[11px] text-dim hover:text-muted underline underline-offset-2 whitespace-nowrap"
            >
              {copied ? 'Copied' : 'Copy finding as JSON'}
            </button>
          </div>

          <div className="grid sm:grid-cols-2 gap-4">
            <div>
              <p className="text-xs uppercase tracking-wide text-dim mb-1.5">Confidence & Detection</p>
              <div className="flex flex-wrap items-center gap-2 mb-2">
                <ConfidenceBadge confidence={a.confidence} score={a.confidenceScore} size="md" />
                {a.sourceContext === 'comment' && (
                  <span className="inline-flex items-center rounded-md border border-dim/30 bg-dim/20 px-2 py-0.5 text-[11px] font-mono text-dim">
                    Inert (Comment / Doc)
                  </span>
                )}
              </div>
              <div className="flex flex-wrap gap-2">
                {(a.evidenceSources.length ? a.evidenceSources : ['—']).map((src, i) => (
                  <span
                    key={i}
                    className="inline-flex items-center rounded-md border border-border bg-raised px-2 py-1 text-[11px] font-mono text-muted"
                  >
                    {EVIDENCE_LABEL[src] || src}
                  </span>
                ))}
              </div>
            </div>

            {a.certificateProperties && (
              <div>
                <p className="text-xs uppercase tracking-wide text-dim mb-1.5">Certificate</p>
                <p className="text-sm text-muted">
                  {a.certificateProperties.subjectName}
                  <br />
                  Expires {new Date(a.certificateProperties.notValidAfter).toLocaleDateString()}
                </p>
              </div>
            )}

            {a.relatedCryptoMaterialProperties && (
              <div>
                <p className="text-xs uppercase tracking-wide text-dim mb-1.5">Material</p>
                <p className="text-sm text-muted capitalize">
                  {a.relatedCryptoMaterialProperties.type} — {a.relatedCryptoMaterialProperties.state}
                  {a.relatedCryptoMaterialProperties.size ? ` — ${a.relatedCryptoMaterialProperties.size} bits` : ''}
                </p>
              </div>
            )}

            {a.classicalSecurityLevel && (
              <div>
                <p className="text-xs uppercase tracking-wide text-dim mb-1.5">Classical security</p>
                <p className="text-sm text-muted font-mono">{a.classicalSecurityLevel}-bit</p>
              </div>
            )}

            <div>
              <p className="text-xs uppercase tracking-wide text-dim mb-1.5">Risk Assessment</p>
              <div className="flex flex-wrap items-center gap-2">
                <span className="inline-flex items-center rounded-md border border-border bg-raised px-2 py-1 text-[11px] font-mono text-muted">
                  Quantum: {a.quantumRisk || (a.quantumSecurityLevel === 0 ? 'CRITICAL' : 'LOW')}
                </span>
                <span
                  className={`inline-flex items-center rounded-md border px-2 py-1 text-[11px] font-mono font-semibold ${
                    a.exposureRisk === 'CRITICAL'
                      ? 'border-red-500/50 bg-red-500/10 text-red-400'
                      : a.exposureRisk === 'HIGH'
                      ? 'border-orange-500/50 bg-orange-500/10 text-orange-400'
                      : 'border-border bg-raised text-muted'
                  }`}
                >
                  Exposure: {a.exposureRisk || 'NONE'}
                </span>
              </div>
            </div>

            {a.dependsOn && a.dependsOn.length > 0 && (
              <div className="sm:col-span-2">
                <p className="text-xs uppercase tracking-wide text-dim mb-1.5">Used by</p>
                <div className="flex flex-wrap gap-2">
                  {a.dependsOn.map((ref) => (
                    <span
                      key={ref}
                      className="inline-flex items-center rounded-md border border-border bg-raised px-2 py-1 text-[11px] font-mono text-muted break-all"
                    >
                      {ref}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {lowConfidence && (
            <p className="mt-3 text-xs text-high">
              Low-confidence finding — flagged for manual review, not auto-trusted.
            </p>
          )}
        </div>
      )}
    </div>
  )
}
