import { formatAnomalyTypeLabel } from '../utils/transform'
import { downloadSbomJson } from '../utils/sbomExport'

const CARDS = [
  { key: 'totalComponents', label: 'Components', color: 'text-text' },
  { key: 'critical', label: 'Critical', color: 'text-critical' },
  { key: 'high', label: 'High', color: 'text-high' },
  { key: 'medium', label: 'Medium', color: 'text-medium' },
  { key: 'low', label: 'Low', color: 'text-low' },
  { key: 'flaggedCount', label: 'Flagged total', color: 'text-accent' },
]

const TYPE_BAR_COLOR = 'bg-accent'

export default function RiskSummary({ riskSummary, typeBreakdown, repoUrl, sbom }) {
  const typeEntries = Object.entries(typeBreakdown).sort((a, b) => b[1] - a[1])
  const maxTypeCount = Math.max(1, ...typeEntries.map(([, count]) => count))

  return (
    <div className="w-full animate-fade-in">
      <div className="flex items-start justify-between mb-4">
        <div>
          <h2 className="text-lg font-semibold text-text">Risk summary</h2>
          <p className="text-xs text-dim font-mono mt-0.5 truncate max-w-md">{repoUrl}</p>
        </div>
        {sbom && (
          <button
            onClick={() => downloadSbomJson(sbom, repoUrl)}
            className="text-xs text-muted hover:text-text border border-border rounded-md px-3 py-1.5 transition-colors whitespace-nowrap"
          >
            Export SBOM (JSON)
          </button>
        )}
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {CARDS.map(({ key, label, color }) => (
          <div
            key={key}
            className="rounded-lg border border-border bg-surface px-4 py-4"
          >
            <p className={`text-2xl font-mono font-semibold ${color}`}>
              {riskSummary[key] ?? 0}
            </p>
            <p className="mt-1 text-xs text-muted">{label}</p>
          </div>
        ))}
      </div>

      {typeEntries.length > 0 && (
        <div className="mt-4 rounded-lg border border-border bg-surface px-5 py-4">
          <p className="text-xs uppercase tracking-wide text-dim mb-3">Flags by type</p>
          <div className="space-y-2.5">
            {typeEntries.map(([type, count]) => (
              <div key={type} className="flex items-center gap-3">
                <span className="w-28 shrink-0 text-xs text-muted truncate">
                  {formatAnomalyTypeLabel(type)}
                </span>
                <div className="flex-1 h-2 rounded-full bg-border overflow-hidden">
                  <div
                    className={`h-full rounded-full ${TYPE_BAR_COLOR}`}
                    style={{ width: `${(count / maxTypeCount) * 100}%` }}
                  />
                </div>
                <span className="w-8 text-right text-xs font-mono text-muted">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
