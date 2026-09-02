export default function CbomSummaryCards({ summary }) {
  const exposedCritical = summary.exposureRisk?.CRITICAL ?? summary.exposureRisk?.critical ?? 0
  const exposedHigh = summary.exposureRisk?.HIGH ?? summary.exposureRisk?.high ?? 0

  const cards = [
    { label: 'Crypto assets found', value: summary.totalAssets, color: 'text-text' },
    { label: 'Quantum-vulnerable (Q0)', value: summary.byQuantumRisk[0] ?? 0, color: 'text-critical' },
    {
      label: 'Exposed keys/certs (Critical)',
      value: exposedCritical,
      subValue: exposedHigh > 0 ? `+${exposedHigh} high` : null,
      color: exposedCritical > 0 ? 'text-critical' : 'text-text',
    },
    { label: 'Certificates expiring soon', value: summary.certsExpiringSoon, color: 'text-high' },
    { label: 'Needs manual review', value: summary.flaggedForReview, color: 'text-medium' },
  ]

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
      {cards.map(({ label, value, subValue, color }) => (
        <div key={label} className="rounded-lg border border-border bg-surface px-4 py-4">
          <div className="flex items-baseline gap-1.5">
            <p className={`text-2xl font-mono font-semibold ${color}`}>{value}</p>
            {subValue && <span className="text-xs font-mono text-high">{subValue}</span>}
          </div>
          <p className="mt-1 text-xs text-muted">{label}</p>
        </div>
      ))}
    </div>
  )
}
