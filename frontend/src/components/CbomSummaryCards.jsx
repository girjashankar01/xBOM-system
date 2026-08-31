export default function CbomSummaryCards({ summary }) {
  const cards = [
    { label: 'Crypto assets found', value: summary.totalAssets, color: 'text-text' },
    { label: 'Quantum-vulnerable (Q0)', value: summary.byQuantumRisk[0] ?? 0, color: 'text-critical' },
    { label: 'Certificates expiring soon', value: summary.certsExpiringSoon, color: 'text-high' },
    { label: 'Needs manual review', value: summary.flaggedForReview, color: 'text-medium' },
  ]

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
      {cards.map(({ label, value, color }) => (
        <div key={label} className="rounded-lg border border-border bg-surface px-4 py-4">
          <p className={`text-2xl font-mono font-semibold ${color}`}>{value}</p>
          <p className="mt-1 text-xs text-muted">{label}</p>
        </div>
      ))}
    </div>
  )
}
