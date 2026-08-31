import { quantumRiskTier, quantumRiskLabel } from '../utils/cbomTransform'

const STYLES = {
  critical: 'bg-critical/15 text-critical border-critical/30',
  high: 'bg-high/15 text-high border-high/30',
  safe: 'bg-safe/15 text-safe border-safe/30',
}

export default function QuantumRiskBadge({ level, size = 'sm' }) {
  if (level === undefined || level === null) return null
  const tier = quantumRiskTier(level)
  const padding = size === 'sm' ? 'px-2 py-0.5 text-[11px]' : 'px-2.5 py-1 text-xs'

  return (
    <span
      title={quantumRiskLabel(level)}
      className={`inline-flex items-center gap-1 rounded-full border font-mono font-medium ${padding} ${STYLES[tier]}`}
    >
      Q{level}
    </span>
  )
}
