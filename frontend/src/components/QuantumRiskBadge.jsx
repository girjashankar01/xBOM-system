import { quantumRiskTier, quantumRiskLabel } from '../utils/cbomTransform'
import { QUANTUM_EXPLANATIONS } from '../utils/cbomRemediation'

const STYLES = {
  critical: 'bg-critical/15 text-critical border-critical/30 hover:bg-critical/25',
  high: 'bg-high/15 text-high border-high/30 hover:bg-high/25',
  safe: 'bg-safe/15 text-safe border-safe/30 hover:bg-safe/25',
}

export default function QuantumRiskBadge({ level, size = 'sm', onClick }) {
  if (level === undefined || level === null) return null
  const tier = quantumRiskTier(level)
  const padding = size === 'sm' ? 'px-2 py-0.5 text-[11px]' : 'px-2.5 py-1 text-xs'
  const exp = QUANTUM_EXPLANATIONS[level]
  const tooltip = exp
    ? `${exp.title}: ${exp.summary} | Fix: ${exp.recommendation}`
    : quantumRiskLabel(level)

  return (
    <span
      onClick={onClick}
      title={tooltip}
      className={`inline-flex items-center gap-1 rounded-full border font-mono font-medium transition-colors ${
        onClick ? 'cursor-pointer' : ''
      } ${padding} ${STYLES[tier]}`}
    >
      Q{level}
    </span>
  )
}
