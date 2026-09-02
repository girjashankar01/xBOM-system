import { CONFIDENCE_LABEL, toCategoricalConfidence } from '../utils/cbomTransform'

const STYLES = {
  'very-high': 'bg-accent/15 text-accent border-accent/30',
  high: 'bg-raised text-muted border-borderLight',
  medium: 'bg-medium/15 text-medium border-medium/30',
  low: 'bg-high/15 text-high border-high/30',
}

export default function ConfidenceBadge({ confidence, score, size = 'sm' }) {
  const category = score != null && !isNaN(score) ? toCategoricalConfidence(score) : confidence
  if (!category) return null
  const padding = size === 'sm' ? 'px-2 py-0.5 text-[11px]' : 'px-2.5 py-1 text-xs'
  const scoreText = score != null && typeof score === 'number' && !isNaN(score) ? `(${score.toFixed(2)})` : null

  return (
    <span
      title="Computed confidence score based on detection method and context"
      className={`inline-flex items-center gap-1 rounded-full border font-mono font-medium ${padding} ${STYLES[category] || STYLES.low}`}
    >
      <span>{CONFIDENCE_LABEL[category] || category}</span>
      {scoreText && <span className="opacity-80 text-[10px]">{scoreText}</span>}
    </span>
  )
}
