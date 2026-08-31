import { CONFIDENCE_LABEL } from '../utils/cbomTransform'

const STYLES = {
  'very-high': 'bg-accent/15 text-accent border-accent/30',
  high: 'bg-raised text-muted border-borderLight',
  medium: 'bg-medium/15 text-medium border-medium/30',
  low: 'bg-high/15 text-high border-high/30',
}

export default function ConfidenceBadge({ confidence, size = 'sm' }) {
  if (!confidence) return null
  const padding = size === 'sm' ? 'px-2 py-0.5 text-[11px]' : 'px-2.5 py-1 text-xs'

  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border font-mono font-medium ${padding} ${STYLES[confidence]}`}
    >
      {CONFIDENCE_LABEL[confidence]}
    </span>
  )
}
