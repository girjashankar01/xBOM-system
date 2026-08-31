import { QUANTUM_LEVELS, quantumRiskTier } from '../utils/cbomTransform'

const TIER_BAR_COLOR = {
  critical: 'bg-critical',
  high: 'bg-high',
  safe: 'bg-safe',
}

const LEVEL_LABEL = {
  0: 'Level 0 — broken by quantum',
  1: 'Level 1',
  2: 'Level 2',
  3: 'Level 3',
  4: 'Level 4',
  5: 'Level 5',
}

export default function QuantumRiskChart({ byQuantumRisk }) {
  const maxCount = Math.max(1, ...QUANTUM_LEVELS.map((l) => byQuantumRisk[l] ?? 0))

  return (
    <div className="rounded-lg border border-border bg-surface px-5 py-4">
      <p className="text-xs uppercase tracking-wide text-dim mb-3">Assets by quantum security level</p>
      <div className="space-y-2.5">
        {QUANTUM_LEVELS.map((level) => {
          const count = byQuantumRisk[level] ?? 0
          const tier = quantumRiskTier(level)
          return (
            <div key={level} className="flex items-center gap-3">
              <span className="w-40 shrink-0 text-xs text-muted truncate">{LEVEL_LABEL[level]}</span>
              <div className="flex-1 h-2 rounded-full bg-border overflow-hidden">
                <div
                  className={`h-full rounded-full ${TIER_BAR_COLOR[tier]}`}
                  style={{ width: `${(count / maxCount) * 100}%` }}
                />
              </div>
              <span className="w-8 text-right text-xs font-mono text-muted">{count}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
