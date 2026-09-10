import { QUANTUM_LEVELS, quantumRiskTier } from '../utils/cbomTransform'
import { QUANTUM_EXPLANATIONS } from '../utils/cbomRemediation'

const TIER_BAR_COLOR = {
  critical: 'bg-critical',
  high: 'bg-high',
  safe: 'bg-safe',
}

const LEVEL_LABEL = {
  0: 'Level 0 — Broken by Quantum (RSA, ECC)',
  1: 'Level 1 — 128-bit Classical (AES-128)',
  2: 'Level 2 — SHA-256 Collision Level',
  3: 'Level 3 — NIST PQC Baseline (Quantum-Safe)',
  4: 'Level 4 — SHA-384 Collision Level',
  5: 'Level 5 — Maximum Quantum-Safe (AES-256)',
}

export default function QuantumRiskChart({ byQuantumRisk = {}, onOpenGuide }) {
  const counts = byQuantumRisk || {}
  const maxCount = Math.max(1, ...QUANTUM_LEVELS.map((l) => counts[l] ?? 0))

  return (
    <div className="rounded-lg border border-border bg-surface px-5 py-4">
      <div className="flex items-center justify-between mb-3">
        <p className="text-xs uppercase tracking-wide text-dim">Assets by quantum security level</p>
        {onOpenGuide && (
          <button
            onClick={onOpenGuide}
            className="text-[11px] text-accent hover:underline font-mono transition-colors"
          >
            What do these levels mean? (NIST PQC Guide)
          </button>
        )}
      </div>

      <div className="space-y-2.5">
        {QUANTUM_LEVELS.map((level) => {
          const count = counts[level] ?? 0
          const tier = quantumRiskTier(level)
          const exp = QUANTUM_EXPLANATIONS[level]
          return (
            <div
              key={level}
              className="flex items-center gap-3 group cursor-pointer"
              onClick={onOpenGuide}
              title={exp ? `${exp.title}: ${exp.summary}` : undefined}
            >
              <span className="w-64 shrink-0 text-xs text-muted group-hover:text-text transition-colors truncate">
                {LEVEL_LABEL[level]}
              </span>
              <div className="flex-1 h-2 rounded-full bg-border overflow-hidden">
                <div
                  className={`h-full rounded-full ${TIER_BAR_COLOR[tier]}`}
                  style={{ width: `${(count / maxCount) * 100}%` }}
                />
              </div>
              <span className="w-8 text-right text-xs font-mono text-muted group-hover:text-text">{count}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
