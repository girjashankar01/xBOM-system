import { QUANTUM_EXPLANATIONS } from '../utils/cbomRemediation'

export default function QuantumRiskGuideModal({ isOpen, onClose }) {
  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-bg/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-2xl max-h-[85vh] flex flex-col rounded-xl border border-border bg-surface shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-raised/50">
          <div>
            <h3 className="text-base font-semibold text-text">
              NIST Post-Quantum Cryptography (PQC) Security Levels
            </h3>
            <p className="text-xs text-muted mt-0.5">
              Reference guide for quantum threat vectors (Shor's &amp; Grover's algorithms) and migration targets
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-muted hover:text-text rounded-md p-1 hover:bg-raised transition-colors text-lg"
          >
            ✕
          </button>
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4 text-xs">
          <div className="rounded-lg border border-accent/20 bg-accent/5 p-3.5 leading-relaxed text-muted">
            <span className="font-semibold text-accent">Why Post-Quantum Matters:</span> Quantum computers running
            <strong className="text-text"> Shor’s algorithm</strong> break classical public-key cryptography (RSA, ECC, Diffie-Hellman)
            in polynomial time. Symmetric ciphers are impacted by <strong className="text-text">Grover’s algorithm</strong>, which
            halves their effective brute-force key length. NIST developed Security Levels 1 through 5 to standardize post-quantum defense.
          </div>

          <div className="space-y-3">
            {Object.entries(QUANTUM_EXPLANATIONS).map(([level, info]) => (
              <div
                key={level}
                className="rounded-lg border border-border bg-raised/40 p-4 space-y-2 hover:border-borderLight transition-colors"
              >
                <div className="flex items-center justify-between">
                  <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 font-mono text-xs font-semibold ${info.badgeColor}`}>
                    Q{level} — {info.title.split('—')[1] || info.title}
                  </span>
                  <span className="font-mono text-[11px] text-dim">Level {level}</span>
                </div>

                <p className="text-text font-medium">{info.summary}</p>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] text-muted pt-1">
                  <div>
                    <span className="text-dim uppercase tracking-wider text-[10px] block">Affected Primitives</span>
                    <span className="font-mono text-text">{info.affectedAlgorithms}</span>
                  </div>
                  <div>
                    <span className="text-dim uppercase tracking-wider text-[10px] block">Quantum Threat Vector</span>
                    <span>{info.quantumAttack}</span>
                  </div>
                </div>

                <div className="pt-1.5 border-t border-border/40 text-[11px]">
                  <span className="text-accent font-semibold">Recommended Fix: </span>
                  <span className="text-muted">{info.recommendation}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Modal Footer */}
        <div className="flex items-center justify-between px-6 py-3 border-t border-border bg-raised/40 text-xs">
          <span className="text-dim font-mono">Standards: NIST FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA)</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-md bg-accent text-bg font-semibold hover:bg-accent/90 transition-colors"
          >
            Got it
          </button>
        </div>
      </div>
    </div>
  )
}
