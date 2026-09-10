import { useEffect, useState } from 'react'

// Honest UX: the backend is fully synchronous with no real progress signal,
// so these are a rotating best-guess of pipeline stage, not a live status.
// See SIH_26077_part3.md §8 — this is a deliberate, acknowledged limitation.
const STAGES = [
  'Cloning repository…',
  'Resolving lockfile dependency tree…',
  'Querying OSV.dev for known vulnerabilities…',
  'Checking for typosquats and install scripts…',
  'Scanning AST for cryptographic assets & keys…',
  'Evaluating post-quantum readiness & assembling xBOM…',
]

const SBOM_ROWS = [
  { nameWidth: '55%', verWidth: '22%', statusColor: 'bg-safe' },
  { nameWidth: '68%', verWidth: '18%', statusColor: 'bg-medium' },
  { nameWidth: '42%', verWidth: '24%', statusColor: 'bg-critical' },
  { nameWidth: '60%', verWidth: '16%', statusColor: 'bg-safe' },
  { nameWidth: '48%', verWidth: '20%', statusColor: 'bg-low' },
  { nameWidth: '58%', verWidth: '25%', statusColor: 'bg-safe' },
]

const CBOM_ROWS = [
  { label: 'AES-256-GCM', tag: 'CIPHER', statusColor: 'bg-safe' },
  { label: 'RSA-2048', tag: 'ASYMMETRIC', statusColor: 'bg-critical' },
  { label: 'SHA-256', tag: 'HASH', statusColor: 'bg-safe' },
  { label: 'X.509 Certificate', tag: 'CERT', statusColor: 'bg-medium' },
  { label: 'ML-KEM / Kyber', tag: 'PQC', statusColor: 'bg-safe' },
  { label: 'ECDSA P-256', tag: 'SIGNATURE', statusColor: 'bg-high' },
]

export default function LoadingState() {
  const [stageIndex, setStageIndex] = useState(0)
  const [elapsed, setElapsed] = useState(0)

  useEffect(() => {
    const stageTimer = setInterval(() => {
      setStageIndex((i) => Math.min(i + 1, STAGES.length - 1))
    }, 9000)
    const clock = setInterval(() => setElapsed((s) => s + 1), 1000)
    return () => {
      clearInterval(stageTimer)
      clearInterval(clock)
    }
  }, [])

  return (
    <div className="w-full max-w-2xl animate-fade-in">
      <div className="relative overflow-hidden rounded-lg border border-border bg-surface shadow-md">
        {/* Sweeping scan beam across both panels */}
        <div className="pointer-events-none absolute left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-accent to-transparent animate-scan-sweep shadow-[0_0_12px_rgba(79,209,197,0.8)] z-10" />

        {/* Dual Stream Header */}
        <div className="grid grid-cols-2 border-b border-border bg-raised/70 text-xs font-mono">
          <div className="flex items-center justify-between px-4 py-2.5 border-r border-border">
            <span className="flex items-center gap-2 text-text font-medium">
              <span className="h-1.5 w-1.5 rounded-full bg-accent animate-pulse-dot" />
              SBOM Stream
            </span>
            <span className="text-[11px] text-dim font-sans hidden sm:inline">Dependencies</span>
          </div>
          <div className="flex items-center justify-between px-4 py-2.5">
            <span className="flex items-center gap-2 text-text font-medium">
              <span className="h-1.5 w-1.5 rounded-full bg-safe animate-pulse-dot" />
              CBOM Stream
            </span>
            <span className="text-[11px] text-dim font-sans hidden sm:inline">Crypto &amp; Quantum</span>
          </div>
        </div>

        {/* Dual Stream Content */}
        <div className="grid grid-cols-2 divide-x divide-border">
          {/* Left: SBOM Skeleton */}
          <div className="divide-y divide-border/40">
            {SBOM_ROWS.map((row, i) => (
              <div key={i} className="flex items-center justify-between px-3.5 py-2.5">
                <div className="flex items-center gap-2 flex-1 min-w-0">
                  <div className="h-1.5 w-1.5 rounded-full bg-dim/60 shrink-0" />
                  <div
                    className="h-2 rounded bg-border animate-pulse"
                    style={{ width: row.nameWidth }}
                  />
                  <div
                    className="h-2 rounded bg-border/60 animate-pulse hidden sm:block"
                    style={{ width: row.verWidth }}
                  />
                </div>
                <div className="flex items-center gap-1.5 shrink-0 pl-2">
                  <div className={`h-1.5 w-1.5 rounded-full ${row.statusColor} animate-pulse`} />
                </div>
              </div>
            ))}
          </div>

          {/* Right: CBOM Skeleton */}
          <div className="divide-y divide-border/40">
            {CBOM_ROWS.map((row, i) => (
              <div key={i} className="flex items-center justify-between px-3.5 py-2.5">
                <div className="flex items-center gap-2 flex-1 min-w-0">
                  <div className="h-1.5 w-1.5 rounded-full bg-dim/60 shrink-0" />
                  <span className="font-mono text-[11px] text-muted truncate">
                    {row.label}
                  </span>
                </div>
                <div className="flex items-center gap-1.5 shrink-0 pl-1">
                  <span className="text-[9px] font-mono px-1 py-0.5 rounded border border-border text-dim hidden sm:inline">
                    {row.tag}
                  </span>
                  <div className={`h-1.5 w-1.5 rounded-full ${row.statusColor} animate-pulse`} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="mt-5 flex items-center justify-between">
        <p className="text-sm text-text flex items-center gap-2">
          <span className="flex gap-1">
            <span className="h-1.5 w-1.5 rounded-full bg-accent animate-pulse-dot" />
            <span className="h-1.5 w-1.5 rounded-full bg-accent animate-pulse-dot [animation-delay:0.2s]" />
            <span className="h-1.5 w-1.5 rounded-full bg-accent animate-pulse-dot [animation-delay:0.4s]" />
          </span>
          {STAGES[stageIndex]}
        </p>
        <span className="text-xs text-dim font-mono">{elapsed}s</span>
      </div>
      <p className="mt-2 text-xs text-dim">
        Scanning dependency trees and extracting cryptographic AST primitives &amp; keys — hang tight.
      </p>
    </div>
  )
}
