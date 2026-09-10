import { useState, useMemo } from 'react'
import { generateRemediationChecklist, formatChecklistAsMarkdown } from '../utils/cbomRemediation'

export default function RemediationChecklist({ assets, repoUrl }) {
  const tasks = useMemo(() => generateRemediationChecklist(assets), [assets])
  const [completed, setCompleted] = useState(() => new Set())
  const [copied, setCopied] = useState(false)

  function toggleTask(id) {
    setCompleted((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  async function handleCopyMarkdown() {
    const md = formatChecklistAsMarkdown(tasks, repoUrl)
    try {
      await navigator.clipboard.writeText(md)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // fallback
    }
  }

  const completedCount = completed.size
  const totalCount = tasks.length
  const progressPercent = totalCount > 0 ? Math.round((completedCount / totalCount) * 100) : 100

  if (tasks.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-surface p-8 text-center animate-fade-in">
        <h3 className="text-base font-semibold text-text mt-2">No Active Remediation Tasks</h3>
        <p className="text-xs text-muted mt-1 max-w-md mx-auto">
          No critical post-quantum vulnerabilities, exposed secrets, or weak hash digests were detected in this cryptographic inventory.
        </p>
      </div>
    )
  }

  return (
    <div className="w-full space-y-4 animate-fade-in">
      {/* Top action header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-lg border border-border bg-surface">
        <div>
          <h3 className="text-sm font-semibold text-text">
            Cryptographic Remediation &amp; PQC Migration Checklist
          </h3>
          <p className="text-xs text-muted mt-0.5">
            {completedCount} of {totalCount} security action items addressed ({progressPercent}%)
          </p>
          <div className="w-48 h-1.5 rounded-full bg-border mt-2 overflow-hidden">
            <div
              className="h-full bg-accent transition-all duration-300"
              style={{ width: `${progressPercent}%` }}
            />
          </div>
        </div>

        <button
          onClick={handleCopyMarkdown}
          className="inline-flex items-center gap-2 text-xs font-semibold px-3 py-2 rounded-md border border-accent/40 bg-accent/10 text-accent hover:bg-accent/20 transition-colors whitespace-nowrap self-start sm:self-auto"
        >
          <span>{copied ? 'Copied to Clipboard' : 'Export as GitHub Issue (Markdown)'}</span>
        </button>
      </div>

      {/* Task cards */}
      <div className="space-y-3">
        {tasks.map((task) => {
          const isDone = completed.has(task.id)
          const priorityStyles = {
            critical: 'border-critical/40 bg-critical/[0.03]',
            high: 'border-high/40 bg-high/[0.03]',
            medium: 'border-medium/40 bg-medium/[0.03]',
            low: 'border-border bg-surface',
          }[task.priority] || 'border-border bg-surface'

          const priorityBadge = {
            critical: 'bg-critical/15 text-critical border-critical/30',
            high: 'bg-high/15 text-high border-high/30',
            medium: 'bg-medium/15 text-medium border-medium/30',
            low: 'bg-dim/20 text-muted border-border',
          }[task.priority]

          return (
            <div
              key={task.id}
              onClick={() => toggleTask(task.id)}
              className={`p-4 rounded-lg border transition-all cursor-pointer select-none ${priorityStyles} ${
                isDone ? 'opacity-50 line-through' : 'hover:border-borderLight'
              }`}
            >
              <div className="flex items-start gap-3">
                <input
                  type="checkbox"
                  checked={isDone}
                  onChange={() => {}} // handled by parent onClick
                  className="mt-1 h-4 w-4 rounded border-border text-accent focus:ring-accent shrink-0 cursor-pointer"
                />

                <div className="flex-1 min-w-0 space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`inline-flex items-center rounded px-2 py-0.5 text-[10px] font-mono font-semibold uppercase border ${priorityBadge}`}>
                      {task.priority}
                    </span>
                    <span className="text-sm font-medium text-text">{task.title}</span>
                    <span className="text-[11px] font-mono text-dim ml-auto">
                      Target: {task.target}
                    </span>
                  </div>

                  <p className="text-xs text-muted leading-relaxed">{task.description}</p>

                  <div className="pt-1 flex items-center gap-2 text-xs">
                    <span className="text-accent font-medium">Recommended Action:</span>
                    <span className="text-text font-mono text-[11px] bg-raised px-2 py-0.5 rounded border border-border">
                      {task.recommendation}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
