import { Progress } from '../../components/ui'
import type { Staleness } from '../../data/findingsState'
import type { RuleDiag } from '../../rules/engine'
import { useStore } from '../../state/store'
import { fmtNum } from '../../util/format'

/**
 * Above the queue: the rule run in progress, or why the findings are behind the evidence, the rules
 * that failed in the last run, and the rules that found more than their cap (and how many findings
 * they left out).
 */
export function FindingsBanners({ stale, staleParts, cuts, onRun }: { stale: Staleness | null; staleParts: string[]; cuts: RuleDiag[]; onRun: () => void }) {
  const running = useStore((s) => s.rulesRun)
  const setView = useStore((s) => s.setView)
  const leftOut = cuts.reduce((n, d) => n + (d.dropped ?? 0), 0)
  return (
    <>
      {running && (
        <div style={{ padding: '6px 16px', background: 'var(--surface)' }} className="col">
          <div className="small dim mono">
            {running.reason === 'ingest' ? 'refreshing findings after ingest · ' : ''}
            {running.done}/{running.total} · {running.rule}
          </div>
          <Progress value={running.done / Math.max(1, running.total)} />
        </div>
      )}
      {!running && staleParts.length > 0 && (
        <div className="bulkbar" style={{ background: 'var(--sev-medium-bg)', borderColor: 'rgba(217,130,43,0.35)', color: 'var(--sev-medium)' }}>
          <b>Findings are behind the evidence:</b>
          <span>{staleParts.join(' · ')}</span>
          <span className="spacer" />
          <button className="btn xs" onClick={onRun}>
            run rules now
          </button>
        </div>
      )}
      {!running && stale && stale.errors.length > 0 && (
        <div className="bulkbar" style={{ background: 'var(--sev-high-bg)', borderColor: 'rgba(209,64,63,0.35)', color: 'var(--sev-high)' }}>
          <b>
            {stale.errors.length} rule{stale.errors.length === 1 ? '' : 's'} failed in the last run
          </b>
          <span className="ellipsis" title={stale.errors.join('\n')}>
            {stale.errors
              .slice(0, 3)
              .map((e) => e.split(':')[0])
              .join(', ')}
            {stale.errors.length > 3 ? ` +${stale.errors.length - 3}` : ''} · their findings are from an earlier run or missing
          </span>
          <span className="spacer" />
          <button className="btn xs" onClick={() => setView('rules')}>
            see diagnostics
          </button>
        </div>
      )}
      {!running && cuts.length > 0 && (
        <div className="bulkbar" data-cut-rules={cuts.length} style={{ background: 'var(--sev-medium-bg)', borderColor: 'rgba(217,130,43,0.35)', color: 'var(--sev-medium)' }}>
          <b>
            {cuts.length} rule{cuts.length === 1 ? '' : 's'} found more than {cuts.length === 1 ? 'its' : 'their'} cap in the last run
          </b>
          <span className="ellipsis" title={cuts.map((d) => `${d.ruleId}: ${d.detail ?? ''}`).join('\n')}>
            {leftOut > 0 ? `${fmtNum(leftOut)} finding${leftOut === 1 ? '' : 's'} left out and not listed · ` : ''}
            {cuts
              .slice(0, 3)
              .map((d) => d.ruleId)
              .join(', ')}
            {cuts.length > 3 ? ` +${cuts.length - 3}` : ''}
          </span>
          <span className="spacer" />
          <button className="btn xs" onClick={() => setView('rules')}>
            see diagnostics
          </button>
        </div>
      )}
    </>
  )
}
