import type { BadgeState, Confidence, Verdict } from '../data/reportHtml'
import { IconReport } from './Icons'

const HEX = (
  <svg viewBox="0 0 100 100" aria-hidden="true">
    <polygon points="50,3 92,26.5 92,73.5 50,97 8,73.5 8,26.5" />
  </svg>
)

/**
 * The state of the case as the report will print it, live: the verdict seal, the confidence, how
 * far the review has come, and the threat profile as one badge per tactic (filled when a confirmed
 * item carries it, outlined when only observed). The same functions build the report's cover, so
 * what the analyst sees here is what the reader will see there.
 */
export function VerdictBar({
  verdict,
  confidence,
  profile,
  done,
  total,
  onReport,
}: {
  verdict: Verdict
  confidence: Confidence
  profile: BadgeState[]
  done: number
  total: number
  onReport: () => void
}) {
  const seen = profile.filter((b) => b.state !== 'none')
  return (
    <div className="verdict-bar" data-kind={verdict.kind}>
      <div className={`seal ${verdict.kind}`} title={verdict.detail}>
        {HEX}
        <div className="seal-in">
          <span className="k">verdict</span>
          <span className="w">{verdict.label}</span>
          {verdict.severity && <span className="s">{verdict.severity}</span>}
        </div>
      </div>
      <div className="verdict-text">
        <div className="line">{verdict.detail}</div>
        <div className="row wrap small" style={{ gap: 10 }}>
          <span className={`conf ${confidence.level}`}>
            <b>confidence {confidence.level}</b>
            <span className="muted">{confidence.reasons.slice(0, 2).join(' · ')}</span>
          </span>
          <span className="muted">
            {done} of {total} decided
          </span>
        </div>
        <div className="review-progress" style={{ marginTop: 6 }}>
          <div style={{ width: `${total ? (done / total) * 100 : 0}%` }} />
        </div>
      </div>
      <div className="verdict-badges">
        <div className="k">
          threat profile · {seen.length} of {profile.length} observed
        </div>
        <div className="hexes">
          {profile.map((b) => (
            <div key={b.def.id} className={`hex ${b.state}`} title={`${b.def.label}: ${b.findings} finding${b.findings === 1 ? '' : 's'}${b.techniques.length ? ' · ' + b.techniques.join(', ') : ''}`}>
              {HEX}
              <span className="code">{b.def.code}</span>
            </div>
          ))}
        </div>
      </div>
      <button className="btn primary" onClick={onReport} title="open the report">
        <IconReport /> report
      </button>
    </div>
  )
}
