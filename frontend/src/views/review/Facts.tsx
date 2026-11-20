import { useMemo } from 'react'
import { Badge, Sev } from '../../components/ui'
import { groupByRule } from '../../data/reportHtml'
import type { Finding } from '../../db/schema'
import { fmtNum, fmtTs, tzLabel } from '../../util/format'
import { STATUS_LABEL, STATUS_SEV, trim, type Status } from './model'

/** The facts behind an item, the way the report prints them: one line per rule with count, span and the values matched. */
export function Facts({ findings, said, onUnlink }: { findings: Finding[]; said: Record<string, string>; onUnlink?: (ids: number[]) => void }) {
  const groups = useMemo(() => groupByRule(findings, said), [findings, said])
  if (!groups.length) return <div className="small muted">no finding</div>
  const idsOf = (ruleId: string) => findings.filter((f) => f.ruleId === ruleId && f.id != null).map((f) => f.id!)
  return (
    <table className="table compact facts">
      <thead>
        <tr>
          <th>severity</th>
          <th>finding</th>
          <th>findings · rows</th>
          <th>when ({tzLabel()})</th>
          <th>what matched</th>
          <th>status</th>
          {onUnlink && <th></th>}
        </tr>
      </thead>
      <tbody>
        {groups.map((g) => (
          <tr key={g.ruleId}>
            <td style={{ width: 96 }}>
              <Sev sev={g.severity} />
              {g.severity !== g.ruleSeverity && <div className="small muted">rule {g.ruleSeverity}</div>}
            </td>
            <td className="sans">
              {g.title}
              <div className="small muted mono">
                {g.ruleId}
                {g.escalations.length ? ` · ${g.escalations.slice(0, 2).join(' · ')}` : ''}
                {g.attack.length ? ` · ${g.attack.slice(0, 4).join(' ')}` : ''}
              </div>
            </td>
            <td className="nowrap" style={{ width: 90 }}>
              {fmtNum(g.findings)} · {fmtNum(g.rows)}
            </td>
            <td className="nowrap small" style={{ width: 150 }}>
              {fmtTs(g.first)}
              {g.last && g.first && g.last !== g.first ? <div className="muted">to {fmtTs(g.last)}</div> : null}
            </td>
            <td className="vals">
              {g.values.length ? (
                <>
                  {g.values.slice(0, 5).map((v) => (
                    <code key={v} title={v}>
                      {trim(v, 110)}
                    </code>
                  ))}
                  {g.values.length > 5 && <span className="small muted">+{g.values.length - 5} more</span>}
                </>
              ) : (
                <span className="muted">–</span>
              )}
            </td>
            <td style={{ width: 110 }}>
              {Object.entries(g.statuses).map(([s, c]) => (
                <span key={s} style={{ marginRight: 4 }}>
                  <Badge sev={STATUS_SEV[s as Status]}>{STATUS_LABEL[s as Status]}</Badge>
                  {c > 1 ? <span className="small muted"> ×{c}</span> : null}
                </span>
              ))}
            </td>
            {onUnlink && (
              <td style={{ width: 60 }}>
                <button className="btn link small" onClick={() => onUnlink(idsOf(g.ruleId))}>
                  unlink
                </button>
              </td>
            )}
          </tr>
        ))}
      </tbody>
    </table>
  )
}
