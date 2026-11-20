/** The small pieces the Findings page draws in its lists and flyouts. */
import { Badge, Sev } from '../../components/ui'
import { isLead, type MeasureReading } from '../../data/ruleMeasures'
import { shortReasons, type Priority } from '../../data/findingPriority'
import type { Finding } from '../../db/schema'
import { effectiveSeverity } from '../../rules/incidents'
import { classNames, fmtNum, fmtTs } from '../../util/format'
import { STATUS_LABEL, STATUS_SEV, type Status } from './model'
import { pressableRow } from '../../components/pressable'

export const StatusBadge = ({ s }: { s: string }) => <Badge sev={STATUS_SEV[s as Status] ?? 'info'}>{STATUS_LABEL[s as Status] ?? s}</Badge>

export const FindingSeverity = ({ finding }: { finding: Finding }) => (
  <span title={finding.severityOverride ? `Review severity override: ${finding.severityOverride}; rule: ${finding.severity}` : undefined}>
    <Sev sev={effectiveSeverity(finding)}>
      {effectiveSeverity(finding)}
      {finding.severityOverride ? '*' : ''}
    </Sev>
  </span>
)

/** A finding's priority score, with the reasons that moved it beside it and all of them in its title. */
export const PriorityCell = ({ p }: { p?: Priority }) =>
  p ? (
    <span className="ellipsis" title={p.reasons.map((r) => r.text).join('\n')}>
      <span className={classNames('mono', p.decided && 'muted')}>{p.score}</span>
      {shortReasons(p) ? <span className="small muted"> · {shortReasons(p)}</span> : null}
    </span>
  ) : null

export const OverrideLabel = ({ finding }: { finding: Finding }) => (finding.severityOverride ? <span className="small muted">review override; rule: {finding.severity}</span> : null)

export function SeverityOverrideNotice({ findings, busy, onReset, chain = false }: { findings: Finding[]; busy: boolean; onReset: () => void; chain?: boolean }) {
  if (!findings.some((f) => f.severityOverride)) return null
  return (
    <div className="section">
      <h3>Review severity override</h3>
      <p className="small muted">
        A saved review overrides the rule severity for the findings marked with *. Rule refreshes preserve these overrides. Resetting keeps review status and notes.
        {chain ? ' Chain severity is managed separately on the Review page.' : ''}
      </p>
      <button className="btn sm" disabled={busy} onClick={onReset}>
        {busy ? 'resetting…' : chain ? 'reset finding overrides' : 'reset to rule severity'}
      </button>
    </div>
  )
}

/** A finding of a rule never seen to detect what it looks for (data/ruleMeasures.ts). */
export function LeadBadge({ reading }: { reading?: MeasureReading }) {
  if (!reading || !isLead(reading)) return null
  return (
    <>
      {' '}
      <Badge sev="outline" title={reading.attacks}>
        lead
      </Badge>
    </>
  )
}

/** One finding as a row of a group or of an incident's list; a click opens it. */
export function MemberRow({ f, priority, reading, onOpen }: { f: Finding; priority?: Priority; reading?: MeasureReading; onOpen: () => void }) {
  return (
    <tr {...pressableRow} onClick={onOpen} style={{ cursor: 'pointer' }}>
      <td style={{ width: 60 }} className="mono" title={priority?.reasons.map((r) => r.text).join('\n')}>
        {priority?.score}
      </td>
      <td style={{ width: 100 }}>
        <FindingSeverity finding={f} />
      </td>
      <td className="sans">
        {f.title}
        {f.escalation ? <span className="muted"> · {f.escalation}</span> : null}
        <LeadBadge reading={reading} />
        {f.severityOverride && (
          <div>
            <OverrideLabel finding={f} />
          </div>
        )}
      </td>
      <td className="muted">{f.ruleId}</td>
      <td style={{ width: 60 }}>{fmtNum(f.count)}</td>
      <td style={{ width: 150 }} className="nowrap">
        {fmtTs(f.ts)}
      </td>
      <td style={{ width: 110 }}>
        <StatusBadge s={f.status} />
      </td>
    </tr>
  )
}
