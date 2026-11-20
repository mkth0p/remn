import { AddToTimeline } from '../../components/AddToTimeline'
import { entityKind } from '../../components/EntityPanel'
import { Badge, Flyout, Sev } from '../../components/ui'
import type { MeasureReading } from '../../data/ruleMeasures'
import type { Priority } from '../../data/findingPriority'
import type { Finding } from '../../db/schema'
import type { Incident } from '../../rules/incidents'
import { useStore } from '../../state/store'
import { classNames, fmtNum, fmtTs } from '../../util/format'
import { attackHref } from '../../util/safe'
import { KIND_LABEL, REFS_OPEN, STATUSES, STATUS_LABEL, type Status } from './model'
import { MemberRow, SeverityOverrideNotice, StatusBadge } from './parts'

/** One incident: its findings in queue order, its status set on all of them, and what to look at next. */
export function IncidentFlyout({
  incident,
  ordered,
  scores,
  readings,
  resetting,
  onClose,
  onOpenFinding,
  onStatus,
  onResetSeverity,
  onExplain,
  onOpenRefs,
  onEntity,
}: {
  incident: Incident
  /** its findings in the order of the queue */
  ordered: Finding[]
  scores: Map<string, Priority>
  readings: Map<string, MeasureReading>
  resetting: boolean
  onClose: () => void
  onOpenFinding: (f: Finding) => void
  onStatus: (ids: number[], s: Status) => void
  onResetSeverity: (findings: Finding[]) => void
  onExplain: (i: Incident) => void
  onOpenRefs: (source: Incident['source'], refs: number[]) => void
  onEntity: (k: string, v: string, source: 'events' | 'mails') => void
}) {
  const setFocus = useStore((s) => s.setFocus)
  const setView = useStore((s) => s.setView)
  return (
    <Flyout
      title={
        <span className="row" style={{ gap: 8 }}>
          <Sev sev={incident.severity} />
          <span>{incident.title}</span>
        </span>
      }
      meta={
        <>
          <Badge>{KIND_LABEL[incident.kind]}</Badge>
          <span>
            {fmtNum(incident.findings.length)} finding(s) from {incident.rules.length} rule(s)
          </span>
          <span>
            {fmtTs(incident.ts)}
            {incident.tsEnd && incident.tsEnd !== incident.ts ? ` → ${fmtTs(incident.tsEnd)}` : ''}
          </span>
          <span>{fmtNum(incident.refs.length)} row(s)</span>
          <StatusBadge s={incident.status} />
          {incident.findings.some((f) => f.severityOverride) && <Badge>review severity override</Badge>}
        </>
      }
      onClose={onClose}
      footer={
        <>
          <AddToTimeline
            ts={incident.ts}
            text={`${incident.title}: ${incident.lead.title}`}
            link={{ source: 'findings', id: incident.lead.id!, label: incident.lead.ruleId }}
            severity={incident.severity}
          />
          <span className="small muted">status</span>
          <div className="segmented">
            {STATUSES.map((s) => (
              <button
                key={s}
                className={classNames(incident.status === s && 'active')}
                onClick={() =>
                  onStatus(
                    incident.findings.map((f) => f.id!),
                    s,
                  )
                }
              >
                {STATUS_LABEL[s]}
              </button>
            ))}
          </div>
          <span className="spacer" />
          <button className="btn sm" onClick={() => onExplain(incident)}>
            ask the analyst
          </button>
          {incident.source !== 'mixed' && (
            <button className="btn sm primary" onClick={() => onOpenRefs(incident.source, incident.refs)}>
              open {fmtNum(Math.min(incident.refs.length, REFS_OPEN))} row(s)
            </button>
          )}
        </>
      }
    >
      <SeverityOverrideNotice findings={incident.findings} busy={resetting} onReset={() => onResetSeverity(incident.findings)} chain={incident.kind === 'chain'} />
      <div className="section">
        <h3>Findings</h3>
        <div className="small muted">
          {incident.subtitle}.{' '}
          {incident.kind === 'chain'
            ? 'These findings have their rows among the steps of the attack chain: the verdict on the Review page decides them together, and a finding can be unlinked there to be decided on its own.'
            : 'The status of the incident is set on every finding below; open one for its own detail.'}
        </div>
        <table className="table compact">
          <tbody>
            {ordered.map((f) => (
              <MemberRow key={f.id} f={f} priority={scores.get(f.key)} reading={readings.get(f.ruleId)} onOpen={() => onOpenFinding(f)} />
            ))}
          </tbody>
        </table>
      </div>
      <div className="section">
        <h3>Investigation</h3>
        <div className="highlight">
          {Object.entries(incident.entities)
            .slice(0, 12)
            .map(([k, v]) => (
              <div className="f" key={k}>
                <span className="k">{k}</span>
                <span className="v" onClick={() => onEntity(k, String(v), incident.source === 'mails' ? 'mails' : 'events')} title={entityKind(k) ? `open the ${entityKind(k)} page` : `pivot on ${k}`}>
                  {String(v)}
                </span>
              </div>
            ))}
          {incident.kind === 'mail' && (
            <div className="f">
              <span className="k">mail</span>
              <span
                className="v"
                onClick={() => {
                  setFocus({ source: 'mails', id: incident.refs[0] })
                  setView('mails')
                }}
              >
                open #{incident.refs[0]}
              </span>
            </div>
          )}
        </div>
        {incident.attack.length > 0 && (
          <div className="row wrap" style={{ gap: 6 }}>
            {incident.attack.map((t) =>
              attackHref(t) ? (
                <a key={t} className="badge outline" href={attackHref(t)} target="_blank" rel="noreferrer noopener">
                  {t}
                </a>
              ) : (
                <Badge key={t} sev="outline">
                  {t}
                </Badge>
              ),
            )}
          </div>
        )}
      </div>
    </Flyout>
  )
}
