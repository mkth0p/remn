import type { ReactNode } from 'react'
import { AddToTimeline } from '../../components/AddToTimeline'
import { entityKind } from '../../components/EntityPanel'
import { IconAi, IconArrowLeft, IconCheck } from '../../components/Icons'
import { Sev, Spinner, Toggle } from '../../components/ui'
import { SEVERITIES, type ReportSettings } from '../../data/review'
import type { Severity } from '../../db/schema'
import type { Incident } from '../../rules/incidents'
import { useStore } from '../../state/store'
import { classNames, fmtNum, fmtTs } from '../../util/format'
import { Facts } from './Facts'
import { DECISIONS, STATUS_LABEL, type Status } from './model'

/** An incident to decide: what was seen, the decision and what it does to the verdict, its severity, whether the report carries it, and its note. */
export function IncidentCard({
  inc,
  settings,
  effect,
  proposals,
  note,
  setNote,
  suggesting,
  onStatus,
  onRescore,
  onExclude,
  onSaveNote,
  onLinkBack,
  onOpenRows,
  onSuggest,
  onPrevious,
  onNext,
}: {
  inc: Incident
  settings: ReportSettings
  /** what each decision would do to the verdict */
  effect: ReactNode
  /** the model's proposals on it */
  proposals: ReactNode
  note: string
  setNote: (s: string) => void
  suggesting: boolean
  onStatus: (s: Status) => void
  onRescore: (sev: Severity | null) => void
  onExclude: (on: boolean) => void
  onSaveNote: () => void
  onLinkBack: (ids: number[]) => void
  onOpenRows: () => void
  onSuggest: () => void
  onPrevious: () => void
  onNext: () => void
}) {
  const setEntity = useStore((s) => s.setEntity)
  const setFocus = useStore((s) => s.setFocus)
  const setView = useStore((s) => s.setView)
  const excluded = inc.findings.length > 0 && inc.findings.every((f) => f.reportExclude)
  const willPrint = SEVERITIES.indexOf(inc.severity) <= SEVERITIES.indexOf(settings.minSeverity)
  return (
    <div className="review-card">
      <div className="head">
        <Sev sev={inc.severity} />
        <div className="col" style={{ gap: 4, flex: 1 }}>
          <h2>{inc.title}</h2>
          <div className="small muted">
            {inc.subtitle} · {inc.kind} · {fmtTs(inc.ts)}
            {inc.tsEnd && inc.tsEnd !== inc.ts ? ` → ${fmtTs(inc.tsEnd)}` : ''} · {fmtNum(inc.refs.length)} row(s)
          </div>
        </div>
        <span className={`stamp st-${inc.status}`}>{STATUS_LABEL[inc.status as Status]}</span>
      </div>
      <div className="section">
        <h3>
          What was seen <span className="muted">· one line per rule, with the values it matched</span>
        </h3>
        <Facts findings={inc.findings} said={inc.entities} />
        <div className="row wrap" style={{ gap: 6, marginTop: 6 }}>
          {Object.entries(inc.entities)
            .slice(0, 8)
            .map(([k, v]) => {
              const kind = entityKind(k)
              return (
                <span key={k} className={classNames('pill', kind && 'click')} onClick={() => kind && setEntity({ kind, value: String(v) })} title={kind ? 'open the entity page' : k}>
                  <span className="muted">{k}</span> {String(v)}
                </span>
              )
            })}
          {inc.kind === 'mail' && (
            <span
              className="pill click"
              onClick={() => {
                setFocus({ source: 'mails', id: inc.refs[0] })
                setView('mails')
              }}
            >
              open the mail
            </span>
          )}
        </div>
      </div>
      <div className="decide">
        <div className="choices">
          {DECISIONS.map((d) => (
            <button key={d.id} className={classNames('choice', d.tone, inc.status === d.id && 'active')} onClick={() => onStatus(d.id)}>
              {d.label} <kbd>{d.key}</kbd>
            </button>
          ))}
        </div>
        {effect}
        <div className="controls">
          <span>
            <span className="lbl">severity</span>
            <span className="segmented">
              {SEVERITIES.map((s) => (
                <button
                  key={s}
                  className={classNames(inc.severity === s && 'active')}
                  onClick={() => onRescore(s)}
                  title={inc.lead.severityOverride ? `rule severity ${inc.lead.severity}` : 'rescore the incident'}
                >
                  {s}
                </button>
              ))}
            </span>
            {inc.findings.some((f) => f.severityOverride) && (
              <button className="btn link small" onClick={() => onRescore(null)}>
                reset
              </button>
            )}
          </span>
          <Toggle on={!excluded} onChange={(v) => onExclude(!v)} label={willPrint && !excluded && (inc.status !== 'false_positive' || settings.includeFp) ? 'in the report' : 'not in the report'} />
        </div>
      </div>
      {inc.lead.decidedBy === 'ai' && inc.lead.aiReason && (
        <div className="ai-note">
          <b>decided by the model:</b> {inc.lead.aiReason} <span className="muted">· change the decision above to make it yours</span>
        </div>
      )}
      {inc.findings.some((f) => f.chainUnlinked) && (
        <div className="ai-note">
          <b>unlinked from its attack chain</b> · decided here on its own.{' '}
          <button className="btn link small" onClick={() => onLinkBack(inc.findings.filter((f) => f.chainUnlinked).map((f) => f.id!))}>
            link back to the chain
          </button>
        </div>
      )}
      {proposals}
      <div className="section">
        <h3>
          Analyst note <span className="muted">(printed with the incident)</span>
        </h3>
        <textarea
          className="textarea"
          style={{ minHeight: 80 }}
          value={note}
          onChange={(e) => setNote(e.target.value)}
          onBlur={onSaveNote}
          placeholder="what this is, what was checked, what was decided…"
        />
        {inc.lead.notesBy === 'ai' && inc.lead.notes && <div className="small muted">written by the model during triage; edit it to make it yours (the next triage then leaves it alone)</div>}
      </div>
      <div className="row wrap" style={{ gap: 6 }}>
        <button className="btn sm ghost" onClick={onPrevious}>
          <IconArrowLeft /> previous
        </button>
        <button className="btn sm" onClick={onOpenRows} disabled={inc.source === 'mixed'}>
          open the rows
        </button>
        <AddToTimeline ts={inc.ts} text={`${inc.title}: ${inc.lead.title}`} link={{ source: 'findings', id: inc.lead.id!, label: inc.lead.ruleId }} severity={inc.severity} />
        <button className="btn sm" disabled={suggesting} onClick={onSuggest}>
          {suggesting ? <Spinner /> : <IconAi />} ask the model to decide
        </button>
        <button
          className="btn sm"
          onClick={() => {
            useStore
              .getState()
              .setAiPrompt(
                `Assess this incident for the report: read its findings and rows with get_finding, then queue your proposal with propose_decision, citing the rows. "${inc.title}" (${inc.severity}), findings: ${inc.findings.map((f) => `finding:${f.id} ${f.severity} ${f.title}`).join('; ')}. Entities: ${JSON.stringify(inc.entities)}.`,
              )
            setView('ai')
          }}
        >
          <IconAi /> ask the analyst
        </button>
        <span className="spacer" />
        <button className="btn sm primary" onClick={onNext}>
          <IconCheck /> {inc.status === 'new' ? 'mark reviewed and next' : 'next'}
        </button>
      </div>
    </div>
  )
}
