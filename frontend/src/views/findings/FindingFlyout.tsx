import { useEffect, useState } from 'react'
import { AddToTimeline } from '../../components/AddToTimeline'
import { usePivot } from '../../components/usePivot'
import { entityKind } from '../../components/entityKind'
import { IconArrowLeft } from '../../components/Icons'
import { Badge, Flyout, JsonView, Tabs } from '../../components/ui'
import { isLead, measuredOn, type MeasureReading } from '../../data/ruleMeasures'
import type { Priority } from '../../data/findingPriority'
import { getSource } from '../../data/source'
import { getDb, type Finding } from '../../db/schema'
import type { RuleDiag } from '../../rules/engine'
import { buildIncidents, effectiveSeverity, type Incident } from '../../rules/incidents'
import { useStore } from '../../state/store'
import { classNames, fmtNum, fmtTs } from '../../util/format'
import { attackHref } from '../../util/safe'
import { REFS_OPEN, relatedChains, STATUSES, STATUS_LABEL, type LastRun, type Status } from './model'
import { FindingSeverity, OverrideLabel, SeverityOverrideNotice, StatusBadge } from './parts'
import { pressable } from '../../components/pressable'
import { ENGINE_NAME } from '../../data/engineDuplicates'

export type FlyTab = 'overview' | 'table' | 'json'

/** One finding: why it ranks where it does, what its rule is worth, its entities, its context in the case, and the analyst's note. */
export function FindingFlyout({
  selected,
  parent,
  all,
  priority,
  readings,
  lastRun,
  cuts,
  tab,
  setTab,
  resetting,
  onBack,
  onClose,
  onStatus,
  onResetSeverity,
  onExplain,
  onOpenRefs,
  onEntity,
  onOpenIncident,
  reload,
}: {
  selected: Finding
  /** the incident it was opened from, which the back button returns to */
  parent: Incident | null
  all: Finding[]
  priority?: Priority
  readings: Map<string, MeasureReading>
  lastRun: LastRun | null
  cuts: RuleDiag[]
  tab: FlyTab
  setTab: (t: FlyTab) => void
  resetting: boolean
  onBack: () => void
  onClose: () => void
  onStatus: (ids: number[], s: Status) => void
  onResetSeverity: (findings: Finding[]) => void
  onExplain: (f: Finding) => void
  onOpenRefs: (source: Finding['source'], refs: number[]) => void
  onEntity: (k: string, v: string, source: 'events' | 'mails') => void
  onOpenIncident: (i: Incident) => void
  reload: () => void
}) {
  const kase = useStore((s) => s.currentCase)
  const setFocus = useStore((s) => s.setFocus)
  const setView = useStore((s) => s.setView)
  const measures = useStore((s) => s.meta?.measures)
  const pivot = usePivot()
  const [prevalence, setPrevalence] = useState<Record<string, number | null>>({})
  // prevalence of the selected finding's entities in the case (Insights section)
  useEffect(() => {
    if (!kase) return
    let alive = true
    const ds = getSource(kase)
    const entries = Object.entries(selected.entities).slice(0, 4)
    setPrevalence({})
    Promise.all(
      entries.map(async ([k, v]) => {
        try {
          const n = selected.source === 'events' ? await ds.countEvents({ conditions: [{ field: k, op: 'eq', value: v }] }) : await ds.countMails({ conditions: [{ field: k, op: 'eq', value: v }] })
          return [k, n] as [string, number | null]
        } catch {
          return [k, null] as [string, number | null]
        }
      }),
    ).then((pairs) => alive && setPrevalence(Object.fromEntries(pairs)))
    return () => {
      alive = false
    }
  }, [selected, kase])

  const inherited = lastRun && selected.status !== 'new' && selected.createdAt < lastRun.ts
  const cut = cuts.find((d) => d.ruleId === selected.ruleId)
  const m = readings.get(selected.ruleId)
  // what the overview's insights read from the whole case, only while it is shown
  const rc = tab === 'overview' ? relatedChains(selected, all) : []
  const inc = tab === 'overview' ? buildIncidents(all).find((i) => i.findings.some((f) => f.id === selected.id)) : undefined
  return (
    <Flyout
      title={
        <span className="row" style={{ gap: 8 }}>
          {parent && (
            <button className="btn icon ghost sm" title="back to the incident" aria-label="back to the incident" onClick={onBack}>
              <IconArrowLeft />
            </button>
          )}
          <FindingSeverity finding={selected} />
          <span>{selected.title}</span>
        </span>
      }
      meta={
        <>
          <span className="mono">{selected.ruleId}</span>
          <span>{selected.source}</span>
          <span>
            {fmtTs(selected.ts)}
            {selected.tsEnd && selected.tsEnd !== selected.ts ? ` → ${fmtTs(selected.tsEnd)}` : ''}
          </span>
          <span>{fmtNum(selected.count)} row(s)</span>
          <StatusBadge s={selected.status} />
          <OverrideLabel finding={selected} />
          {selected.confidence && <span title="rule confidence">confidence {selected.confidence}</span>}
          {inherited && <span title="the status was set on an earlier evaluation of this finding key and carried over by the last run">status carried over from {fmtTs(selected.createdAt)}</span>}
        </>
      }
      tabs={
        <Tabs
          tabs={[
            { id: 'overview', label: 'Overview' },
            { id: 'table', label: 'Table' },
            { id: 'json', label: 'JSON' },
          ]}
          active={tab}
          onChange={setTab}
        />
      }
      onClose={onClose}
      footer={
        <>
          <AddToTimeline ts={selected.ts} text={selected.title} link={{ source: 'findings', id: selected.id!, label: selected.ruleId }} severity={effectiveSeverity(selected)} />
          <span className="small muted">status</span>
          <div className="segmented">
            {STATUSES.map((s) => (
              <button key={s} className={classNames(selected.status === s && 'active')} onClick={() => onStatus([selected.id!], s)}>
                {STATUS_LABEL[s]}
              </button>
            ))}
          </div>
          <span className="spacer" />
          <button className="btn sm" onClick={() => onExplain(selected)}>
            ask the analyst
          </button>
          <button className="btn sm primary" onClick={() => onOpenRefs(selected.source, selected.refs)}>
            open {fmtNum(Math.min(selected.refs.length, REFS_OPEN))} row(s)
          </button>
        </>
      }
    >
      <SeverityOverrideNotice findings={[selected]} busy={resetting} onReset={() => onResetSeverity([selected])} />
      {tab === 'overview' && (
        <>
          {priority && (
            <div className="section" data-priority>
              <h3>
                Priority <span className="mono">{priority.score}</span>
              </h3>
              <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
                {priority.reasons.map((r, i) => (
                  <li key={i} className={r.tone === 'neutral' ? 'muted' : undefined} data-tone={r.tone}>
                    {r.text}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <div className="section">
            <h3>About</h3>
            <div>{selected.description || <span className="muted">the rule has no description</span>}</div>
            <div className="row wrap" style={{ gap: 6 }}>
              {selected.attack.map((t) =>
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
              {(selected.tags ?? []).map((t) => (
                <Badge key={t}>{t}</Badge>
              ))}
            </div>
            {selected.escalation && (
              <div className="small" style={{ color: 'var(--danger)' }}>
                escalated by: {selected.escalation}
              </div>
            )}
            {selected.alsoBy?.length ? (
              <div className="small" data-also-by>
                Also found on the same record by {selected.alsoBy.map((a) => `${ENGINE_NAME[a.engine] ?? a.engine} ("${a.title}", ${a.severity})`).join(' and ')}, which ran the same Sigma rule: one
                finding is kept for both.
              </div>
            ) : null}
            {lastRun?.errors?.some((e) => e.startsWith(selected.ruleId)) && (
              <div className="small" style={{ color: 'var(--warn)' }}>
                this rule reported an error in the last run; the finding may be from an earlier run
              </div>
            )}
            {cut && (
              <div className="small" style={{ color: 'var(--warn)' }}>
                this rule found more than its cap in the last run: {cut.detail}
              </div>
            )}
            {m?.label && (
              <div className="small" data-measure={m.verdict}>
                {m.verdict === 'detects' ? <strong>Measured. </strong> : isLead(m) ? <strong>A lead, not a detection. </strong> : null}
                {m.attacks} {m.clean}
                {measures && <div className="muted">{measuredOn(measures)}</div>}
              </div>
            )}
          </div>
          <div className="section">
            <h3>Investigation</h3>
            <div className="highlight">
              {Object.entries(selected.entities).map(([k, v]) => (
                <div className="f" key={k}>
                  <span className="k">{k}</span>
                  <span {...pressable} className="v" onClick={() => onEntity(k, String(v), selected.source)} title={entityKind(k) ? `open the ${entityKind(k)} page` : `pivot on ${k}`}>
                    {String(v)}
                  </span>
                </div>
              ))}
              <div className="f">
                <span className="k">referenced rows</span>
                <span {...pressable} className="v" onClick={() => onOpenRefs(selected.source, selected.refs)}>
                  {fmtNum(selected.refs.length)}
                  {selected.refs.length > REFS_OPEN ? ` (first ${REFS_OPEN} open)` : ''}
                </span>
              </div>
              {selected.refs.slice(0, 1).map((id) => (
                <div className="f" key={id}>
                  <span className="k">first row</span>
                  <span
                    {...pressable}
                    className="v"
                    onClick={() => {
                      setFocus({ source: selected.source, id })
                      setView(selected.source)
                    }}
                  >
                    #{id}
                  </span>
                </div>
              ))}
            </div>
          </div>
          <div className="section">
            <h3>Insights</h3>
            <div className="kv">
              {Object.entries(selected.entities)
                .slice(0, 4)
                .map(([k, v]) => (
                  <div key={k} style={{ display: 'contents' }}>
                    <div className="k">{k} in this case</div>
                    <div className="v">
                      {prevalence[k] == null ? <span className="muted">…</span> : `${fmtNum(prevalence[k]!)} ${selected.source === 'events' ? 'event(s)' : 'mail(s)'} with ${String(v)}`}
                    </div>
                  </div>
                ))}
              {rc.length ? (
                <>
                  <div className="k">attack chains</div>
                  <div className="v">
                    {rc.map((c) => (
                      <button key={c.id} className="btn link" style={{ display: 'block' }} onClick={() => setView('stories')}>
                        {c.title}
                      </button>
                    ))}
                  </div>
                </>
              ) : null}
              {inc && inc.findings.length > 1 ? (
                <>
                  <div className="k">incident</div>
                  <div {...pressable} className="v click" onClick={() => onOpenIncident(inc)}>
                    {inc.title} · {inc.findings.length} finding(s)
                  </div>
                </>
              ) : null}
              <div className="k">same rule</div>
              <div className="v">
                {fmtNum(all.filter((f) => f.ruleId === selected.ruleId).length)} finding(s) · {fmtNum(all.filter((f) => f.ruleId === selected.ruleId && f.status === 'false_positive').length)} marked
                false positive
              </div>
            </div>
          </div>
          <div className="section">
            <h3>Notes</h3>
            <textarea
              key={selected.id}
              className="textarea"
              placeholder="analyst notes…"
              defaultValue={selected.notes ?? ''}
              onBlur={(e) => {
                getDb().findings.update(selected.id!, { notes: e.target.value })
                reload()
              }}
            />
          </div>
        </>
      )}
      {tab === 'table' && (
        <div className="kv">
          {Object.entries(selected)
            .filter(([k, v]) => !['id', 'caseId', 'entities', 'refs'].includes(k) && v != null && v !== '' && !(Array.isArray(v) && !v.length))
            .map(([k, v]) => (
              <div key={k} style={{ display: 'contents' }}>
                <div className="k">{k}</div>
                <div className="v">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</div>
              </div>
            ))}
          {Object.entries(selected.entities).map(([k, v]) => (
            <div key={'e' + k} style={{ display: 'contents' }}>
              <div className="k">entity.{k}</div>
              <div {...pressable} className="v click" onClick={() => pivot(String(v), k, selected.source)}>
                {String(v)}
              </div>
            </div>
          ))}
        </div>
      )}
      {tab === 'json' && <JsonView value={selected} />}
    </Flyout>
  )
}
