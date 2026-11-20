import { AddToTimeline } from '../../components/AddToTimeline'
import { LinkList } from '../../components/Explore'
import { Badge, Dot } from '../../components/ui'
import { recordLinks, type RelationshipGraph } from '../../components/useRelationshipGraph'
import { type RelationshipRef } from '../../data/relationships'
import { type MeasureReading } from '../../data/ruleMeasures'
import { PHASE_LABEL, type Process, refRow, type Story, type StoryStep } from '../../data/stories'
import { useStore } from '../../state/store'
import { fmtNum, fmtTs } from '../../util/format'
import { HopLine, ProcessTrees, SessionLine } from './LineagePanels'
import { CONFIDENCE_SEV, ORIGIN_LABEL } from './model'
import { useMemo } from 'react'
import { pressable } from '../../components/pressable'

export function StepPane({
  story,
  step,
  readings,
  labels,
  g,
  onOpen,
  onOpenAll,
  onExplore,
  onClose,
  children,
}: {
  story: Story
  step: StoryStep
  readings: Map<string, MeasureReading>
  labels: Map<string, string>
  g: RelationshipGraph
  onOpen: (source: 'events' | 'mails', id: number) => void
  onOpenAll: (step: StoryStep) => void
  onExplore: (nodeId: string) => void
  onClose: () => void
  /** the analyst's decision on the step (StoryDecisions.tsx) */
  children?: React.ReactNode
}) {
  const setEntity = useStore((s) => s.setEntity)
  const session = story.lineage.sessions.find((s) => s.id === step.session)
  const hops = story.lineage.hops.filter((h) => step.hops.includes(h.id))
  const processes = useMemo(() => {
    const byId = new Map(story.lineage.processes.map((p) => [p.id, p]))
    const out: Process[] = []
    let p = step.process ? byId.get(step.process) : undefined
    while (p && out.length < 8) {
      out.unshift(p)
      p = p.parent ? byId.get(p.parent) : undefined
    }
    return out
  }, [story, step])
  const rows = step.refs.map(refRow).filter((r): r is NonNullable<ReturnType<typeof refRow>> => !!r)
  const links = useMemo(() => recordLinks(g.result, rows.slice(0, 200)), [g.result, rows])
  return (
    <div className="pane-side">
      <div className="col" style={{ gap: 14 }}>
        <div className="section">
          <h3>{step.phase ? PHASE_LABEL[step.phase] : 'Context'}</h3>
          <div style={{ fontWeight: 500, color: 'var(--fg-1)', overflowWrap: 'anywhere' }}>{step.title}</div>
          <div className="kv">
            <div className="k">source</div>
            <div className="v">{ORIGIN_LABEL[step.origin]}</div>
            <div className="k">time</div>
            <div className="v">
              {fmtTs(step.ts)}
              {step.tsEnd > step.ts ? ` → ${fmtTs(step.tsEnd)}` : ''}
            </div>
            <div className="k">records</div>
            <div className="v">{fmtNum(step.count)}</div>
            {step.host && (
              <>
                <div className="k">host</div>
                <div {...pressable} className="v click" onClick={() => setEntity({ kind: 'host', value: step.host! })}>
                  {step.host}
                </div>
              </>
            )}
            {step.ip && (
              <>
                <div className="k">address</div>
                <div {...pressable} className="v click" onClick={() => setEntity({ kind: 'ip', value: step.ip! })}>
                  {step.ip}
                </div>
              </>
            )}
            {step.accounts.length > 0 && (
              <>
                <div className="k">accounts</div>
                <div className="v">{step.accounts.map((a) => labels.get(a) ?? a).join(', ')}</div>
              </>
            )}
            {step.phase && (
              <>
                <div className="k">phase</div>
                <div className="v">{step.phaseBasis}</div>
              </>
            )}
          </div>
        </div>
        <div className="section">
          <h3>Why it is in the story</h3>
          <div className="small">
            <Dot sev={CONFIDENCE_SEV[step.tie.confidence]} /> <strong>{step.tie.confidence}</strong>: {step.tie.basis}
          </div>
          {step.rarity && <div className="small muted">In this case: {step.rarity.text}</div>}
          {step.notes.map((n, i) => (
            <div key={i} className="small muted">
              {n}
            </div>
          ))}
        </div>
        {children}
        {step.findings.length > 0 && (
          <div className="section">
            <h3>Findings, and what their rules are worth</h3>
            {step.findings.map((f) => {
              const r = readings.get(f.ruleId)
              return (
                <div key={f.key ?? f.ruleId} className="col" style={{ gap: 2, marginBottom: 6 }}>
                  <div className="row" style={{ gap: 6 }}>
                    <Dot sev={f.severity} />
                    <span className="small">{f.title}</span>
                    {r && r.verdict !== 'unmeasured' && <Badge sev={r.verdict === 'detects' ? 'ok' : 'outline'}>{r.label}</Badge>}
                  </div>
                  <div className="small muted" style={{ paddingLeft: 16 }}>
                    {r ? `${r.attacks} ${r.clean}` : 'This rule was not measured on recorded attacks.'}
                  </div>
                </div>
              )
            })}
          </div>
        )}
        {(session || hops.length > 0 || processes.length > 0) && (
          <div className="section">
            <h3>Around it</h3>
            {session && <SessionLine s={session} />}
            {hops.map((h) => (
              <HopLine key={h.id} h={h} />
            ))}
            {processes.length > 0 && <ProcessTrees processes={processes} highlight={step.process} />}
          </div>
        )}
        <div className="section">
          <h3>What its records name</h3>
          {g.result ? (
            links.length ? (
              <LinkList edges={links} g={g} onExplore={onExplore} onOpen={(ref: RelationshipRef) => ref.id != null && onOpen(ref.source, ref.id)} keyPrefix={step.id} limit={30} />
            ) : (
              <div className="small muted">The relationship graph holds no link from these records.</div>
            )
          ) : (
            <div className="small muted">Build relationships in Explore to see the hosts, accounts, processes, files and addresses these records name, and review those links for the report.</div>
          )}
        </div>
        <div className="row wrap" style={{ gap: 6 }}>
          {rows.length === 1 ? (
            <button className="btn sm" onClick={() => onOpen(rows[0].source, rows[0].id)}>
              open the record
            </button>
          ) : (
            <button className="btn sm" onClick={() => onOpenAll(step)}>
              open {fmtNum(Math.min(rows.length, 500))} records
            </button>
          )}
          <AddToTimeline
            ts={step.ts}
            text={`${story.title}: ${step.title}${step.phase ? ` (${PHASE_LABEL[step.phase]})` : ''}`}
            link={rows.length === 1 ? { source: rows[0].source, id: rows[0].id, label: step.title } : { source: 'stories', id: `${story.id}#${step.id}`, label: `${story.title}: ${step.title}` }}
            severity={step.severity ?? (step.tie.kind === 'flag' ? 'high' : 'info')}
          />
          <button className="btn sm ghost" onClick={onClose}>
            close
          </button>
        </div>
        <div className="hint">j / k move between steps</div>
      </div>
    </div>
  )
}
