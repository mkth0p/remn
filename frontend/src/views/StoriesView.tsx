import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AddToTimeline } from '../components/AddToTimeline'
import { EventDetail, MailDetail } from '../components/Detail'
import { Explorer, ExploreList, LinkList } from '../components/Explore'
import { recordLinks, useRelationshipGraph, type RelationshipGraph } from '../components/useRelationshipGraph'
import { IconAi, IconCloud, IconDownload, IconHost, IconMail, IconPlay, IconUser } from '../components/Icons'
import { StorySpine } from '../components/StorySpine'
import { Badge, Dot, Sev, Spinner, Tabs } from '../components/ui'
import { checkText, readRows, type TextCheck } from '../data/claims'
import { loadEvidenceGaps, type GapStatement } from '../data/evidenceGaps'
import type { RelationshipRef } from '../data/relationships'
import { readMeasure, type MeasureReading } from '../data/ruleMeasures'
import { loadRules } from '../data/rules'
import { getSource } from '../data/source'
import {
  attachStoryNote,
  buildStories,
  cheapToRebuild,
  deleteStoryNote,
  findStory,
  loadStories,
  loadStoryNotes,
  PHASE_LABEL,
  PHASES,
  refRow,
  HOP_LABEL,
  resolveStoryNotes,
  saveStoryNote,
  storiesStaleness,
  storyCoverageWarnings,
  storyGaps,
  storyInputs,
  storyQuestion,
  storyRowIds,
  type Campaign,
  type Confidence,
  type Hop,
  type Identity,
  type NoteOnStory,
  type OrphanNote,
  type Process,
  type Session,
  type Story,
  type StoryNotes,
  type StoryResult,
  type StoryStep,
} from '../data/stories'
import { downloadAttackFlow, downloadCampaignGrouping, spineSteps } from '../data/storyExport'
import { getDb, type EventRow, type MailRow, type Severity } from '../db/schema'
import { toast, useStore } from '../state/store'
import { fmtNum, fmtTs } from '../util/format'

/**
 * Stories: one per person or host incident (backend/services/analysis/stories.py). The left list
 * ranks them; the right reads the selected one along ATT&CK's phases, step by step, each step
 * saying why it is in the story and how surely, with the rule's measure on each finding, the
 * sessions, hops and process trees around it, and what the evidence cannot show. Campaigns group
 * the stories that share the attacker's infrastructure; Explore browses the relationship graph.
 */

type Mode = 'stories' | 'campaigns' | 'explore'
type Tab = 'story' | 'lineage' | 'identity' | 'gaps' | 'json'
type Detail = { source: 'events'; row: EventRow } | { source: 'mails'; row: MailRow } | null

/** What a build keeps open: the story that was (and its step), or the story a link asked for. */
type Follow = ({ story: Story; identities: Identity[] } | { link: string }) & { step?: string }

const SEV_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical']
const ORIGIN_ICON = { mail: IconMail, cloud: IconCloud, host: IconHost } as const
const ORIGIN_CLASS = { mail: 'mail', cloud: 'm365', host: 'host' } as const
const ORIGIN_LABEL = { mail: 'mailbox', cloud: 'Microsoft 365 / Entra', host: 'Windows host' } as const
const TIE_LABEL: Record<StoryStep['tie']['kind'], string> = {
  flag: 'flagged',
  chain: 'phishing chain',
  session: 'same session',
  hop: 'same way in',
  process: 'process tree',
  address: 'same source',
  identity: 'same person',
}
const CONFIDENCE_SEV: Record<Confidence, string> = { strong: 'ok', medium: 'medium', weak: 'info' }

function spanText(ms: number): string {
  const m = ms / 60_000
  return m < 1 ? 'under a minute' : m < 90 ? `${Math.round(m)} min` : m < 48 * 60 ? `${(m / 60).toFixed(1)} h` : `${(m / 1440).toFixed(1)} d`
}
const day = (ts: number) => fmtTs(ts, { date: true }).slice(0, 10)

/** A tiny strip of the fifteen phases, filled where the story has one: the shape of an intrusion at a glance. */
function PhaseStrip({ story }: { story: Story }) {
  const by = new Map(story.phases.map((p) => [p.phase, p]))
  return (
    <span className="phase-strip" aria-label={`phases: ${story.phases.map((p) => p.label).join(', ') || 'none'}`}>
      {PHASES.map((p) => {
        const hit = by.get(p.id)
        return <span key={p.id} className={'cell' + (hit ? ` on ${hit.severity ?? 'info'}` : '')} title={hit ? `${p.label}: ${hit.steps} step(s)` : p.label} />
      })}
    </span>
  )
}

/** The phases of ATT&CK in their order, the story's in its own time order (1, 2, 3 ...), each a filter for the timeline. */
function PhaseRail({ story, active, onPick }: { story: Story; active: string | null; onPick: (p: string | null) => void }) {
  const order = new Map(story.phases.map((p, i) => [p.phase, i + 1]))
  const by = new Map(story.phases.map((p) => [p.phase, p]))
  return (
    <div className="phase-rail" role="list" aria-label="ATT&CK phases of the story">
      {PHASES.map((p) => {
        const hit = by.get(p.id)
        return (
          <button
            key={p.id}
            role="listitem"
            className={'phase' + (hit ? ` on ${hit.severity ?? 'info'}` : '') + (active === p.id ? ' active' : '')}
            disabled={!hit}
            onClick={() => onPick(active === p.id ? null : p.id)}
            title={hit ? `${p.label}: ${hit.steps} step(s), ${hit.records} record(s), ${hit.findings} finding(s), ${fmtTs(hit.first)} → ${fmtTs(hit.last)}` : `${p.label}: nothing in this story`}
          >
            <span className="code">{p.short}</span>
            <span className="lbl">{p.label}</span>
            {hit && <span className="ord">{order.get(p.id)}</span>}
          </button>
        )
      })}
    </div>
  )
}

function StoryList({ stories, active, onSelect }: { stories: Story[]; active: string | null; onSelect: (id: string) => void }) {
  return (
    <>
      {stories.map((s) => (
        <div key={s.id} className={'story-row' + (active === s.id ? ' active' : '')} onClick={() => onSelect(s.id)} role="button" aria-label={`Story ${s.title}`}>
          <Dot sev={s.severity} />
          <div style={{ minWidth: 0 }}>
            <div className="ellipsis name">
              {s.kind === 'host' ? <IconHost /> : <IconUser />} {s.title}
            </div>
            <div className="ellipsis small" style={{ color: 'var(--fg-2)' }} title={s.headline}>
              {s.headline}
            </div>
            <PhaseStrip story={s} />
            <div className="small mono" style={{ color: 'var(--fg-3)' }}>
              {fmtTs(s.start)} · {spanText(s.end - s.start)}
            </div>
          </div>
          <div className="meta">
            <span className="score">{s.score}</span>
            <span>{s.steps.length} steps</span>
            <span>{fmtNum(s.records)} records</span>
            <span className={s.confidence === 'strong' ? 'bridged' : ''} title="the weakest tie of a flagged step">
              {s.confidence} ties
            </span>
          </div>
        </div>
      ))}
    </>
  )
}

/** A finding on a step, with what its rule's measure says it is worth. */
function FindingBadge({ f, reading }: { f: StoryStep['findings'][number]; reading?: MeasureReading }) {
  const mark = reading && reading.verdict !== 'unmeasured' ? reading.label : ''
  return (
    <Badge sev={f.severity} title={`${f.title}${reading ? `\n${reading.attacks}${reading.clean ? `\n${reading.clean}` : ''}` : ''}`}>
      {f.title}
      {mark && <span className={'measure ' + reading!.verdict}> · {mark}</span>}
    </Badge>
  )
}

function Timeline({
  story,
  phase,
  selected,
  onSelect,
  readings,
  labels,
}: {
  story: Story
  phase: string | null
  selected: string | null
  onSelect: (id: string) => void
  readings: Map<string, MeasureReading>
  labels: Map<string, string>
}) {
  const steps = phase ? story.steps.filter((s) => s.phase === phase) : story.steps
  return (
    <div className="story">
      {!steps.length && (
        <div className="muted small" style={{ padding: 14 }}>
          No step in this phase.
        </div>
      )}
      {steps.map((s, i) => {
        const d = day(s.ts)
        const header = i === 0 || d !== day(steps[i - 1].ts)
        const Icon = ORIGIN_ICON[s.origin]
        const who = s.accounts.map((a) => labels.get(a) ?? a).slice(0, 3)
        return (
          <div key={s.id}>
            {header && <div className="story-day">{d}</div>}
            <div className={'step' + (selected === s.id ? ' active' : '') + (s.routine ? ' routine' : '')} onClick={() => onSelect(s.id)}>
              <span className="t">
                {fmtTs(s.ts).slice(11, 19) || fmtTs(s.ts)}
                <br />
                <span className="phase-tag" title={s.phase ? `${PHASE_LABEL[s.phase]}: ${s.phaseBasis}` : 'context: no phase'}>
                  {s.phase ? (PHASES.find((p) => p.id === s.phase)?.short ?? '') : '·'}
                </span>
              </span>
              <span className={'n ' + ORIGIN_CLASS[s.origin]} title={ORIGIN_LABEL[s.origin]}>
                <Icon />
              </span>
              <span style={{ minWidth: 0 }}>
                <div className="title">
                  {s.title}
                  {s.count > 1 && (
                    <span className="muted" style={{ fontWeight: 400 }}>
                      {' '}
                      ×{fmtNum(s.count)}
                      {s.tsEnd > s.ts ? ` over ${spanText(s.tsEnd - s.ts)}` : ''}
                    </span>
                  )}
                </div>
                <div className="sub">{[s.host, s.ip, who.join(', ') + (s.accounts.length > 3 ? ` +${s.accounts.length - 3}` : '')].filter(Boolean).join(' · ')}</div>
                <div className="row wrap" style={{ gap: 4, marginTop: 3 }}>
                  {s.phase && <span className="phase-chip">{PHASE_LABEL[s.phase]}</span>}
                  {s.findings.map((f) => (
                    <FindingBadge key={f.key ?? f.ruleId} f={f} reading={readings.get(f.ruleId)} />
                  ))}
                  <span className="tie" title={s.tie.basis}>
                    <Dot sev={CONFIDENCE_SEV[s.tie.confidence]} /> {TIE_LABEL[s.tie.kind]}
                  </span>
                </div>
              </span>
            </div>
          </div>
        )
      })}
    </div>
  )
}

function SessionLine({ s }: { s: Session }) {
  return (
    <div className="small">
      <strong>{s.account || 'an account'}</strong> on {s.host}, logon {s.logonId} ({s.typeName}){s.ip || s.workstation ? ` from ${[s.workstation, s.ip].filter(Boolean).join(' / ')}` : ''}
      {s.from ? `, the host ${s.from}` : ''} · {fmtTs(s.start)}
      {s.end ? ` → ${fmtTs(s.end)}` : ' · no logoff recorded'}
      {s.privileged ? ' · special privileges' : ''}
      {!s.logonSeen ? ' · its logon is not in the evidence' : ''} · {fmtNum(s.activity)} record(s) in it
      {Object.keys(s.actions ?? {}).length ? ` · ${Object.keys(s.actions).join(', ')}` : ''}
    </div>
  )
}

function HopLine({ h }: { h: Hop }) {
  const from = [h.from.host, h.from.workstation && h.from.workstation.toLowerCase() !== h.from.host ? h.from.workstation : null, h.from.ip].filter(Boolean).join(' / ')
  return (
    <div className="small">
      <Dot sev={CONFIDENCE_SEV[h.confidence]} /> <strong>{HOP_LABEL[h.kind] ?? h.kind}</strong> {from || 'an unknown source'}
      {h.from.external ? ' (outside)' : ''} → <strong>{h.to}</strong>
      {h.account ? ` as ${h.account}` : ''} · {fmtTs(h.ts)}
      {h.count > 1 ? ` · ${h.count} times` : ''}
      <div className="muted" style={{ paddingLeft: 18 }}>
        {h.basis}
        {h.evidence.length ? ` · ${h.evidence.join('; ')}` : ''}
        {h.from.basis ? ` · the source host is known from ${h.from.basis}` : ''}
      </div>
    </div>
  )
}

/** The processes of a story as trees: each root with what it started, as far as the evidence goes. */
function ProcessTrees({ processes, highlight }: { processes: Process[]; highlight?: string | null }) {
  const byId = new Map(processes.map((p) => [p.id, p]))
  const roots = processes.filter((p) => !p.parent || !byId.has(p.parent))
  const render = (p: Process, depth: number): React.ReactNode => (
    <div key={p.id}>
      <div className={'small mono proc' + (highlight === p.id ? ' active' : '')} style={{ paddingLeft: depth * 16 }} title={p.commandLine ?? ''}>
        {depth ? '└ ' : ''}
        {p.name || p.image} {p.pid != null ? `(${p.pid})` : ''}{' '}
        <span className="muted">
          {p.host} · {fmtTs(p.ts)} · {p.source === 'both' ? 'Sysmon and 4688' : p.source === 'sysmon' ? 'Sysmon' : '4688'}
          {!p.parent && p.parentImage ? ` · started by ${p.parentImage.split('\\').pop()} (not in the evidence)` : ''}
        </span>
      </div>
      {p.children.filter((c) => byId.has(c)).map((c) => render(byId.get(c)!, depth + 1))}
    </div>
  )
  if (!processes.length) return <div className="small muted">No process of this story is in the evidence.</div>
  return <>{roots.map((r) => render(r, 0))}</>
}

function LineagePanel({ story, highlight }: { story: Story; highlight?: string | null }) {
  const { sessions, hops, processes, devices = [] } = story.lineage
  return (
    <div className="view-body col" style={{ gap: 14 }}>
      <div className="section">
        <h3>How the accounts got in</h3>
        {hops.length ? (
          hops.map((h) => <HopLine key={h.id} h={h} />)
        ) : (
          <div className="small muted">No hop of this story is in the evidence: no RDP logon, admin share, remote service, WMI or WinRM execution or explicit credentials towards its hosts.</div>
        )}
      </div>
      {devices.length > 0 && (
        <div className="section">
          <h3>The devices its sign-ins came from</h3>
          {devices.map((d) => (
            <div key={d.key} className="small">
              <strong>{d.name}</strong>
              {d.trustTypes.length ? ` · ${d.trustTypes.join(', ')}` : ' · not joined'}
              {d.host ? ` · the host ${d.host} of this case` : ' · a device the case has no logs of'} · {d.signIns} sign-in(s)
              {d.accounts.length ? ` by ${d.accounts.join(', ')}` : ''}
            </div>
          ))}
        </div>
      )}
      <div className="section">
        <h3>Logon sessions</h3>
        {sessions.length ? sessions.map((s) => <SessionLine key={s.id} s={s} />) : <div className="small muted">No logon session of this story is in the evidence.</div>}
      </div>
      <div className="section">
        <h3>What ran</h3>
        <ProcessTrees processes={processes} highlight={highlight} />
      </div>
    </div>
  )
}

function IdentityPanel({ identity }: { identity: Identity | undefined }) {
  if (!identity) return <div className="view-body muted">This story is about a host; its accounts are named on each step.</div>
  return (
    <div className="view-body col" style={{ gap: 14 }}>
      <div className="section">
        <h3>
          {identity.label}{' '}
          <span className="muted small">
            · {identity.kind}
            {identity.org ? ` · ${identity.org}` : ''}
          </span>
        </h3>
        <p className="small muted" style={{ margin: 0 }}>
          The forms the evidence names this account by, and how surely each is the same account: strong when one record states both, medium when the organisation's naming rules join them.
        </p>
        <table className="table compact" style={{ marginTop: 8 }}>
          <thead>
            <tr>
              <th>form</th>
              <th>value</th>
              <th>records</th>
              <th>confidence</th>
            </tr>
          </thead>
          <tbody>
            {identity.forms.map((f) => (
              <tr key={f.kind + f.value}>
                <td>{f.kind}</td>
                <td className="mono" style={{ overflowWrap: 'anywhere' }}>
                  {f.value}
                </td>
                <td>{fmtNum(f.seen)}</td>
                <td>
                  <Dot sev={CONFIDENCE_SEV[f.confidence]} /> {f.confidence}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {identity.joins.length > 0 && (
        <div className="section">
          <h3>Why they are one account</h3>
          {identity.joins.map((j, i) => (
            <div key={i} className="small">
              <Dot sev={CONFIDENCE_SEV[j.confidence]} /> <span className="mono">{j.a}</span> = <span className="mono">{j.b}</span>: {j.basis}
              {j.count > 1 ? ` (${fmtNum(j.count)} records)` : ''}
            </div>
          ))}
        </div>
      )}
      {(identity.namesakes.length > 0 || identity.possibly.length > 0 || identity.conflicts.length > 0 || identity.notes.length > 0) && (
        <div className="section">
          <h3>Kept apart</h3>
          {identity.namesakes.map((n) => (
            <div key={'n' + n.id} className="small">
              Namesake <span className="mono">{n.label}</span>: {n.basis}.
            </div>
          ))}
          {identity.possibly.map((n) => (
            <div key={'p' + n.id} className="small">
              Possibly <span className="mono">{n.label}</span>, never joined without a record that says so: {n.basis}.
            </div>
          ))}
          {identity.conflicts.map((c, i) => (
            <div key={'c' + i} className="small">
              Not joined, <span className="mono">{c.a}</span> and <span className="mono">{c.b}</span>: {c.why}.
            </div>
          ))}
          {identity.notes.map((n, i) => (
            <div key={'x' + i} className="small">
              {n}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function GapsPanel({ story, stats, caseGaps }: { story: Story; stats: StoryResult['stats'] | undefined; caseGaps: GapStatement[] }) {
  const gaps = storyGaps(story, stats)
  return (
    <div className="view-body col" style={{ gap: 14 }}>
      <div className="section">
        <h3>Where this story stops</h3>
        {gaps.length ? (
          gaps.map((g, i) => (
            <div key={i} className="small">
              · {g}
            </div>
          ))
        ) : (
          <div className="small muted">Every host of the story logs its logons and what ran.</div>
        )}
      </div>
      <div className="section">
        <h3>Where the case's files stop</h3>
        {caseGaps.length ? (
          caseGaps.map((g, i) => (
            <div key={i} className="small">
              <Dot sev={g.severity} /> {g.text}
            </div>
          ))
        ) : (
          <div className="small muted">The files record no hole, no clock set back, no damaged chunk and no log that starts after the first finding.</div>
        )}
      </div>
    </div>
  )
}

/**
 * The analyst's note on a story, checked against the story's own rows: every address, hash and name it
 * gives should be in them. A saved note is checked again whenever it is shown, and the page asks
 * before a story switch throws away what is typed and not saved.
 */
function StoryNote({
  story,
  entry,
  names,
  onSave,
  onDirty,
}: {
  story: Story
  entry: NoteOnStory | undefined
  names: string[]
  onSave: (text: string) => Promise<void>
  onDirty: (dirty: boolean) => void
}) {
  const kase = useStore((s) => s.currentCase)
  const saved = entry?.note.text ?? ''
  // what the analyst is typing; null while the note shown is the saved one
  const [draft, setDraft] = useState<string | null>(null)
  const [check, setCheck] = useState<TextCheck | null>(null)
  const text = draft ?? saved
  const dirty = draft !== null && draft !== saved
  useEffect(() => onDirty(dirty), [dirty, onDirty])
  useEffect(() => {
    let alive = true
    setCheck(null)
    if (!kase || !saved.trim()) return
    const ds = getSource(kase)
    const ids = storyRowIds(story)
    Promise.all([readRows(ds, 'events', ids.events), readRows(ds, 'mails', ids.mails)])
      .then(([ev, ml]) => alive && setCheck(checkText(saved, [...ev.values(), ...ml.values()], names)))
      .catch(() => undefined)
    return () => {
      alive = false
    }
  }, [kase, story, saved, names])
  const save = async () => {
    await onSave(text)
    setDraft(null)
  }
  return (
    <div className="col" style={{ gap: 6 }}>
      <textarea
        className="input"
        aria-label="Story note"
        rows={2}
        placeholder="Your reading of this story: it is checked against the story's own records"
        value={text}
        onChange={(e) => setDraft(e.target.value)}
      />
      <div className="row" style={{ gap: 8 }}>
        <button className="btn sm" disabled={!dirty} onClick={save}>
          Save note
        </button>
        {check && !dirty && (
          <span className="small" role="status">
            <Dot sev={check.status === 'verified' ? 'ok' : 'high'} />{' '}
            {check.status === 'verified' ? `every value it names is in the story's records (${check.named.length})` : check.reasons.join('; ')}
          </span>
        )}
      </div>
    </div>
  )
}

/** The notes whose story this build no longer holds: kept and listed, to put back on a story or delete. */
function OrphanNotes({ orphans, story, onAttach, onDelete }: { orphans: OrphanNote[]; story: Story | null; onAttach: (o: OrphanNote) => void; onDelete: (o: OrphanNote) => void }) {
  return (
    <div className="section" role="region" aria-label="Notes whose story is gone" style={{ padding: '10px 14px', borderTop: '1px solid var(--line)' }}>
      <h3>Notes whose story is gone ({orphans.length})</h3>
      <div className="small muted" style={{ lineHeight: 1.5 }}>
        The stories were built again and none of them holds what these notes were written on. They are kept: open the story a note belongs to and attach it there, or delete it.
      </div>
      {orphans.map((o) => (
        <div key={o.key} className="col" style={{ gap: 3, marginTop: 10 }}>
          <div className="small">
            <strong>{o.title}</strong>
            {o.start != null && <span className="muted"> · {day(o.start)}</span>}
          </div>
          <div className="small" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', color: 'var(--fg-2)' }}>
            {o.note.text}
          </div>
          <div className="row" style={{ gap: 6 }}>
            <button className="btn xs" disabled={!story} onClick={() => onAttach(o)} title={story ? `put this note on the story of ${story.title}` : 'open a story first'}>
              attach to the open story
            </button>
            <button className="btn xs ghost" onClick={() => onDelete(o)}>
              delete
            </button>
          </div>
        </div>
      ))}
    </div>
  )
}

function StepPane({
  story,
  step,
  readings,
  labels,
  g,
  onOpen,
  onOpenAll,
  onExplore,
  onClose,
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
                <div className="v click" onClick={() => setEntity({ kind: 'host', value: step.host! })}>
                  {step.host}
                </div>
              </>
            )}
            {step.ip && (
              <>
                <div className="k">address</div>
                <div className="v click" onClick={() => setEntity({ kind: 'ip', value: step.ip! })}>
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
          {step.notes.map((n, i) => (
            <div key={i} className="small muted">
              {n}
            </div>
          ))}
        </div>
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

function CampaignList({ campaigns, stories, active, onSelect }: { campaigns: Campaign[]; stories: Map<string, Story>; active: string | null; onSelect: (id: string) => void }) {
  if (!campaigns.length)
    return (
      <div className="muted small" style={{ padding: 14, lineHeight: 1.5 }}>
        No campaign: no two stories share an address, a sender, a link, an attachment, a forwarding address or an application, and no flagged mail or failed logon stands outside a story.
      </div>
    )
  return (
    <>
      {campaigns.map((c) => (
        <div key={c.id} className={'story-row' + (active === c.id ? ' active' : '')} onClick={() => onSelect(c.id)} role="button" aria-label={`Campaign ${c.label}`}>
          <Dot sev={c.severity} />
          <div style={{ minWidth: 0 }}>
            <div className="ellipsis name mono">{c.label}</div>
            <div className="ellipsis small" style={{ color: 'var(--fg-2)' }}>
              {c.stories.length ? c.stories.map((s) => stories.get(s)?.title ?? s).join(', ') : 'no story'}
            </div>
            <div className="small mono" style={{ color: 'var(--fg-3)' }}>
              {fmtTs(c.start)} · {spanText(c.end - c.start)}
            </div>
          </div>
          <div className="meta">
            <span className="score">{c.stories.length}</span>
            <span>{c.stories.length === 1 ? 'story' : 'stories'}</span>
            <span>{fmtNum(c.targets.length)} other accounts</span>
          </div>
        </div>
      ))}
    </>
  )
}

function CampaignDetail({
  campaign,
  stories,
  onStory,
  onOpenRefs,
  onExport,
}: {
  campaign: Campaign
  stories: Map<string, Story>
  onStory: (id: string) => void
  onOpenRefs: (refs: string[]) => void
  onExport: () => void
}) {
  const setEntity = useStore((s) => s.setEntity)
  const members = campaign.stories.map((s) => stories.get(s)).filter((s): s is Story => !!s)
  return (
    <div className="view-body col" style={{ gap: 14 }}>
      <div className="section">
        <h3>
          <Sev sev={campaign.severity} /> {campaign.label}
        </h3>
        <div className="small muted">
          {campaign.labelKind.replace('-', ' ')} · {fmtTs(campaign.start)} → {fmtTs(campaign.end)} · {members.length} {members.length === 1 ? 'story' : 'stories'} · {fmtNum(campaign.targets.length)}{' '}
          other account(s) reached
        </div>
        <div className="row" style={{ marginTop: 8 }}>
          <button
            className="btn sm"
            onClick={onExport}
            title="the campaign as a STIX 2.1 grouping (suspicious activity): the Attack Flow of each story, the infrastructure they share, the accounts reached"
          >
            <IconDownload /> Download STIX grouping
          </button>
        </div>
      </div>
      {members.length > 0 && (
        <div className="section">
          <h3>Stories</h3>
          {members.map((s) => (
            <div key={s.id} className="story-row" onClick={() => onStory(s.id)} role="button">
              <Dot sev={s.severity} />
              <div style={{ minWidth: 0 }}>
                <div className="name ellipsis">{s.title}</div>
                <div className="small ellipsis" style={{ color: 'var(--fg-2)' }}>
                  {s.headline}
                </div>
                <PhaseStrip story={s} />
              </div>
              <div className="meta">
                <span>{fmtTs(s.start)}</span>
              </div>
            </div>
          ))}
        </div>
      )}
      <div className="section">
        <h3>The infrastructure</h3>
        <table className="table compact">
          <thead>
            <tr>
              <th>kind</th>
              <th>value</th>
              <th>stories</th>
            </tr>
          </thead>
          <tbody>
            {campaign.artifacts.map((a) => (
              <tr key={a.kind + a.value}>
                <td>{a.kind.replace('-', ' ')}</td>
                <td
                  className="mono click"
                  style={{ overflowWrap: 'anywhere' }}
                  onClick={() => (a.kind === 'ip' ? setEntity({ kind: 'ip', value: a.value }) : a.kind.endsWith('domain') ? setEntity({ kind: 'domain', value: a.value }) : undefined)}
                >
                  {a.value}
                </td>
                <td>{a.stories.map((s) => stories.get(s)?.title ?? s).join(', ')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {campaign.targets.length > 0 && (
        <div className="section">
          <h3>Other accounts it reached</h3>
          <p className="small muted" style={{ margin: 0 }}>
            Accounts in no story that the same sources reached: the recipients of its flagged mails, the accounts its addresses tried. Nothing here says they were compromised.
          </p>
          <table className="table compact" style={{ marginTop: 8 }}>
            <thead>
              <tr>
                <th>account</th>
                <th>what</th>
                <th>through</th>
                <th>records</th>
              </tr>
            </thead>
            <tbody>
              {campaign.targets.map((t) => (
                <tr key={t.id} style={{ cursor: 'pointer' }} onClick={() => onOpenRefs(t.refs)} title="open the records">
                  <td className="mono">{t.account}</td>
                  <td>{t.how.join(', ')}</td>
                  <td className="mono">{t.via.join(', ')}</td>
                  <td>{fmtNum(t.refs.length)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export function StoriesView() {
  const kase = useStore((s) => s.currentCase)
  const setView = useStore((s) => s.setView)
  const setFocus = useStore((s) => s.setFocus)
  const setEventsFilter = useStore((s) => s.setEventsFilter)
  const setEntity = useStore((s) => s.setEntity)
  const setAiPrompt = useStore((s) => s.setAiPrompt)
  const setFocusChain = useStore((s) => s.setFocusChain)
  const bump = useStore((s) => s.bumpRules)
  const rulesVersion = useStore((s) => s.rulesVersion)
  const [res, setRes] = useState<StoryResult | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  /** why the snapshot no longer reads the case as it is; empty when it does */
  const [stale, setStale] = useState<string[]>([])
  /** what the page could not open as asked: a story or step a link points to that the stories no longer hold */
  const [notice, setNotice] = useState('')
  const [notes, setNotes] = useState<StoryNotes>({})
  const [mode, setMode] = useState<Mode>('stories')
  const [storyId, setStoryId] = useState<string | null>(null)
  const [stepId, setStepId] = useState<string | null>(null)
  const [phase, setPhase] = useState<string | null>(null)
  const [full, setFull] = useState(false)
  const [tab, setTab] = useState<Tab>('story')
  const [campaignId, setCampaignId] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState<'' | 'person' | 'host'>('')
  const [readings, setReadings] = useState<Map<string, MeasureReading>>(new Map())
  const [caseGaps, setCaseGaps] = useState<GapStatement[]>([])
  const [detail, setDetail] = useState<Detail>(null)
  const [explored, setExplored] = useState('')
  const g = useRelationshipGraph(kase)
  // whether the open story's note holds text not saved yet (StoryNote says so as it changes)
  const noteDirty = useRef(false)
  const onNoteDirty = useCallback((d: boolean) => {
    noteDirty.current = d
  }, [])
  /** True when the analyst keeps an unsaved note rather than let what they do next throw it away. */
  const keepNote = () => noteDirty.current && !confirm('The note on this story is not saved. Discard it?')

  /**
   * Build the stories. What was open stays open: the story (followed by what it shares when its id
   * changed) and its step, or the story a link asked for; the page says so when it is gone.
   */
  const build = useCallback(
    async (follow?: Follow | null) => {
      if (!kase) return
      setBusy(true)
      setError('')
      try {
        const r = await buildStories(kase)
        setRes(r)
        setStale([])
        let next: Story | null = null
        if (follow && 'link' in follow) {
          next = r.stories.find((s) => s.id === follow.link || s.chains.includes(follow.link)) ?? null
          if (next) setNotice('')
        } else if (follow) {
          next = findStory(follow.story, follow.identities, r.stories, r.identities)
          if (!next) setNotice(`The story of ${follow.story.title} that was open is not among the stories built again: pick one from the list.`)
        }
        setStoryId(follow ? (next?.id ?? null) : (r.stories[0]?.id ?? null))
        setStepId(follow?.step && next?.steps.some((s) => s.id === follow.step) ? follow.step : null)
        bump()
        toast(
          r.stories.length ? 'ok' : 'warn',
          `${r.stories.length} ${r.stories.length === 1 ? 'story' : 'stories'} and ${r.campaigns.length} campaign(s) from ${fmtNum(Number(r.stats.events ?? 0))} event(s) and ${fmtNum(Number(r.stats.mails ?? 0))} mail(s)`,
        )
      } catch (e) {
        setError((e as Error).message)
      } finally {
        setBusy(false)
      }
    },
    [kase, bump],
  )

  // the snapshot, the notes, the rule measures and the case's gaps. A case with findings and no snapshot is read
  // into stories at once, and so is an out-of-date snapshot when building it again is cheap.
  useEffect(() => {
    if (!kase?.id) return
    let alive = true
    setLoaded(false)
    setRes(null)
    setNotice('')
    Promise.all([loadStories(kase.id), loadStoryNotes(kase.id)]).then(async ([r, n]) => {
      if (!alive) return
      setRes(r)
      setNotes(n)
      // a link from the case timeline or the review: a chain's story, or a story and, after '#', one of its steps
      const want = useStore.getState().focusChain
      if (want) setFocusChain(null)
      const wantId = want ? want.split('#')[0] : null
      const wantStep = want && want.includes('#') ? want.slice(want.indexOf('#') + 1) : null
      const focus = wantId ? (r?.stories.find((s) => s.chains.includes(wantId) || s.id === wantId) ?? null) : null
      const focusStep = focus && wantStep ? (focus.steps.find((s) => s.id === wantStep) ?? null) : null
      if (wantId && r && !focus) setNotice('The story this link points to is not among the stories: they were built again since it was added. Pick it from the list.')
      else if (focus && wantStep && !focusStep) setNotice(`The step this link points to is no longer in the story of ${focus.title}: it was built again since the link was added.`)
      setStoryId(focus?.id ?? (wantId ? null : (r?.stories[0]?.id ?? null)))
      setStepId(focusStep?.id ?? null)
      setLoaded(true)
      if (!r) {
        if (await getDb().findings.where('caseId').equals(kase.id!).count()) build()
        return
      }
      const reasons = storiesStaleness(r, await storyInputs(kase))
      const open = focus ?? (wantId ? null : (r.stories[0] ?? null))
      if (alive && reasons.length && cheapToRebuild(r)) build(open ? { story: open, identities: r.identities, step: focusStep?.id } : wantId ? { link: wantId, step: wantStep ?? undefined } : null)
    })
    loadRules(kase.id)
      .then((rules) => alive && setReadings(new Map(rules.map((r) => [r.rule.id, readMeasure(r.measured, r.origin)]))))
      .catch(() => {})
    loadEvidenceGaps(kase.id, getSource(kase))
      .then((gaps) => alive && setCaseGaps(gaps))
      .catch(() => {})
    return () => {
      alive = false
    }
    // build is stable for a case; running it again on its identity change would double the first build
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kase?.id])

  // does the snapshot still read the case as it is? Asked again after a rule run, a decision on a finding or a settings change
  useEffect(() => {
    if (!kase?.id || !res) return setStale([])
    let alive = true
    storyInputs(kase)
      .then((now) => alive && setStale(storiesStaleness(res, now)))
      .catch(() => undefined)
    return () => {
      alive = false
    }
  }, [kase, res, rulesVersion])

  const labels = useMemo(() => new Map((res?.identities ?? []).map((i) => [i.id, i.label])), [res])
  const byStory = useMemo(() => new Map((res?.stories ?? []).map((s) => [s.id, s])), [res])
  const resolved = useMemo(() => resolveStoryNotes(res?.stories ?? [], res?.identities ?? [], notes), [res, notes])
  const shown = useMemo(
    () =>
      (res?.stories ?? []).filter(
        (s) =>
          (!kind || s.kind === kind) && (!query || `${s.title} ${s.headline} ${s.hosts.join(' ')} ${s.attackerAddresses.join(' ')} ${s.ips.join(' ')}`.toLowerCase().includes(query.toLowerCase())),
      ),
    [res, kind, query],
  )
  const story = storyId ? (byStory.get(storyId) ?? null) : null
  const step = story && stepId ? (story.steps.find((s) => s.id === stepId) ?? null) : null
  const campaign = res?.campaigns.find((c) => c.id === campaignId) ?? null
  const identity = story?.kind === 'person' ? res?.identities.find((i) => i.id === story.subject.id) : undefined
  // what a note on the open story is checked for: its hosts, its accounts and the addresses it came from
  const noteNames = useMemo(() => (story ? [...story.hosts, ...story.accounts.map((a) => labels.get(a) ?? a), ...story.attackerAddresses] : []), [story, labels])
  // a story opens on its spine; the full timeline when asked, when a phase filters it, when the step open is off the spine
  const spine = useMemo(() => (story ? spineSteps(story) : null), [story])
  const showAll = full || !!phase || !spine?.length || (!!stepId && !spine.some((s) => s.id === stepId))

  // j / k move between the steps of the open story
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null
      if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable)) return
      if (mode !== 'stories' || !story || (e.key !== 'j' && e.key !== 'k')) return
      const steps = !showAll && spine ? spine : phase ? story.steps.filter((s) => s.phase === phase) : story.steps
      const i = stepId ? steps.findIndex((s) => s.id === stepId) : -1
      setStepId(steps[e.key === 'j' ? Math.min(steps.length - 1, i + 1) : Math.max(0, i - 1)]?.id ?? null)
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [mode, story, stepId, phase, showAll, spine])

  if (!kase) return null
  const openRow = async (source: 'events' | 'mails', id: number) => {
    try {
      const ds = getSource(kase)
      if (source === 'events') {
        const row = await ds.getEvent(id)
        if (!row) throw new Error(`Event #${id} is no longer in the case. Build the stories again.`)
        setDetail({ source: 'events', row })
      } else {
        const mail = await ds.getMail(id)
        if (!mail) throw new Error(`Mail #${id} is no longer in the case. Build the stories again.`)
        setDetail({ source: 'mails', row: mail.row })
      }
    } catch (e) {
      setError((e as Error).message)
    }
  }
  const openRefs = (refs: string[]) => {
    const rows = refs.map(refRow).filter((r): r is NonNullable<ReturnType<typeof refRow>> => !!r)
    const events = rows.filter((r) => r.source === 'events').map((r) => r.id)
    if (rows.length === 1) return openRow(rows[0].source, rows[0].id)
    if (!events.length && rows.length) {
      setFocus({ source: 'mails', id: rows[0].id })
      return setView('mails')
    }
    setEventsFilter({ conditions: [{ field: 'id', op: 'in', value: events.slice(0, 500) }], sort: { field: 'ts', dir: 'asc' } })
    setView('events')
  }
  const selectStory = (id: string) => {
    if (id !== storyId && keepNote()) return
    setMode('stories')
    setStoryId(id)
    setStepId(null)
    setPhase(null)
    setNotice('')
  }
  // the note is shown in the Stories mode only: leaving it asks first, as a story switch does
  const switchMode = (m: Mode) => {
    if (m !== mode && mode === 'stories' && keepNote()) return
    setMode(m)
  }
  const explore = (nodeId: string) => {
    if (keepNote()) return
    setMode('explore')
    setExplored(nodeId)
  }
  const rebuild = () => {
    if (keepNote()) return
    build(story ? { story, identities: res?.identities ?? [], step: stepId ?? undefined } : null)
  }
  // the request is the analyst's; what the story took from the records reaches the model as evidence
  const ask = (s: Story) => {
    setAiPrompt(storyQuestion(s, res?.stats))
    setView('ai')
  }
  const saveNote = async (text: string) => {
    if (!story) return
    setNotes(await saveStoryNote(kase.id!, story, res?.identities ?? [], text, resolved.byStory.get(story.id)?.key))
  }
  const attachNote = async (o: OrphanNote) => {
    if (!story) return
    setNotes(await attachStoryNote(kase.id!, o.key, story, res?.identities ?? [], resolved.byStory.get(story.id)?.key))
  }
  const dropNote = async (o: OrphanNote) => {
    if (!confirm(`Delete the note written on the story of ${o.title}? It cannot be undone.`)) return
    setNotes(await deleteStoryNote(kase.id!, o.key))
  }
  const sevCounts = (res?.stories ?? []).reduce<Record<string, number>>((m, s) => ((m[s.severity] = (m[s.severity] ?? 0) + 1), m), {})
  const warnings = storyCoverageWarnings(res?.stats)
  return (
    <div className="view">
      <div className="view-header">
        <div className="desc">
          <h1>Stories</h1>
          <span className="sub">
            {res
              ? `${res.stories.length} ${res.stories.length === 1 ? 'story' : 'stories'} · ${
                  SEV_ORDER.slice()
                    .reverse()
                    .filter((k) => sevCounts[k])
                    .map((k) => `${sevCounts[k]} ${k}`)
                    .join(', ') || 'none'
                } · ${res.campaigns.length} campaign(s) · built ${res.builtAt ? fmtTs(res.builtAt) : ''}`
              : loaded
                ? busy
                  ? 'reading the case into stories…'
                  : 'not built yet: run the rules first, the stories start from their findings'
                : ''}
          </span>
        </div>
        <span className="spacer" />
        <button className="btn sm primary" onClick={rebuild} disabled={busy}>
          {busy ? <Spinner /> : <IconPlay />} {res ? 'Rebuild stories' : 'Build stories'}
        </button>
      </div>
      {error && (
        <div role="alert" className="hint" style={{ color: 'var(--danger)', padding: '6px 16px' }}>
          {error}
        </div>
      )}
      {stale.length > 0 && !busy && (
        <div className="panel row" role="status" aria-label="Stories out of date" style={{ margin: '6px 16px', padding: '6px 10px', gap: 10, borderColor: 'var(--sev-medium)' }}>
          <span>
            <strong>Out of date:</strong> {stale.join('; ')}. These stories read the case as it was then.
          </span>
          <span className="spacer" />
          <button className="btn xs primary" onClick={rebuild}>
            rebuild
          </button>
        </div>
      )}
      {notice && (
        <div className="panel row" role="status" style={{ margin: '6px 16px', padding: '6px 10px', gap: 10 }}>
          <span>{notice}</span>
          <span className="spacer" />
          <button className="btn xs ghost" onClick={() => setNotice('')}>
            dismiss
          </button>
        </div>
      )}
      {warnings.map((w) => (
        <div className="panel" role="status" key={w} style={{ margin: '6px 16px', padding: '6px 10px' }}>
          Incomplete: {w} An absent step or story is not a negative result.
        </div>
      ))}
      {resolved.orphans.length > 0 && (
        <div className="panel" role="status" style={{ margin: '6px 16px', padding: '6px 10px' }}>
          {resolved.orphans.length === 1 ? 'A note is' : `${resolved.orphans.length} notes are`} on a story these stories no longer hold: listed under the stories, to attach again or delete.
        </div>
      )}
      <div className="split" style={{ gridTemplateColumns: '340px 1fr' }}>
        <div className="left">
          <div className="row" style={{ padding: '10px 14px', gap: 10, borderBottom: '1px solid var(--line)' }}>
            <div className="segmented">
              <button className={mode === 'stories' ? 'active' : ''} onClick={() => switchMode('stories')}>
                Stories
              </button>
              <button className={mode === 'campaigns' ? 'active' : ''} onClick={() => switchMode('campaigns')}>
                Campaigns
              </button>
              <button className={mode === 'explore' ? 'active' : ''} onClick={() => switchMode('explore')}>
                Explore
              </button>
            </div>
          </div>
          {mode === 'stories' && (
            <>
              {res && res.stories.length > 0 && (
                <div className="row" style={{ gap: 6, padding: '8px 14px' }}>
                  <input className="input" placeholder="Search stories" aria-label="Search stories" value={query} onChange={(e) => setQuery(e.target.value)} style={{ flex: 1 }} />
                  <select className="select" aria-label="Story kind" value={kind} onChange={(e) => setKind(e.target.value as '' | 'person' | 'host')}>
                    <option value="">All</option>
                    <option value="person">People</option>
                    <option value="host">Hosts</option>
                  </select>
                </div>
              )}
              {!res && loaded && !busy && (
                <div className="muted small" style={{ padding: 14, lineHeight: 1.5 }}>
                  A story is what happened to one person, or to one host when its records name no one: the records around a finding of medium severity or more, or a phishing mail and what its
                  recipient did next, read along ATT&CK's phases. Each step says why it belongs and how surely; the sessions, hops and process trees around it are drawn from the evidence, and each
                  host says what its logs cannot show.
                </div>
              )}
              {res && res.stories.length === 0 && (
                <div className="muted small" style={{ padding: 14, lineHeight: 1.5 }}>
                  No story: no finding of medium severity or more names a person or a host beyond a mail received or a failed logon.
                  {res.unstoried.length ? ` ${res.unstoried.length} flag(s) stand outside any story; Campaigns groups them by sender and address.` : ''}
                </div>
              )}
              <StoryList stories={shown} active={storyId} onSelect={selectStory} />
              {resolved.orphans.length > 0 && <OrphanNotes orphans={resolved.orphans} story={story} onAttach={attachNote} onDelete={dropNote} />}
            </>
          )}
          {mode === 'campaigns' && <CampaignList campaigns={res?.campaigns ?? []} stories={byStory} active={campaignId} onSelect={setCampaignId} />}
          {mode === 'explore' && <ExploreList g={g} selected={explored} onSelect={setExplored} />}
        </div>
        <div className="right">
          {mode === 'explore' && <Explorer g={g} selected={explored} onSelect={setExplored} onOpen={(ref) => ref.id != null && openRow(ref.source, ref.id)} />}
          {mode === 'campaigns' &&
            (campaign ? (
              <CampaignDetail
                campaign={campaign}
                stories={byStory}
                onStory={selectStory}
                onOpenRefs={openRefs}
                onExport={() => downloadCampaignGrouping(kase, campaign, [...byStory.values()], res?.identities ?? []).catch((e) => setError((e as Error).message))}
              />
            ) : (
              <div className="muted" style={{ padding: 24 }}>
                {res?.campaigns.length ? 'select a campaign' : ''}
              </div>
            ))}
          {mode === 'stories' && !story && (
            <div className="muted" style={{ padding: 24 }}>
              {res?.stories.length ? 'select a story' : ''}
            </div>
          )}
          {mode === 'stories' && story && (
            <>
              <div className="story-head">
                <div className="row" style={{ gap: 10, alignItems: 'flex-start' }}>
                  <Sev sev={story.severity} />
                  <div className="col" style={{ gap: 3, flex: 1, minWidth: 0 }}>
                    <div style={{ fontWeight: 600, color: 'var(--fg-1)', fontSize: 14 }}>
                      <span
                        className="click"
                        style={{ cursor: 'pointer' }}
                        onClick={() => (story.kind === 'host' ? setEntity({ kind: 'host', value: story.subject.id }) : setTab('identity'))}
                        title={story.kind === 'host' ? 'open the host page' : 'who is who: the forms of this account'}
                      >
                        {story.title}
                      </span>
                      <span className="muted" style={{ fontWeight: 400 }}>
                        {' '}
                        · score {story.score} · {story.steps.length} steps, {fmtNum(story.records)} records over {spanText(story.end - story.start)} ·{' '}
                        <span title="the weakest tie of a flagged step: strong when records state it, medium when naming rules or time and place join it">{story.confidence} ties</span>
                      </span>
                    </div>
                    <div className="small" style={{ color: 'var(--fg-1)' }}>
                      {story.headline}
                    </div>
                    <div className="small" style={{ color: 'var(--fg-2)' }}>
                      {story.summary}
                    </div>
                  </div>
                  <AddToTimeline ts={story.start} text={`Story ${story.title}: ${story.headline}`} link={{ source: 'stories', id: story.id, label: story.title }} severity={story.severity} />
                  <button className="btn sm" onClick={() => ask(story)}>
                    <IconAi /> ask the analyst
                  </button>
                  <button
                    className="btn sm"
                    onClick={() => downloadAttackFlow(kase, story, res?.identities ?? []).catch((e) => setError((e as Error).message))}
                    title="the story as a MITRE Attack Flow: a STIX 2.1 bundle, one action per step of its spine"
                  >
                    <IconDownload /> Download Attack Flow
                  </button>
                </div>
                <div className="row wrap small" style={{ gap: 6, marginTop: 8 }}>
                  {story.attackerAddresses.map((ip) => (
                    <span key={ip} className="pill" onClick={() => setEntity({ kind: 'ip', value: ip })} title="a source the story's findings name">
                      {ip}
                    </span>
                  ))}
                  {story.hosts.map((h) => (
                    <span key={h} className="pill" onClick={() => setEntity({ kind: 'host', value: h })} title="a host of the story">
                      <IconHost /> {h}
                    </span>
                  ))}
                  {story.campaigns.map((c) => {
                    const camp = res?.campaigns.find((x) => x.id === c)
                    return (
                      <span
                        key={c}
                        className="pill"
                        onClick={() => {
                          if (keepNote()) return
                          setMode('campaigns')
                          setCampaignId(c)
                        }}
                        title="the campaign this story is part of"
                      >
                        campaign {camp?.label ?? c}
                      </span>
                    )
                  })}
                  {story.chains.length > 0 && (
                    <span
                      className="pill"
                      onClick={() => {
                        setFocusChain(story.chains[0])
                        setView('review')
                      }}
                      title="review the phishing chain of this story"
                    >
                      review the chain
                    </span>
                  )}
                </div>
                <StoryNote key={story.id} story={story} entry={resolved.byStory.get(story.id)} names={noteNames} onSave={saveNote} onDirty={onNoteDirty} />
              </div>
              <PhaseRail story={story} active={phase} onPick={setPhase} />
              <Tabs
                tabs={[
                  { id: 'story' as const, label: 'Story' },
                  { id: 'lineage' as const, label: `Lineage (${story.lineage.sessions.length + story.lineage.hops.length + story.lineage.processes.length})` },
                  { id: 'identity' as const, label: 'Who is who' },
                  { id: 'gaps' as const, label: `Where it stops (${storyGaps(story, res?.stats).length + caseGaps.length})` },
                  { id: 'json' as const, label: 'JSON' },
                ]}
                active={tab}
                onChange={setTab}
              />
              {tab === 'story' && (
                <div className="pane" style={{ flex: 1, height: 'auto', borderTop: 0, gridTemplateColumns: step ? '1fr 380px' : '1fr' }}>
                  <div className="pane-main" style={{ overflow: 'auto' }}>
                    <StorySpine
                      story={story}
                      full={showAll}
                      onFull={(on) => {
                        setFull(on)
                        if (on) return
                        setPhase(null)
                        if (stepId && !spine?.some((s) => s.id === stepId)) setStepId(null)
                      }}
                      selected={stepId}
                      onSelect={setStepId}
                      labels={labels}
                    />
                    {showAll && <Timeline story={story} phase={phase} selected={stepId} onSelect={setStepId} readings={readings} labels={labels} />}
                  </div>
                  {step && (
                    <StepPane
                      story={story}
                      step={step}
                      readings={readings}
                      labels={labels}
                      g={g}
                      onOpen={openRow}
                      onOpenAll={(s) => openRefs(s.refs)}
                      onExplore={explore}
                      onClose={() => setStepId(null)}
                    />
                  )}
                </div>
              )}
              {tab === 'lineage' && <LineagePanel story={story} highlight={step?.process} />}
              {tab === 'identity' && <IdentityPanel identity={identity} />}
              {tab === 'gaps' && <GapsPanel story={story} stats={res?.stats} caseGaps={caseGaps} />}
              {tab === 'json' && (
                <div className="view-body">
                  <pre className="codeblock">{JSON.stringify(story, null, 2)}</pre>
                </div>
              )}
            </>
          )}
        </div>
      </div>
      {detail?.source === 'events' && <EventDetail row={detail.row} onClose={() => setDetail(null)} />}
      {detail?.source === 'mails' && <MailDetail row={detail.row} onClose={() => setDetail(null)} />}
    </div>
  )
}
