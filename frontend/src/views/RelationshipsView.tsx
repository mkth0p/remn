import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { RelationshipInvestigation } from '../components/RelationshipInvestigation'
import { assessStory, INTELLIGENCE_VERSION } from '../data/relationshipIntelligence'
import { AddToTimeline } from '../components/AddToTimeline'
import { ChainGraph } from '../components/ChainGraph'
import { EventDetail, MailDetail } from '../components/Detail'
import { IconAi, IconHost, IconLayers, IconMail, IconPlay } from '../components/Icons'
import { Badge, Dot, Sev, Spinner, Tabs } from '../components/ui'
import { buildRelationships, scanRelationships, type RelationshipAliases, type RelationshipEdge, type RelationshipNode, type RelationshipRef, type RelationshipResult } from '../data/relationships'
import { loadRelationshipReviews, relationshipKey, reviewedRelationships, saveRelationshipReview, type RelationshipReview } from '../data/relationshipReviews'
import { relationshipLeads } from '../data/relationshipLeads'
import { buildStories, recordTime, type Story, type StoryEntity, type StoryRecord, type StoryResult } from '../data/relationshipStories'
import { buildStoryGraph } from '../data/storyGraph'
import { getSource } from '../data/source'
import { getDb, type EventRow, type Evidence, type MailRow, type Severity } from '../db/schema'
import { useStore, type EntityRef } from '../state/store'
import { fmtNum, fmtTs } from '../util/format'

/**
 * Relationships as stories: the left list ranks the stories the graph yields (see
 * data/relationshipStories.ts), the right column reads the selected one as a time-ordered
 * narrative, a swimlane graph, the links to review, and the entities it names. Explore keeps the
 * flat graph browser: any entity, its neighbours, and the edges with their reviews.
 */

type Mode = 'stories' | 'explore'
type StoryTab = 'investigate' | 'story' | 'graph' | 'links' | 'entities' | 'json'
type Detail = { source: 'events'; row: EventRow } | { source: 'mails'; row: MailRow } | null

const SEV_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical']
const worstSeverity = (items: { severity: Severity }[]): Severity | null =>
  items.reduce<Severity | null>((w, f) => (w == null || SEV_ORDER.indexOf(f.severity) > SEV_ORDER.indexOf(w) ? f.severity : w), null)
const basename = (path: string | null) => (path ? path.replace(/\\/g, '/').split('/').pop() || path : 'source file unavailable')
const spanText = (ms: number) => {
  const m = ms / 60_000
  return m < 1 ? 'under a minute' : m < 90 ? `${Math.round(m)} min` : m < 48 * 60 ? `${(m / 60).toFixed(1)} h` : `${(m / 1440).toFixed(1)} d`
}
const recordKindText = (r: StoryRecord) => (r.recordKind === 'observation' ? 'collected' : r.source === 'mails' ? 'mail' : 'event')
const shortLabel = (e: { kind: string; label: string }) =>
  e.kind === 'hash'
    ? e.label.replace(/^(sha256|sha1|md5):([0-9a-f]{12})[0-9a-f]*$/i, '$1:$2…')
    : e.kind === 'file'
      ? (e.label.split(/[\\/]/).pop() ?? e.label)
      : e.label.length > 48
        ? e.label.slice(0, 47) + '…'
        : e.label
/** the entity flyout covers hosts, addresses, domains and accounts; everything else is browsed in Explore */
const entityRef = (kind: string, value: string): EntityRef | null =>
  kind === 'host' || kind === 'ip' || kind === 'domain' ? { kind, value } : kind === 'account' ? { kind: value.includes('@') ? 'address' : 'user', value } : null
const SEED_TEXT = { finding: 'started the story: finding', lead: 'cross-source entity' }
const noop = () => {}

function fingerprint(rows: Evidence[]): string {
  return JSON.stringify(rows.map((e) => [e.id, e.sha256Client, e.count, e.status]).sort((a, b) => Number(a[0]) - Number(b[0])))
}

function relatedTimeline(result: RelationshipResult | null, selected: string): RelationshipRef[] {
  if (!result || !selected) return []
  const touched = new Set([selected])
  const refs = new Map<string, RelationshipRef>()
  for (let hop = 0; hop < 2; hop++) {
    const frontier = new Set(touched)
    for (const edge of result.edges) {
      if (!frontier.has(edge.source) && !frontier.has(edge.target)) continue
      if (touched.size < 500) {
        touched.add(edge.source)
        touched.add(edge.target)
      }
      for (const ref of edge.refs) if (refs.size < 200) refs.set(`${ref.source}:${ref.id}:${ref.evidenceId}`, ref)
    }
  }
  const time = (r: RelationshipRef) => (r.recordKind === 'observation' ? r.observedAt : r.ts) ?? Infinity
  return [...refs.values()].sort((a, b) => time(a) - time(b))
}

function RelationshipEditor({
  edge,
  nodes,
  aliases,
  review,
  onSave,
}: {
  edge: RelationshipEdge
  nodes: Map<string, RelationshipNode>
  aliases: RelationshipAliases
  review?: RelationshipReview
  onSave: (r: RelationshipReview) => Promise<void>
}) {
  const [draft, setDraft] = useState<RelationshipReview>(() => ({
    key: relationshipKey(edge, nodes),
    status: 'unreviewed',
    notes: '',
    includeInReport: false,
    sourceLabel: nodes.get(edge.source)?.label ?? '',
    targetLabel: nodes.get(edge.target)?.label ?? '',
    relation: edge.relation,
    reason: edge.reason,
    confidence: edge.confidence,
    references: edge.refs,
    aliases,
    updatedAt: Date.now(),
    ...review,
  }))
  const [message, setMessage] = useState('')
  const save = async () => {
    setMessage('Saving…')
    try {
      await onSave({ ...draft, references: edge.refs, updatedAt: Date.now() })
      setMessage('Saved')
    } catch {
      setMessage('Save failed')
    }
  }
  return (
    <div className="col" style={{ gap: 8, marginBottom: 12 }}>
      <div className="row">
        <select
          className="select"
          aria-label="Relationship decision"
          value={draft.status}
          onChange={(e) => {
            setDraft({ ...draft, status: e.target.value as RelationshipReview['status'] })
            setMessage('Unsaved')
          }}
        >
          <option value="unreviewed">Unreviewed</option>
          <option value="accepted">Accepted link</option>
          <option value="rejected">Rejected link</option>
        </select>
        <label>
          <input
            type="checkbox"
            checked={draft.includeInReport}
            onChange={(e) => {
              setDraft({ ...draft, includeInReport: e.target.checked })
              setMessage('Unsaved')
            }}
          />{' '}
          Include accepted link in report
        </label>
      </div>
      <textarea
        className="input"
        aria-label="Relationship notes"
        rows={2}
        placeholder="Analyst notes and interpretation"
        value={draft.notes}
        onChange={(e) => {
          setDraft({ ...draft, notes: e.target.value })
          setMessage('Unsaved')
        }}
      />
      <div className="row">
        <button className="btn sm" onClick={save}>
          Save relationship review
        </button>
        <span role="status" className="small muted">
          {message}
        </span>
      </div>
    </div>
  )
}

/** The edges of a story or of a selected entity, each with its review, its explore buttons and its supporting rows. */
function LinkList({
  edges,
  nodes,
  aliases,
  reviews,
  onSave,
  onExplore,
  onOpen,
  keyPrefix,
  limit = 100,
}: {
  edges: RelationshipEdge[]
  nodes: Map<string, RelationshipNode>
  aliases: RelationshipAliases
  reviews: Record<string, RelationshipReview>
  onSave: (r: RelationshipReview) => Promise<void>
  onExplore: (nodeId: string) => void
  onOpen: (ref: RelationshipRef) => void
  keyPrefix: string
  limit?: number
}) {
  return (
    <>
      {edges.slice(0, limit).map((edge, i) => (
        <details key={`${keyPrefix}-${i}`} className="card">
          <summary style={{ cursor: 'pointer', overflowWrap: 'anywhere' }}>
            {nodes.get(edge.source)?.label} → <strong>{edge.relation}</strong> → {nodes.get(edge.target)?.label} <Badge sev={edge.confidence === 'high' ? 'ok' : 'info'}>{edge.confidence}</Badge> ·{' '}
            {edge.count} supporting observations{edge.supportTruncated ? ' (capped sample; total may include duplicate imports)' : ''} · {edge.assertion ?? 'observed'}
          </summary>
          <p>{edge.reason}</p>
          <div className="small muted">
            Rule: {edge.rule ?? 'explicit source fields'} · {(edge.assumptions ?? []).join('; ')}
          </div>
          {edge.refs.some((r) => r.context) && (
            <details>
              <summary>Matching fields and time constraints</summary>
              {edge.refs.slice(0, 5).map((ref, idx) => (
                <pre className="small" key={idx}>
                  {JSON.stringify({ source: ref.source, id: ref.id, ts: ref.ts, observedAt: ref.observedAt, fields: ref.context }, null, 2)}
                </pre>
              ))}
            </details>
          )}
          <RelationshipEditor key={relationshipKey(edge, nodes)} edge={edge} nodes={nodes} aliases={aliases} review={reviews[relationshipKey(edge, nodes)]} onSave={onSave} />
          <div className="row">
            <button className="btn xs" onClick={() => onExplore(edge.source)}>
              Explore source
            </button>
            <button className="btn xs" onClick={() => onExplore(edge.target)}>
              Explore target
            </button>
          </div>
          {edge.refs.map((ref, j) => (
            <div key={j} style={{ marginTop: 12, overflowWrap: 'anywhere' }}>
              <button className="btn sm" disabled={ref.id == null} onClick={() => onOpen(ref)}>
                Open {ref.source} #{ref.id}
              </button>{' '}
              {ref.title}
              <div className="small muted">
                {ref.recordKind === 'observation' ? `Snapshot · collected ${fmtTs(ref.observedAt)}` : `Event time ${fmtTs(ref.ts)}`} · evidence #{ref.evidenceId} ·{' '}
                {ref.sourceFile ?? 'source file unavailable'}
                {ref.sourceIndex != null ? ` · record ${ref.sourceIndex + 1}` : ''}
              </div>
              {ref.sourceSha256 && <div className="small mono">SHA-256 {ref.sourceSha256}</div>}
            </div>
          ))}
          {edge.count > edge.refs.length && (
            <p className="small muted">
              Showing {edge.refs.length} of {edge.count} supporting observations.
            </p>
          )}
        </details>
      ))}
      {edges.length > limit && (
        <span className="small muted">
          Showing {limit} of {fmtNum(edges.length)} links.
        </span>
      )}
    </>
  )
}

/** Left column, Stories mode: the ranked stories, or why there are none. */
function StoryList({ result, stories, active, onSelect }: { result: RelationshipResult | null; stories: StoryResult | null; active: string | null; onSelect: (id: string) => void }) {
  if (!result)
    return (
      <div className="hint" style={{ padding: 14, lineHeight: 1.5 }}>
        A story is a group of records tied together by something specific they share, such as a file digest, a process, a URL, a domain, an account or an address, started from the rows the findings
        cite and the rows marked relevant or pivot. Build relationships scans the evidence for those shared entities, and the stories are read from the result.
      </div>
    )
  if (!stories)
    return (
      <div className="muted small" style={{ padding: 14 }}>
        reading the stories…
      </div>
    )
  if (!stories.stories.length)
    return (
      <div className="muted small" style={{ padding: 14, lineHeight: 1.5 }}>
        No story: no finding cites a scanned record, no row is marked relevant or pivot, and no specific entity appears in two source files. Use Explore to browse the entities.
      </div>
    )
  return (
    <>
      {stories.stories.map((s) => {
        const bridges = s.entities.filter((e) => e.bridge).length
        return (
          <div key={s.id} className={'story-row' + (active === s.id ? ' active' : '')} onClick={() => onSelect(s.id)}>
            <Dot sev={s.severity} />
            <div style={{ minWidth: 0 }}>
              <div className="ellipsis name">{s.title}</div>
              <div className="ellipsis small" style={{ color: 'var(--fg-2)' }}>
                {s.summary}
              </div>
              <div className="small mono" style={{ color: 'var(--fg-3)' }}>
                {s.start != null ? `${fmtTs(s.start)} · ${spanText((s.end ?? s.start) - s.start)}` : 'no timed record'}
              </div>
            </div>
            <div className="meta">
              <span className="score">{s.score}</span>
              <span>{s.records.length} records</span>
              <span className={bridges ? 'bridged' : ''}>{bridges} links</span>
            </div>
          </div>
        )
      })}
    </>
  )
}

/** Left column, Explore mode: search, kind filter and the entities by degree. */
function ExploreList({
  result,
  nodes,
  degrees,
  query,
  kind,
  selected,
  onQuery,
  onKind,
  onSelect,
}: {
  result: RelationshipResult | null
  nodes: RelationshipNode[]
  degrees: Map<string, number>
  query: string
  kind: string
  selected: string
  onQuery: (q: string) => void
  onKind: (k: string) => void
  onSelect: (id: string) => void
}) {
  if (!result)
    return (
      <div className="hint" style={{ padding: 14, lineHeight: 1.5 }}>
        Explore lists every host, account, file, process, digest, address and domain the scan found, with the records that name it. Build relationships first.
      </div>
    )
  return (
    <>
      <div className="col" style={{ gap: 8, padding: '10px 14px' }}>
        <input className="input" placeholder="Search entities and records" aria-label="Search entities" value={query} onChange={(e) => onQuery(e.target.value)} />
        <select className="select" aria-label="Entity type" value={kind} onChange={(e) => onKind(e.target.value)}>
          <option value="">All types</option>
          {[...new Set(result.nodes.map((n) => n.kind))].sort().map((k) => (
            <option key={k} value={k}>
              {k}
            </option>
          ))}
        </select>
        <div className="small muted">{fmtNum(nodes.length)} matches · showing up to 200</div>
      </div>
      <div className="col" style={{ gap: 4, padding: '0 10px 10px' }}>
        {nodes.slice(0, 200).map((n) => (
          <button
            key={n.id}
            className={`btn ${selected === n.id ? 'primary' : 'ghost'}`}
            style={{ textAlign: 'left', display: 'block', whiteSpace: 'normal', overflowWrap: 'anywhere' }}
            onClick={() => onSelect(n.id)}
          >
            {n.kind} · {n.label}
            <div className="small muted">
              {degrees.get(n.id) ?? 0} links{n.scope ? ` · ${n.scope}` : ''}
            </div>
          </button>
        ))}
      </div>
    </>
  )
}

/** Severity, title, summary, the score breakdown and the entity pills of the selected story. */
function StoryHeader({ story, onEntity, onAsk }: { story: Story; onEntity: (e: StoryEntity) => void; onAsk: () => void }) {
  const b = story.scoreBreakdown
  const assessment = useMemo(() => assessStory(story), [story])
  return (
    <div style={{ padding: '12px 16px 8px', borderBottom: '1px solid var(--line)', background: 'var(--surface)' }}>
      <div className="row" style={{ gap: 10, alignItems: 'flex-start' }}>
        <Sev sev={story.severity} />
        <div className="col" style={{ gap: 3, flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 600, color: 'var(--fg-1)', fontSize: 14, overflowWrap: 'anywhere' }}>{story.title}</div>
          <div className="small" style={{ color: 'var(--fg-2)' }}>
            {story.summary}
          </div>
        </div>
        <AddToTimeline ts={story.start} text={`Story: ${story.title}: ${story.summary}`} severity={story.severity} />
        <button className="btn sm" onClick={onAsk}>
          <IconAi /> investigate
        </button>
      </div>
      <div
        className="small mono"
        style={{ marginTop: 6, color: 'var(--fg-3)' }}
        title="how the score is built: each part is bounded, so a long story of routine rows cannot outscore a short corroborated one"
      >
        {`priority ${b.total} = findings ${b.findings}/40 · links ${b.bridges}/30 · sources ${b.sources}/15 · marks ${b.marks}/15`}
      </div>
      <div className="small" style={{ marginTop: 6 }}>
        Association confidence: {assessment.confidence} · {assessment.coverage.uniqueRecords} unique records · {assessment.coverage.sources} source contents · {assessment.issues.length} checks or
        caveats
      </div>
      {story.truncated && (
        <div className="hint" style={{ marginTop: 4, color: 'var(--sev-medium)' }}>
          Partial story: a record, entity or link limit was reached. Seeds and records with findings or marks were kept first.
        </div>
      )}
      <div className="row wrap small" style={{ gap: 6, marginTop: 8 }}>
        {story.entities.slice(0, 12).map((e) => (
          <span
            key={e.id}
            className={'pill' + (e.bridge ? ' active' : '')}
            onClick={() => onEntity(e)}
            title={`${e.kind} · ${e.records} record${e.records === 1 ? '' : 's'} in ${e.sources.length} source file${e.sources.length === 1 ? '' : 's'}${e.bridge ? ' · bridge' : e.hub ? ' · hub' : ''}`}
          >
            {e.kind === 'host' ? <IconHost /> : e.kind === 'account' && e.value.includes('@') ? <IconMail /> : null}
            {e.kind} {shortLabel(e)}
          </span>
        ))}
      </div>
    </div>
  )
}

/** The records of a story in time order: time gutter, source icon, title, provenance and badges. */
function StoryTimeline({ story, selected, onSelect }: { story: Story; selected: string | null; onSelect: (nodeId: string) => void }) {
  return (
    <div className="story">
      {story.records.map((r) => {
        const time = recordTime(r)
        const collected = r.recordKind === 'observation'
        const Icon = r.source === 'mails' ? IconMail : collected ? IconLayers : IconHost
        const via = r.via[0]
        return (
          <div key={r.nodeId} className={'step' + (selected === r.nodeId ? ' active' : '')} onClick={() => onSelect(r.nodeId)}>
            <span className="t">
              {time != null ? fmtTs(time) : 'no time'}
              <br />
              {r.nodeId === story.anchor ? <span style={{ color: 'var(--accent)' }}>anchor</span> : <span>{recordKindText(r)}</span>}
            </span>
            <span
              className={'n ' + (r.source === 'mails' ? 'mail' : 'host') + (collected ? ' collected' : '')}
              title={r.source === 'mails' ? 'mailbox' : collected ? 'collected artifact' : 'Windows host'}
            >
              <Icon />
            </span>
            <span style={{ minWidth: 0 }}>
              <div className="title">{r.title}</div>
              <div className="sub" style={{ overflowWrap: 'anywhere' }}>
                {basename(r.sourceFile)}
                {via ? ` · via ${via.kind} ${shortLabel(via)}` : ''}
              </div>
              {(r.findings.length > 0 || r.marks.length > 0 || r.seed.length > 0) && (
                <div className="row wrap" style={{ gap: 4, marginTop: 3 }}>
                  {r.findings.map((f) => (
                    <Badge key={f.ruleId} sev={f.severity} title={f.title}>
                      {f.ruleId}
                    </Badge>
                  ))}
                  {r.marks.map((m, i) => (
                    <Badge key={`${m}-${i}`} sev="flag">
                      marked {m}
                    </Badge>
                  ))}
                  {r.seed.includes('lead') && (
                    <Badge sev="accent" title="entered the story on its own: it names an entity that another source file also names">
                      cross-source
                    </Badge>
                  )}
                </div>
              )}
            </span>
          </div>
        )
      })}
    </div>
  )
}

/** Right-hand pane of the Story and Graph tabs: the selected record, why it belongs, and where to go from it. */
function RecordPane({ story, record, onOpen, onClose }: { story: Story; record: StoryRecord; onOpen: (r: StoryRecord) => void; onClose: () => void }) {
  const index = story.records.findIndex((r) => r.nodeId === record.nodeId)
  const time = recordTime(record)
  const titleOf = (nodeId: string) => story.records.find((r) => r.nodeId === nodeId)?.title ?? nodeId
  const reasons = record.seed.map((s) => (s === 'mark' ? (record.marks.includes('pivot') ? 'marked pivot' : 'marked relevant') : SEED_TEXT[s]))
  return (
    <div className="pane-side">
      <div className="col" style={{ gap: 14 }}>
        <div className="section">
          <h3>
            Record {index + 1} of {story.records.length}
          </h3>
          <div style={{ fontWeight: 500, color: 'var(--fg-1)', overflowWrap: 'anywhere' }}>{record.title}</div>
          <div className="kv">
            <div className="k">time</div>
            <div className="v">{time != null ? fmtTs(time) : 'no time'}</div>
            <div className="k">kind</div>
            <div className="v">{recordKindText(record)}</div>
            <div className="k">source file</div>
            <div className="v">{record.sourceFile ?? 'source file unavailable'}</div>
            <div className="k">evidence id</div>
            <div className="v">{record.evidenceId ?? 'unknown'}</div>
            <div className="k">record id</div>
            <div className="v">{record.id != null ? `${record.source} #${record.id}` : 'not stored'}</div>
          </div>
        </div>
        <div className="section">
          <h3>Why it is in the story</h3>
          {!reasons.length && !record.via.length && <div className="muted small">reached from another record of the story</div>}
          {reasons.map((text) => (
            <div key={text} className="row" style={{ gap: 6 }}>
              <Dot sev="critical" />
              <span className="small">{text}</span>
            </div>
          ))}
          {record.via.map((v) => (
            <div key={v.entityId} className="row" style={{ gap: 6, alignItems: 'flex-start' }}>
              <Dot sev="high" />
              <span className="small" style={{ overflowWrap: 'anywhere' }}>
                {v.relation} {v.kind} {v.label}, from {titleOf(v.fromNodeId)}
              </span>
            </div>
          ))}
          {record.findings.map((f) => (
            <div key={f.ruleId} className="row" style={{ gap: 6 }}>
              <Dot sev={f.severity} />
              <span className="small">{f.title}</span>
              <span className="mono small muted">{f.ruleId}</span>
            </div>
          ))}
          {record.marks.map((m, i) => (
            <div key={`${m}-${i}`} className="row" style={{ gap: 6 }}>
              <Dot sev="flag" />
              <span className="small">marked {m}</span>
            </div>
          ))}
        </div>
        <div className="row wrap" style={{ gap: 6 }}>
          <button className="btn sm" disabled={record.id == null} onClick={() => onOpen(record)}>
            open the row
          </button>
          <AddToTimeline
            ts={time}
            text={`${story.title}: ${record.title}`}
            link={record.id != null ? { source: record.source, id: record.id } : undefined}
            severity={worstSeverity(record.findings) ?? 'info'}
          />
          <button className="btn sm ghost" onClick={onClose}>
            close
          </button>
        </div>
        <div className="hint">j / k move between records</div>
      </div>
    </div>
  )
}

/** Right column, Explore mode: the selected entity, its neighbours, the related records and the edges to review. */
function Explorer({
  result,
  nodes: byId,
  selected,
  onSelect,
  aliases,
  reviews,
  onSave,
  onOpen,
}: {
  result: RelationshipResult | null
  nodes: Map<string, RelationshipNode>
  selected: string
  onSelect: (id: string) => void
  aliases: RelationshipAliases
  reviews: Record<string, RelationshipReview>
  onSave: (r: RelationshipReview) => Promise<void>
  onOpen: (ref: RelationshipRef) => void
}) {
  const edges = useMemo(() => result?.edges.filter((e) => e.source === selected || e.target === selected) ?? [], [result, selected])
  const neighbors = useMemo(() => [...new Set(edges.map((e) => (e.source === selected ? e.target : e.source)))].slice(0, 12), [edges, selected])
  const timeline = useMemo(() => relatedTimeline(result, selected), [result, selected])
  if (!result)
    return (
      <div className="muted" style={{ padding: 24 }}>
        Build relationships to browse the entities.
      </div>
    )
  const node = byId.get(selected)
  return (
    <div className="view-body col" style={{ gap: 10 }}>
      {selected && (
        <div className="card">
          <strong style={{ overflowWrap: 'anywhere' }}>{node?.label}</strong>
          <div className="small muted">
            {node?.kind} {node?.scope && `· ${node.scope}`}
          </div>
          <svg viewBox="0 0 720 340" role="img" aria-label="Connections around the selected entity" style={{ width: '100%', maxHeight: 340 }}>
            {neighbors.map((id, i) => {
              const angle = (2 * Math.PI * i) / Math.max(neighbors.length, 1)
              const x = 360 + Math.cos(angle) * 245,
                y = 170 + Math.sin(angle) * 135
              const n = byId.get(id)
              return (
                <g key={id}>
                  <line x1="360" y1="170" x2={x} y2={y} stroke="var(--muted, #888)" opacity="0.4" />
                  <g
                    role="button"
                    tabIndex={0}
                    aria-label={`Explore ${n?.label}`}
                    onClick={() => onSelect(id)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault()
                        onSelect(id)
                      }
                    }}
                    style={{ cursor: 'pointer' }}
                  >
                    <title>{n?.label}</title>
                    <circle cx={x} cy={y} r="9" fill="var(--accent, #6a9)" />
                    <text x={x} y={y + 24} textAnchor="middle" fill="currentColor" fontSize="11">
                      {(n?.label ?? '').slice(0, 27)}
                      {(n?.label.length ?? 0) > 27 ? '…' : ''}
                    </text>
                  </g>
                </g>
              )
            })}
            <circle cx="360" cy="170" r="14" fill="var(--accent, #6a9)" />
            <text x="360" y="201" textAnchor="middle" fill="currentColor" fontSize="12">
              selected entity
            </text>
          </svg>
          <div className="small muted">Diagram shows up to 12 neighbors; relationships below show up to 100. Search to explore other entities.</div>
        </div>
      )}
      {timeline.length > 0 && (
        <details className="card">
          <summary>Related evidence timeline · {timeline.length} records</summary>
          <p className="small muted">Up to 200 records within two connections of this entity. Event times and collection snapshots are labeled separately; order does not establish causation.</p>
          {timeline.map((ref, i) => (
            <div className="row" key={i} style={{ marginTop: 8 }}>
              <button className="btn xs" disabled={ref.id == null} onClick={() => onOpen(ref)}>
                Open {ref.source} #{ref.id}
              </button>
              <span>
                {ref.recordKind === 'observation' ? 'Collected' : 'Event'} {fmtTs(ref.recordKind === 'observation' ? ref.observedAt : ref.ts)} · {ref.title}
              </span>
            </div>
          ))}
        </details>
      )}
      <LinkList edges={edges} nodes={byId} aliases={aliases} reviews={reviews} onSave={onSave} onExplore={onSelect} onOpen={onOpen} keyPrefix={selected} />
      {!result.nodes.length && <div className="hint">No recognized entities in this scope. Check package coverage on the Evidence page.</div>}
    </div>
  )
}

/** Nodes plus edges a cached graph may hold; past it only the cursor and options are kept. */
const CACHE_BUDGET = 20_000

export function RelationshipsView() {
  const kase = useStore((s) => s.currentCase)
  const setEntity = useStore((s) => s.setEntity)
  const rulesVersion = useStore((s) => s.rulesVersion)
  const [result, setResult] = useState<RelationshipResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [progress, setProgress] = useState('')
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [evidenceId, setEvidenceId] = useState('')
  const [aliasesText, setAliasesText] = useState('{}')
  const [activeAliases, setActiveAliases] = useState<RelationshipAliases>({})
  const [reviews, setReviews] = useState<Record<string, RelationshipReview>>({})
  const [detail, setDetail] = useState<Detail>(null)
  // stories
  const [hoursText, setHoursText] = useState('72')
  const [stories, setStories] = useState<StoryResult | null>(null)
  const [mode, setMode] = useState<Mode>('stories')
  const [storyId, setStoryId] = useState<string | null>(null)
  const [selectedRecord, setSelectedRecord] = useState<string | null>(null)
  const [tab, setTab] = useState<StoryTab>('story')
  // explore
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState('')
  const [selected, setSelected] = useState('')
  const alive = useRef(true)
  const stopped = useRef(false)
  const generation = useRef(0)
  const hours = useMemo(() => {
    const v = Number(hoursText)
    return Number.isFinite(v) && v >= 1 ? Math.min(720, v) : 72
  }, [hoursText])

  useEffect(() => {
    alive.current = true
    const current = ++generation.current
    setBusy(false)
    setResult(null)
    setSelected('')
    setStoryId(null)
    setSelectedRecord(null)
    setError('')
    if (kase?.id)
      getDb()
        .evidence.where('caseId')
        .equals(kase.id)
        .toArray()
        .then(async (rows) => {
          const [saved, aliases, cache] = await Promise.all([loadRelationshipReviews(kase.id!), getDb().kv.get(`relationship-aliases-${kase.id}`), getDb().kv.get(`relationship-cache-${kase.id}`)])
          if (!alive.current || current !== generation.current) return
          setEvidence(rows)
          setReviews(saved)
          setAliasesText(JSON.stringify(aliases?.value ?? {}, null, 2))
          const cached = cache?.value as { version?: number; fingerprint: string; result?: RelationshipResult; aliases: RelationshipAliases; scope: string; tooLarge?: number } | undefined
          if (cached?.version === INTELLIGENCE_VERSION && cached.fingerprint === fingerprint(rows) && cached.result) {
            setResult(cached.result)
            setActiveAliases(cached.aliases)
            setEvidenceId(cached.scope)
            setSelected(relationshipLeads(cached.result)[0]?.node.id ?? cached.result.nodes.find((n) => n.kind !== 'record')?.id ?? '')
          } else if (cached?.tooLarge) {
            setError('The previous graph was too large to cache. Rebuild to scan the evidence again; your saved reviews are retained.')
          }
        })
    return () => {
      alive.current = false
    }
  }, [kase?.id])

  // stories: from the graph, the findings and the analyst's marks; again when the rules ran or the window changed
  useEffect(() => {
    const caseId = kase?.id
    if (!caseId || !result) {
      setStories(null)
      return
    }
    let cancelled = false
    Promise.all([getDb().findings.where('caseId').equals(caseId).toArray(), getDb().rowMarks.where('caseId').equals(caseId).toArray()])
      .then(([findings, marks]) => {
        if (cancelled) return
        const built = buildStories(reviewedRelationships(result, reviews), findings, marks, { windowMs: hours * 3_600_000 })
        setStories(built)
        setStoryId((cur) => (cur && built.stories.some((s) => s.id === cur) ? cur : (built.stories[0]?.id ?? null)))
      })
      .catch((e) => {
        if (!cancelled) setError((e as Error).message)
      })
    return () => {
      cancelled = true
    }
  }, [kase?.id, result, hours, rulesVersion, reviews])

  const byId = useMemo(() => new Map(result?.nodes.map((n) => [n.id, n]) ?? []), [result])
  const degrees = useMemo(() => {
    const counts = new Map<string, number>()
    for (const edge of result?.edges ?? []) for (const id of [edge.source, edge.target]) counts.set(id, (counts.get(id) ?? 0) + 1)
    return counts
  }, [result])
  const exploreNodes = useMemo(
    () =>
      (result?.nodes ?? [])
        .filter((n) => (!kind || n.kind === kind) && `${n.label} ${n.scope}`.toLowerCase().includes(query.toLowerCase()))
        .sort((a, b) => (degrees.get(b.id) ?? 0) - (degrees.get(a.id) ?? 0)),
    [result, kind, query, degrees],
  )
  const story = useMemo(() => stories?.stories.find((s) => s.id === storyId) ?? null, [stories, storyId])
  const record = useMemo(() => story?.records.find((r) => r.nodeId === selectedRecord) ?? null, [story, selectedRecord])
  const storyGraph = useMemo(() => (story && tab === 'graph' ? buildStoryGraph(story) : null), [story, tab])
  const selectedNode = useMemo(() => (storyGraph && record ? (storyGraph.nodes.find((n) => n.recordIds?.includes(record.nodeId))?.id ?? null) : null), [storyGraph, record])
  const storyJson = useMemo(() => (story && tab === 'json' ? JSON.stringify({ ...story, records: story.records.map(({ ref: _ref, ...r }) => r) }, null, 2) : ''), [story, tab])
  const storySources = useMemo(() => new Set(stories?.stories.flatMap((s) => s.sources) ?? []).size, [stories])
  const onRecords = useCallback((ids: string[]) => setSelectedRecord(ids[0] ?? null), [])

  // keyboard: j / k move between the records of the open story
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null
      if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable)) return
      if (mode !== 'stories' || !story || (e.key !== 'j' && e.key !== 'k')) return
      const i = selectedRecord ? story.records.findIndex((r) => r.nodeId === selectedRecord) : -1
      const next = e.key === 'j' ? Math.min(story.records.length - 1, i + 1) : Math.max(0, i - 1)
      setSelectedRecord(story.records[next]?.nodeId ?? null)
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [mode, story, selectedRecord])

  if (!kase) return null
  const build = async (append = false) => {
    setBusy(true)
    setError('')
    setDetail(null)
    stopped.current = false
    const current = generation.current
    setProgress('Scanning evidence…')
    try {
      const aliases = append ? activeAliases : (JSON.parse(aliasesText) as RelationshipAliases)
      if (!aliases || Array.isArray(aliases) || typeof aliases !== 'object') throw new Error('Aliases must be a JSON object containing hosts and/or accounts maps')
      const next = await scanRelationships(
        append ? result : null,
        (previous) => buildRelationships(kase, evidenceId ? Number(evidenceId) : undefined, previous?.cursor ?? undefined, aliases, previous?.processContext, previous?.processContextTruncated),
        () => stopped.current || !alive.current || generation.current !== current,
        (partial) => {
          if (alive.current && generation.current === current) setProgress(`Scanned ${fmtNum(partial.stats.events + partial.stats.mails)} records…`)
        },
      )
      if (!next || !alive.current || generation.current !== current) return
      // The graph grows with every page and the merge caps only stop it at 100,000 nodes, so
      // persisting the whole thing rewrites an ever larger row on each click and can exceed what a
      // single structured clone will carry. Cache only what a reload needs to resume.
      const cacheable = next.nodes.length + next.edges.length <= CACHE_BUDGET
      await getDb().kv.bulkPut([
        { key: `relationship-aliases-${kase.id}`, value: aliases },
        {
          key: `relationship-cache-${kase.id}`,
          value: cacheable
            ? { version: INTELLIGENCE_VERSION, fingerprint: fingerprint(evidence), result: next, aliases, scope: evidenceId }
            : { version: INTELLIGENCE_VERSION, fingerprint: fingerprint(evidence), aliases, scope: evidenceId, cursor: next.cursor, tooLarge: next.nodes.length + next.edges.length },
        },
      ])
      if (!alive.current || generation.current !== current) return
      setResult(next)
      setActiveAliases(aliases)
      if (!append) {
        // a fresh graph: the first story and the first cross-source entity are selected once the stories are read
        setStoryId(null)
        setSelectedRecord(null)
        setSelected(relationshipLeads(next)[0]?.node.id ?? next.nodes.find((n) => n.kind !== 'record')?.id ?? '')
      }
    } catch (e) {
      if (alive.current && generation.current === current) setError((e as Error).message)
    } finally {
      if (alive.current && generation.current === current) {
        setBusy(false)
        setProgress('')
      }
    }
  }
  const openRow = async (source: 'events' | 'mails', id: number | null) => {
    if (id == null) return
    try {
      const ds = getSource(kase)
      if (source === 'events') {
        const row = await ds.getEvent(id)
        if (!row) throw new Error(`Event #${id} is no longer available. Rebuild relationships.`)
        if (row && alive.current) setDetail({ source: 'events', row })
      } else {
        const mail = await ds.getMail(id)
        if (!mail) throw new Error(`Mail #${id} is no longer available. Rebuild relationships.`)
        if (mail && alive.current) setDetail({ source: 'mails', row: mail.row })
      }
    } catch (e) {
      if (alive.current) setError((e as Error).message)
    }
  }
  const open = (ref: RelationshipRef) => openRow(ref.source, ref.id)
  const saveReview = async (review: RelationshipReview) => {
    try {
      await saveRelationshipReview(kase.id!, review)
      setReviews((old) => ({ ...old, [review.key]: review }))
    } catch (e) {
      setError(`Could not save review: ${(e as Error).message}`)
      throw e
    }
  }
  const explore = (nodeId: string) => {
    setMode('explore')
    setSelected(nodeId)
    setQuery('')
    setKind('')
  }
  const selectStory = (id: string) => {
    setStoryId(id)
    setSelectedRecord(null)
  }
  const onPill = (e: StoryEntity) => {
    const ref = entityRef(e.kind, e.value)
    if (ref) setEntity(ref)
    else explore(e.id)
  }
  const ask = (_s: Story) => setTab('investigate')
  const recordPane = story && record && <RecordPane story={story} record={record} onOpen={(r) => openRow(r.source, r.id)} onClose={() => setSelectedRecord(null)} />
  return (
    <div className="view">
      <div className="view-header">
        <div className="desc">
          <h1>Relationships</h1>
          <span className="sub">{stories ? `${fmtNum(stories.stories.length)} stories · ${fmtNum(stories.stats.records)} records in ${fmtNum(storySources)} sources` : 'not built yet'}</span>
        </div>
        <span className="spacer" />
        <select
          className="select"
          aria-label="Evidence scope"
          value={evidenceId}
          onChange={(e) => {
            setEvidenceId(e.target.value)
            setResult(null)
            setSelected('')
            setStoryId(null)
            setSelectedRecord(null)
          }}
          disabled={busy}
        >
          <option value="">All evidence</option>
          {evidence.map((e) => (
            <option key={e.id} value={e.id}>
              {e.name}
            </option>
          ))}
        </select>
        <label className="row" style={{ gap: 6 }} title="two timed records joined through a medium entity (a domain, an address, an account) must be this close">
          <span className="muted small">window</span>
          <input className="input" type="number" aria-label="Story window (hours)" style={{ width: 64 }} value={hoursText} min={1} max={720} onChange={(e) => setHoursText(e.target.value)} />
          <span className="muted small">h</span>
        </label>
        <button className="btn sm primary" disabled={busy} onClick={() => build()}>
          {busy ? <Spinner /> : <IconPlay />} {result ? 'Rebuild relationships' : 'Build relationships'}
        </button>
        {busy && (
          <button
            className="btn sm"
            onClick={() => {
              stopped.current = true
            }}
          >
            Stop after this page
          </button>
        )}
        {result?.cursor && (
          <button className="btn sm" disabled={busy} onClick={() => build(true)}>
            Continue scanning
          </button>
        )}
      </div>
      <div className="col" style={{ gap: 6, padding: '8px 16px', borderBottom: '1px solid var(--line)', background: 'var(--surface)' }}>
        <details>
          <summary className="small muted" style={{ cursor: 'pointer' }}>
            Explicit host and account aliases
          </summary>
          <p className="small muted">Map known names to a canonical name, then rebuild. Accounts use qualified names such as DOMAIN\user or user@example.com. Aliases are saved with each review.</p>
          <textarea
            className="input mono"
            aria-label="Relationship aliases"
            rows={5}
            disabled={busy}
            value={aliasesText}
            onChange={(e) => setAliasesText(e.target.value)}
            placeholder={'{"hosts":{"pc01":"pc01.example.com"},"accounts":{}}'}
          />
        </details>
        {error && (
          <div role="alert" className="hint" style={{ color: 'var(--danger)' }}>
            {error}
          </div>
        )}
        {busy && (
          <div className="hint" role="status">
            {progress} The scan continues across pages; larger cases take longer.
          </div>
        )}
        {result?.cursor && (
          <div className="hint" role="status">
            This scan is incomplete. Continue scanning to include later sources, or narrow the evidence scope if a graph limit was reached.
          </div>
        )}
        {result?.stats.truncated && (
          <div role="status" className="hint">
            Partial graph: an input or graph limit was reached. Select an evidence item to narrow the build. Absence of a link here is not evidence of absence.
          </div>
        )}
        {stories?.stats.truncated && (
          <div role="status" className="hint">
            Some stories were cut at a record, entity, link or story limit. Narrow the evidence scope or the window to read them whole.
          </div>
        )}
      </div>
      <div className="split" style={{ gridTemplateColumns: '320px 1fr' }}>
        <div className="left">
          <div className="row" style={{ padding: '10px 14px', gap: 10, borderBottom: '1px solid var(--line)' }}>
            <div className="segmented">
              <button className={mode === 'stories' ? 'active' : ''} onClick={() => setMode('stories')}>
                Stories
              </button>
              <button className={mode === 'explore' ? 'active' : ''} onClick={() => setMode('explore')}>
                Explore
              </button>
            </div>
            {result && (
              <span className="small muted">
                {mode === 'stories' ? `${fmtNum(stories?.stories.length ?? 0)} stories` : `${fmtNum(result.nodes.length)} nodes · ${fmtNum(result.edges.length)} links`}
              </span>
            )}
          </div>
          {mode === 'stories' ? (
            <StoryList result={result} stories={stories} active={storyId} onSelect={selectStory} />
          ) : (
            <ExploreList result={result} nodes={exploreNodes} degrees={degrees} query={query} kind={kind} selected={selected} onQuery={setQuery} onKind={setKind} onSelect={setSelected} />
          )}
        </div>
        <div className="right">
          {mode === 'explore' && <Explorer result={result} nodes={byId} selected={selected} onSelect={setSelected} aliases={activeAliases} reviews={reviews} onSave={saveReview} onOpen={open} />}
          {mode === 'stories' && !story && (
            <div className="muted" style={{ padding: 24 }}>
              {stories?.stories.length ? 'select a story' : ''}
            </div>
          )}
          {mode === 'stories' && story && (
            <>
              <StoryHeader story={story} onEntity={onPill} onAsk={() => ask(story)} />
              <Tabs
                tabs={[
                  { id: 'story' as const, label: 'Story' },
                  { id: 'graph' as const, label: 'Graph' },
                  { id: 'links' as const, label: 'Links' },
                  { id: 'investigate' as const, label: 'Investigate' },
                  { id: 'entities' as const, label: 'Entities' },
                  { id: 'json' as const, label: 'JSON' },
                ]}
                active={tab}
                onChange={setTab}
              />
              {tab === 'story' && (
                <div className="pane" style={{ flex: 1, height: 'auto', borderTop: 0, gridTemplateColumns: record ? '1fr 340px' : '1fr' }}>
                  <div className="pane-main" style={{ overflow: 'auto' }}>
                    <StoryTimeline story={story} selected={selectedRecord} onSelect={setSelectedRecord} />
                  </div>
                  {recordPane}
                </div>
              )}
              {tab === 'graph' && (
                <div className="pane" style={{ flex: 1, height: 'auto', borderTop: 0, gridTemplateColumns: record ? '1fr 340px' : '1fr' }}>
                  <div className="pane-main" style={{ overflow: 'hidden' }}>
                    <div className="row" style={{ padding: '6px 12px', gap: 10, borderBottom: '1px solid var(--line)' }}>
                      <span className="small muted">
                        time runs left to right, one lane per source; the entities the records name sit above and below, and the ones tying two sources together carry the accent edges
                      </span>
                    </div>
                    {storyGraph && (
                      <ChainGraph
                        mode="chain"
                        chain={null}
                        chains={[]}
                        graph={storyGraph}
                        selectedStep={null}
                        selectedNode={selectedNode}
                        onRecords={onRecords}
                        onEntityNode={explore}
                        onStep={noop}
                        onEntity={setEntity}
                        onChain={noop}
                      />
                    )}
                  </div>
                  {recordPane}
                </div>
              )}
              {tab === 'investigate' && (
                <RelationshipInvestigation key={`${kase.id}:${story.id}`} kase={kase} story={story} partial={!!result?.cursor || !!result?.stats.truncated} reviews={reviews} onOpen={openRow} />
              )}
              {tab === 'links' && (
                <div className="view-body col" style={{ gap: 10 }}>
                  <p className="small muted" style={{ margin: 0 }}>
                    Every link between two members of the story, the ones through a bridge entity first. Links describe what the evidence reports; a shared entity alone does not establish an attack.
                  </p>
                  <LinkList edges={story.edges} nodes={byId} aliases={activeAliases} reviews={reviews} onSave={saveReview} onExplore={explore} onOpen={open} keyPrefix={story.id} />
                </div>
              )}
              {tab === 'entities' && (
                <div className="view-body">
                  <table className="table compact">
                    <thead>
                      <tr>
                        <th>kind</th>
                        <th>entity</th>
                        <th>records</th>
                        <th>sources</th>
                        <th>role</th>
                      </tr>
                    </thead>
                    <tbody>
                      {story.entities.map((e) => (
                        <tr key={e.id} style={{ cursor: 'pointer' }} onClick={() => explore(e.id)} title="browse this entity in Explore">
                          <td>{e.kind}</td>
                          <td className="sans" style={{ overflowWrap: 'anywhere' }}>
                            {e.label}
                          </td>
                          <td>{e.records}</td>
                          <td>{e.sources.length}</td>
                          <td>{e.bridge ? 'bridge' : e.hub ? 'hub' : 'context'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {tab === 'json' && (
                <div className="view-body">
                  <pre className="codeblock">{storyJson}</pre>
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
