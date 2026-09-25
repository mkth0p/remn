import { useEffect, useMemo, useState } from 'react'
import type { RelationshipAliases, RelationshipEdge, RelationshipNode, RelationshipRef, RelationshipResult } from '../data/relationships'
import { relationshipKey, type RelationshipReview } from '../data/relationshipReviews'
import { relationshipLeads } from '../data/relationshipLeads'
import { fmtNum, fmtTs } from '../util/format'
import type { RelationshipGraph } from './useRelationshipGraph'
import { IconPlay } from './Icons'
import { Badge, Spinner } from './ui'

/**
 * Explore: the relationship graph of the evidence (backend/services/analysis/relationships.py),
 * browsed entity by entity, and the review of its links. Every host, account, file, process,
 * digest, address and domain the records name explicitly is a node; a link is two of them named
 * by one record, with the records as its support. A story step shows the links of its own records
 * here too: the evidence for what its record names.
 */

/** The build controls: evidence scope, aliases, build, continue and stop, with what the scan could not cover. */
export function ExploreControls({ g }: { g: RelationshipGraph }) {
  return (
    <div className="col" style={{ gap: 6, padding: '8px 14px', borderBottom: '1px solid var(--line)' }}>
      <div className="row wrap" style={{ gap: 6 }}>
        <select className="select" aria-label="Evidence scope" value={g.evidenceId} onChange={(e) => g.setEvidenceId(e.target.value)} disabled={g.busy} style={{ maxWidth: 180 }}>
          <option value="">All evidence</option>
          {g.evidence.map((e) => (
            <option key={e.id} value={e.id}>
              {e.name}
            </option>
          ))}
        </select>
        <button className="btn sm primary" disabled={g.busy} onClick={() => g.build()}>
          {g.busy ? <Spinner /> : <IconPlay />} {g.result ? 'Rebuild relationships' : 'Build relationships'}
        </button>
        {g.busy && (
          <button className="btn sm" onClick={g.stop}>
            Stop after this page
          </button>
        )}
        {g.result?.cursor && (
          <button className="btn sm" disabled={g.busy} onClick={() => g.build(true)}>
            Continue scanning
          </button>
        )}
      </div>
      <details>
        <summary className="small muted" style={{ cursor: 'pointer' }}>
          Explicit host and account aliases
        </summary>
        <p className="small muted">Map known names to a canonical name, then rebuild. Accounts use qualified names such as DOMAIN\user or user@example.com. Aliases are saved with each review.</p>
        <textarea
          className="input mono"
          aria-label="Relationship aliases"
          rows={4}
          disabled={g.busy}
          value={g.aliasesText}
          onChange={(e) => g.setAliasesText(e.target.value)}
          placeholder={'{"hosts":{"pc01":"pc01.example.com"},"accounts":{}}'}
        />
      </details>
      {g.error && (
        <div role="alert" className="hint" style={{ color: 'var(--danger)' }}>
          {g.error}
        </div>
      )}
      {g.busy && (
        <div className="hint" role="status">
          {g.progress} The scan continues across pages; larger cases take longer.
        </div>
      )}
      {g.result?.cursor && (
        <div className="hint" role="status">
          This scan is incomplete. Continue scanning to include later sources, or narrow the evidence scope if a graph limit was reached.
        </div>
      )}
      {g.result?.stats.truncated && (
        <div role="status" className="hint">
          Partial graph: an input or graph limit was reached. Select an evidence item to narrow the build. Absence of a link here is not evidence of absence.
        </div>
      )}
    </div>
  )
}

/** Left column: search, kind filter and the entities by degree. */
export function ExploreList({ g, selected, onSelect }: { g: RelationshipGraph; selected: string; onSelect: (id: string) => void }) {
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState('')
  const degrees = useMemo(() => {
    const counts = new Map<string, number>()
    for (const edge of g.result?.edges ?? []) for (const id of [edge.source, edge.target]) counts.set(id, (counts.get(id) ?? 0) + 1)
    return counts
  }, [g.result])
  const nodes = useMemo(
    () =>
      (g.result?.nodes ?? [])
        .filter((n) => n.kind !== 'record' && (!kind || n.kind === kind) && `${n.label} ${n.scope}`.toLowerCase().includes(query.toLowerCase()))
        .sort((a, b) => (degrees.get(b.id) ?? 0) - (degrees.get(a.id) ?? 0)),
    [g.result, kind, query, degrees],
  )
  // a fresh graph selects the first entity seen in two sources, else the first entity
  useEffect(() => {
    if (g.result && !selected) onSelect(relationshipLeads(g.result)[0]?.node.id ?? g.result.nodes.find((n) => n.kind !== 'record')?.id ?? '')
  }, [g.result, selected, onSelect])
  return (
    <>
      <ExploreControls g={g} />
      {!g.result ? (
        <div className="hint" style={{ padding: 14, lineHeight: 1.5 }}>
          Explore lists every host, account, file, process, digest, address and domain the evidence names, with the records that name it and the links between them. Build relationships first.
        </div>
      ) : (
        <>
          <div className="col" style={{ gap: 8, padding: '10px 14px' }}>
            <input className="input" placeholder="Search entities" aria-label="Search entities" value={query} onChange={(e) => setQuery(e.target.value)} />
            <select className="select" aria-label="Entity type" value={kind} onChange={(e) => setKind(e.target.value)}>
              <option value="">All types</option>
              {[...new Set(g.result.nodes.map((n) => n.kind))]
                .filter((k) => k !== 'record')
                .sort()
                .map((k) => (
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
      )}
    </>
  )
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

/** The selected entity: its neighbours, the records around it, and its links with their reviews. */
export function Explorer({ g, selected, onSelect, onOpen }: { g: RelationshipGraph; selected: string; onSelect: (id: string) => void; onOpen: (ref: RelationshipRef) => void }) {
  const result = g.result
  const edges = useMemo(() => result?.edges.filter((e) => e.source === selected || e.target === selected) ?? [], [result, selected])
  const neighbors = useMemo(() => [...new Set(edges.map((e) => (e.source === selected ? e.target : e.source)))].slice(0, 12), [edges, selected])
  const timeline = useMemo(() => relatedTimeline(result, selected), [result, selected])
  if (!result)
    return (
      <div className="muted" style={{ padding: 24 }}>
        Build relationships to browse the entities.
      </div>
    )
  const node = g.nodes.get(selected)
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
              const n = g.nodes.get(id)
              return (
                <g key={id}>
                  <line x1="360" y1="170" x2={x} y2={y} stroke="var(--fg-3)" opacity="0.4" />
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
                    <circle cx={x} cy={y} r="9" fill="var(--accent)" />
                    <text x={x} y={y + 24} textAnchor="middle" fill="currentColor" fontSize="11">
                      {(n?.label ?? '').slice(0, 27)}
                      {(n?.label.length ?? 0) > 27 ? '…' : ''}
                    </text>
                  </g>
                </g>
              )
            })}
            <circle cx="360" cy="170" r="14" fill="var(--accent)" />
            <text x="360" y="201" textAnchor="middle" fill="currentColor" fontSize="12">
              selected entity
            </text>
          </svg>
          <div className="small muted">The diagram shows up to 12 neighbours; the links below, up to 100. Search to explore other entities.</div>
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
      <LinkList edges={edges} g={g} onExplore={onSelect} onOpen={onOpen} keyPrefix={selected} />
      {!result.nodes.length && <div className="hint">No recognized entities in this scope. Check package coverage on the Evidence page.</div>}
    </div>
  )
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

/** Links, each with its review, its explore buttons and its supporting records. */
export function LinkList({
  edges,
  g,
  onExplore,
  onOpen,
  keyPrefix,
  limit = 100,
}: {
  edges: RelationshipEdge[]
  g: RelationshipGraph
  onExplore: (nodeId: string) => void
  onOpen: (ref: RelationshipRef) => void
  keyPrefix: string
  limit?: number
}) {
  return (
    <>
      {/* keyed by the link, not its place: a rebuild can reorder the links, and a place key would hand an open link and its unsaved form to another one */}
      {edges.slice(0, limit).map((edge) => (
        <LinkItem key={`${keyPrefix}-${JSON.stringify([edge.source, edge.target, edge.relation])}`} edge={edge} g={g} onExplore={onExplore} onOpen={onOpen} />
      ))}
      {edges.length > limit && (
        <span className="small muted">
          Showing {limit} of {fmtNum(edges.length)} links.
        </span>
      )}
    </>
  )
}

/** One link: its summary always, its review form and supporting records once opened. */
function LinkItem({ edge, g, onExplore, onOpen }: { edge: RelationshipEdge; g: RelationshipGraph; onExplore: (nodeId: string) => void; onOpen: (ref: RelationshipRef) => void }) {
  const [open, setOpen] = useState(false)
  const label = (id: string) => g.nodes.get(id)?.label ?? id
  const key = relationshipKey(edge, g.nodes)
  return (
    <details className="card" onToggle={(e) => setOpen((e.currentTarget as HTMLDetailsElement).open)}>
      <summary style={{ cursor: 'pointer', overflowWrap: 'anywhere' }}>
        {label(edge.source)} → <strong>{edge.relation}</strong> → {label(edge.target)} <Badge sev={edge.confidence === 'high' ? 'ok' : 'info'}>{edge.confidence}</Badge> · {edge.count} supporting
        observations
        {edge.supportTruncated ? ' (capped sample; total may include duplicate imports)' : ''} · {edge.assertion ?? 'observed'}
        {g.reviews[key]?.status && g.reviews[key].status !== 'unreviewed' ? ` · ${g.reviews[key].status}` : ''}
      </summary>
      {open && (
        <>
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
          <RelationshipEditor key={key} edge={edge} nodes={g.nodes} aliases={g.aliases} review={g.reviews[key]} onSave={g.save} />
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
        </>
      )}
    </details>
  )
}
