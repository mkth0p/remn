import { useEffect, useMemo, useRef, useState } from 'react'
import { EventDetail, MailDetail } from '../components/Detail'
import { Badge } from '../components/ui'
import { buildRelationships, mergeRelationships, type RelationshipAliases, type RelationshipEdge, type RelationshipNode, type RelationshipRef, type RelationshipResult } from '../data/relationships'
import { loadRelationshipReviews, relationshipKey, saveRelationshipReview, type RelationshipReview } from '../data/relationshipReviews'
import { getSource } from '../data/source'
import { getDb, type EventRow, type Evidence, type MailRow } from '../db/schema'
import { useStore } from '../state/store'
import { fmtNum, fmtTs } from '../util/format'

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
    key: relationshipKey(edge, nodes, aliases),
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

/** Nodes plus edges a cached graph may hold; past it only the cursor and options are kept. */
const CACHE_BUDGET = 20_000

export function RelationshipsView() {
  const kase = useStore((s) => s.currentCase)
  const [result, setResult] = useState<RelationshipResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState('')
  const [kind, setKind] = useState('')
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [evidenceId, setEvidenceId] = useState('')
  const [aliasesText, setAliasesText] = useState('{}')
  const [activeAliases, setActiveAliases] = useState<RelationshipAliases>({})
  const [reviews, setReviews] = useState<Record<string, RelationshipReview>>({})
  const [detail, setDetail] = useState<{ source: 'events'; row: EventRow } | { source: 'mails'; row: MailRow } | null>(null)
  const alive = useRef(true)
  useEffect(() => {
    alive.current = true
    if (kase?.id)
      getDb()
        .evidence.where('caseId')
        .equals(kase.id)
        .toArray()
        .then(async (rows) => {
          const [saved, aliases, cache] = await Promise.all([loadRelationshipReviews(kase.id!), getDb().kv.get(`relationship-aliases-${kase.id}`), getDb().kv.get(`relationship-cache-${kase.id}`)])
          if (!alive.current) return
          setEvidence(rows)
          setReviews(saved)
          setAliasesText(JSON.stringify(aliases?.value ?? {}, null, 2))
          const cached = cache?.value as { fingerprint: string; result: RelationshipResult; aliases: RelationshipAliases; scope: string } | undefined
          if (cached?.fingerprint === fingerprint(rows)) {
            setResult(cached.result)
            setActiveAliases(cached.aliases)
            setEvidenceId(cached.scope)
            setSelected(cached.result.nodes[0]?.id ?? '')
          }
        })
    return () => {
      alive.current = false
    }
  }, [kase?.id])
  const byId = useMemo(() => new Map(result?.nodes.map((n) => [n.id, n]) ?? []), [result])
  const degrees = useMemo(() => {
    const counts = new Map<string, number>()
    for (const edge of result?.edges ?? []) for (const id of [edge.source, edge.target]) counts.set(id, (counts.get(id) ?? 0) + 1)
    return counts
  }, [result])
  const nodes = useMemo(
    () =>
      (result?.nodes ?? [])
        .filter((n) => (!kind || n.kind === kind) && `${n.label} ${n.scope}`.toLowerCase().includes(query.toLowerCase()))
        .sort((a, b) => (degrees.get(b.id) ?? 0) - (degrees.get(a.id) ?? 0)),
    [result, kind, query, degrees],
  )
  const edges = useMemo(() => result?.edges.filter((e) => e.source === selected || e.target === selected) ?? [], [result, selected])
  const neighbors = useMemo(() => [...new Set(edges.map((e) => (e.source === selected ? e.target : e.source)))].slice(0, 12), [edges, selected])
  const timeline = useMemo(() => relatedTimeline(result, selected), [result, selected])
  if (!kase) return null
  const build = async (append = false) => {
    setBusy(true)
    setError('')
    setDetail(null)
    try {
      const aliases = append ? activeAliases : (JSON.parse(aliasesText) as RelationshipAliases)
      if (!aliases || Array.isArray(aliases) || typeof aliases !== 'object') throw new Error('Aliases must be a JSON object containing hosts and/or accounts maps')
      const page = await buildRelationships(kase, evidenceId ? Number(evidenceId) : undefined, append ? (result?.cursor ?? undefined) : undefined, aliases, append ? result?.processContext : undefined)
      const next = mergeRelationships(append ? result : null, page)
      // The graph grows with every page and the merge caps only stop it at 100,000 nodes, so
      // persisting the whole thing rewrites an ever larger row on each click and can exceed what a
      // single structured clone will carry. Cache only what a reload needs to resume.
      const cacheable = next.nodes.length + next.edges.length <= CACHE_BUDGET
      await getDb().kv.bulkPut([
        { key: `relationship-aliases-${kase.id}`, value: aliases },
        {
          key: `relationship-cache-${kase.id}`,
          value: cacheable
            ? { fingerprint: fingerprint(evidence), result: next, aliases, scope: evidenceId }
            : { fingerprint: fingerprint(evidence), aliases, scope: evidenceId, cursor: next.cursor, tooLarge: next.nodes.length + next.edges.length },
        },
      ])
      if (!alive.current) return
      setResult(next)
      setActiveAliases(aliases)
      if (!append) setSelected(next.nodes.find((n) => n.kind === 'host')?.id ?? next.nodes[0]?.id ?? '')
    } catch (e) {
      if (alive.current) setError((e as Error).message)
    } finally {
      if (alive.current) setBusy(false)
    }
  }
  const open = async (ref: RelationshipRef) => {
    if (ref.id == null) return
    try {
      const ds = getSource(kase)
      if (ref.source === 'events') {
        const row = await ds.getEvent(ref.id)
        if (row && alive.current) setDetail({ source: 'events', row })
      } else {
        const mail = await ds.getMail(ref.id)
        if (mail && alive.current) setDetail({ source: 'mails', row: mail.row })
      }
    } catch (e) {
      if (alive.current) setError((e as Error).message)
    }
  }
  return (
    <div className="view">
      <div className="view-header">
        <h1>Relationships</h1>
        <span className="sub">Explore hosts, accounts, files and processes across the evidence</span>
        <select
          className="select"
          aria-label="Evidence scope"
          value={evidenceId}
          onChange={(e) => {
            setEvidenceId(e.target.value)
            setResult(null)
            setSelected('')
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
        <button className="btn primary" disabled={busy} onClick={() => build()}>
          {busy ? 'Building…' : result ? 'Rebuild relationships' : 'Build relationships'}
        </button>
        {result?.cursor && (
          <button className="btn" disabled={busy} onClick={() => build(true)}>
            Load more records
          </button>
        )}
      </div>
      <div className="view-body col" style={{ gap: 12 }}>
        <div className="hint">
          Choose any entity to follow its connections and inspect the source records. Links describe what the evidence reports; shared entities alone do not establish an attack. Rebuild after
          importing or removing evidence.
        </div>
        <details className="card">
          <summary>Explicit host and account aliases</summary>
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
        {result && (
          <>
            <div className="row">
              <Badge sev="accent">{fmtNum(result.nodes.length)} entities and records</Badge>
              <span>
                {fmtNum(result.edges.length)} relationships · {fmtNum(result.stats.events)} event/observation rows · {fmtNum(result.stats.mails)} mails
              </span>
            </div>
            {result.cursor && (
              <div className="hint" role="status">
                More evidence remains. Use Load more records to extend this graph; the saved snapshot resumes here next time.
              </div>
            )}
            {result.stats.truncated && (
              <div role="status" className="hint">
                Partial graph: an input or graph limit was reached. Select an evidence item to narrow the build. Absence of a link here is not evidence of absence.
              </div>
            )}
            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(220px, 28%) minmax(0, 1fr)', gap: 16 }}>
              <div className="card col" style={{ gap: 8 }}>
                <input className="input" placeholder="Search entities and records" aria-label="Search entities" value={query} onChange={(e) => setQuery(e.target.value)} />
                <select className="select" aria-label="Entity type" value={kind} onChange={(e) => setKind(e.target.value)}>
                  <option value="">All types</option>
                  {[...new Set(result.nodes.map((n) => n.kind))].sort().map((k) => (
                    <option key={k}>{k}</option>
                  ))}
                </select>
                <div className="small muted">{fmtNum(nodes.length)} matches · showing up to 200</div>
                <div className="col" style={{ maxHeight: '65vh', overflow: 'auto', gap: 5 }}>
                  {nodes.slice(0, 200).map((n) => (
                    <button
                      key={n.id}
                      className={`btn ${selected === n.id ? 'primary' : 'ghost'}`}
                      style={{ textAlign: 'left', display: 'block', whiteSpace: 'normal', overflowWrap: 'anywhere' }}
                      onClick={() => setSelected(n.id)}
                    >
                      <span className="small muted">
                        {n.kind} · {degrees.get(n.id) ?? 0} links
                      </span>
                      <br />
                      {n.label}
                      {n.scope && <div className="small muted">{n.scope}</div>}
                    </button>
                  ))}
                </div>
              </div>
              <div className="col" style={{ minWidth: 0, gap: 10 }}>
                {selected && (
                  <div className="card">
                    <strong style={{ overflowWrap: 'anywhere' }}>{byId.get(selected)?.label}</strong>
                    <div className="small muted">
                      {byId.get(selected)?.kind} {byId.get(selected)?.scope && `· ${byId.get(selected)?.scope}`}
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
                              onClick={() => setSelected(id)}
                              onKeyDown={(e) => {
                                if (e.key === 'Enter' || e.key === ' ') {
                                  e.preventDefault()
                                  setSelected(id)
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
                    <p className="small muted">
                      Up to 200 records within two connections of this entity. Event times and collection snapshots are labeled separately; order does not establish causation.
                    </p>
                    {timeline.map((ref, i) => (
                      <div className="row" key={i} style={{ marginTop: 8 }}>
                        <button className="btn xs" onClick={() => open(ref)}>
                          Open {ref.source} #{ref.id}
                        </button>
                        <span>
                          {ref.recordKind === 'observation' ? 'Collected' : 'Event'} {fmtTs(ref.recordKind === 'observation' ? ref.observedAt : ref.ts)} · {ref.title}
                        </span>
                      </div>
                    ))}
                  </details>
                )}
                {edges.slice(0, 100).map((edge, i) => (
                  <details key={`${selected}-${i}`} className="card">
                    <summary style={{ cursor: 'pointer', overflowWrap: 'anywhere' }}>
                      {byId.get(edge.source)?.label} → <strong>{edge.relation}</strong> → {byId.get(edge.target)?.label}{' '}
                      <Badge sev={edge.confidence === 'high' ? 'ok' : 'info'}>{edge.confidence}</Badge> · {edge.count} observations
                    </summary>
                    <p>{edge.reason}</p>
                    <RelationshipEditor
                      key={relationshipKey(edge, byId, activeAliases)}
                      edge={edge}
                      nodes={byId}
                      aliases={activeAliases}
                      review={reviews[relationshipKey(edge, byId, activeAliases)]}
                      onSave={async (review) => {
                        try {
                          await saveRelationshipReview(kase.id!, review)
                          setReviews((old) => ({ ...old, [review.key]: review }))
                        } catch (e) {
                          setError(`Could not save review: ${(e as Error).message}`)
                          throw e
                        }
                      }}
                    />
                    <div className="row">
                      <button className="btn xs" onClick={() => setSelected(edge.source)}>
                        Explore source
                      </button>
                      <button className="btn xs" onClick={() => setSelected(edge.target)}>
                        Explore target
                      </button>
                    </div>
                    {edge.refs.map((ref, j) => (
                      <div key={j} style={{ marginTop: 12, overflowWrap: 'anywhere' }}>
                        <button className="btn sm" disabled={ref.id == null} onClick={() => open(ref)}>
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
                {!result.nodes.length && <div className="hint">No recognized entities in this scope. Check package coverage on the Evidence page.</div>}
              </div>
            </div>
          </>
        )}
      </div>
      {detail?.source === 'events' && <EventDetail row={detail.row} onClose={() => setDetail(null)} />}
      {detail?.source === 'mails' && <MailDetail row={detail.row} onClose={() => setDetail(null)} />}
    </div>
  )
}
