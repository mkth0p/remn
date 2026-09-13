import type { Finding, RowMark, Severity } from '../db/schema'
import { relationshipLeads } from './relationshipLeads'
import { joinDecision } from './relationshipIntelligence'
import { referenceIdentity, sourceIdentity } from './relationships'
import type { RelationshipEdge, RelationshipNode, RelationshipRef, RelationshipResult } from './relationships'

/**
 * Stories: the relationship graph read the way an analyst reads it.
 *
 * The graph itself is exhaustive and flat: every record is a node, every entity a record names
 * is a node, and an edge says the record reports the entity. That is the right thing to build
 * and the wrong thing to show. A story is a cluster of records that are tied together through
 * entities specific enough to mean something (a digest, a file path on a host, a process
 * instance, a URL, a service, an account, an address, a domain), started from what already
 * matters in the case: the rows findings cite, the rows the analyst marked relevant or pivot,
 * and the entities that appear in more than one source file.
 *
 * Hosts, groups and any entity that touches a great many records are hubs. They give a story its
 * context (which machine, which account) but never glue unrelated activity together: a domain
 * controller's Security log would otherwise turn the whole case into one story.
 *
 * A story carries a severity (the worst finding inside it) and a bounded score (how much
 * corroboration ties it together). The two are kept apart on purpose: one critical detection on
 * one row is critical and lonely; a medium finding whose digest also appears in a mail
 * attachment and a prefetch entry is medium and well corroborated.
 */

export type StoryLane = 'mail' | 'host'

export interface StoryVia {
  /** the entity this record was reached through */
  entityId: string
  kind: string
  label: string
  /** the relation between this record and the entity, as the graph states it */
  relation: string
  /** the record it was reached from */
  fromNodeId: string
}

export interface StoryRecord {
  nodeId: string
  source: 'events' | 'mails'
  id: number | null
  evidenceId: number | null
  /** event time for events and mails; null for a collection observation */
  ts: number | null
  /** collection time for an observation */
  observedAt: number | null
  recordKind: string
  title: string
  sourceFile: string | null
  lane: StoryLane
  /** how far from a seed it was reached (0 = seed) */
  hop: number
  /** why it started a story, when it did */
  seed: ('finding' | 'mark' | 'lead')[]
  via: StoryVia[]
  findings: { ruleId: string; title: string; severity: Severity }[]
  marks: RowMark['verdict'][]
  ref: RelationshipRef | null
}

export interface StoryEntity {
  id: string
  kind: string
  label: string
  value: string
  scope: string
  /** records of this story that name it */
  records: number
  /** distinct source files among those records */
  sources: string[]
  /** how specific the kind is (see WEIGHT) */
  weight: number
  /** named by records from two or more source files: the corroboration the score rewards */
  bridge: boolean
  /** too many records case-wide to be walked; shown as context only */
  hub: boolean
}

export interface StoryScore {
  findings: number
  bridges: number
  sources: number
  marks: number
  total: number
}

export interface Story {
  blockedLinks?: { from: string; ref: RelationshipRef; reason: string }[]
  id: string
  /** the record the story is anchored on: its strongest seed (worst finding, then a pivot mark, then a relevant mark, then a cross-source entity), earliest first */
  anchor: string
  title: string
  summary: string
  severity: Severity
  score: number
  scoreBreakdown: StoryScore
  start: number | null
  end: number | null
  /** time-ordered; records without any time come last */
  records: StoryRecord[]
  /** bridges first, then by how many records name them */
  entities: StoryEntity[]
  /** every graph edge between two members of the story (record to entity, entity to entity) */
  edges: RelationshipEdge[]
  /** distinct source files */
  sources: string[]
  findings: { ruleId: string; title: string; severity: Severity; count: number }[]
  /** the record cap was reached while expanding, or when merging */
  truncated: boolean
}

export interface StoryResult {
  stories: Story[]
  stats: {
    /** records that started a story, by reason */
    seeds: { finding: number; mark: number; lead: number }
    records: number
    entities: number
    hubs: number
    /** the number of stories or the number of records was cut */
    truncated: boolean
  }
}

export interface StoryOptions {
  /** two timed records joined through a medium entity must be this close (ms); strong entities ignore time */
  windowMs?: number
  /** an entity named by more records than this, case-wide, is a hub */
  hubRecords?: number
  maxStoryRecords?: number
  maxStories?: number
  maxSeeds?: number
}

/** How specific an entity kind is. Strong (>= 4) always joins records; medium (2..3) joins them
 * when their times are compatible; weak (<= 1) is context and never walked. */
export const WEIGHT: Record<string, number> = {
  hash: 8,
  file: 6,
  process: 6,
  'logon-session': 6,
  url: 5,
  service: 5,
  task: 5,
  autorun: 5,
  program: 4,
  'deception-exhibit': 4,
  'deception-episode': 3,
  domain: 3,
  ip: 3,
  sid: 3,
  account: 2,
  group: 1,
  host: 1,
  'process-observation': 0,
  record: 0,
}
export const STRONG = 4
export const MEDIUM = 2

const DEFAULTS: Required<StoryOptions> = { windowMs: 72 * 3_600_000, hubRecords: 150, maxStoryRecords: 600, maxStories: 200, maxSeeds: 2_000 }
const SEV: Severity[] = ['info', 'low', 'medium', 'high', 'critical']
const rank = (s: string) => Math.max(0, SEV.indexOf(s as Severity))
const worst = (items: { severity: Severity }[]): Severity | null => (items.length ? SEV[Math.max(...items.map((f) => rank(f.severity)))] : null)
/** the time a record is placed at: event time, else collection time */
export const recordTime = (r: { ts: number | null; observedAt: number | null }): number | null => r.ts ?? r.observedAt ?? null
const basename = (path: string | null) => (path ? path.replace(/\\/g, '/').split('/').pop() || path : 'unnamed source')

interface Index {
  nodes: Map<string, RelationshipNode>
  /** edge indexes touching a node */
  adjacent: Map<string, number[]>
  /** record node id by "source:rowId" */
  recordByRow: Map<string, string>
  /** the record's own reference (title, times, source file), from any edge it is the source of */
  refOf: Map<string, RelationshipRef>
  /** entity id -> record node ids naming it */
  recordsOf: Map<string, Set<string>>
}

function parseRecord(node: RelationshipNode): { source: 'events' | 'mails'; id: number | null; evidenceId: number | null } | null {
  // The builder scopes a record node as "<source>:<row id>:<evidence id>"; a row that had no id
  // was numbered by its position instead, which is not a row id the store can open.
  const m = /^(events|mails):(-?\d+|None|null|undefined):(-?\d+|None|null|undefined)$/.exec(node.value)
  if (!m) return null
  const num = (s: string) => (/^-?\d+$/.test(s) ? Number(s) : null)
  return { source: m[1] as 'events' | 'mails', id: num(m[2]), evidenceId: num(m[3]) }
}

function index(result: RelationshipResult): Index {
  const nodes = new Map(result.nodes.map((n) => [n.id, n]))
  const adjacent = new Map<string, number[]>()
  const recordByRow = new Map<string, string>()
  const refOf = new Map<string, RelationshipRef>()
  const recordsOf = new Map<string, Set<string>>()
  const push = (id: string, i: number) => {
    const list = adjacent.get(id)
    if (list) list.push(i)
    else adjacent.set(id, [i])
  }
  result.edges.forEach((e, i) => {
    push(e.source, i)
    push(e.target, i)
    const src = nodes.get(e.source)
    if (src?.kind === 'record') {
      if (!refOf.has(e.source) && e.refs[0]) refOf.set(e.source, e.refs[0])
      const set = recordsOf.get(e.target)
      if (set) set.add(e.source)
      else recordsOf.set(e.target, new Set([e.source]))
    }
  })
  // The reference a record carries is the row it was built from; the scope in the node value
  // falls back to the row's position when the row had no id, which is not something a finding
  // can cite. Only a real id enters the lookup.
  for (const n of result.nodes) {
    if (n.kind !== 'record') continue
    const ref = refOf.get(n.id)
    if (ref) {
      if (ref.id != null) recordByRow.set(`${ref.source}:${ref.id}`, n.id)
      continue
    }
    const parsed = parseRecord(n)
    if (parsed && parsed.id != null) recordByRow.set(`${parsed.source}:${parsed.id}`, n.id)
  }
  return { nodes, adjacent, recordByRow, refOf, recordsOf }
}

class Union {
  private parent: number[] = []
  make(): number {
    this.parent.push(this.parent.length)
    return this.parent.length - 1
  }
  find(i: number): number {
    while (this.parent[i] !== i) {
      this.parent[i] = this.parent[this.parent[i]]
      i = this.parent[i]
    }
    return i
  }
  union(a: number, b: number): number {
    a = this.find(a)
    b = this.find(b)
    if (a === b) return a
    // the lower index was seeded first, by a stronger reason: it names the merged story
    if (a < b) this.parent[b] = a
    else this.parent[a] = b
    return Math.min(a, b)
  }
}

function makeRecord(ix: Index, nodeId: string, hop: number): StoryRecord | null {
  const node = ix.nodes.get(nodeId)
  if (!node || node.kind !== 'record') return null
  const parsed = parseRecord(node)
  const ref = ix.refOf.get(nodeId) ?? null
  const source = parsed?.source ?? ref?.source ?? 'events'
  return {
    nodeId,
    source,
    id: ref ? ref.id : (parsed?.id ?? null),
    evidenceId: parsed?.evidenceId ?? ref?.evidenceId ?? null,
    ts: ref?.ts ?? null,
    observedAt: ref?.observedAt ?? null,
    recordKind: ref?.recordKind ?? 'event',
    title: ref?.title || node.label || `${source} record`,
    sourceFile: ref?.sourceFile ?? null,
    lane: source === 'mails' ? 'mail' : 'host',
    hop,
    seed: [],
    via: [],
    findings: [],
    marks: [],
    ref,
  }
}

/** Two records may be joined through an entity of this weight: strong entities always, medium
 * ones when both are timed and close, or both are collection snapshots. */
export function buildStories(result: RelationshipResult | null, findings: Finding[], marks: RowMark[], options: StoryOptions = {}): StoryResult {
  const opt = { ...DEFAULTS, ...options }
  const empty: StoryResult = { stories: [], stats: { seeds: { finding: 0, mark: 0, lead: 0 }, records: 0, entities: 0, hubs: 0, truncated: false } }
  if (!result || !result.nodes.length) return empty
  const ix = index(result)
  const weightOf = (id: string) => WEIGHT[ix.nodes.get(id)?.kind ?? ''] ?? 2
  const isHub = (id: string) => (ix.recordsOf.get(id)?.size ?? 0) > opt.hubRecords
  const noise = new Set<string>()
  const markedBy = new Map<string, RowMark['verdict'][]>()
  for (const m of marks) {
    const node = ix.recordByRow.get(`${m.source}:${m.rowId}`)
    if (!node) continue
    if (m.verdict === 'noise') noise.add(node)
    else markedBy.set(node, [...(markedBy.get(node) ?? []), m.verdict])
  }
  const findingsOn = new Map<string, { ruleId: string; title: string; severity: Severity }[]>()
  // a finding kept out of the report is still evidence; only a false positive is not
  const live = findings.filter((f) => f.status !== 'false_positive').sort((a, b) => rank(b.severityOverride ?? b.severity) - rank(a.severityOverride ?? a.severity) || b.count - a.count)
  for (const f of live) {
    const severity = f.severityOverride ?? f.severity
    for (const id of f.refs.slice(0, 2000)) {
      const node = ix.recordByRow.get(`${f.source}:${id}`)
      if (!node) continue
      const list = findingsOn.get(node) ?? []
      if (!list.some((x) => x.ruleId === f.ruleId)) list.push({ ruleId: f.ruleId, title: f.title, severity })
      findingsOn.set(node, list)
    }
  }

  // --- seeds, in the order that decides which story a shared record belongs to
  const seeds: { node: string; reason: 'finding' | 'mark' | 'lead' }[] = []
  const seen = new Set<string>()
  const seed = (node: string | undefined, reason: 'finding' | 'mark' | 'lead') => {
    if (!node || seen.has(node) || noise.has(node) || seeds.length >= opt.maxSeeds) return
    seen.add(node)
    seeds.push({ node, reason })
  }
  for (const f of live) for (const id of f.refs.slice(0, 2000)) seed(ix.recordByRow.get(`${f.source}:${id}`), 'finding')
  for (const [node, verdicts] of markedBy) if (verdicts.includes('pivot')) seed(node, 'mark')
  for (const [node] of markedBy) seed(node, 'mark')
  // an entity in two source files starts a story when it is specific enough on its own: a digest,
  // a path, a process, a URL, a domain or an address; an account or a host in two logs is not news
  for (const lead of relationshipLeads(result).slice(0, 60))
    if ((WEIGHT[lead.node.kind] ?? 0) >= 3) for (const ref of lead.references) if (ref.id != null) seed(ix.recordByRow.get(`${ref.source}:${ref.id}`), 'lead')
  const seedReasons = new Map<string, ('finding' | 'mark' | 'lead')[]>()
  for (const s of seeds) seedReasons.set(s.node, [...(seedReasons.get(s.node) ?? []), s.reason])
  const stats = { finding: 0, mark: 0, lead: 0 }
  for (const s of seeds) stats[s.reason]++

  // --- expansion: seed -> entity -> record, and on from records that carry a finding or a mark
  const owner = new Map<string, number>()
  const records = new Map<string, StoryRecord>()
  const union = new Union()
  const capped = new Set<number>()
  const blockedLinks: NonNullable<Story['blockedLinks']> = []
  let truncated = false
  const interesting = (node: string) => findingsOn.has(node) || markedBy.has(node)
  const recordsVia = (entity: string): string[] => [...(ix.recordsOf.get(entity) ?? [])]
  const relationBetween = (record: string, entity: string): string => {
    for (const i of ix.adjacent.get(record) ?? []) {
      const e = result.edges[i]
      if (e.source === record && e.target === entity) return e.relation
    }
    return 'names'
  }
  for (const s of seeds) {
    // Findings and analyst marks get their own bounded expansion, even when reached at
    // another seed's hop limit. Covered automatic leads remain leaves to control noise.
    if (owner.has(s.node) && s.reason === 'lead') continue
    const story = owner.get(s.node) ?? union.make()
    let count = 0
    const queue: { node: string; hop: number; via: StoryVia | null }[] = [{ node: s.node, hop: 0, via: null }]
    while (queue.length) {
      const { node, hop, via } = queue.shift()!
      const existing = owner.get(node)
      if (existing != null) {
        if (union.find(existing) !== union.find(story)) union.union(existing, story)
        const known = records.get(node)
        if (known && via && !known.via.some((v) => v.entityId === via.entityId)) known.via.push(via)
        if (hop !== 0 || via !== null) continue
      }
      if (count >= opt.maxStoryRecords) {
        truncated = true
        capped.add(story)
        break
      }
      const rec = records.get(node) ?? makeRecord(ix, node, hop)
      if (!rec) continue
      owner.set(node, story)
      records.set(node, rec)
      if (existing == null) count++
      if (via) rec.via.push(via)
      rec.seed = seedReasons.get(node) ?? []
      rec.findings = findingsOn.get(node) ?? []
      rec.marks = markedBy.get(node) ?? []
      if (hop >= 3 || (hop > 0 && !interesting(node))) continue
      for (const i of ix.adjacent.get(node) ?? []) {
        const e = result.edges[i]
        const entity = e.source === node ? e.target : e.source
        const en = ix.nodes.get(entity)
        if (!en || en.kind === 'record') continue
        const w = weightOf(entity)
        if (w < MEDIUM || isHub(entity)) continue
        const reach = (through: string, witness?: RelationshipEdge) => {
          for (const other of recordsVia(through)) {
            if (other === node || noise.has(other) || (owner.get(other) != null && union.find(owner.get(other)!) === union.find(story))) continue
            const probe = records.get(other) ?? makeRecord(ix, other, hop + 1)
            if (!probe) continue
            const decisions = [joinDecision(rec, probe, en, opt.windowMs), joinDecision(rec, probe, ix.nodes.get(through)!, opt.windowMs)]
            const blocked = decisions.find((decision) => !decision.allowed)
            if (blocked) {
              if (
                probe.ref &&
                blockedLinks.length < 1000 &&
                !blockedLinks.some((link) => link.from === rec.nodeId && referenceIdentity(link.ref) === referenceIdentity(probe.ref!) && link.reason === blocked.reason)
              )
                blockedLinks.push({ from: rec.nodeId, ref: probe.ref, reason: blocked.reason })
              continue
            }
            // A file->digest assertion is about the version in its witness record, not every
            // record naming that path. Never borrow another record's content attribution.
            if (witness && witness.relation !== 'has host' && !witness.refs.some((ref) => [rec.ref, probe.ref].some((r) => r && referenceIdentity(r) === referenceIdentity(ref)))) continue
            const tn = ix.nodes.get(through)!
            queue.push({ node: other, hop: hop + 1, via: { entityId: through, kind: tn.kind, label: tn.label, relation: relationBetween(other, through), fromNodeId: node } })
          }
        }
        reach(entity)
        // one entity hop more when one of the two is strong: attachment digest <- file <- process
        // record, DNS domain <- URL <- mail, in either direction. The weaker of the two decides
        // whether time still matters.
        for (const j of ix.adjacent.get(entity) ?? []) {
          const f = result.edges[j]
          if (f.assertion === 'hypothesized' || f.assertion === 'correlated') continue
          const next = f.source === entity ? f.target : f.source
          const fn = ix.nodes.get(next)
          if (!fn || fn.kind === 'record' || next === entity || isHub(next)) continue
          const wn = weightOf(next)
          if (wn < MEDIUM || Math.max(w, wn) < STRONG) continue
          reach(next, f)
        }
      }
    }
  }

  // --- assemble
  const members = new Map<number, string[]>()
  for (const [node, story] of owner) {
    const root = union.find(story)
    const list = members.get(root)
    if (list) list.push(node)
    else members.set(root, [node])
  }
  const stories: Story[] = []
  const hubs = new Set<string>()
  for (const [, nodeIds] of members) {
    let recs = nodeIds.map((n) => records.get(n)!)
    let cut = [...capped].some((i) => union.find(i) === union.find(owner.get(nodeIds[0])!))
    if (recs.length > opt.maxStoryRecords) {
      // seeds and interesting records first, then the nearest hops: what was cut is noted
      recs = recs
        .sort((a, b) => Number(b.seed.length > 0) - Number(a.seed.length > 0) || Number(b.findings.length + b.marks.length > 0) - Number(a.findings.length + a.marks.length > 0) || a.hop - b.hop)
        .slice(0, opt.maxStoryRecords)
      cut = true
    }
    const entityMap = new Map<string, StoryEntity>()
    const sourcesOf = new Map<string, Map<string, string>>()
    for (const r of recs) {
      const named = new Set<string>()
      for (const i of ix.adjacent.get(r.nodeId) ?? []) {
        const e = result.edges[i]
        const entity = e.source === r.nodeId ? e.target : e.source
        const en = ix.nodes.get(entity)
        if (!en || en.kind === 'record' || named.has(entity)) continue
        named.add(entity)
        let ent = entityMap.get(entity)
        if (!ent) {
          ent = { id: entity, kind: en.kind, label: en.label, value: en.value, scope: en.scope, records: 0, sources: [], weight: weightOf(entity), bridge: false, hub: isHub(entity) }
          entityMap.set(entity, ent)
          sourcesOf.set(entity, new Map())
        }
        ent.records++
        sourcesOf.get(entity)!.set(r.ref ? sourceIdentity(r.ref) : r.nodeId, r.sourceFile ?? `evidence ${r.evidenceId ?? '?'}`)
      }
    }
    for (const ent of entityMap.values()) {
      ent.sources = [...sourcesOf.get(ent.id)!.values()]
      ent.bridge = ent.sources.length >= 2 && ent.weight >= MEDIUM && !ent.hub
      if (ent.hub) hubs.add(ent.id)
    }
    const entities = [...entityMap.values()].sort((a, b) => Number(b.bridge) - Number(a.bridge) || b.weight - a.weight || b.records - a.records || a.label.localeCompare(b.label))
    const entityIds = new Set(entityMap.keys())
    const edges: RelationshipEdge[] = []
    const seenEdge = new Set<number>()
    for (const r of recs)
      for (const i of ix.adjacent.get(r.nodeId) ?? []) {
        if (seenEdge.has(i)) continue
        seenEdge.add(i)
        edges.push(result.edges[i])
      }
    for (const ent of entities)
      for (const i of ix.adjacent.get(ent.id) ?? []) {
        const e = result.edges[i]
        if (seenEdge.has(i) || !entityIds.has(e.source) || !entityIds.has(e.target)) continue
        seenEdge.add(i)
        edges.push(e)
      }
    // a bridge's edges first: those are the links worth reviewing
    const bridgeIds = new Set(entities.filter((e) => e.bridge).map((e) => e.id))
    edges.sort((a, b) => Number(bridgeIds.has(b.source) || bridgeIds.has(b.target)) - Number(bridgeIds.has(a.source) || bridgeIds.has(a.target)))
    const timed = recs.filter((r) => recordTime(r) != null)
    recs.sort((a, b) => {
      const ta = recordTime(a)
      const tb = recordTime(b)
      if (ta != null && tb != null) return ta - tb || a.title.localeCompare(b.title)
      if (ta != null) return -1
      if (tb != null) return 1
      return a.hop - b.hop || a.title.localeCompare(b.title)
    })
    const findingMap = new Map<string, { ruleId: string; title: string; severity: Severity; count: number }>()
    for (const r of recs)
      for (const f of r.findings) {
        const cur = findingMap.get(f.ruleId)
        if (cur) cur.count++
        else findingMap.set(f.ruleId, { ...f, count: 1 })
      }
    const storyFindings = [...findingMap.values()].sort((a, b) => rank(b.severity) - rank(a.severity) || b.count - a.count)
    const sources = [...new Set(recs.map((r) => r.sourceFile ?? `evidence ${r.evidenceId ?? '?'}`))]
    const breakdown = scoreStory(storyFindings, entities, [...new Set(recs.map((r) => (r.ref ? sourceIdentity(r.ref) : r.nodeId)))], recs)
    const worstFinding = worst(storyFindings)
    const severity = worstFinding ?? 'info'
    const start = timed.length ? Math.min(...timed.map((r) => recordTime(r)!)) : null
    const end = timed.length ? Math.max(...timed.map((r) => recordTime(r)!)) : null
    const first = anchorOf(recs)
    const keptEntities = entities.slice(0, 80)
    const keptNodes = new Set([...recs.map((r) => r.nodeId), ...keptEntities.map((e) => e.id)])
    const keptEdges = edges.filter((e) => keptNodes.has(e.source) && keptNodes.has(e.target)).slice(0, 600)
    if (keptEntities.length < entities.length || keptEdges.length < edges.length) cut = true
    stories.push({
      blockedLinks: blockedLinks.filter((link) => keptNodes.has(link.from)).slice(0, 30),
      id: `story:${first.source}:${first.id ?? first.nodeId}:${first.evidenceId ?? ''}`,
      anchor: first.nodeId,
      title: titleOf(storyFindings, entities, first),
      summary: summaryOf(recs, storyFindings, entities, sources, start, end),
      severity,
      score: breakdown.total,
      scoreBreakdown: breakdown,
      start,
      end,
      records: recs,
      entities: keptEntities,
      edges: keptEdges,
      sources,
      findings: storyFindings,
      truncated: cut,
    })
    if (cut) truncated = true
  }
  stories.sort((a, b) => rank(b.severity) - rank(a.severity) || b.score - a.score || (a.start ?? Infinity) - (b.start ?? Infinity) || a.title.localeCompare(b.title))
  const shown = stories.slice(0, opt.maxStories)
  return {
    stories: shown,
    stats: { seeds: stats, records: records.size, entities: new Set(shown.flatMap((s) => s.entities.map((e) => e.id))).size, hubs: hubs.size, truncated: truncated || stories.length > opt.maxStories },
  }
}

/** The seed the story hangs from: worst finding first, then a pivot mark, a relevant mark, a cross-source entity; ties go to the earliest record. */
export function anchorOf(records: StoryRecord[]): StoryRecord {
  const priority = (r: StoryRecord) =>
    (r.seed.length ? 1 : 0) * 1000 +
    (worst(r.findings) ? rank(worst(r.findings)!) + 1 : 0) * 100 +
    (r.marks.includes('pivot') ? 20 : r.marks.includes('relevant') ? 10 : 0) +
    (r.seed.includes('lead') ? 1 : 0)
  return records.reduce((best, r) => (priority(r) > priority(best) ? r : best), records[0])
}

/** Bounded, like a chain's: each part saturates so a long story of routine rows cannot outscore a short corroborated one. */
export function scoreStory(findings: { severity: Severity; count: number }[], entities: StoryEntity[], sources: string[], records: StoryRecord[]): StoryScore {
  const worstSev = worst(findings)
  const sevPoints: Record<Severity, number> = { critical: 30, high: 24, medium: 16, low: 8, info: 4 }
  const f = worstSev ? Math.min(40, sevPoints[worstSev] + Math.min(10, (findings.length - 1) * 3)) : 0
  const strong = entities.filter((e) => e.bridge && e.weight >= STRONG).length
  const medium = entities.filter((e) => e.bridge && e.weight < STRONG).length
  const b = Math.min(30, strong * 8 + Math.min(6, medium * 3))
  const s = Math.min(15, Math.max(0, sources.length - 1) * 5)
  const m = Math.min(
    15,
    [...new Map(records.map((r) => [r.ref ? referenceIdentity(r.ref) : r.nodeId, r])).values()].reduce(
      (t, r) => t + r.marks.reduce((u, v) => u + (v === 'pivot' ? 6 : v === 'relevant' ? 4 : 0), 0),
      0,
    ),
  )
  return { findings: f, bridges: b, sources: s, marks: m, total: Math.min(100, f + b + s + m) }
}

const KIND_WORD: Record<string, string> = {
  hash: 'digest',
  file: 'file',
  process: 'process',
  url: 'URL',
  service: 'service',
  task: 'scheduled task',
  autorun: 'autorun',
  program: 'program',
  domain: 'domain',
  ip: 'address',
  account: 'account',
  host: 'host',
  sid: 'SID',
  group: 'group',
}
const shortLabel = (e: { kind: string; label: string }) =>
  e.kind === 'hash' ? e.label.replace(/^(sha256|sha1|md5):([0-9a-f]{12})[0-9a-f]*$/i, '$1:$2…') : e.label.length > 60 ? e.label.slice(0, 59) + '…' : e.label

function titleOf(findings: { title: string }[], entities: StoryEntity[], first: StoryRecord): string {
  if (findings.length) return findings[0].title
  const bridge = entities.find((e) => e.bridge)
  if (bridge) return `${KIND_WORD[bridge.kind] ?? bridge.kind} ${shortLabel(bridge)} in ${bridge.sources.length} sources`
  return first.title
}

function spanText(ms: number): string {
  const m = ms / 60_000
  return m < 1 ? 'under a minute' : m < 90 ? `${Math.round(m)} min` : m < 48 * 60 ? `${(m / 60).toFixed(1)} h` : `${(m / 1440).toFixed(1)} d`
}

function summaryOf(records: StoryRecord[], findings: { severity: Severity }[], entities: StoryEntity[], sources: string[], start: number | null, end: number | null): string {
  const parts: string[] = []
  parts.push(
    `${records.length} record${records.length === 1 ? '' : 's'} from ${sources.length} source${sources.length === 1 ? '' : 's'}${start != null && end != null && end > start ? ` over ${spanText(end - start)}` : ''}`,
  )
  const w = worst(findings)
  if (w) parts.push(`${findings.length} finding${findings.length === 1 ? '' : 's'}, worst ${w}`)
  for (const b of entities.filter((e) => e.bridge).slice(0, 2)) parts.push(`${KIND_WORD[b.kind] ?? b.kind} ${shortLabel(b)} ties ${b.sources.slice(0, 3).map(basename).join(', ')}`)
  const context = (kind: string) =>
    entities
      .filter((e) => e.kind === kind)
      .sort((a, b) => b.records - a.records)
      .slice(0, 2)
      .map((e) => e.label)
  const hosts = context('host')
  const accounts = context('account')
  if (hosts.length) parts.push(`host ${hosts.join(', ')}`)
  if (accounts.length) parts.push(`account ${accounts.join(', ')}`)
  const marks = records.reduce((t, r) => t + r.marks.length, 0)
  if (marks) parts.push(`${marks} analyst mark${marks === 1 ? '' : 's'}`)
  return parts.join(' · ')
}
