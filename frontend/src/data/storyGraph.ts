import type { GEdge, GNode, Graph, Lane } from './chainGraph'
import { recordTime, STRONG, type Story, type StoryEntity, type StoryRecord } from './relationshipStories'

/**
 * A story as a swimlane graph, drawn by the chain renderer: records in time order across the
 * middle lanes (mailbox, host), the entities they name above and below (sender addresses,
 * URLs and domains on the attacker side; accounts on the identity lane; files, processes,
 * digests and configuration on the artifact lane; machines and addresses at the bottom).
 *
 * Bridges, the entities that tie records from different source files together, are drawn with
 * the accent edges the chain graph uses for ties to the seed mail. The story's anchor record is
 * the diamond; records that carry no finding, mark or seed reason and share a title with their
 * neighbour fold into one node, the way a run of routine sign-ins does in a chain.
 */

/** widest graph before adjacent plain records are folded together */
export const MAX_STORY_COLUMNS = 16

const laneOfEntity = (e: StoryEntity): Lane => {
  switch (e.kind) {
    case 'host':
    case 'ip':
      return 'infra'
    case 'account':
    case 'sid':
    case 'group':
      return 'identity'
    case 'url':
    case 'domain':
      return 'attacker'
    default:
      return 'artifact'
  }
}
const kindOfEntity = (e: StoryEntity): GNode['kind'] => {
  switch (e.kind) {
    case 'host':
      return 'host'
    case 'ip':
      return 'ip'
    case 'account':
      return e.value.includes('@') ? 'address' : 'user'
    case 'sid':
    case 'group':
      return 'user'
    case 'url':
    case 'domain':
      return 'domain'
    case 'hash':
      return 'hash'
    case 'file':
      return 'file'
    case 'process':
    case 'process-observation':
      return 'process'
    default:
      return 'config'
  }
}
const KIND_WORD: Record<string, string> = {
  hash: 'digest',
  file: 'file',
  process: 'process',
  'process-observation': 'process (unresolved)',
  url: 'URL',
  service: 'service',
  task: 'task',
  autorun: 'autorun',
  program: 'program',
  domain: 'domain',
  ip: 'address',
  account: 'account',
  host: 'host',
  sid: 'SID',
  group: 'group',
  'deception-exhibit': 'exhibit',
  'deception-episode': 'episode',
}
const shortLabel = (e: StoryEntity) =>
  e.kind === 'hash' ? e.label.replace(/^(sha256|sha1|md5):([0-9a-f]{12})[0-9a-f]*$/i, '$1:$2…') : e.kind === 'file' ? (e.label.split(/[\\/]/).pop() ?? e.label) : e.label
const ORDER = ['critical', 'high', 'medium', 'low', 'info']
const worstSeverity = (fs: { severity: string }[]): string | undefined => ORDER.find((s) => fs.some((f) => f.severity === s))
const plain = (r: StoryRecord) => !r.findings.length && !r.marks.length && !r.seed.length
/** "logon from 10.0.0.5" and "logon from 10.0.0.9" fold together; numbers and addresses are wildcards, and what follows from / on / by / via / to / for is dropped */
const titleKey = (t: string) =>
  t
    .toLowerCase()
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, '#')
    .replace(/\d+/g, '#')
    .replace(/ (?:from|on|by|via|to|for) .*$/, '')
    .slice(0, 40)

export function buildStoryGraph(story: Story): Graph {
  const nodes: GNode[] = []
  const edges: GEdge[] = []
  const byId = new Map<string, GNode>()
  const add = (n: GNode) => {
    byId.set(n.id, n)
    nodes.push(n)
    return n
  }
  const entities = new Map(story.entities.map((e) => [e.id, e]))
  // entity nodes the graph keeps: bridges, everything strong, and the context the summary names
  const shown = new Set<string>()
  for (const e of story.entities) if (e.bridge || e.weight >= STRONG || e.kind === 'host' || e.kind === 'account' || e.kind === 'ip' || e.kind === 'domain') shown.add(e.id)

  // --- records: time order, plain neighbours with the same title fold together
  type Group = { items: StoryRecord[]; lane: Lane; key: string; pinned: boolean }
  const groups: Group[] = []
  for (const r of story.records) {
    const lane: Lane = r.lane === 'mail' ? 'mail' : 'host'
    const key = titleKey(r.title)
    const pinned = !plain(r)
    const last = groups[groups.length - 1]
    if (last && !last.pinned && !pinned && last.lane === lane && last.key === key) last.items.push(r)
    else groups.push({ items: [r], lane, key, pinned })
  }
  // still too wide: merge adjacent plain groups, same lane first, then across lanes (the group
  // keeps the lane most of its records are on)
  const mergeOnce = (sameLane: boolean): boolean => {
    for (let g = 0; g < groups.length - 1; g++) {
      const a = groups[g]
      const b = groups[g + 1]
      if (a.pinned || b.pinned || (sameLane && a.lane !== b.lane)) continue
      a.items.push(...b.items)
      a.key = '*'
      if (!sameLane) a.lane = a.items.filter((r) => r.lane === 'mail').length * 2 >= a.items.length ? 'mail' : 'host'
      groups.splice(g + 1, 1)
      return true
    }
    return false
  }
  while (groups.length > MAX_STORY_COLUMNS && (mergeOnce(true) || mergeOnce(false))) {
    /* fold */
  }
  const recordNode = new Map<string, string>()
  let col = 0
  for (const g of groups) {
    const first = g.items[0]
    const n = g.items.length
    const findings = g.items.flatMap((x) => x.findings)
    const marks = g.items.flatMap((x) => x.marks)
    const time = recordTime(first)
    const last = recordTime(g.items[n - 1])
    const id = n === 1 ? `record:${first.nodeId}` : `records:${first.nodeId}`
    const titles = [...new Set(g.items.map((x) => x.title))]
    const collected = g.items.every((x) => x.recordKind === 'observation')
    const label = n === 1 ? first.title : g.key !== '*' ? `${titles[0]} ×${n}` : `${n} records`
    const sub =
      n === 1
        ? `${collected ? 'collected' : first.source === 'mails' ? 'mail' : 'event'}${first.sourceFile ? ' · ' + (first.sourceFile.split(/[\\/]/).pop() ?? '') : ''}`
        : `${collected ? 'collected' : 'events'} · ${[...new Set(g.items.map((x) => x.sourceFile?.split(/[\\/]/).pop()).filter(Boolean))].slice(0, 2).join(', ')}`
    add({
      id,
      label,
      sub,
      lane: g.lane,
      kind: n === 1 && first.nodeId === story.anchor ? 'seed' : g.pinned ? 'step' : 'routine',
      x: col++,
      severity: worstSeverity(findings) ?? (marks.includes('pivot') ? 'high' : marks.includes('relevant') ? 'medium' : undefined),
      weight: g.pinned ? 4 + Math.min(4, findings.length + marks.length) : 1,
      linked: g.pinned,
      ts: time ?? undefined,
      recordIds: g.items.map((x) => x.nodeId),
      detail: [
        ...(time != null && last != null && last > time ? [`until ${new Date(last).toISOString()}`] : []),
        ...[...new Set(findings.map((f) => `${f.severity}: ${f.title}`))].slice(0, 6),
        ...[...new Set(marks.map((m) => `marked ${m}`))],
        ...[...new Set(g.items.flatMap((x) => x.via.map((v) => `via ${KIND_WORD[v.kind] ?? v.kind} ${v.label}`)))].slice(0, 4),
      ],
    })
    for (const r of g.items) recordNode.set(r.nodeId, id)
  }

  // --- entities, from the story's edges: record -> entity, and entity -> entity among shown ones
  const seenEdge = new Set<string>()
  const ensureEntity = (e: StoryEntity): string => {
    const id = `entity:${e.id}`
    if (!byId.has(id))
      add({
        id,
        label: shortLabel(e),
        sub: `${KIND_WORD[e.kind] ?? e.kind}${e.bridge ? ` · ${e.sources.length} sources` : e.hub ? ' · hub' : ''}`,
        lane: laneOfEntity(e),
        kind: kindOfEntity(e),
        x: 0,
        weight: e.bridge ? 4 : e.weight >= STRONG ? 3 : 2,
        linked: e.bridge,
        entity:
          e.kind === 'host'
            ? { kind: 'host', value: e.value }
            : e.kind === 'ip'
              ? { kind: 'ip', value: e.value }
              : e.kind === 'domain'
                ? { kind: 'domain', value: e.value }
                : e.kind === 'account'
                  ? { kind: e.value.includes('@') ? 'address' : 'user', value: e.value }
                  : undefined,
        detail: [e.label, ...(e.sources.length > 1 ? [`named by ${e.records} records in ${e.sources.length} source files`] : [`named by ${e.records} record${e.records === 1 ? '' : 's'}`])],
        degree: e.records,
        entityId: e.id,
      })
    return id
  }
  // one drawn edge per record, entity and (for a bridge, whose label is the relation) relation
  const edgeKey = (record: string, ent: StoryEntity, relation: string) => `${record}>${ent.id}${ent.bridge ? '>' + relation : ''}`
  for (const e of story.edges) {
    const rs = recordNode.get(e.source)
    const rt = recordNode.get(e.target)
    if (rs && entities.has(e.target) && shown.has(e.target)) {
      const ent = entities.get(e.target)!
      const key = edgeKey(rs, ent, e.relation)
      if (seenEdge.has(key)) continue
      seenEdge.add(key)
      edges.push({ source: rs, target: ensureEntity(ent), kind: ent.bridge ? 'artifact' : 'entity', label: ent.bridge ? e.relation : undefined })
    } else if (rt && entities.has(e.source) && shown.has(e.source)) {
      const ent = entities.get(e.source)!
      const key = edgeKey(rt, ent, e.relation)
      if (seenEdge.has(key)) continue
      seenEdge.add(key)
      edges.push({ source: rt, target: ensureEntity(ent), kind: ent.bridge ? 'artifact' : 'entity', label: ent.bridge ? e.relation : undefined })
    } else if (entities.has(e.source) && entities.has(e.target) && shown.has(e.source) && shown.has(e.target)) {
      const key = `${e.source}>${e.target}`
      if (seenEdge.has(key)) continue
      seenEdge.add(key)
      edges.push({ source: ensureEntity(entities.get(e.source)!), target: ensureEntity(entities.get(e.target)!), kind: 'entity', label: e.relation })
    }
  }
  // entity nodes sit at the mean column of the records they connect to; a tie to another entity
  // does not count, that entity may not have been placed yet
  for (const n of nodes) {
    if (!n.id.startsWith('entity:')) continue
    const around = edges
      .filter((e) => e.source === n.id || e.target === n.id)
      .map((e) => byId.get(e.source === n.id ? e.target : e.source))
      .filter((m): m is GNode => !!m)
    const records = around.filter((m) => !m.id.startsWith('entity:'))
    const cols = (records.length ? records : around).map((m) => m.x)
    if (cols.length) n.x = cols.reduce((a, b) => a + b, 0) / cols.length
  }
  // spread the ones that landed on the same lane and column
  const taken = new Set<string>()
  for (const n of nodes.filter((n) => n.id.startsWith('entity:')).sort((a, b) => a.x - b.x)) {
    let x = Math.round(n.x * 2) / 2
    while (taken.has(`${n.lane}:${x}`)) x += 0.5
    taken.add(`${n.lane}:${x}`)
    n.x = x
  }
  return { nodes, edges, columns: Math.max(1, col) }
}
