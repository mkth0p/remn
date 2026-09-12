import { describe, expect, it } from 'vitest'
import { graphOption, PRINT_TOKENS } from '../components/ChainGraph'
import type { Finding } from '../db/schema'
import type { Graph } from './chainGraph'
import { buildStories, WEIGHT, type Story, type StoryEntity, type StoryRecord } from './relationshipStories'
import type { RelationshipEdge, RelationshipNode, RelationshipRef, RelationshipResult } from './relationships'
import { buildStoryGraph, MAX_STORY_COLUMNS } from './storyGraph'

const H = 3_600_000
const T0 = Date.UTC(2026, 7, 19, 8, 0, 0)

// --- story fixtures built by hand: the graph only reads the Story shape, not the relationship result
const rec = (nodeId: string, p: Partial<StoryRecord> = {}): StoryRecord => ({
  nodeId,
  source: 'events',
  id: 1,
  evidenceId: 9,
  ts: null,
  observedAt: null,
  recordKind: 'event',
  title: nodeId,
  sourceFile: 'logs/Security.evtx',
  lane: 'host',
  hop: 0,
  seed: [],
  via: [],
  findings: [],
  marks: [],
  ref: null,
  ...p,
})
const ent = (id: string, kind: string, p: Partial<StoryEntity> = {}): StoryEntity => ({
  id,
  kind,
  label: id,
  value: id,
  scope: '',
  records: 1,
  sources: ['logs/Security.evtx'],
  weight: WEIGHT[kind] ?? 2,
  bridge: false,
  hub: false,
  ...p,
})
const edge = (source: string, target: string, relation: string): RelationshipEdge => ({ source, target, relation, reason: relation, confidence: 'high', refs: [], count: 1 })
const story = (records: StoryRecord[], entities: StoryEntity[] = [], edges: RelationshipEdge[] = [], p: Partial<Story> = {}): Story => ({
  id: 'story:events:1:9',
  anchor: records.find((r) => r.seed.length)?.nodeId ?? records[0]?.nodeId ?? '',
  title: 'A story',
  summary: '',
  severity: 'info',
  score: 0,
  scoreBreakdown: { findings: 0, bridges: 0, sources: 0, marks: 0, total: 0 },
  start: null,
  end: null,
  records,
  entities,
  edges,
  sources: [],
  findings: [],
  truncated: false,
  ...p,
})
const finding = (severity: Finding['severity'], title = 'A finding') => ({ ruleId: 'r', title, severity })
const recordNodes = (g: Graph) => g.nodes.filter((n) => n.recordIds)
const node = (g: Graph, id: string) => {
  const n = g.nodes.find((x) => x.id === id)
  if (!n) throw new Error(`no node ${id} in ${g.nodes.map((x) => x.id).join(', ')}`)
  return n
}
/** three timed plain records in one lane, one column each */
const threeRecords = () => [rec('r0', { ts: T0, title: 'first thing' }), rec('r1', { ts: T0 + H, title: 'second thing' }), rec('r2', { ts: T0 + 2 * H, title: 'third thing' })]

describe('records', () => {
  it('lays records out in time order, one column each, and types them by what they carry', () => {
    const s = story([
      rec('mail', { source: 'mails', lane: 'mail', ts: T0, title: 'Invoice 2026-08', sourceFile: 'mailbox/invoice.eml', seed: ['finding'], findings: [finding('high', 'Credential phishing')] }),
      rec('dns', { ts: T0 + 2 * H, title: 'DNS query evil-login.test', sourceFile: 'logs/Sysmon.evtx', findings: [finding('medium', 'DNS to a phishing domain')] }),
      rec('svc', { ts: T0 + 3 * H, title: 'service started', sourceFile: 'logs/System.evtx' }),
      rec('rdp', { ts: T0 + 4 * H, title: 'rdp session', marks: ['pivot'] }),
      rec('proc', { ts: null, observedAt: T0 + 30 * H, recordKind: 'observation', title: 'process upd.exe', sourceFile: 'Processes/processes.csv', marks: ['relevant'] }),
    ])
    const g = buildStoryGraph(s)
    const records = recordNodes(g)
    expect(records.map((n) => n.id)).toEqual(['record:mail', 'record:dns', 'record:svc', 'record:rdp', 'record:proc'])
    expect(records.map((n) => n.x)).toEqual([0, 1, 2, 3, 4])
    expect(records.map((n) => n.ts)).toEqual([T0, T0 + 2 * H, T0 + 3 * H, T0 + 4 * H, T0 + 30 * H])
    expect(g.columns).toBe(5)
    expect(records.map((n) => n.kind)).toEqual(['seed', 'step', 'routine', 'step', 'step'])
    expect(records.map((n) => n.severity)).toEqual(['high', 'medium', undefined, 'high', 'medium'])
    expect(records.map((n) => n.lane)).toEqual(['mail', 'host', 'host', 'host', 'host'])
    expect(records.map((n) => n.linked)).toEqual([true, true, false, true, true])
    expect(records.every((n) => n.recordIds?.length === 1)).toBe(true)
    expect(node(g, 'record:mail').sub).toBe('mail · invoice.eml')
    expect(node(g, 'record:dns').sub).toBe('event · Sysmon.evtx')
    expect(node(g, 'record:proc').sub).toBe('collected · processes.csv')
    expect(node(g, 'record:dns').detail).toContain('medium: DNS to a phishing domain')
    expect(node(g, 'record:rdp').detail).toContain('marked pivot')
  })

  it('folds adjacent plain records with the same title into one node; a finding, a mark or a seed reason keeps a record on its own', () => {
    const s = story([
      rec('a', { ts: T0, title: 'logon 4624 from 10.0.0.5' }),
      rec('b', { ts: T0 + 1000, title: 'logon 4624 from 10.0.0.9' }),
      rec('c', { ts: T0 + 2000, title: 'logon 4625 from 10.0.0.7' }),
      rec('d', { ts: T0 + 3000, title: 'logon 4624 from 10.0.0.8', findings: [finding('low')] }),
      rec('e', { ts: T0 + 4000, title: 'logon 4624 from 10.0.0.2' }),
      rec('f', { ts: T0 + 5000, title: 'service started' }),
      rec('g', { ts: T0 + 6000, title: 'service started', lane: 'mail', source: 'mails' }),
    ])
    const g = buildStoryGraph(s)
    const records = recordNodes(g)
    expect(records.map((n) => n.id)).toEqual(['records:a', 'record:d', 'record:e', 'record:f', 'record:g'])
    expect(records.map((n) => n.x)).toEqual([0, 1, 2, 3, 4])
    const fold = node(g, 'records:a')
    expect(fold.recordIds).toEqual(['a', 'b', 'c'])
    expect(fold.label).toBe('logon 4624 from 10.0.0.5 ×3')
    expect(fold.kind).toBe('routine')
    expect(fold.severity).toBeUndefined()
    expect(fold.ts).toBe(T0)
    expect(fold.detail).toContain(`until ${new Date(T0 + 2000).toISOString()}`)
    expect(fold.sub).toBe('events · Security.evtx')
    // a record with a finding never folds, and a plain record after it starts a new group
    expect(node(g, 'record:d').kind).toBe('step')
    expect(node(g, 'record:e').recordIds).toEqual(['e'])
    // the same title on another lane stays apart
    expect(node(g, 'record:f').lane).toBe('host')
    expect(node(g, 'record:g').lane).toBe('mail')
  })

  it('folds a wide story down to MAX_STORY_COLUMNS record nodes and never folds a pinned record', () => {
    const word = (i: number) => String.fromCharCode(97 + (i % 26)).repeat(3) + String.fromCharCode(97 + Math.floor(i / 26))
    const records: StoryRecord[] = []
    for (let i = 0; i < 26; i++) {
      const pinned = i === 8 ? { seed: ['finding' as const], findings: [finding('high')] } : i === 17 ? { marks: ['relevant' as const] } : {}
      records.push(rec(`r${i}`, { ts: T0 + i * H, title: `${word(i)} happened`, ...pinned }))
    }
    const g = buildStoryGraph(story(records))
    const shown = recordNodes(g)
    expect(shown.length).toBeGreaterThan(1)
    expect(shown.length).toBeLessThanOrEqual(MAX_STORY_COLUMNS)
    expect(g.columns).toBe(shown.length)
    expect(shown.map((n) => n.x)).toEqual(shown.map((_, i) => i))
    // every record is drawn exactly once, in time order
    expect(shown.flatMap((n) => n.recordIds ?? [])).toEqual(records.map((r) => r.nodeId))
    const seed = node(g, 'record:r8')
    expect(seed.kind).toBe('seed')
    expect(seed.recordIds).toEqual(['r8'])
    const marked = node(g, 'record:r17')
    expect(marked.kind).toBe('step')
    expect(marked.recordIds).toEqual(['r17'])
    // records with different titles that were folded to fit are labelled by their count
    const merged = shown.find((n) => (n.recordIds?.length ?? 0) > 1)!
    expect(merged.label).toBe(`${merged.recordIds!.length} records`)
    expect(merged.kind).toBe('routine')
  })

  it('a story with one record has one column; an empty story draws nothing', () => {
    const one = buildStoryGraph(story([rec('only', { ts: T0 })]))
    expect(one.columns).toBe(1)
    expect(one.nodes.map((n) => n.id)).toEqual(['record:only'])
    expect(one.edges).toEqual([])
    const none = buildStoryGraph(story([]))
    expect(none.columns).toBe(1)
    expect(none.nodes).toEqual([])
  })
})

describe('entities', () => {
  it('places each entity kind on its lane with the node kind the renderer draws', () => {
    const r0 = rec('r0', { ts: T0 })
    const entities = [
      ent('host:ws01', 'host'),
      ent('ip:203.0.113.9', 'ip'),
      ent('account:corp\\alice', 'account', { value: 'corp\\alice' }),
      ent('account:billing@evil.test', 'account', { value: 'billing@evil.test' }),
      ent('sid:S-1-5-21-1', 'sid', { bridge: true, sources: ['a', 'b'] }),
      ent('group:Domain Admins', 'group', { bridge: true, sources: ['a', 'b'] }),
      ent('url:https://evil-login.test/x', 'url'),
      ent('domain:evil-login.test', 'domain'),
      ent('hash:sha256:ab', 'hash'),
      ent('file:c:\\users\\jdoe\\downloads\\upd.exe', 'file'),
      ent('process:{guid-1}', 'process'),
      ent('service:updsvc', 'service'),
      ent('task:Updater', 'task'),
      ent('autorun:Run\\upd', 'autorun'),
      ent('program:Updater 1.0', 'program'),
    ]
    const g = buildStoryGraph(
      story(
        [r0],
        entities,
        entities.map((e) => edge('r0', e.id, 'names')),
      ),
    )
    const placed = Object.fromEntries(g.nodes.filter((n) => n.id.startsWith('entity:')).map((n) => [n.id.slice('entity:'.length), [n.lane, n.kind]]))
    expect(placed).toEqual({
      'host:ws01': ['infra', 'host'],
      'ip:203.0.113.9': ['infra', 'ip'],
      'account:corp\\alice': ['identity', 'user'],
      'account:billing@evil.test': ['identity', 'address'],
      'sid:S-1-5-21-1': ['identity', 'user'],
      'group:Domain Admins': ['identity', 'user'],
      'url:https://evil-login.test/x': ['attacker', 'domain'],
      'domain:evil-login.test': ['attacker', 'domain'],
      'hash:sha256:ab': ['artifact', 'hash'],
      'file:c:\\users\\jdoe\\downloads\\upd.exe': ['artifact', 'file'],
      'process:{guid-1}': ['artifact', 'process'],
      'service:updsvc': ['artifact', 'config'],
      'task:Updater': ['artifact', 'config'],
      'autorun:Run\\upd': ['artifact', 'config'],
      'program:Updater 1.0': ['artifact', 'config'],
    })
    // the entity reference the flyout opens: hosts, addresses, domains and accounts only
    expect(node(g, 'entity:host:ws01').entity).toEqual({ kind: 'host', value: 'host:ws01' })
    expect(node(g, 'entity:ip:203.0.113.9').entity).toEqual({ kind: 'ip', value: 'ip:203.0.113.9' })
    expect(node(g, 'entity:domain:evil-login.test').entity).toEqual({ kind: 'domain', value: 'domain:evil-login.test' })
    expect(node(g, 'entity:account:corp\\alice').entity).toEqual({ kind: 'user', value: 'corp\\alice' })
    expect(node(g, 'entity:account:billing@evil.test').entity).toEqual({ kind: 'address', value: 'billing@evil.test' })
    expect(node(g, 'entity:hash:sha256:ab').entity).toBeUndefined()
    expect(node(g, 'entity:file:c:\\users\\jdoe\\downloads\\upd.exe').label).toBe('upd.exe')
  })

  it('omits entities that are neither bridges, strong, nor context; a bridge of any kind stays', () => {
    const r0 = rec('r0', { ts: T0, title: 'first thing' })
    const r1 = rec('r1', { ts: T0 + H, title: 'second thing', sourceFile: 'logs/System.evtx' })
    const entities = [
      ent('group:Users', 'group'),
      ent('sid:S-1-5-18', 'sid'),
      ent('deception-episode:1', 'deception-episode'),
      ent('process-observation:x', 'process-observation'),
      ent('ip:10.0.0.5', 'ip'),
      ent('sid:S-1-5-21-9', 'sid', { bridge: true, sources: ['logs/Security.evtx', 'logs/System.evtx'], records: 2 }),
    ]
    const g = buildStoryGraph(story([r0, r1], entities, [...entities.map((e) => edge('r0', e.id, 'names')), edge('r1', 'sid:S-1-5-21-9', 'names'), edge('sid:S-1-5-18', 'group:Users', 'member of')]))
    expect(g.nodes.filter((n) => n.id.startsWith('entity:')).map((n) => n.id)).toEqual(['entity:ip:10.0.0.5', 'entity:sid:S-1-5-21-9'])
    // no edge points at an omitted entity, and an edge between two omitted entities is dropped
    for (const e of g.edges) {
      expect(g.nodes.some((n) => n.id === e.source)).toBe(true)
      expect(g.nodes.some((n) => n.id === e.target)).toBe(true)
    }
    expect(g.edges).toHaveLength(3)
  })

  it('draws a bridge with labelled accent edges and a plain entity with unlabelled entity edges', () => {
    const [r0, r1, r2] = threeRecords()
    r2.sourceFile = 'Processes/processes.csv'
    const digest = ent('hash:sha256:' + 'ab12'.repeat(16), 'hash', { label: 'sha256:' + 'ab12'.repeat(16), bridge: true, records: 2, sources: ['logs/Security.evtx', 'Processes/processes.csv'] })
    const host = ent('host:ws01', 'host', { records: 3 })
    const hub = ent('host:dc01', 'host', { hub: true, records: 3 })
    const url = ent('url:https://evil-login.test/x', 'url')
    const g = buildStoryGraph(
      story(
        [r0, r1, r2],
        [digest, host, hub, url],
        [
          edge('r0', digest.id, 'attachment digest'),
          edge('r2', digest.id, 'reports hash'),
          edge('r0', host.id, 'observed on'),
          edge('r1', host.id, 'observed on'),
          edge('r2', host.id, 'observed on'),
          edge('r1', hub.id, 'observed on'),
          edge('r1', url.id, 'contains URL'),
        ],
      ),
    )
    const d = node(g, `entity:${digest.id}`)
    expect(d).toMatchObject({ label: 'sha256:ab12ab12ab12…', sub: 'digest · 2 sources', weight: 4, linked: true, degree: 2 })
    expect(d.detail).toEqual(['sha256:' + 'ab12'.repeat(16), 'named by 2 records in 2 source files'])
    expect(g.edges.filter((e) => e.target === d.id)).toEqual([
      { source: 'record:r0', target: d.id, kind: 'artifact', label: 'attachment digest' },
      { source: 'record:r2', target: d.id, kind: 'artifact', label: 'reports hash' },
    ])
    const h = node(g, `entity:${host.id}`)
    expect(h).toMatchObject({ sub: 'host', weight: 2, linked: false })
    expect(h.detail).toEqual([host.id, 'named by 3 records'])
    expect(g.edges.filter((e) => e.target === h.id)).toEqual([
      { source: 'record:r0', target: h.id, kind: 'entity', label: undefined },
      { source: 'record:r1', target: h.id, kind: 'entity', label: undefined },
      { source: 'record:r2', target: h.id, kind: 'entity', label: undefined },
    ])
    expect(node(g, `entity:${hub.id}`).sub).toBe('host · hub')
    // strong but not a bridge: a heavier node, still an entity edge
    expect(node(g, `entity:${url.id}`)).toMatchObject({ sub: 'URL', weight: 3, linked: false })
    expect(g.edges.find((e) => e.target === `entity:${url.id}`)).toMatchObject({ kind: 'entity', label: undefined })
  })

  it('keeps one edge per record and entity whatever the direction or relation, and entity-to-entity edges between shown entities with the relation as label', () => {
    const [r0, r1, r2] = threeRecords()
    const url = ent('url:https://evil-login.test/x', 'url')
    const domain = ent('domain:evil-login.test', 'domain')
    const file = ent('file:c:\\tmp\\upd.exe', 'file')
    const digest = ent('hash:sha256:cd', 'hash')
    const group = ent('group:Users', 'group')
    const g = buildStoryGraph(
      story(
        [r0, r1, r2],
        [url, domain, file, digest, group],
        [
          edge('r0', url.id, 'contains URL'),
          edge('r0', url.id, 'names URL'),
          edge(domain.id, 'r1', 'resolved by'),
          edge(url.id, domain.id, 'has host'),
          edge(file.id, digest.id, 'reported digest'),
          edge('r2', file.id, 'names executable'),
          edge('r2', digest.id, 'reports hash'),
          edge(file.id, group.id, 'owned by'),
        ],
      ),
    )
    expect(g.edges.filter((e) => e.source === 'record:r0')).toEqual([{ source: 'record:r0', target: `entity:${url.id}`, kind: 'entity', label: undefined }])
    // the record is always the source, even when the story edge ran the other way
    expect(g.edges.filter((e) => e.source === 'record:r1')).toEqual([{ source: 'record:r1', target: `entity:${domain.id}`, kind: 'entity', label: undefined }])
    expect(g.edges).toContainEqual({ source: `entity:${url.id}`, target: `entity:${domain.id}`, kind: 'entity', label: 'has host' })
    expect(g.edges).toContainEqual({ source: `entity:${file.id}`, target: `entity:${digest.id}`, kind: 'entity', label: 'reported digest' })
    expect(g.edges.some((e) => e.target === `entity:${group.id}` || e.source === `entity:${group.id}`)).toBe(false)
    expect(g.nodes.some((n) => n.id === `entity:${group.id}`)).toBe(false)
  })

  it('sits an entity at the mean column of its records, whatever other entities it is tied to, and spreads entities sharing a lane and column', () => {
    const [r0, r1, r2] = threeRecords()
    const digest = ent('hash:sha256:cd', 'hash', { bridge: true, records: 2, sources: ['a', 'b'] })
    const file = ent('file:c:\\tmp\\upd.exe', 'file')
    const ip = ent('ip:203.0.113.9', 'ip')
    const host = ent('host:ws01', 'host')
    const alice = ent('account:corp\\alice', 'account')
    const g = buildStoryGraph(
      story(
        [r0, r1, r2],
        [digest, file, ip, host, alice],
        [
          edge('r0', digest.id, 'attachment digest'),
          edge('r2', digest.id, 'reports hash'),
          edge(file.id, digest.id, 'reported digest'),
          edge('r2', file.id, 'names executable'),
          edge('r0', ip.id, 'names address'),
          edge('r0', host.id, 'observed on'),
          edge('r1', alice.id, 'names account'),
        ],
      ),
    )
    expect(node(g, `entity:${digest.id}`).x).toBe(1)
    expect(node(g, `entity:${file.id}`).x).toBe(2)
    expect(node(g, `entity:${alice.id}`).x).toBe(1)
    const infra = g.nodes.filter((n) => n.lane === 'infra').map((n) => n.x)
    expect(infra.sort()).toEqual([0, 0.5])
  })
})

/** The builder's shapes, so one story can come from buildStories and be drawn end to end. */
class Fixture {
  nodes: RelationshipNode[] = []
  edges: RelationshipEdge[] = []
  private refs = new Map<string, RelationshipRef>()
  entity(kind: string, value: string, scope = '', label?: string): string {
    const id = `${kind}:${scope}:${value}`
    if (!this.nodes.some((n) => n.id === id)) this.nodes.push({ id, kind, value, scope, label: label ?? value })
    return id
  }
  record(source: 'events' | 'mails', id: number, opts: { title: string; sourceFile: string; ts?: number | null; observedAt?: number | null }): string {
    const value = `${source}:${id}:9`
    const nodeId = `record:${value}`
    this.nodes.push({ id: nodeId, kind: 'record', value, scope: '', label: opts.title })
    this.refs.set(nodeId, {
      id,
      evidenceId: 9,
      source,
      sourceFile: opts.sourceFile,
      sourceSha256: null,
      sourceIndex: id,
      recordKind: opts.observedAt != null ? 'observation' : 'event',
      ts: opts.ts ?? null,
      observedAt: opts.observedAt ?? null,
      title: opts.title,
    })
    return nodeId
  }
  link(source: string, target: string, relation: string, confidence = 'high'): void {
    const ref = this.refs.get(source) ?? this.refs.get(target)
    this.edges.push({ source, target, relation, reason: relation, confidence, refs: ref ? [ref] : [], count: 1 })
  }
  result(): RelationshipResult {
    return { nodes: this.nodes, edges: this.edges, stats: { events: 0, mails: 0, truncated: false, rowCap: 20000, referenceCap: 30 } }
  }
}
const dbFinding = (p: Partial<Finding> & { refs: number[]; source: 'events' | 'mails' }): Finding => ({
  caseId: 1,
  ruleId: 'r',
  key: 'k',
  title: 'A finding',
  severity: 'high',
  ts: T0,
  entities: {},
  count: 1,
  attack: [],
  status: 'new',
  createdAt: T0,
  ...p,
})

/** A phishing mail, the DNS query for its link domain, and the collected process carrying the attachment digest. */
function phishingStory() {
  const f = new Fixture()
  const mail = f.record('mails', 1, { title: 'Invoice 2026-08', sourceFile: 'mailbox/invoice.eml', ts: T0 })
  const digest = f.entity('hash', 'sha256:' + 'ab12'.repeat(16))
  const sender = f.entity('account', 'billing@evil.test')
  const url = f.entity('url', 'https://evil-login.test/x')
  const domain = f.entity('domain', 'evil-login.test')
  f.link(mail, digest, 'attachment digest')
  f.link(mail, sender, 'sent by', 'contextual')
  f.link(mail, url, 'contains URL')
  f.link(url, domain, 'has host')
  const host = f.entity('host', 'ws01')
  const proc = f.record('events', 10, { title: 'process upd.exe', sourceFile: 'Processes/processes.csv', observedAt: T0 + 30 * H })
  const file = f.entity('file', 'c:\\users\\jdoe\\downloads\\upd.exe', 'ws01')
  const instance = f.entity('process', '{guid-1}', 'ws01', 'upd.exe · {guid-1}')
  f.link(proc, host, 'observed on')
  f.link(proc, file, 'names executable')
  f.link(proc, instance, 'observed process')
  f.link(instance, file, 'uses executable')
  f.link(proc, digest, 'reports hash')
  f.link(file, digest, 'reported digest')
  const dns = f.record('events', 20, { title: 'DNS query evil-login.test', sourceFile: 'Sysmon.evtx', ts: T0 + 2 * H })
  f.link(dns, host, 'observed on')
  f.link(dns, domain, 'names domain')
  const { stories } = buildStories(f.result(), [dbFinding({ source: 'mails', refs: [1], title: 'Credential phishing', severity: 'high', ruleId: 'mail-phish' })], [])
  const s = stories.find((x) => x.title === 'Credential phishing')
  if (!s) throw new Error('the phishing story was not built')
  return { s, mail, dns, proc, digest, host, domain, url, file, instance, sender }
}

describe('a story from buildStories', () => {
  it('is drawn end to end: records across the middle lanes, the bridge on the artifact lane between them', () => {
    const { s, mail, dns, proc, digest, host, domain, url, file, instance, sender } = phishingStory()
    const g = buildStoryGraph(s)
    // the mail is the anchor (seeded by the finding); the process was seeded by the digest seen in two sources and is a
    // step; the DNS query was only reached
    expect(recordNodes(g).map((n) => [n.id, n.lane, n.kind, n.x])).toEqual([
      [`record:${mail}`, 'mail', 'seed', 0],
      [`record:${dns}`, 'host', 'routine', 1],
      [`record:${proc}`, 'host', 'step', 2],
    ])
    expect(node(g, `entity:${digest}`).entityId).toBe(digest)
    expect(node(g, `record:${proc}`).recordIds).toEqual([proc])
    expect(node(g, `record:${mail}`)).toMatchObject({ severity: 'high', sub: 'mail · invoice.eml', ts: T0 })
    expect(node(g, `record:${proc}`)).toMatchObject({ sub: 'collected · processes.csv', ts: T0 + 30 * H })
    expect(node(g, `record:${proc}`).detail).toContain('via digest sha256:' + 'ab12'.repeat(16))
    expect(g.columns).toBe(3)
    const d = node(g, `entity:${digest}`)
    expect(d).toMatchObject({ lane: 'artifact', kind: 'hash', linked: true, sub: 'digest · 2 sources', x: 1 })
    expect(g.edges.filter((e) => e.kind === 'artifact')).toEqual([
      { source: `record:${mail}`, target: d.id, kind: 'artifact', label: 'attachment digest' },
      { source: `record:${proc}`, target: d.id, kind: 'artifact', label: 'reports hash' },
    ])
    expect(node(g, `entity:${host}`)).toMatchObject({ lane: 'infra', kind: 'host', linked: false, x: 1.5 })
    expect(node(g, `entity:${domain}`)).toMatchObject({ lane: 'attacker', kind: 'domain', x: 1 })
    expect(node(g, `entity:${url}`)).toMatchObject({ lane: 'attacker', kind: 'domain', x: 0 })
    expect(node(g, `entity:${sender}`)).toMatchObject({ lane: 'identity', kind: 'address', x: 0, entity: { kind: 'address', value: 'billing@evil.test' } })
    expect(node(g, `entity:${file}`)).toMatchObject({ lane: 'artifact', kind: 'file', label: 'upd.exe', x: 2 })
    expect(node(g, `entity:${instance}`)).toMatchObject({ lane: 'artifact', kind: 'process', x: 2.5 })
    expect(g.edges).toContainEqual({ source: `entity:${url}`, target: `entity:${domain}`, kind: 'entity', label: 'has host' })
    expect(g.edges).toContainEqual({ source: `entity:${instance}`, target: `entity:${file}`, kind: 'entity', label: 'uses executable' })
    expect(g.edges).toContainEqual({ source: `entity:${file}`, target: `entity:${digest}`, kind: 'entity', label: 'reported digest' })
    // every edge joins two drawn nodes
    const ids = new Set(g.nodes.map((n) => n.id))
    for (const e of g.edges) expect(ids.has(e.source) && ids.has(e.target)).toBe(true)
  })

  it('is laid out by the chain renderer with fixed positions: the artifact lane between host and infra, the selected record outlined', () => {
    const { s, mail, dns, digest, file, host } = phishingStory()
    const g = buildStoryGraph(s)
    type Datum = { id: string; symbol: string; x?: number; y?: number; itemStyle: { borderWidth: number } }
    const opt = graphOption(g, 'chain', 1200, 700, PRINT_TOKENS, null, true, `record:${mail}`) as unknown as { series: { layout: string; data: Datum[] }[] }
    const data = opt.series[0].data
    const of = (id: string) => {
      const d = data.find((x) => x.id === id)
      if (!d) throw new Error(`no datum ${id}`)
      return d
    }
    expect(opt.series[0].layout).toBe('none')
    const y = (id: string) => {
      const v = of(id).y
      if (v == null) throw new Error(`${id} has no fixed position`)
      return v
    }
    expect(y('lane:mail')).toBeLessThan(y('lane:host'))
    expect(y('lane:host')).toBeLessThan(y('lane:artifact'))
    expect(y('lane:artifact')).toBeLessThan(y('lane:infra'))
    expect(data.some((d) => d.id === 'lane:cloud')).toBe(false)
    // the digest sits inside the artifact lane, the mail inside the mailbox lane
    expect(y(`entity:${digest}`)).toBeGreaterThan(y('lane:artifact'))
    expect(y(`entity:${digest}`)).toBeLessThan(y('lane:infra'))
    expect(y(`record:${mail}`)).toBeLessThan(y('lane:host'))
    expect(of(`record:${mail}`).itemStyle.borderWidth).toBe(3)
    expect(of(`record:${dns}`).itemStyle.borderWidth).toBe(0)
    expect(of(`record:${mail}`).symbol).toBe('diamond')
    expect(of(`entity:${digest}`).symbol).toBe('triangle')
    expect(of(`entity:${file}`).symbol).toBe('rect')
    expect(of(`entity:${host}`).symbol).toBe('circle')
    expect(of(`record:${dns}`).x).toBeGreaterThan(of(`record:${mail}`).x ?? Infinity)
  })
})
