import { describe, expect, it } from 'vitest'
import type { Finding, RowMark } from '../db/schema'
import { buildStories, recordTime, scoreStory, type StoryEntity } from './relationshipStories'
import type { RelationshipEdge, RelationshipNode, RelationshipRef, RelationshipResult } from './relationships'

const H = 3_600_000
const T0 = Date.UTC(2026, 7, 19, 8, 0, 0)

it('bounds snapshot-to-snapshot address links by collection time', () => {
  const f = new Fixture()
  const account = f.entity('ip', '198.51.100.42')
  for (const [id, elapsed] of [
    [1, 0],
    [2, H],
    [3, 10 * 24 * H],
  ]) {
    f.link(f.record('events', id, { title: `snapshot ${id}`, sourceFile: 'snapshot.csv', observedAt: T0 + elapsed }), account, 'names account')
  }
  const result = buildStories(f.result(), [], [mark('events', 1, 'pivot')])
  expect(result.stories[0].records.map((r) => r.id)).toEqual([1, 2])
})

it("expands a finding seed already reached at another seed's hop limit", () => {
  const f = new Fixture()
  const records = [1, 2, 3, 4, 5].map((id) => f.record('events', id, { title: `record ${id}`, sourceFile: 'host.csv', ts: T0 + id * H }))
  for (let i = 0; i < 4; i++) {
    const hash = f.entity('hash', `digest-${i}`)
    f.link(records[i], hash, 'reports hash')
    f.link(records[i + 1], hash, 'reports hash')
  }
  const result = buildStories(
    f.result(),
    [1, 2, 3, 4].map((id) => finding({ source: 'events', refs: [id], ruleId: `r${id}` })),
    [],
  )
  expect(result.stories).toHaveLength(1)
  expect(result.stories[0].records.map((r) => r.nodeId)).toEqual(records)
  expect(result.stories[0].records[4].via).toContainEqual(expect.objectContaining({ fromNodeId: records[3] }))
})

it('flags entity limits and keeps all exported link endpoints inside the story', () => {
  const f = new Fixture()
  const r = f.record('events', 1, { title: 'many entities', sourceFile: 'host.csv', ts: T0 })
  for (let i = 0; i < 81; i++) f.link(r, f.entity('file', `c:\\file${i}`, 'ws01'), 'names file')
  const result = buildStories(f.result(), [finding({ source: 'events', refs: [1] })], [])
  const s = result.stories[0]
  expect(s.entities).toHaveLength(80)
  expect(s.truncated && result.stats.truncated).toBe(true)
  const ids = new Set([...s.records.map((record) => record.nodeId), ...s.entities.map((entity) => entity.id)])
  expect(s.edges.every((edge) => ids.has(edge.source) && ids.has(edge.target))).toBe(true)
})

it('counts supporting records once across different relations and flags the link cap', () => {
  const f = new Fixture()
  const r = f.record('events', 1, { title: 'many relations', sourceFile: 'host.csv', ts: T0 })
  const hash = f.entity('hash', 'sha256:' + 'ab'.repeat(32))
  for (let i = 0; i < 601; i++) f.link(r, hash, `relation ${i}`)
  const result = buildStories(f.result(), [finding({ source: 'events', refs: [1] })], [])
  expect(result.stories[0].entities[0].records).toBe(1)
  expect(result.stories[0].edges).toHaveLength(600)
  expect(result.stories[0].truncated && result.stats.truncated).toBe(true)
})

/** A small builder that mirrors the shapes the backend produces: record nodes scoped "<source>:<id>:<evidence>", entities by kind. */
class Fixture {
  nodes: RelationshipNode[] = []
  edges: RelationshipEdge[] = []
  private refs = new Map<string, RelationshipRef>()
  entity(kind: string, value: string, scope = '', label?: string): string {
    const id = `${kind}:${scope}:${value}`
    if (!this.nodes.some((n) => n.id === id)) this.nodes.push({ id, kind, value, scope, label: label ?? value })
    return id
  }
  record(source: 'events' | 'mails', id: number | null, opts: { title: string; sourceFile: string; ts?: number | null; observedAt?: number | null; evidenceId?: number; index?: number }): string {
    const evidenceId = opts.evidenceId ?? 9
    const value = `${source}:${id ?? opts.index ?? 0}:${evidenceId}`
    const nodeId = `record:${value}`
    this.nodes.push({ id: nodeId, kind: 'record', value, scope: '', label: opts.title })
    this.refs.set(nodeId, {
      id,
      evidenceId,
      source,
      sourceFile: opts.sourceFile,
      sourceSha256: null,
      sourceIndex: opts.index ?? id,
      recordKind: opts.observedAt != null ? 'observation' : 'event',
      ts: opts.ts ?? null,
      observedAt: opts.observedAt ?? null,
      title: opts.title,
    })
    return nodeId
  }
  link(source: string, target: string, relation: string, confidence = 'high'): void {
    const ref = this.refs.get(source) ?? this.refs.get(target)
    const existing = this.edges.find((e) => e.source === source && e.target === target && e.relation === relation)
    if (existing) {
      existing.count++
      if (ref) existing.refs.push(ref)
      return
    }
    this.edges.push({ source, target, relation, reason: relation, confidence, refs: ref ? [ref] : [], count: 1 })
  }
  result(): RelationshipResult {
    return { nodes: this.nodes, edges: this.edges, stats: { events: 0, mails: 0, truncated: false, rowCap: 20000, referenceCap: 30 } }
  }
}

const finding = (p: Partial<Finding> & { refs: number[]; source: 'events' | 'mails' }): Finding => ({
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
const mark = (source: 'events' | 'mails', rowId: number, verdict: RowMark['verdict']): RowMark => ({
  caseId: 1,
  source,
  rowId,
  evidenceId: 9,
  verdict,
  tags: [],
  reason: '',
  by: 'analyst',
  createdAt: T0,
  updatedAt: T0,
})

/** Mail with an attachment digest, the same digest on a collected process, plus host events that share only the host. */
function caseFixture() {
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
  const logon = f.record('events', 21, { title: 'logon alice', sourceFile: 'Security.evtx', ts: T0 + 1 * H })
  const alice = f.entity('account', 'corp\\alice')
  const ip = f.entity('ip', '203.0.113.9')
  f.link(logon, host, 'observed on')
  f.link(logon, alice, 'names account')
  f.link(logon, ip, 'names address')
  const later = f.record('events', 22, { title: 'logon alice again', sourceFile: 'Security.evtx', ts: T0 + 10 * 24 * H })
  f.link(later, host, 'observed on')
  f.link(later, alice, 'names account')
  f.link(later, ip, 'names address')
  const unrelated = f.record('events', 99, { title: 'service started', sourceFile: 'System.evtx', ts: T0 + 3 * H })
  f.link(unrelated, host, 'observed on')
  return { f, mail, proc, dns, logon, later, unrelated, digest, host, ip, alice, domain, file }
}

describe('stories from the relationship graph', () => {
  it('a finding on a mail reaches the collected process through the attachment digest, and not the rest of the host', () => {
    const { f } = caseFixture()
    const { stories, stats } = buildStories(f.result(), [finding({ source: 'mails', refs: [1], title: 'Credential phishing', severity: 'high', ruleId: 'mail-phish' })], [])
    expect(stats.seeds).toEqual({ finding: 1, mark: 0, lead: 1 })
    const story = stories.find((s) => s.title === 'Credential phishing')!
    expect(story).toBeDefined()
    expect(story.records.map((r) => r.title)).toEqual(['Invoice 2026-08', 'DNS query evil-login.test', 'process upd.exe'])
    expect(story.severity).toBe('high')
    const proc = story.records.find((r) => r.title === 'process upd.exe')!
    expect(proc.hop).toBe(1)
    expect(proc.via.map((v) => [v.kind, v.relation])).toEqual(expect.arrayContaining([['hash', 'reports hash']]))
    expect(story.records.find((r) => r.title === 'logon alice')).toBeUndefined()
    const bridge = story.entities.find((e) => e.bridge)!
    expect(bridge.kind).toBe('hash')
    expect(bridge.sources.sort()).toEqual(['Processes/processes.csv', 'mailbox/invoice.eml'])
    expect(story.entities.find((e) => e.kind === 'host')?.bridge).toBe(false)
    expect(story.summary).toContain('digest sha256:ab12ab12ab12… ties invoice.eml, processes.csv')
    expect(story.summary).toContain('host ws01')
    expect(story.scoreBreakdown).toMatchObject({ findings: 24, bridges: 8, sources: 10 })
  })

  it('a medium entity joins records only inside the time window; a strong one ignores time', () => {
    const { f } = caseFixture()
    const { stories } = buildStories(f.result(), [finding({ source: 'events', refs: [21], title: 'Odd logon', severity: 'medium' })], [])
    const story = stories.find((s) => s.title === 'Odd logon')!
    expect(story.records.map((r) => r.title)).toEqual(['logon alice'])
    const { stories: wide } = buildStories(f.result(), [finding({ source: 'events', refs: [21], title: 'Odd logon', severity: 'medium' })], [], { windowMs: 30 * 24 * H })
    expect(wide.find((s) => s.title === 'Odd logon')!.records.map((r) => r.title)).toEqual(['logon alice', 'logon alice again'])
  })

  it('an entity named by too many records is a hub: context, never a path', () => {
    const { f, ip } = caseFixture()
    for (let i = 0; i < 5; i++) {
      const r = f.record('events', 200 + i, { title: `noise ${i}`, sourceFile: 'Security.evtx', ts: T0 + 1 * H + i })
      f.link(r, ip, 'names address')
    }
    const { stories, stats } = buildStories(f.result(), [finding({ source: 'events', refs: [21], title: 'Odd logon' })], [], { hubRecords: 4 })
    const story = stories.find((s) => s.title === 'Odd logon')!
    expect(story.records).toHaveLength(1)
    expect(story.entities.find((e) => e.kind === 'ip')).toMatchObject({ hub: true, bridge: false })
    expect(stats.hubs).toBe(2) // the address, and the host every record names
  })

  it('a cross-source seed story merges with the finding story that touches it', () => {
    const { f } = caseFixture()
    const seedDns = finding({ source: 'events', refs: [20], title: 'DNS to a phishing domain', severity: 'high' })
    // dns -> domain -> url -> mail (2 h apart, inside the window); the mail already sits in the
    // story the shared digest seeded with the process, so the two become one
    const { stories } = buildStories(f.result(), [seedDns], [])
    const story = stories.find((s) => s.title === 'DNS to a phishing domain')!
    expect(story.records.map((r) => r.title)).toEqual(['Invoice 2026-08', 'DNS query evil-login.test', 'process upd.exe'])
    expect(stories.filter((s) => s.records.some((r) => r.title === 'Invoice 2026-08'))).toHaveLength(1)
    const mail = story.records.find((r) => r.title === 'Invoice 2026-08')!
    // reached from the DNS query through the URL, and from the process through the digest
    expect(mail.via.map((v) => [v.kind, v.relation]).sort()).toEqual([
      ['hash', 'attachment digest'],
      ['url', 'contains URL'],
    ])
    expect(mail.seed).toEqual(['lead'])
  })

  it('expansion continues past a record only when that record carries a finding or a mark', () => {
    const f = new Fixture()
    const ip = f.entity('ip', '198.51.100.7')
    const bob = f.entity('logon-session', 'boot1:123', 'ws01')
    const logon = f.record('events', 1, { title: 'logon from the address', sourceFile: 'Security.evtx', ts: T0 })
    const rdp = f.record('events', 2, { title: 'rdp session', sourceFile: 'TerminalServices.evtx', ts: T0 + 1 * H })
    const bobMail = f.record('mails', 3, { title: 'bob forwards the invoice', sourceFile: 'bob.eml', ts: T0 + 2 * H })
    f.link(logon, ip, 'names address')
    f.link(rdp, ip, 'names address')
    f.link(rdp, bob, 'names account')
    f.link(bobMail, bob, 'sent by')
    const seed = finding({ source: 'events', refs: [1], title: 'Logon from a known bad address', severity: 'high' })
    const leaf = buildStories(f.result(), [seed], []).stories[0]
    expect(leaf.records.map((r) => r.title)).toEqual(['logon from the address', 'rdp session'])
    const marked = buildStories(f.result(), [seed], [mark('events', 2, 'relevant')]).stories[0]
    expect(marked.records.map((r) => r.title)).toEqual(['logon from the address', 'rdp session', 'bob forwards the invoice'])
    expect(marked.records[2].hop).toBe(2)
    expect(marked.records[2].via[0]).toMatchObject({ kind: 'logon-session', relation: 'sent by', fromNodeId: rdp })
  })

  it('analyst marks seed stories, add to the score, and a noise mark keeps a row out', () => {
    const { f } = caseFixture()
    const marked = buildStories(f.result(), [], [mark('events', 21, 'pivot'), mark('events', 99, 'relevant')]).stories
    const pivot = marked.find((s) => s.records.some((r) => r.title === 'logon alice'))!
    expect(pivot.records[0].seed).toEqual(['mark'])
    expect(pivot.scoreBreakdown.marks).toBe(6)
    expect(marked.find((s) => s.records.some((r) => r.title === 'service started'))?.scoreBreakdown.marks).toBe(4)
    const silenced = buildStories(f.result(), [finding({ source: 'mails', refs: [1] })], [mark('events', 10, 'noise')]).stories[0]
    expect(silenced.records.map((r) => r.title)).not.toContain('process upd.exe')
  })

  it('without findings or marks, cross-source entities still seed stories', () => {
    const { f } = caseFixture()
    const { stories, stats } = buildStories(f.result(), [], [])
    expect(stats.seeds.lead).toBeGreaterThan(0)
    expect(stories[0].title).toBe('digest sha256:ab12ab12ab12… in 2 sources')
    expect(stories[0].severity).toBe('info')
    expect(stories[0].score).toBe(18) // one strong bridge (8) across three sources (10): the DNS query joins through the link
  })

  it('ranks by severity, then by corroboration, and ignores false positives', () => {
    const { f } = caseFixture()
    const findings = [
      finding({ source: 'events', refs: [99], title: 'Lonely critical', severity: 'critical', ruleId: 'a' }),
      finding({ source: 'mails', refs: [1], title: 'Corroborated high', severity: 'high', ruleId: 'b' }),
      finding({ source: 'events', refs: [21], title: 'Dismissed', severity: 'critical', ruleId: 'c', status: 'false_positive' }),
      finding({ source: 'events', refs: [22], title: 'Downgraded', severity: 'critical', severityOverride: 'low', ruleId: 'd' }),
    ]
    const { stories } = buildStories(f.result(), findings, [])
    expect(stories.map((s) => s.title)).toEqual(['Lonely critical', 'Corroborated high', 'Downgraded'])
    // the story hangs from its strongest seed: the mail with the high finding, not the process the digest seeded
    expect(stories[1].anchor).toBe('record:mails:1:9')
    expect(stories[1].id).toBe('story:mails:1:9')
    expect(stories[0].score).toBeLessThan(stories[1].score)
    expect(stories.find((s) => s.title === 'Dismissed')).toBeUndefined()
    expect(stories[2].severity).toBe('low')
  })

  it('orders records by event time, then collection time, and keeps untimed records last', () => {
    const f = new Fixture()
    const shared = f.entity('hash', 'sha256:' + 'cd'.repeat(32))
    const a = f.record('events', 1, { title: 'late event', sourceFile: 'a.evtx', ts: T0 + 5 * H })
    const b = f.record('events', 2, { title: 'collected', sourceFile: 'b.csv', observedAt: T0 + 1 * H })
    const c = f.record('events', 3, { title: 'untimed', sourceFile: 'c.csv' })
    const d = f.record('events', 4, { title: 'early event', sourceFile: 'd.evtx', ts: T0 })
    for (const r of [a, b, c, d]) f.link(r, shared, 'reports hash')
    const { stories } = buildStories(f.result(), [finding({ source: 'events', refs: [1] })], [])
    expect(stories[0].records.map((r) => r.title)).toEqual(['early event', 'collected', 'late event', 'untimed'])
    expect(stories[0].start).toBe(T0)
    expect(stories[0].end).toBe(T0 + 5 * H)
    expect(recordTime({ ts: null, observedAt: 5 })).toBe(5)
  })

  it('caps a story and the number of stories, and says so', () => {
    const f = new Fixture()
    const shared = f.entity('hash', 'sha256:' + 'ef'.repeat(32))
    for (let i = 1; i <= 12; i++) f.link(f.record('events', i, { title: `r${i}`, sourceFile: 'a.csv', ts: T0 + i }), shared, 'reports hash')
    const big = buildStories(f.result(), [finding({ source: 'events', refs: [1] })], [], { maxStoryRecords: 5 })
    expect(big.stories[0].records).toHaveLength(5)
    expect(big.stories[0].truncated).toBe(true)
    expect(big.stats.truncated).toBe(true)
    const many = new Fixture()
    for (let i = 1; i <= 4; i++) many.link(many.record('events', i, { title: `lone ${i}`, sourceFile: 'a.evtx', ts: T0 }), many.entity('host', `h${i}`), 'observed on')
    const few = buildStories(
      many.result(),
      [1, 2, 3, 4].map((i) => finding({ source: 'events', refs: [i], ruleId: `r${i}` })),
      [],
      { maxStories: 2 },
    )
    expect(few.stories).toHaveLength(2)
    expect(few.stats.truncated).toBe(true)
  })

  it('an empty or absent graph yields no stories', () => {
    expect(buildStories(null, [], []).stories).toEqual([])
    expect(buildStories({ nodes: [], edges: [], stats: { events: 0, mails: 0, truncated: false, rowCap: 1, referenceCap: 1 } }, [], []).stories).toEqual([])
  })

  it('score parts are bounded', () => {
    const entity = (kind: string, weight: number): StoryEntity => ({ id: kind, kind, label: kind, value: kind, scope: '', records: 2, sources: ['a', 'b'], weight, bridge: true, hub: false })
    const s = scoreStory(
      Array.from({ length: 9 }, () => ({ severity: 'critical' as const, count: 1 })),
      [entity('hash', 8), entity('file', 6), entity('process', 6), entity('url', 5), entity('ip', 3), entity('domain', 3), entity('account', 2)],
      ['a', 'b', 'c', 'd', 'e', 'f'],
      Array.from({ length: 5 }, (_, i) => ({ nodeId: `record:${i}`, marks: ['pivot' as const] }) as never),
    )
    expect(s).toEqual({ findings: 40, bridges: 30, sources: 15, marks: 15, total: 100 })
  })
})
