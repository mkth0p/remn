import { afterEach, expect, it, vi } from 'vitest'
import { buildRelationships, relationshipRow, mergeRelationships, scanRelationships, type RelationshipResult } from './relationships'
import { relationshipKey, reportRelationships, saveRelationshipReview, strandedRelationships, type RelationshipReview } from './relationshipReviews'
import { duplicateEvidence } from './duplicateEvidence'
import { defaultSettings, getDb } from '../db/schema'
import { caseSummary } from './queries'

const post = vi.hoisted(() => vi.fn(async (_url: string, _body: Record<string, unknown>) => ({ nodes: [], edges: [], stats: {} })))
vi.mock('../api/client', () => ({ apiPost: post }))

it('scans through later sources and keeps progress when stopped', async () => {
  const first: RelationshipResult = {
    nodes: [],
    edges: [],
    stats: { events: 1000, mails: 0, truncated: false, rowCap: 20000, referenceCap: 30 },
    cursor: { events: 1000, mails: 0 },
    processContext: [{ id: 5000 }],
    processContextTruncated: true,
  }
  const second: RelationshipResult = { ...first, stats: { ...first.stats, events: 12 }, cursor: null }
  const load = vi.fn(async (previous: RelationshipResult | null) => (previous ? second : first))
  const all = await scanRelationships(
    null,
    load,
    () => false,
    () => {},
  )
  expect(all?.stats.events).toBe(1012)
  expect(all?.cursor).toBeNull()
  expect(load.mock.calls[1][0]?.processContextTruncated).toBe(true)
  let stop = false
  const partial = await scanRelationships(
    null,
    load,
    () => stop,
    () => {
      stop = true
    },
  )
  expect(partial?.cursor?.events).toBe(1000)
  expect(partial?.stats.events).toBe(1000)
})

it('keeps an incomplete process context explicitly incomplete on subsequent requests', async () => {
  await buildRelationships({ id: 1, name: 'case', createdAt: 1, updatedAt: 1, settings: defaultSettings() }, undefined, { events: 1000, mails: 0 }, {}, [{ id: 1 }], true)
  expect(post.mock.calls.at(-1)?.[1]).toMatchObject({ truncated: true })
})
afterEach(async () => {
  for (const table of getDb().tables) await table.clear()
  post.mockClear()
})

it('omits message content and attachment analysis from graph requests while keeping provenance', () => {
  expect(relationshipRow({ id: 1, raw: 'raw', data: {}, hiddenText: 'secret', sourceFile: 'member.eml', attachments: [{ name: 'a', sha256: 'abc', details: { large: 'analysis' } }] })).toEqual({
    id: 1,
    sourceFile: 'member.eml',
    attachments: [{ name: 'a', sha256: 'abc' }],
  })
})
it('scopes graph input to the selected case and evidence', async () => {
  await getDb().events.bulkAdd([
    { caseId: 1, evidenceId: 1, ts: null, eventId: null, recordKind: 'observation' },
    { caseId: 2, evidenceId: 1, ts: 1, eventId: 1 },
    { caseId: 1, evidenceId: 2, ts: 1, eventId: 1 },
  ])
  await buildRelationships({ id: 1, name: 'test', createdAt: 1, updatedAt: 1, settings: defaultSettings() }, 1)
  const body = post.mock.calls[0][1] as { events: Record<string, unknown>[] }
  expect(body.events).toHaveLength(1)
  expect(body.events[0]).toMatchObject({ evidenceId: 1, recordKind: 'observation' })
})
it('retains signed reference lineage for imported deception observations', async () => {
  const row = {
    caseId: 1,
    evidenceId: 1,
    ts: 1,
    eventId: null,
    recordKind: 'event' as const,
    artifactType: 'deception',
    deceptionEpisodeId: 'a'.repeat(32),
    deceptionExhibitId: 'b'.repeat(32),
    deceptionParentExhibitId: 'c'.repeat(32),
    deceptionScope: 'challenge',
    deceptionStage: 3,
    data: { private: 'not forwarded' },
  }
  await getDb().events.add(row)
  await buildRelationships({ id: 1, name: 'archive', createdAt: 1, updatedAt: 1, settings: defaultSettings() }, 1)
  const events = (post.mock.calls[0][1] as { events: Record<string, unknown>[] }).events
  expect(events[0]).toMatchObject({
    artifactType: 'deception',
    deceptionEpisodeId: row.deceptionEpisodeId,
    deceptionExhibitId: row.deceptionExhibitId,
    deceptionParentExhibitId: row.deceptionParentExhibitId,
    deceptionScope: 'challenge',
    deceptionStage: 3,
  })
  expect(events[0]).not.toHaveProperty('data')
})
it('keeps package event and mail ranges separate without inventing snapshot times', async () => {
  await getDb().evidence.add({
    caseId: 1,
    name: 'p.zip',
    kind: 'package',
    size: 1,
    status: 'done',
    integrity: 'verified',
    count: 5,
    addedAt: 1000,
    stats: { eventRange: { firstTs: 10, lastTs: 20 }, mailRange: { firstTs: 1, lastTs: 2 }, observations: 3 },
  })
  const summary = await caseSummary(1)
  expect(summary.eventsTimeRange).toEqual({ firstIso: new Date(10).toISOString(), lastIso: new Date(20).toISOString() })
  expect(summary.mailsTimeRange).toEqual({ firstIso: new Date(1).toISOString(), lastIso: new Date(2).toISOString() })
})

it('pages without skipping IDs and includes process context from later pages', async () => {
  const db = getDb()
  await db.events.bulkAdd(Array.from({ length: 1002 }, (_, i) => ({ id: i + 1, caseId: 1, evidenceId: 1, ts: null, eventId: null, ...(i === 1001 ? { artifactType: 'process' } : {}) })))
  const kase = { id: 1, name: 'test', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
  const first = await buildRelationships(kase)
  expect(first.cursor).toEqual({ events: 1000, mails: 0 })
  expect(post.mock.calls[0][1]).toMatchObject({ processContext: [{ id: 1002, evidenceId: 1, artifactType: 'process' }] })
  const next = await buildRelationships(kase, undefined, first.cursor!)
  expect(next.cursor).toBeNull()
  expect((post.mock.calls[1][1] as { events: { id: number }[] }).events.map((e) => e.id)).toEqual([1001, 1002])
}, 15000)

it('merges graph pages without duplicating entities and retains support totals', () => {
  const page: RelationshipResult = {
    nodes: [
      { id: 'a', kind: 'host', scope: '', value: 'A', label: 'A' },
      { id: 'b', kind: 'host', scope: '', value: 'B', label: 'B' },
    ],
    edges: [{ source: 'a', target: 'b', relation: 'link', reason: 'source', confidence: 'high', refs: [], count: 1 }],
    stats: { events: 1, mails: 0, truncated: false, rowCap: 20000, referenceCap: 30 },
  }
  const merged = mergeRelationships(page, page)
  expect(merged.nodes).toHaveLength(2)
  expect(merged.edges).toHaveLength(1)
  expect(merged.edges[0].count).toBe(2)
  expect(merged.stats.events).toBe(2)
})

it('retains review identity across restore and excludes removed or rejected evidence from reports', async () => {
  const ref = {
    id: 5,
    evidenceId: 9,
    source: 'events' as const,
    sourceFile: 'processes.csv',
    sourceSha256: 'abc',
    sourceIndex: 0,
    recordKind: 'observation',
    ts: null,
    observedAt: 1,
    title: 'process',
  }
  const edge = { source: 'record-5', target: 'host', relation: 'observed on', reason: 'collected', confidence: 'high', refs: [ref], count: 1 }
  const nodes = new Map([
    ['record-5', { id: 'record-5', kind: 'record', scope: '', value: '5', label: 'process' }],
    ['host', { id: 'host', kind: 'host', scope: '', value: 'pc', label: 'pc' }],
  ])
  const key = relationshipKey(edge, nodes)
  expect(relationshipKey({ ...edge, refs: [{ ...ref, id: 50, evidenceId: 90 }] }, nodes)).toBe(key)
  const review: RelationshipReview = {
    key,
    status: 'accepted',
    includeInReport: true,
    notes: 'Analyst decision',
    sourceLabel: 'process',
    targetLabel: 'pc',
    relation: 'observed on',
    reason: 'collected',
    confidence: 'high',
    references: [ref],
    aliases: {},
    updatedAt: 1,
  }
  await getDb().evidence.add({ id: 9, caseId: 1, name: 'p.zip', kind: 'package', status: 'done', integrity: 'verified', size: 1, count: 1, addedAt: 1 })
  await saveRelationshipReview(1, review)
  expect(await reportRelationships(1)).toEqual([review])
  await saveRelationshipReview(1, { ...review, status: 'rejected' })
  expect(await reportRelationships(1)).toEqual([])
  await saveRelationshipReview(1, review)
  await getDb().evidence.delete(9)
  expect(await reportRelationships(1)).toEqual([])
})

it('skips only verified repeated sources and permits retries of failed packages', async () => {
  const evidence = { id: 1, caseId: 1, name: 'p.zip', kind: 'package' as const, status: 'done' as const, integrity: 'verified' as const, sha256Client: 'abc', count: 1, size: 1, addedAt: 1 }
  await getDb().evidence.add(evidence)
  expect((await duplicateEvidence(1, 2, 'p.zip', 'package', 'abc'))?.id).toBe(1)
  expect(await duplicateEvidence(2, 2, 'p.zip', 'package', 'abc')).toBeUndefined()
  expect(await duplicateEvidence(1, 2, 'other/p.zip', 'package', 'abc')).toBeUndefined()
  await getDb().evidence.update(1, { stats: { errors: 1 } })
  expect(await duplicateEvidence(1, 2, 'p.zip', 'package', 'abc')).toBeUndefined()
})

it('keeps review identity for imports that carry no member digest', async () => {
  // Only package members get sourceSha256; a plain .evtx or .eml import has none. The fallback
  // used to key on raw row IDs, so a case restore renumbered every row and orphaned the decisions.
  const ref = {
    id: 5,
    evidenceId: 9,
    source: 'events' as const,
    sourceFile: 'Security.evtx',
    sourceSha256: null,
    sourceIndex: 0,
    recordKind: 'event',
    ts: 1700000000000,
    observedAt: null,
    title: 'logon',
  }
  const edge = { source: 'record-5', target: 'host', relation: 'observed on', reason: 'collected', confidence: 'high', refs: [ref], count: 1 }
  const nodes = new Map([
    ['record-5', { id: 'record-5', kind: 'record', scope: '', value: '5', label: 'logon' }],
    ['host', { id: 'host', kind: 'host', scope: '', value: 'pc', label: 'pc' }],
  ])
  const key = relationshipKey(edge, nodes)
  const restored = relationshipKey({ ...edge, refs: [{ ...ref, id: 1005, evidenceId: 109 }] }, nodes)
  expect(restored).toBe(key)
})

it('keeps a reviewed relationship whose supporting references only partly survive', async () => {
  // references is a bounded sample of the support, not the whole of it, so requiring every sampled
  // reference to resolve dropped relationships whose evidence was still present.
  const base = { source: 'events' as const, sourceFile: 'a.csv', sourceSha256: 'abc', sourceIndex: 0, recordKind: 'observation', ts: null, observedAt: 1, title: 'x' }
  const live = { ...base, id: 1, evidenceId: 9 }
  const dead = { ...base, id: 2, evidenceId: 77 }
  const review: RelationshipReview = {
    key: 'k',
    status: 'accepted',
    includeInReport: true,
    notes: '',
    sourceLabel: 'a',
    targetLabel: 'b',
    relation: 'observed on',
    reason: 'collected',
    confidence: 'high',
    references: [live, dead],
    aliases: {},
    updatedAt: 1,
  }
  await getDb().evidence.add({ id: 9, caseId: 1, name: 'p.zip', kind: 'package', status: 'done', integrity: 'verified', size: 1, count: 1, addedAt: 1 })
  await saveRelationshipReview(1, review)
  const reported = await reportRelationships(1)
  expect(reported).toHaveLength(1)
  expect(reported[0].references).toEqual([live])
  expect((await strandedRelationships(1)).evidenceGone).toBe(0)

  // when nothing survives it is dropped, and counted so the report can say so
  await saveRelationshipReview(1, { ...review, key: 'gone', references: [dead] })
  expect(await reportRelationships(1)).toHaveLength(1)
  expect((await strandedRelationships(1)).evidenceGone).toBe(1)
})

it('an unrelated alias edit keeps existing review keys', async () => {
  // The key used to embed the whole alias map, so adding one account alias re-keyed every review
  // in the case at once: the saved decisions orphaned while the rebuilt edges came back unreviewed,
  // and the report printed both.
  const ref = {
    id: 1,
    evidenceId: 9,
    source: 'events' as const,
    sourceFile: 'Security.evtx',
    sourceSha256: null,
    sourceIndex: 0,
    recordKind: 'event',
    ts: 1700000000000,
    observedAt: null,
    title: 'logon',
  }
  const edge = { source: 'acct', target: 'host', relation: 'observed on', reason: 'collected', confidence: 'high', refs: [ref], count: 1 }
  const nodes = new Map([
    ['acct', { id: 'acct', kind: 'account', scope: 'ws01', value: 'alice', label: 'alice' }],
    ['host', { id: 'host', kind: 'host', scope: '', value: 'ws01', label: 'ws01' }],
  ])
  expect(relationshipKey(edge, nodes)).toBe(relationshipKey(edge, nodes))

  // an alias that DOES matter still changes the key, because it changes the node value itself
  const aliased = new Map(nodes)
  aliased.set('host', { id: 'host', kind: 'host', scope: '', value: 'ws01.example', label: 'ws01.example' })
  expect(relationshipKey(edge, aliased)).not.toBe(relationshipKey(edge, nodes))
})

it('the report excludes accepted relationships the graph no longer produces', async () => {
  const ref = { id: 1, evidenceId: 9, source: 'events' as const, sourceFile: 'a.csv', sourceSha256: 'abc', sourceIndex: 0, recordKind: 'observation', ts: null, observedAt: 1, title: 'x' }
  const review: RelationshipReview = {
    key: 'still-here',
    status: 'accepted',
    includeInReport: true,
    notes: '',
    sourceLabel: 'a',
    targetLabel: 'b',
    relation: 'observed on',
    reason: 'collected',
    confidence: 'high',
    references: [ref],
    aliases: {},
    updatedAt: 1,
  }
  await getDb().evidence.add({ id: 9, caseId: 1, name: 'p.zip', kind: 'package', status: 'done', integrity: 'verified', size: 1, count: 1, addedAt: 1 })
  await saveRelationshipReview(1, review)
  await saveRelationshipReview(1, { ...review, key: 'vanished' })

  expect(await reportRelationships(1)).toHaveLength(2)
  const live = new Set(['still-here'])
  expect((await reportRelationships(1, live)).map((r) => r.key)).toEqual(['still-here'])
  expect(await strandedRelationships(1, live)).toEqual({ evidenceGone: 0, notProduced: 1 })
})
