import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { CASE_TABLES, defaultSettings, deleteCaseData, RemnDB, setDb, type Case } from '../db/schema'
import { clearRowMarks, loadRowMarks, markedRowIds, markRows, rowMarkSummary, rowProvenance } from './rowMarks'
import { restoreCaseBundle, writeCaseBundle } from './caseBundle'

vi.mock('../api/client', () => ({ apiPost: vi.fn(), API_HEADERS: {}, readNdjsonBody: vi.fn() }))

let db: RemnDB
const kase: Case = { id: 1, name: 'Marked case', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }

const event = (id: number, extra: Record<string, unknown> = {}) => ({
  id,
  caseId: 1,
  evidenceId: 7,
  ts: 1_700_000_000_000 + id,
  eventId: 4624,
  channel: 'Security',
  computer: 'WS01',
  recordId: 9000 + id,
  sourceFile: 'Security.evtx',
  summary: `logon ${id}`,
  ...extra,
})

beforeEach(async () => {
  db = new RemnDB(`marks-${Math.random()}`)
  setDb(db)
  await db.cases.add(kase)
  await db.evidence.add({ id: 7, caseId: 1, name: 'Security.evtx', kind: 'evtx', status: 'done', integrity: 'verified', size: 1, count: 3, addedAt: 1 } as never)
  await db.events.bulkAdd([event(1), event(2), event(3)] as never[])
})
afterEach(async () => {
  await db.delete()
  setDb(null)
})

it('marks rows in bulk, merges tags on re-mark and keeps the first decision time', async () => {
  await markRows(1, 'events', [event(1), event(2)], { verdict: 'noise', addTags: ['scanner'], reason: 'known vulnerability scan' })
  let marks = await loadRowMarks(1, 'events', [1, 2, 3])
  expect(marks.size).toBe(2)
  expect(marks.get(1)).toMatchObject({ verdict: 'noise', tags: ['scanner'], reason: 'known vulnerability scan', by: 'analyst' })
  const firstDecision = marks.get(1)!.createdAt

  await markRows(1, 'events', [event(1)], { verdict: 'pivot', addTags: ['lateral'] })
  marks = await loadRowMarks(1, 'events', [1])
  // a second decision refines the mark rather than replacing it, and the reason survives
  expect(marks.get(1)).toMatchObject({ verdict: 'pivot', tags: ['lateral', 'scanner'], reason: 'known vulnerability scan' })
  expect(marks.get(1)!.createdAt).toBe(firstDecision)

  await markRows(1, 'events', [event(1)], { removeTags: ['scanner'] })
  expect((await loadRowMarks(1, 'events', [1])).get(1)!.tags).toEqual(['lateral'])
})

it('captures the provenance of the row so a later re-ingest can be re-attached', async () => {
  await markRows(1, 'events', [event(1)], { verdict: 'relevant' })
  const mark = (await loadRowMarks(1, 'events', [1])).get(1)!
  expect(mark.provenance).toMatchObject({ sourceFile: 'Security.evtx', recordId: 9001, channel: 'Security', computer: 'WS01' })
  expect(mark.evidenceId).toBe(7)
})

it('reads back the marked ids and a summary for filtering and facets', async () => {
  await markRows(1, 'events', [event(1), event(2)], { verdict: 'noise', addTags: ['scanner'] })
  await markRows(1, 'events', [event(3)], { verdict: 'pivot', addTags: ['lateral', 'scanner'] })

  expect((await markedRowIds(1, 'events')).ids.sort()).toEqual([1, 2, 3])
  expect((await markedRowIds(1, 'events', { verdict: 'pivot' })).ids).toEqual([3])
  expect((await markedRowIds(1, 'events', { tag: 'scanner' })).ids.sort()).toEqual([1, 2, 3])
  expect((await markedRowIds(1, 'events', {}, 2)).truncated).toBe(true)

  const summary = await rowMarkSummary(1)
  expect(summary).toMatchObject({ total: 3, verdicts: { noise: 2, pivot: 1 }, tags: { scanner: 3, lateral: 1 } })

  expect(await clearRowMarks(1, 'events', [1, 2])).toBe(2)
  expect((await markedRowIds(1, 'events')).ids).toEqual([3])
})

it('marks of one case never reach another, and are removed with the case', async () => {
  await db.cases.add({ ...kase, id: 2, name: 'Other' })
  await markRows(1, 'events', [event(1)], { verdict: 'noise' })
  await markRows(2, 'events', [{ ...event(1), caseId: 2 }], { verdict: 'pivot' })

  expect((await rowMarkSummary(1)).total).toBe(1)
  expect((await rowMarkSummary(2)).total).toBe(1)

  // the delete list is derived from one place; a table missing from it would leak rows here
  expect(CASE_TABLES(db).map((t) => t.name)).toContain('rowMarks')
  await deleteCaseData(db, 1)
  expect((await rowMarkSummary(1)).total).toBe(0)
  expect((await rowMarkSummary(2)).total).toBe(1)
})

it('survives a backup and restore with the mark still on the right row', async () => {
  await markRows(1, 'events', [event(2)], { verdict: 'pivot', addTags: ['lateral'], reason: 'first lateral move' })

  const chunks: string[] = []
  await writeCaseBundle(kase, {
    write: async (text) => {
      chunks.push(text)
    },
  })
  const restored = await restoreCaseBundle(new File(chunks, 'case.remn.ndjson'))

  const events = await db.events.where('caseId').equals(restored).sortBy('ts')
  const marks = await db.rowMarks.where('caseId').equals(restored).toArray()
  expect(marks).toHaveLength(1)
  // the row ids were renumbered by the restore; the mark must follow its row, not keep the old id
  expect(marks[0].rowId).not.toBe(2)
  expect(marks[0].rowId).toBe(events[1].id)
  expect(marks[0]).toMatchObject({ verdict: 'pivot', tags: ['lateral'], reason: 'first lateral move' })
  expect((await db.events.get(marks[0].rowId))?.summary).toBe('logon 2')
})

it('reads provenance out of a mail row using its own fields', () => {
  const provenance = rowProvenance({ id: 5, messageId: '<a@b.example>', date: 1_700_000_000_000, sourceFile: 'inbox.mbox' }, 'mails')
  expect(provenance).toMatchObject({ messageId: '<a@b.example>', ts: 1_700_000_000_000, sourceFile: 'inbox.mbox', channel: null })
})

it('an existing version-3 case opens on version 4 without losing a row', async () => {
  // The upgrade adds a table and touches no existing store, so it must need no upgrade function
  // and must not rewrite anything. This opens a real v3 database and then the current schema.
  const { default: Dexie } = await import('dexie')
  const name = `upgrade-${Math.random()}`
  const old = new Dexie(name)
  old.version(3).stores({
    cases: '++id, name, createdAt',
    evidence: '++id, caseId, kind, status, sha256Client',
    events:
      '++id, caseId, evidenceId, ts, eventId, [caseId+id], [caseId+artifactType], [caseId+ts], [caseId+eventId], [caseId+evidenceId], computer, targetUser, subjectUser, ipAddress, logonType, channel, provider, category',
    kv: 'key',
  })
  await old.open()
  await old.table('cases').add({ id: 1, name: 'Existing', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() })
  await old.table('events').add(event(1))
  await old.table('kv').put({ key: 'chains-1', value: { chains: [] } })
  old.close()

  const upgraded = new RemnDB(name)
  setDb(upgraded)
  await upgraded.open()
  expect(upgraded.verno).toBe(4)
  // nothing was rewritten or lost
  expect((await upgraded.events.where('caseId').equals(1).toArray()).map((e) => e.id)).toEqual([1])
  expect((await upgraded.kv.get('chains-1'))?.value).toEqual({ chains: [] })
  // and the new table is usable straight away
  await markRows(1, 'events', [event(1)], { verdict: 'relevant', addTags: ['carried over'] })
  expect((await rowMarkSummary(1)).total).toBe(1)
  await upgraded.delete()
})
