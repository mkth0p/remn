import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { RemnDB, setDb } from '../db/schema'
import { persistEngineFindings, refKey, resolveEngineRefs, type EngineFinding } from './engineFindings'
import { pruneOrphanFindings } from './findingReviews'

vi.mock('../api/client', () => ({ apiPost: vi.fn(), API_HEADERS: {} }))

let db: RemnDB
beforeEach(() => {
  db = new RemnDB(`engine-${Math.random()}`)
  setDb(db)
})
afterEach(async () => {
  await db.delete()
})

const detection = (record: number, ruleId = 'engine:hayabusa:susp-downloads-exec'): EngineFinding => ({
  ruleId,
  key: `${ruleId}|WS01|Security|${record}`,
  title: 'Suspicious Process Creation In Downloads',
  severity: 'high',
  source: 'events',
  ts: 1,
  entities: { computer: 'WS01', channel: 'Security' },
  count: 1,
  refs: [],
  attack: ['T1204.002'],
  tags: ['engine:hayabusa'],
  engine: 'hayabusa',
  refKeys: [`WS01|Security|${record}`],
})

describe('engine findings link to the rows the browser stored', () => {
  it('resolves refKeys through the index built at insert time and drops what it cannot find', () => {
    const index = new Map([[refKey({ computer: 'WS01', channel: 'Security', recordId: 1 }), 41]])
    const [linked, unlinked] = resolveEngineRefs([detection(1), detection(2)], index)
    expect(linked.refs).toEqual([41])
    expect(unlinked.refs).toEqual([])
    expect('refKeys' in linked).toBe(false)
  })

  it('stores per evidence, replaces only that evidence, and keeps analyst decisions by key', async () => {
    expect(await persistEngineFindings(1, 5, 'hayabusa', [detection(1), detection(2)])).toBe(2)
    expect(await persistEngineFindings(1, 6, 'hayabusa', [detection(3)])).toBe(1)
    const first = (await db.findings.where('caseId').equals(1).toArray()).find((f) => f.key.endsWith('|1'))!
    await db.findings.update(first.id!, { status: 'false_positive', notes: 'benign updater' })

    // evidence 5 re-ingested: record 2 is gone, record 1 keeps its review, evidence 6 is untouched
    expect(await persistEngineFindings(1, 5, 'hayabusa', [detection(1)])).toBe(1)
    const all = await db.findings.where('caseId').equals(1).toArray()
    expect(all.map((f) => f.key).sort()).toEqual([detection(1).key, detection(3).key])
    const kept = all.find((f) => f.key === detection(1).key)!
    expect(kept.status).toBe('false_positive')
    expect(kept.notes).toBe('benign updater')
    expect(kept.tags).toContain('evidence:5')
  })

  it('is left alone by orphan pruning, which knows no rule for it', async () => {
    await persistEngineFindings(1, 5, 'hayabusa', [detection(1)])
    await db.findings.add({ ...detection(9, 'mail-gone'), caseId: 1, status: 'new', createdAt: 1, tags: [] } as never)
    expect(await pruneOrphanFindings(1, ['mail-x'])).toBe(1)
    expect((await db.findings.where('caseId').equals(1).toArray()).map((f) => f.ruleId)).toEqual(['engine:hayabusa:susp-downloads-exec'])
  })
})
