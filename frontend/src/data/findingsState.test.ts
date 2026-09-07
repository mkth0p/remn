import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case } from '../db/schema'
import { findingsStaleness } from './findingsState'

vi.mock('../api/client', () => ({ apiPost: vi.fn() }))
vi.mock('./rules', () => ({ loadRules: vi.fn(async () => []), runRulesFor: vi.fn() }))

const kase: Case = { id: 1, name: 'Stale', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
let db: RemnDB
beforeEach(() => {
  db = new RemnDB(`findings-state-${Math.random()}`)
  setDb(db)
})
afterEach(() => db.delete())

const evidence = (addedAt: number, status: 'done' | 'error' = 'done') => ({
  caseId: kase.id!,
  name: `f${addedAt}`,
  kind: 'mail' as const,
  size: 1,
  addedAt,
  status,
  count: 0,
  integrity: 'verified' as const,
  progress: 1,
})

describe('findingsStaleness', () => {
  it('reports evidence that finished after the last rule run', async () => {
    await db.evidence.bulkAdd([evidence(100), evidence(300), evidence(400, 'error')] as never[])
    await db.kv.put({ key: 'ruleDiags-1', value: { ts: 200, errors: ['mail-x: boom'] } })
    const s = await findingsStaleness(1)
    expect(s.lastRun).toBe(200)
    expect(s.evidenceAfter).toBe(1)
    expect(s.errors).toEqual(['mail-x: boom'])
    expect(s.rescoreIncomplete).toBe(false)
    expect(s.baselineAfter).toBe(false)
  })

  it('counts every finished file when rules never ran, and flags an unfinished rescore and a later baseline', async () => {
    await db.evidence.bulkAdd([evidence(100), evidence(300)] as never[])
    expect((await findingsStaleness(1)).evidenceAfter).toBe(2)
    await db.kv.put({ key: 'ruleDiags-1', value: { ts: 500 } })
    await db.kv.put({ key: 'mail-calibration-1', value: { state: 'scores_done', at: 600 } })
    await db.kv.put({ key: 'baseline-1', value: { at: 700 } })
    const s = await findingsStaleness(1)
    expect(s.evidenceAfter).toBe(0)
    expect(s.rescoreIncomplete).toBe(true)
    expect(s.baselineAfter).toBe(true)
    await db.kv.put({ key: 'mail-calibration-1', value: { state: 'done', at: 800 } })
    expect((await findingsStaleness(1)).rescoreIncomplete).toBe(false)
  })
})
