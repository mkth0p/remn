import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { RemnDB, setDb, type Finding } from '../db/schema'
import { clearDerivedState } from './caseState'
import { heldKey, reconcileEngineDuplicates } from './engineDuplicates'
import { persistEngineFindings, type EngineFinding } from './engineFindings'
import { pruneOrphanFindings } from './findingReviews'

vi.mock('../api/client', () => ({ apiPost: vi.fn(), API_HEADERS: {} }))

// invented ids: a SigmaHQ rule REMN converted as sigma-<id>, and a part Hayabusa split off it under an id of its own
const SIGMA_ID = '0d3c4a5b-0000-4000-8000-000000000001'
const DERIVED_ID = '0d3c4a5b-0000-4000-8000-0000000000ff'

let db: RemnDB
beforeEach(async () => {
  db = new RemnDB(`engine-dup-${Math.random()}`)
  setDb(db)
  await db.evidence.bulkAdd([5, 6].map((id) => ({ id, caseId: 1, name: `Security-${id}.evtx`, size: 1, kind: 'evtx', integrity: 'verified', addedAt: 1, status: 'done', count: 2 }) as never))
})
afterEach(async () => {
  await db.delete()
})

/** Hayabusa's finding on one event row, as the server sends it once its row is resolved. */
const hayabusa = (row: number, sigmaId: string | undefined = SIGMA_ID): EngineFinding => ({
  ruleId: 'engine:hayabusa:proc-creation-win-susp-downloads-exec',
  key: `engine:hayabusa:proc-creation-win-susp-downloads-exec|WS01|Security|${row}`,
  title: 'Suspicious Process Creation In Downloads',
  severity: 'high',
  source: 'events',
  ts: 1,
  entities: { computer: 'WS01' },
  count: 1,
  refs: [row],
  attack: ['T1204.002'],
  tags: ['engine:hayabusa'],
  engine: 'hayabusa',
  sigmaId,
})

/** REMN's finding of its conversion of the Sigma rule on one event row. */
const ours = (row: number, sigmaId = SIGMA_ID): Finding => ({
  caseId: 1,
  ruleId: `sigma-${sigmaId}`,
  key: `sigma-${sigmaId}|${row}`,
  title: 'Suspicious Process Creation In Downloads',
  severity: 'medium',
  source: 'events',
  ts: 1,
  entities: { computer: 'WS01', user: 'jdoe' },
  count: 1,
  refs: [row],
  attack: ['T1204.002'],
  status: 'new',
  createdAt: 1,
})

const findings = () => db.findings.where('caseId').equals(1).toArray()

describe('a detection both Hayabusa and REMN made of the same Sigma rule on the same record', () => {
  it('is one finding, REMN’s, which names Hayabusa’s, whichever engine stored its finding first', async () => {
    await db.findings.add(ours(41))
    await persistEngineFindings(1, 5, 'hayabusa', [hayabusa(41)])
    let all = await findings()
    expect(all.map((f) => f.ruleId)).toEqual([`sigma-${SIGMA_ID}`])
    expect(all[0].alsoBy).toEqual([{ engine: 'hayabusa', ruleId: 'engine:hayabusa:proc-creation-win-susp-downloads-exec', title: 'Suspicious Process Creation In Downloads', severity: 'high' }])

    // the other way round: Hayabusa's finding stored at ingest, REMN's made by a later rule run
    await db.findings.clear()
    await db.kv.clear()
    await persistEngineFindings(1, 5, 'hayabusa', [hayabusa(41)])
    expect((await findings()).map((f) => f.ruleId)).toEqual(['engine:hayabusa:proc-creation-win-susp-downloads-exec'])
    await db.findings.add(ours(41))
    expect(await reconcileEngineDuplicates(1)).toBe(1)
    all = await findings()
    expect(all.map((f) => f.ruleId)).toEqual([`sigma-${SIGMA_ID}`])
    expect(all[0].alsoBy?.[0].engine).toBe('hayabusa')
  })

  it('stays two findings when the ids differ, as for a rule Hayabusa split into parts with new ids', async () => {
    await db.findings.add(ours(41))
    await persistEngineFindings(1, 5, 'hayabusa', [hayabusa(41, DERIVED_ID), hayabusa(42, undefined)])
    const all = await findings()
    expect(all.map((f) => f.ruleId).sort()).toEqual(['engine:hayabusa:proc-creation-win-susp-downloads-exec', 'engine:hayabusa:proc-creation-win-susp-downloads-exec', `sigma-${SIGMA_ID}`])
    expect(all.find((f) => f.ruleId.startsWith('sigma-'))!.alsoBy).toBeUndefined()
  })

  it('stays two findings when the same rule fired on two different records', async () => {
    await db.findings.add(ours(41))
    await persistEngineFindings(1, 5, 'hayabusa', [hayabusa(42)])
    expect(await findings()).toHaveLength(2)
  })

  it('gives Hayabusa’s finding back when REMN’s goes, and drops it with its evidence', async () => {
    await db.findings.add(ours(41))
    await persistEngineFindings(1, 5, 'hayabusa', [hayabusa(41)])
    // the converted rule is no longer loaded: REMN's finding is pruned and Hayabusa's stands alone again
    await pruneOrphanFindings(1, [])
    await reconcileEngineDuplicates(1)
    expect((await findings()).map((f) => f.key)).toEqual([hayabusa(41).key])
    // and joins REMN's again when the rule comes back
    await db.findings.add(ours(41))
    await reconcileEngineDuplicates(1)
    expect((await findings()).map((f) => f.ruleId)).toEqual([`sigma-${SIGMA_ID}`])
    // the evidence is removed: REMN's findings are cleared for the next run, Hayabusa's of that file go
    await clearDerivedState(1, 5)
    expect(await findings()).toEqual([])
    expect((await db.kv.get(heldKey(1)))?.value).toEqual({})
  })

  it('stands alone again when the evidence of another file is removed and REMN’s findings are cleared', async () => {
    await db.findings.add(ours(41))
    await persistEngineFindings(1, 5, 'hayabusa', [hayabusa(41)])
    await clearDerivedState(1, 6)
    const all = await findings()
    expect(all.map((f) => f.key)).toEqual([hayabusa(41).key])
    expect(all[0].tags).toContain('evidence:5')
  })

  it('is replaced, not doubled, when the engine stores its findings for the same file again', async () => {
    await db.findings.add(ours(41))
    await persistEngineFindings(1, 5, 'hayabusa', [hayabusa(41)])
    await persistEngineFindings(1, 5, 'hayabusa', [hayabusa(41)])
    const all = await findings()
    expect(all.map((f) => f.ruleId)).toEqual([`sigma-${SIGMA_ID}`])
    expect(all[0].alsoBy).toHaveLength(1)
    expect(Object.keys((await db.kv.get(heldKey(1)))?.value as object)).toEqual([hayabusa(41).key])
  })

  it('leaves alone a Hayabusa finding the analyst already decided on', async () => {
    await persistEngineFindings(1, 5, 'hayabusa', [hayabusa(41)])
    const [h] = await findings()
    await db.findings.update(h.id!, { status: 'escalated', decidedBy: 'analyst' })
    await db.findings.add(ours(41))
    await reconcileEngineDuplicates(1)
    expect(await findings()).toHaveLength(2)
  })
})
