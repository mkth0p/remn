import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { RemnDB, setDb } from '../db/schema'
import { appendLedger, loadLedger, summariseLedger, verifyLedger } from './ledger'

let db: RemnDB
beforeEach(() => {
  db = new RemnDB(`ledger-${Math.random()}`)
  setDb(db)
})
afterEach(async () => {
  db.close()
  await db.delete()
})

describe('the AI ledger', () => {
  it('chains every entry to the one before, in order, even when appends race', async () => {
    await Promise.all([
      appendLedger(1, 'run', 'what happened?', { model: 'qwen3:8b', transport: 'browser' }),
      appendLedger(1, 'tool', 'search_events', { refs: 3 }),
      appendLedger(1, 'tool', 'get_event', { refs: 1 }),
      appendLedger(2, 'run', 'another case', { model: 'x' }),
    ])
    const all = await loadLedger(1)
    expect(all.map((e) => e.seq)).toEqual([1, 2, 3])
    expect(all[1].prev).toBe(all[0].hash)
    expect(all[2].prev).toBe(all[1].hash)
    expect(await verifyLedger(1)).toMatchObject({ entries: 3, intact: true, head: all[2].hash })
    expect((await loadLedger(2)).map((e) => e.seq)).toEqual([1])
  })

  it('shows where an entry was changed or removed afterwards', async () => {
    for (const t of ['a', 'b', 'c', 'd']) await appendLedger(1, 'tool', t)
    const all = await loadLedger(1)
    await db.aiLedger.update(all[1].id!, { text: 'rewritten' })
    expect(await verifyLedger(1)).toMatchObject({ intact: false, brokenAt: 2 })
    await db.aiLedger.update(all[1].id!, { text: 'b' })
    expect((await verifyLedger(1)).intact).toBe(true)
    await db.aiLedger.delete(all[2].id!)
    expect(await verifyLedger(1)).toMatchObject({ intact: false, brokenAt: 4 })
  })

  it('sums up runs, models and what came of the proposals', async () => {
    await appendLedger(1, 'run', 'q', { model: 'qwen3:8b', transport: 'browser' })
    await appendLedger(1, 'tool', 'search_events')
    await appendLedger(1, 'proposal', 'note: x', { id: 'p1', kind: 'note' })
    await appendLedger(1, 'proposal', 'decision: y', { id: 'p2', kind: 'decision' })
    await appendLedger(1, 'accepted', 'note: x', { id: 'p1' })
    await appendLedger(1, 'rejected', 'decision: y', { id: 'p2' })
    await appendLedger(1, 'triage', 'triage of 3 item(s)', { model: 'sonnet', transport: 'claude' })
    const s = await summariseLedger(1)
    expect(s).toMatchObject({ runs: 2, toolCalls: 1, proposals: 2, accepted: 1, rejected: 1, models: ['qwen3:8b', 'sonnet'], transports: ['browser', 'claude'] })
    expect(s.byProposalKind).toEqual({ note: { proposed: 1, accepted: 1, rejected: 0 }, decision: { proposed: 1, accepted: 0, rejected: 1 } })
    expect(s.check.intact).toBe(true)
  })
})
