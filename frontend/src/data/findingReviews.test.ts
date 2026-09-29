import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { RemnDB, setDb, type Finding } from '../db/schema'
import { refoldWidespread, rememberReviews, replaceFindings, resetFindingSeverityOverrides } from './findingReviews'

let db: RemnDB
const row = (patch: Partial<Finding> = {}): Finding => ({
  caseId: 1,
  key: 'replyto|3307',
  ruleId: 'replyto',
  title: 'Reply-To diverted',
  source: 'mails',
  severity: 'medium',
  severityOverride: 'high',
  refs: [3307],
  entities: {},
  count: 1,
  attack: [],
  ts: 1,
  status: 'reviewed',
  notes: 'Supplier confirmed',
  decidedBy: 'analyst',
  reportExclude: true,
  createdAt: 5,
  ...patch,
})

beforeEach(() => {
  db = new RemnDB(`severity-reset-${Math.random()}`)
  setDb(db)
})
afterEach(async () => {
  await db.delete()
})

describe('explicit finding severity reset', () => {
  it('keeps every other decision and clears the archived override through disappearance and reappearance', async () => {
    const original = row()
    const id = await db.findings.add(original)
    const otherId = await db.findings.add(row({ caseId: 2 }))
    await rememberReviews(1, [{ ...original, id }])
    await resetFindingSeverityOverrides(1, [id, id])
    const { severityOverride: _override, ...kept } = original
    expect(await db.findings.get(id)).toEqual({ ...kept, id })
    expect((await db.findings.get(otherId))?.severityOverride).toBe('high')
    expect((await db.kv.get('finding-reviews-1'))?.value).toMatchObject({ [original.key]: { status: 'reviewed', notes: original.notes, reportExclude: true } })
    await replaceFindings(1, ['replyto'], [])
    await replaceFindings(1, ['replyto'], [{ ...kept, status: 'new' }])
    const returned = await db.findings.where('caseId').equals(1).first()
    expect(returned).toMatchObject({ severity: 'medium', status: original.status, notes: original.notes, decidedBy: original.decidedBy, reportExclude: true, createdAt: original.createdAt })
    expect(returned?.severityOverride).toBeUndefined()
  })

  it('does not revive an override when it was the only saved decision', async () => {
    const original = row({ status: 'new', notes: undefined, decidedBy: undefined, reportExclude: undefined })
    const id = await db.findings.add(original)
    await rememberReviews(1, [{ ...original, id }])
    await resetFindingSeverityOverrides(1, [id])
    await replaceFindings(1, ['replyto'], [])
    await replaceFindings(1, ['replyto'], [{ ...original, severityOverride: undefined }])
    expect((await db.findings.where('caseId').equals(1).first())?.severityOverride).toBeUndefined()
  })

  it('rejects missing or cross-case rows before changing any finding or saved review', async () => {
    const id = await db.findings.add(row())
    const otherId = await db.findings.add(row({ caseId: 2 }))
    for (const invalid of [otherId, 99999]) {
      await expect(resetFindingSeverityOverrides(1, [id, invalid])).rejects.toThrow('Findings changed')
      expect((await db.findings.get(id))?.severityOverride).toBe('high')
    }
    expect(await db.kv.get('finding-reviews-1')).toBeUndefined()
  })
})

describe('the detection level when findings are replaced', () => {
  const found = (key: string, severity: Finding['severity']) => ({
    ...row({ key, severity, status: 'new', notes: undefined, decidedBy: undefined, reportExclude: undefined, severityOverride: undefined }),
  })

  it('folds the findings below their rule floor into one per host, and keeps the others on their own', async () => {
    const on = (key: string, severity: Finding['severity'], computer: string, ref: number) => ({ ...found(key, severity), entities: { computer }, refs: [ref], ts: ref })
    const n = await replaceFindings(1, ['replyto'], [on('a', 'low', 'WS1', 3), on('b', 'low', 'WS1', 1), on('c', 'medium', 'WS1', 2), on('d', 'low', 'WS2', 4), on('e', 'high', 'WS1', 5)], undefined, {
      replyto: 3,
    })
    expect(n).toBe(3)
    const rows = await db.findings.toArray()
    const alone = rows.find((f) => f.key === 'e')!
    expect(alone.folded).toBeUndefined()
    const ws1 = rows.find((f) => f.key === 'replyto|folded|ws1')!
    expect(ws1).toMatchObject({ severity: 'medium', folded: 3, count: 3, ts: 1, tsEnd: 3 })
    expect(ws1.refs.sort()).toEqual([1, 2, 3])
    expect(ws1.title).toContain('3 findings on ws1')
    expect(rows.find((f) => f.key === 'd')).toMatchObject({ folded: 1, severity: 'low' })
  })

  it('keeps a finding below the floor an analyst already decided on on its own', async () => {
    const decided = { ...found('a', 'low'), status: 'escalated' as const, decidedBy: 'analyst' as const }
    const id = await db.findings.add(decided)
    await rememberReviews(1, [{ ...decided, id }])
    await replaceFindings(1, ['replyto'], [found('a', 'low'), found('z', 'low')], undefined, { replyto: 3 })
    const kept = await db.findings.toArray()
    expect(kept.map((f) => [f.key, f.status, f.folded])).toEqual([
      ['a', 'escalated', undefined],
      ['z', 'new', 1],
    ])
  })
})

describe('the case own hosts as the measure of noise', () => {
  let ref = 0
  const on = (ruleId: string, computer: string, patch: Partial<Finding> = {}): Finding => {
    ref++
    return row({
      ruleId,
      key: `${ruleId}|${ref}`,
      title: ruleId,
      severity: 'medium',
      entities: { computer },
      refs: [ref],
      ts: ref,
      status: 'new',
      notes: undefined,
      decidedBy: undefined,
      reportExclude: undefined,
      severityOverride: undefined,
      ...patch,
    })
  }

  it('folds a rule that stands alone on most of the case hosts, per host, and leaves a rare rule and a touched finding alone', async () => {
    await db.findings.bulkAdd([
      // everywhere: two findings on each of three hosts of four, one of them already escalated
      on('everywhere', 'ws1'),
      on('everywhere', 'ws1'),
      on('everywhere', 'ws2'),
      on('everywhere', 'ws2', { status: 'escalated', decidedBy: 'analyst' }),
      on('everywhere', 'ws3'),
      on('everywhere', 'ws3', { folded: 4, key: 'everywhere|folded|ws3', title: 'everywhere (4 findings on ws3, folded at this detection level)' }),
      // rare: two findings on one host
      on('rare', 'ws4'),
      on('rare', 'ws4'),
    ])
    const removed = await refoldWidespread(1, { everywhere: 2, rare: 2 })
    expect(removed).toBe(2)
    const rows = await db.findings.toArray()
    const ws1 = rows.find((f) => f.key === 'everywhere|folded|ws1')!
    expect(ws1).toMatchObject({ folded: 2, count: 2, title: "everywhere (2 findings on ws1, folded, its rule fired on 3 of the case's 4 hosts)" })
    expect(rows.find((f) => f.key === 'everywhere|folded|ws3')).toMatchObject({ folded: 5, title: "everywhere (5 findings on ws3, folded, its rule fired on 3 of the case's 4 hosts)" })
    // on ws2 the escalated finding stays, and the other one with it, alone
    expect(rows.filter((f) => f.entities.computer === 'ws2').map((f) => [f.status, f.folded])).toEqual([
      ['new', undefined],
      ['escalated', undefined],
    ])
    expect(rows.filter((f) => f.ruleId === 'rare')).toHaveLength(2)
  })

  it('gives the new folded finding its own key when a decided folded finding has that key', async () => {
    await db.findings.bulkAdd([on('wide', 'ws1', { key: 'wide|folded|ws1', folded: 3, status: 'reviewed' }), on('wide', 'ws1'), on('wide', 'ws1'), on('wide', 'ws2'), on('x', 'ws3')])
    await refoldWidespread(1, { wide: 2, x: 2 })
    const keys = (await db.findings.where('ruleId').equals('wide').toArray()).map((f) => [f.key.startsWith('wide|folded|ws1'), f.folded, f.status])
    expect(keys).toHaveLength(3)
    expect(new Set((await db.findings.toArray()).map((f) => f.key)).size).toBe(4)
  })

  it('leaves a rule the level never folds, and a case of fewer than three hosts, as they are', async () => {
    await db.findings.bulkAdd([on('mine', 'ws1'), on('mine', 'ws1'), on('mine', 'ws2'), on('mine', 'ws2'), on('x', 'ws3')])
    expect(await refoldWidespread(1, { mine: 0, x: 2 })).toBe(0)
    expect(await refoldWidespread(1, undefined)).toBe(0)
    await db.findings.where('ruleId').equals('x').delete()
    expect(await refoldWidespread(1, { mine: 2 })).toBe(0)
  })
})
