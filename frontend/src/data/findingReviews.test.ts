import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { RemnDB, setDb, type Finding } from '../db/schema'
import { rememberReviews, replaceFindings, resetFindingSeverityOverrides } from './findingReviews'

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
