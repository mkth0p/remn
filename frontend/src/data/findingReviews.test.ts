import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { RemnDB, setDb, type Finding } from '../db/schema'
import { rememberReviews, replaceFindings, resetFindingSeverityOverrides } from './findingReviews'

let db: RemnDB
const row = (patch: Partial<Finding> = {}): Finding => ({ caseId: 1, key: 'replyto|3307', ruleId: 'replyto', title: 'Reply-To diverted', source: 'mails', severity: 'medium', severityOverride: 'high', refs: [3307], entities: {}, count: 1, attack: [], ts: 1, status: 'reviewed', notes: 'Supplier confirmed', decidedBy: 'analyst', reportExclude: true, createdAt: 5, ...patch })

beforeEach(() => { db = new RemnDB(`severity-reset-${Math.random()}`); setDb(db) })
afterEach(async () => { await db.delete() })

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
