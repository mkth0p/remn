import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { RemnDB, deleteEvidenceData, setDb } from '../db/schema'
import { clearDerivedState } from './caseState'
import { anchorKey } from './findingAnchors'
import { replaceFindings } from './findingReviews'

vi.mock('../api/client', () => ({ apiPost: vi.fn(), API_HEADERS: {} }))

const SHA = 'a'.repeat(64)
const evidence = (id: number) => ({ id, caseId: 1, name: 'inbox.mbox', size: 1, kind: 'mail', sha256Client: SHA, integrity: 'verified', addedAt: 1 }) as never
const mail = (id: number, evidenceId: number, sourceIndex: number) =>
  ({ id, caseId: 1, evidenceId, sourceIndex, messageId: `<m${sourceIndex}@x.example>`, date: 1, subject: 's', fromAddr: 'x@y.z', to: [], cc: [], bcc: [], flags: [], risk: 90 }) as never
const finding = (rowId: number, key = `mail-x|${rowId}`): Record<string, unknown> => ({
  caseId: 1,
  ruleId: 'mail-x',
  key,
  title: 't',
  severity: 'high',
  source: 'mails',
  ts: 1,
  entities: {},
  count: 1,
  refs: [rowId],
  attack: [],
})

let db: RemnDB
beforeEach(() => {
  db = new RemnDB(`anchors-${Math.random()}`)
  setDb(db)
})
afterEach(async () => {
  await db.delete()
})

describe('findings follow their records', () => {
  it('stores the record key of each row a finding cites', async () => {
    await db.evidence.add(evidence(5))
    await db.mails.bulkAdd([mail(1, 5, 0), mail(2, 5, 1)])
    await replaceFindings(1, ['mail-x'], [{ ...finding(1), refs: [1, 2, 99] }])
    const [f] = await db.findings.toArray()
    expect(f.recordKeys).toEqual([`${SHA}:#m0`, `${SHA}:#m1`, ''])
  })

  it("keeps the analyst's decision when the evidence is removed and added again under new row ids", async () => {
    await db.evidence.add(evidence(5))
    await db.mails.bulkAdd([mail(1, 5, 0), mail(2, 5, 1)])
    await replaceFindings(1, ['mail-x'], [finding(2)])
    const [f] = await db.findings.toArray()
    await db.findings.update(f.id!, { status: 'false_positive', notes: 'newsletter' })

    await deleteEvidenceData(db, 1, 5)
    await clearDerivedState(1)
    // the same file again: new evidence id, new row ids
    await db.evidence.add(evidence(6))
    await db.mails.bulkAdd([mail(10, 6, 0), mail(11, 6, 1)])
    await replaceFindings(1, ['mail-x'], [finding(11), finding(10)])

    const rows = await db.findings.orderBy('key').toArray()
    expect(rows.find((r) => r.key === 'mail-x|11')).toMatchObject({ status: 'false_positive', notes: 'newsletter' })
    // the other record's finding was never decided and does not inherit the decision
    expect(rows.find((r) => r.key === 'mail-x|10')).toMatchObject({ status: 'new' })
  })

  it('a finding whose key names a group, not a row, keeps its own key', () => {
    expect(anchorKey({ key: 'rule|alice|10.0.0.1', refs: [4], recordKeys: ['k'] })).toBeNull()
    expect(anchorKey({ key: 'rule|4', refs: [4], recordKeys: [''] })).toBeNull()
    expect(anchorKey({ key: 'chain|alice|4', refs: [4], recordKeys: ['k'] })).toBe('chain|alice|rk:k')
  })

  it('an existing case gets record keys on its findings and its archived decisions on the upgrade', async () => {
    const { default: Dexie } = await import('dexie')
    const name = `anchor-upgrade-${Math.random()}`
    const old = new Dexie(name)
    // version 6 of the schema, as RemnDB declared it before findings carried record keys
    const v6 = new RemnDB(`${name}-shape`)
    old.version(6).stores(Object.fromEntries(v6.tables.map((t) => [t.name, [t.schema.primKey.src, ...t.schema.indexes.map((i) => i.src)].join(', ')])))
    await v6.delete()
    await old.open()
    await old.table('evidence').add(evidence(5))
    await old.table('mails').bulkAdd([mail(1, 5, 0), mail(2, 5, 1)])
    await old.table('findings').add({ ...finding(1), status: 'escalated', createdAt: 1 })
    await old.table('kv').put({ key: 'finding-reviews-1', value: { 'mail-x|2': { source: 'mails', refs: [2], ruleId: 'mail-x', status: 'false_positive', createdAt: 1 } } })
    old.close()

    const upgraded = new RemnDB(name)
    setDb(upgraded)
    await upgraded.open()
    expect((await upgraded.findings.toArray())[0].recordKeys).toEqual([`${SHA}:#m0`])
    const archive = (await upgraded.kv.get('finding-reviews-1'))?.value as Record<string, { status: string; key: string }>
    expect(Object.keys(archive)).toEqual([`mail-x|rk:${SHA}:#m1`])
    expect(archive[`mail-x|rk:${SHA}:#m1`]).toMatchObject({ status: 'false_positive', key: 'mail-x|2' })
    await upgraded.delete()
  })
})
