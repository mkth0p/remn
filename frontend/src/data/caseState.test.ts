import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, deleteCaseData, deleteEvidenceData, RemnDB, setDb, type Case } from '../db/schema'
import { clearDerivedState } from './caseState'
import { buildChains, loadChains } from './chains'
import { pruneOrphanFindings, replaceFindings } from './findingReviews'

vi.mock('../api/client', () => ({ apiPost: vi.fn() }))
vi.mock('./rules', () => ({ settingsForRules: (k: Case) => ({ internal_domains: k.settings.internalDomains }) }))

const kase: Case = { id: 1, name: 'Stale', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
const finding = (key: string, ruleId = 'mail-x'): Record<string, unknown> => ({
  caseId: 1,
  ruleId,
  key,
  title: key,
  severity: 'high',
  source: 'mails',
  ts: 1,
  entities: {},
  count: 1,
  refs: [1],
  attack: [],
  tags: [],
  status: 'new',
  createdAt: 1,
})
let db: RemnDB

beforeEach(() => {
  db = new RemnDB(`stale-${Math.random()}`)
  setDb(db)
})
afterEach(async () => {
  await db.delete()
})

describe('derived state follows the evidence', () => {
  it('removing evidence clears findings, the chain snapshot and diagnostics but archives analyst decisions', async () => {
    await db.evidence.add({ id: 5, caseId: 1, name: 'a.eml', size: 1, kind: 'mail', integrity: 'pending', addedAt: 1 } as never)
    await db.mails.add({ id: 1, caseId: 1, evidenceId: 5, date: 1, subject: 's', fromAddr: 'x@y.z', to: [], cc: [], bcc: [], flags: [], risk: 90 } as never)
    await replaceFindings(1, ['mail-x'], [finding('mail-x|1')])
    const f = (await db.findings.toArray())[0]
    await db.findings.update(f.id!, { status: 'false_positive', notes: 'reviewed' })
    await db.kv.bulkPut([
      { key: 'chains-1', value: { chains: [{ id: 'c1' }], stats: {} } },
      { key: 'ruleDiags-1', value: { ts: 1 } },
      { key: 'chains-2', value: { chains: [], stats: {} } },
    ])
    await deleteEvidenceData(db, 1, 5)
    const cleared = await clearDerivedState(1)
    expect(cleared).toEqual({ findings: 1, chains: 1 })
    expect(await db.findings.count()).toBe(0)
    expect(await db.kv.get('chains-1')).toBeUndefined()
    expect(await db.kv.get('ruleDiags-1')).toBeUndefined()
    expect(await db.kv.get('chains-2')).toBeDefined()
    // the decision comes back with the finding on the next rule run
    await replaceFindings(1, ['mail-x'], [finding('mail-x|1')])
    expect((await db.findings.toArray())[0]).toMatchObject({ status: 'false_positive', notes: 'reviewed' })
  })

  it('rebuilding chains with no seed left replaces the stored snapshot and its findings', async () => {
    await db.kv.put({ key: 'chains-1', value: { chains: [{ id: 'old' }], stats: { seeds: 1, identities: 1, events: 3, mails: 1, chains: 1 } } })
    await replaceFindings(1, ['chain'], [finding('chain|alice|9', 'chain')])
    const r = await buildChains(kase)
    expect(r.chains).toEqual([])
    expect((await loadChains(1))?.chains).toEqual([])
    expect(await db.findings.where('[caseId+ruleId]').equals([1, 'chain']).count()).toBe(0)
  })

  it('deleting a case drops its kv entries and leaves other cases alone', async () => {
    await db.kv.bulkPut([
      { key: 'chains-1', value: {} },
      { key: 'ruleDiags-1', value: {} },
      { key: 'finding-reviews-1', value: {} },
      { key: 'report-summary-1', value: 'x' },
      { key: 'chains-2', value: {} },
      { key: 'disabledRules', value: [] },
    ])
    await deleteCaseData(db, 1)
    expect((await db.kv.toArray()).map((k) => k.key).sort()).toEqual(['chains-2', 'disabledRules'])
  })

  it('prunes findings of rules that no longer exist, keeps chains, archives the decisions', async () => {
    await replaceFindings(1, ['sigma-gone', 'mail-x', 'chain'], [finding('sigma-gone|1', 'sigma-gone'), finding('mail-x|1'), finding('chain|a|1', 'chain')])
    const gone = await db.findings.where('[caseId+ruleId]').equals([1, 'sigma-gone']).first()
    await db.findings.update(gone!.id!, { status: 'reviewed', notes: 'seen' })
    expect(await pruneOrphanFindings(1, ['mail-x'])).toBe(1)
    expect((await db.findings.toArray()).map((f) => f.ruleId).sort()).toEqual(['chain', 'mail-x'])
    expect(((await db.kv.get('finding-reviews-1'))?.value as Record<string, unknown>)['sigma-gone|1']).toMatchObject({ status: 'reviewed', notes: 'seen' })
  })
})
