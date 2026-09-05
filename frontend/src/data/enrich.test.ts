import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { defaultSettings, RemnDB, setDb, type Case, type MailRow } from '../db/schema'
import { apiPost } from '../api/client'
import { waitForJob } from './jobs'
import { applyScoreBatch, rescoreMails } from './enrich'
import { replaceFindings } from './findingReviews'

vi.mock('../api/client', () => ({ apiPost: vi.fn() }))
vi.mock('./jobs', () => ({ waitForJob: vi.fn() }))
vi.mock('./rules', () => ({ settingsForRules: (k: Case) => ({ internal_domains: k.settings.internalDomains }) }))

const fixture = JSON.parse(readFileSync(join(__dirname, '../../../samples/synthetic/mail-calibration.json'), 'utf8'))
const kase: Case = { id: 1, name: 'Calibration', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
const row = (id = 1, caseId = 1): MailRow => ({ ...fixture.examples[2].row, id, caseId, evidenceId: 42, risk: 90, flags: ['att_html_smuggling'] })
const update = (id = 1) => ({ id, risk: 31, flags: ['att_html_file_download'], attachments: fixture.examples[2].row.attachments, maxAttachmentRisk: 35, assessment: fixture.examples[2].row.assessment })
const summary = { version: 'mail-2', mails: 1, changed: 1, limited: 0, highBefore: 1, highAfter: 0 }
let db: RemnDB

beforeEach(() => { vi.clearAllMocks(); db = new RemnDB(`rescore-${Math.random()}`); setDb(db) })
afterEach(async () => { await db.delete() })

describe('mail score refresh', () => {
  it('updates mail and attachment rows together while preserving evidence and body IDs', async () => {
    await db.mails.add(row())
    const a = row().attachments[0]
    await db.attachments.add({ ...a, id: 7, caseId: 1, mailId: 1, evidenceId: 42, risk: 100 })
    await db.mailBodies.add({ caseId: 1, mailId: 1, bodyText: 'original evidence', bodyHtml: null, headersText: null, visibleText: null })
    await applyScoreBatch(1, [1], [update()])
    expect(await db.mails.get(1)).toMatchObject({ id: 1, caseId: 1, evidenceId: 42, risk: 31 })
    expect(await db.attachments.get(7)).toMatchObject({ id: 7, mailId: 1, evidenceId: 42, risk: a.risk })
    expect((await db.mailBodies.toArray())[0].bodyText).toBe('original evidence')
  })

  it('rejects incomplete responses and rolls back the batch on cross-case IDs', async () => {
    await db.mails.bulkAdd([row(), row(2, 2)])
    await expect(applyScoreBatch(1, [1, 2], [update()])).rejects.toThrow('Incomplete')
    await expect(applyScoreBatch(1, [1, 2], [update(), update(2)])).rejects.toThrow('Case changed')
    expect((await db.mails.get(1))?.risk).toBe(90)
    expect((await db.mails.get(2))?.risk).toBe(90)
  })

  it('baselines first, scopes scores to the case, and rebuilds risk and flag facets', async () => {
    await db.mails.bulkAdd([row(), row(2, 2)])
    await db.facets.add({ caseId: 1, source: 'mails', field: 'riskBand', value: 'critical', count: 1 })
    vi.mocked(apiPost).mockImplementation(async (path, body) => {
      if (path === '/api/enrich/mails') return { rows: [{ id: 1, senderPriorCount: 8 }], summary: {} }
      const sent = body as { mails: MailRow[] }
      expect(sent.mails.map((m) => m.id)).toEqual([1])
      expect(sent.mails[0].senderPriorCount).toBe(8)
      return { rows: [update()], summary }
    })
    expect(await rescoreMails(kase)).toEqual(summary)
    expect((await db.mails.get(2))?.risk).toBe(90)
    const facets = await db.facets.toArray()
    expect(facets).toEqual(expect.arrayContaining([expect.objectContaining({ field: 'riskBand', value: 'low', count: 1 }), expect.objectContaining({ field: 'flags', value: 'att_html_file_download', count: 1 })]))
    expect(facets.some((f) => f.value === 'critical')).toBe(false)
    expect((await db.kv.get('mail-calibration-1'))?.value).toMatchObject({ state: 'scores_done', summary })
  })

  it('records an interrupted refresh and permits a later retry', async () => {
    await db.mails.add(row())
    vi.mocked(apiPost).mockResolvedValueOnce({ rows: [], summary: {} }).mockRejectedValueOnce(new Error('connection lost'))
    await expect(rescoreMails(kase)).rejects.toThrow('connection lost')
    expect((await db.kv.get('mail-calibration-1'))?.value).toMatchObject({ state: 'incomplete' })
    expect((await db.mails.get(1))?.risk).toBe(90)
    vi.mocked(apiPost).mockResolvedValueOnce({ rows: [], summary: {} }).mockResolvedValueOnce({ rows: [update()], summary })
    expect((await rescoreMails(kase)).highAfter).toBe(0)
  })

  it('handles an empty browser case without an unbounded range', async () => {
    vi.mocked(apiPost).mockResolvedValue({ rows: [], summary: {} })
    expect((await rescoreMails(kase)).mails).toBe(0)
    expect(apiPost).toHaveBeenCalledTimes(1)
  })

  it('waits for server job completion without uploading browser mail rows', async () => {
    vi.mocked(apiPost).mockResolvedValue({ jobId: 'job1' })
    vi.mocked(waitForJob).mockResolvedValue({ result: summary } as never)
    expect(await rescoreMails({ ...kase, storage: 'server', serverKey: 'server-case' })).toEqual(summary)
    expect(apiPost).toHaveBeenCalledWith('/api/enrich/mails/rescore', { storeKey: 'server-case', settings: { internal_domains: [] } })
    expect(waitForJob).toHaveBeenCalledWith('job1', expect.any(Function))
  })
})

describe('findings refresh', () => {
  it('preserves analyst decisions when a rule stops matching and later reappears', async () => {
    const f = { ruleId: 'html-review', key: 'html-review|1', source: 'mails', severity: 'critical', refs: [1], title: 'HTML', ts: 1, entities: {}, count: 1, attack: [] }
    await replaceFindings(1, ['html-review'], [f])
    const first = (await db.findings.toArray())[0]
    await db.findings.update(first.id!, { status: 'false_positive', notes: 'Reviewed: ordinary CSV export' })
    await replaceFindings(2, ['html-review'], [f])
    await replaceFindings(1, ['html-review'], [])
    expect(await db.findings.where('caseId').equals(1).count()).toBe(0)
    await replaceFindings(1, ['html-review'], [{ ...f, severity: 'low' }])
    expect((await db.findings.where('caseId').equals(1).first())).toMatchObject({ severity: 'low', status: 'false_positive', notes: 'Reviewed: ordinary CSV export', createdAt: first.createdAt })
    expect((await db.findings.where('caseId').equals(2).first())?.status).toBe('new')
  })
})
