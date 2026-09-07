import { apiPost } from '../api/client'
import { getDb, type Case } from '../db/schema'
import { settingsForRules } from './rules'
import type { MailRow } from '../db/schema'
import { waitForJob } from './jobs'

export interface RescoreSummary {
  version: string
  mails: number
  changed: number
  limited: number
  highBefore: number
  highAfter: number
}
type ScoreUpdate = Pick<MailRow, 'id' | 'risk' | 'flags' | 'attachments' | 'maxAttachmentRisk' | 'assessment'>

/** Update scores and normalized child rows together; keep evidence IDs and bodies. */
export async function applyScoreBatch(caseId: number, requested: number[], updates: ScoreUpdate[]): Promise<void> {
  const db = getDb()
  const ids = new Set(requested)
  if (updates.length !== ids.size || new Set(updates.map((r) => r.id)).size !== ids.size || updates.some((r) => r.id == null || !ids.has(r.id)))
    throw new Error('Incomplete or invalid rescore response')
  await db.transaction('rw', [db.mails, db.attachments], async () => {
    for (const r of updates) {
      const current = await db.mails.get(r.id!)
      if (!current || current.caseId !== caseId) throw new Error('Case changed during rescoring')
      const { id, ...changes } = r
      await db.mails.update(id!, changes)
      const children = await db.attachments.where('mailId').equals(id!).toArray()
      for (const child of children) {
        const a = r.attachments.find((a) => a.name === child.name && a.sha256 === child.sha256)
        if (a && child.caseId === caseId) await db.attachments.update(child.id!, { risk: a.risk, flags: a.flags, details: a.details, rescoreLimited: a.rescoreLimited })
      }
    }
  })
}

async function rebuildScoreFacets(caseId: number): Promise<void> {
  const db = getDb()
  const counts = new Map<string, Map<string, number>>([
    ['flags', new Map()],
    ['riskBand', new Map()],
  ])
  await db.mails
    .where('caseId')
    .equals(caseId)
    .each((m) => {
      const band = m.risk >= 80 ? 'critical' : m.risk >= 60 ? 'high' : m.risk >= 40 ? 'medium' : m.risk >= 20 ? 'low' : 'clean'
      for (const [field, values] of [
        ['flags', m.flags],
        ['riskBand', [band]],
      ] as [string, string[]][]) {
        const c = counts.get(field)!
        for (const v of new Set(values)) c.set(v, (c.get(v) ?? 0) + 1)
      }
    })
  await db.transaction('rw', db.facets, async () => {
    for (const [field, entries] of counts) {
      await db.facets.where('[caseId+source+field]').equals([caseId, 'mails', field]).delete()
      await db.facets.bulkAdd([...entries].map(([value, count]) => ({ caseId, source: 'mails' as const, field, value, count })))
    }
  })
}

const rescoring = new Set<number>()
export async function rescoreMails(kase: Case, onProgress?: (text: string) => void): Promise<RescoreSummary> {
  const db = getDb()
  const caseId = kase.id!
  if (rescoring.has(caseId)) throw new Error('This case is already being rescored')
  rescoring.add(caseId)
  const key = `mail-calibration-${caseId}`
  const settings = settingsForRules(kase)
  try {
    await db.kv.put({ key, value: { state: 'running', at: Date.now() } })
    let summary: RescoreSummary
    if (kase.storage === 'server' && kase.serverKey) {
      const { jobId } = await apiPost<{ jobId: string }>('/api/enrich/mails/rescore', { storeKey: kase.serverKey, settings })
      const job = await waitForJob(jobId, (j) => onProgress?.(`${j.progress.done ?? 0} / ${j.progress.total ?? '…'} mails`))
      summary = job.result as unknown as RescoreSummary
    } else {
      onProgress?.('Updating sender history…')
      await baselineSenders(kase)
      summary = { version: '', mails: 0, changed: 0, limited: 0, highBefore: 0, highAfter: 0 }
      let last = 0
      const max = (await db.mails.where('caseId').equals(caseId).reverse().first())?.id ?? 0
      for (;;) {
        if (last >= max) break
        const rows = await db.mails
          .where('id')
          .between(last, max, false, true)
          .filter((m) => m.caseId === caseId)
          .limit(100)
          .toArray()
        if (!rows.length) break
        const result = await apiPost<{ rows: ScoreUpdate[]; summary: RescoreSummary }>('/api/enrich/mails/rescore', { mails: rows, settings })
        await applyScoreBatch(
          caseId,
          rows.map((m) => m.id!),
          result.rows,
        )
        summary.version = result.summary.version
        for (const k of ['mails', 'changed', 'limited', 'highBefore', 'highAfter'] as const) summary[k] += result.summary[k]
        last = rows[rows.length - 1].id!
        onProgress?.(`${summary.mails.toLocaleString()} mails rescored`)
      }
    }
    await db.kv.put({ key, value: { state: 'scores_done', at: Date.now(), summary } })
    return summary
  } catch (e) {
    await db.kv.put({ key, value: { state: 'incomplete', at: Date.now(), error: (e as Error).message } })
    throw e
  } finally {
    rescoring.delete(caseId)
    if (kase.storage !== 'server') await rebuildScoreFacets(caseId)
  }
}

export interface BaselineSummary {
  mails: number
  newSenders: number
  unsolicitedNew: number
  authRegressions: number
  campaigns: number
  largestCampaign: number
  updated?: number
}
interface EnrichRow {
  id: number
  senderPrevalence?: string
  senderPriorCount?: number
  senderFirstSeen?: number
  senderDaysKnown?: number
  senderSolicited?: boolean | null
  senderAuthRegression?: boolean
  campaignId?: string
  campaignSize?: number
  campaignSenders?: number
}

/**
 * Sender baselining + campaign clustering. Server cases: the API updates DuckDB in place.
 * Browser cases: the minimal mail rows are posted and the enrichment columns written back to Dexie.
 */
export async function baselineSenders(kase: Case): Promise<BaselineSummary> {
  const settings = settingsForRules(kase)
  if (kase.storage === 'server' && kase.serverKey) {
    const r = await apiPost<{ summary: BaselineSummary }>('/api/enrich/mails', { storeKey: kase.serverKey, settings })
    await getDb().kv.put({ key: `baseline-${kase.id}`, value: { ...r.summary, at: Date.now() } })
    return r.summary
  }
  const db = getDb()
  const all = await db.mails.where('caseId').equals(kase.id!).toArray()
  const mails = all.map((m) => ({
    id: m.id,
    date: m.date,
    fromAddr: m.fromAddr,
    fromRegistrable: m.fromRegistrable,
    to: m.to,
    cc: m.cc,
    bcc: m.bcc,
    subject: m.subject,
    spf: m.auth?.spf ?? null,
    dkim: m.auth?.dkim ?? null,
    dmarc: m.auth?.dmarc ?? null,
    flags: m.flags,
    urls: (m.urls ?? []).map((u) => ({ domain: u.domain })),
    attachments: (m.attachments ?? []).map((a) => ({ name: a.name, sha256: a.sha256 })),
  }))
  const r = await apiPost<{ rows: EnrichRow[]; summary: BaselineSummary }>('/api/enrich/mails', { mails, settings })
  const updates = r.rows.map((row) => {
    const { id, ...changes } = row
    return { key: id, changes: changes as Record<string, unknown> }
  })
  for (let i = 0; i < updates.length; i += 2000) await db.mails.bulkUpdate(updates.slice(i, i + 2000))
  await db.kv.put({ key: `baseline-${kase.id}`, value: { ...r.summary, at: Date.now() } })
  return r.summary
}
