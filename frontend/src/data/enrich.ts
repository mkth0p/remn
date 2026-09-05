import { apiPost } from '../api/client'
import { getDb, type Case } from '../db/schema'
import { settingsForRules } from './rules'

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
  senderSolicited?: boolean
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
    id: m.id, date: m.date, fromAddr: m.fromAddr, fromRegistrable: m.fromRegistrable, to: m.to, cc: m.cc, bcc: m.bcc, subject: m.subject,
    spf: m.auth?.spf ?? null, dkim: m.auth?.dkim ?? null, dmarc: m.auth?.dmarc ?? null, flags: m.flags,
    urls: (m.urls ?? []).map((u) => ({ domain: u.domain })), attachments: (m.attachments ?? []).map((a) => ({ name: a.name, sha256: a.sha256 })),
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
