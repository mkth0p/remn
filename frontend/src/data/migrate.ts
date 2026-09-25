/** Stage rows with their original IDs, then atomically switch storage and remove browser copies. */
import { API_HEADERS } from '../api/client'
import { getDb, newServerKey, type Case } from '../db/schema'
import { toast, useStore } from '../state/store'
import { caseRows, importServerBatch } from './caseTransfer'

export async function migrateCaseToServer(kase: Case, onProgress?: (msg: string) => void): Promise<Case> {
  if (kase.storage === 'server' && kase.serverKey) return kase
  const db = getDb()
  const caseId = kase.id!
  const key = newServerKey()
  let total = 0
  const updated: Case = { ...kase, storage: 'server', serverKey: key, updatedAt: Date.now() }
  try {
    const evidence = await db.evidence.where('caseId').equals(caseId).toArray()
    for (const ev of evidence) await importServerBatch(key, ev.id!, [{ ...ev, type: 'evidence' }])
    const before = await Promise.all(['events', 'mails'].map((t) => db.table(t).where('caseId').equals(caseId).count()))
    for (const source of ['events', 'mails']) {
      for await (const page of caseRows(source, caseId)) {
        const bodies = source === 'mails' ? await db.mailBodies.bulkGet(page.map((r) => Number(r.id))) : []
        const groups = new Map<number, Record<string, unknown>[]>()
        for (const [i, r] of page.entries()) {
          const eid = Number(r.evidenceId)
          if (!evidence.some((e) => e.id === eid)) throw new Error('Evidence changed during migration; retry when ingestion is complete.')
          const rows = groups.get(eid) ?? []
          rows.push({ ...r, ...bodies[i], id: r.id, type: source === 'mails' ? 'mail' : 'event' })
          groups.set(eid, rows)
        }
        for (const [eid, rows] of groups) await importServerBatch(key, eid, rows)
        total += page.length
        onProgress?.(`${total.toLocaleString()} rows transferred`)
      }
    }
    await db.transaction('rw', [db.cases, db.events, db.mails, db.mailBodies, db.attachments, db.urls, db.facets], async () => {
      const after = await Promise.all(['events', 'mails'].map((t) => db.table(t).where('caseId').equals(caseId).count()))
      if (after.some((count, i) => count !== before[i]) || total !== before[0] + before[1]) throw new Error('Evidence changed during migration; retry when ingestion is complete.')
      await db.cases.update(caseId, { storage: 'server', serverKey: key, updatedAt: updated.updatedAt })
      for (const t of [db.events, db.mails, db.mailBodies, db.attachments, db.urls, db.facets]) await t.where('caseId').equals(caseId).delete()
    })
  } catch (error) {
    await fetch(`/api/store/${key}`, { method: 'DELETE', headers: API_HEADERS }).catch(() => undefined)
    throw error
  }
  useStore.getState().setCurrentCase(updated)
  useStore.getState().bumpRules()
  toast('ok', `Case moved to server storage (${total.toLocaleString()} rows); findings, links and reviews preserved.`, 8000)
  onProgress?.('done')
  return updated
}
