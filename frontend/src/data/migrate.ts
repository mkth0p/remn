/**
 * Move a browser-stored case to a server case store (DuckDB). Rows are
 * streamed as NDJSON to /api/store/<key>/import, then the browser copies are
 * deleted. Findings are dropped because their row references change.
 */
import { API_HEADERS } from '../api/client'
import { getDb, newServerKey, type Case } from '../db/schema'
import { log, toast, useStore } from '../state/store'

const BATCH_LINES = 4000

async function postBatch(key: string, evidenceId: number, lines: string[]): Promise<void> {
  if (!lines.length) return
  const resp = await fetch(`/api/store/${key}/import?evidenceId=${evidenceId}`, { method: 'POST', headers: { ...API_HEADERS, 'Content-Type': 'application/x-ndjson' }, body: lines.join('\n') + '\n' })
  if (!resp.ok) throw new Error(`import failed (${resp.status}): ${(await resp.text()).slice(0, 200)}`)
}

export async function migrateCaseToServer(kase: Case, onProgress?: (msg: string) => void): Promise<Case> {
  if (kase.storage === 'server' && kase.serverKey) return kase
  const db = getDb()
  const caseId = kase.id!
  const key = newServerKey()
  const evidence = await db.evidence.where('caseId').equals(caseId).toArray()
  let total = 0
  for (const ev of evidence) {
    onProgress?.(`${ev.name}: evidence record`)
    await postBatch(key, ev.id!, [JSON.stringify({ type: 'evidence', id: ev.id, name: ev.name, kind: ev.kind, format: ev.format, size: ev.size, sha256Client: ev.sha256Client, sha256Server: ev.sha256Server, count: ev.count, stats: ev.stats, addedAt: ev.addedAt, status: ev.status })])
    let lines: string[] = []
    let n = 0
    if (ev.kind === 'evtx') {
      await db.events
        .where('[caseId+evidenceId]')
        .equals([caseId, ev.id!])
        .each((r) => {
          const { id, caseId: _c, evidenceId: _e, ...rest } = r
          void id
          void _c
          void _e
          lines.push(JSON.stringify({ type: 'event', ...rest }))
          n++
        })
      for (let i = 0; i < lines.length; i += BATCH_LINES) {
        await postBatch(key, ev.id!, lines.slice(i, i + BATCH_LINES))
        onProgress?.(`${ev.name}: ${Math.min(i + BATCH_LINES, lines.length).toLocaleString('en-US')} / ${lines.length.toLocaleString('en-US')} events`)
      }
      lines = []
    } else {
      const mails = await db.mails.where('[caseId+evidenceId]').equals([caseId, ev.id!]).toArray()
      for (let i = 0; i < mails.length; i += 200) {
        const slice = mails.slice(i, i + 200)
        const bodies = await db.mailBodies.where('mailId').anyOf(slice.map((m) => m.id!)).toArray()
        const byId = new Map(bodies.map((b) => [b.mailId, b]))
        const batch = slice.map((m) => {
          const { id, caseId: _c, evidenceId: _e, ...rest } = m
          void id
          void _c
          void _e
          const b = byId.get(m.id!)
          return JSON.stringify({ type: 'mail', ...rest, bodyText: b?.bodyText ?? null, bodyHtml: b?.bodyHtml ?? null, headersText: b?.headersText ?? null, visibleText: b?.visibleText ?? null })
        })
        await postBatch(key, ev.id!, batch)
        n += slice.length
        onProgress?.(`${ev.name}: ${n} / ${mails.length} mails`)
      }
    }
    total += n
    log('ok', `[migrate] ${ev.name}: ${n} rows moved`)
  }
  const updated: Case = { ...kase, storage: 'server', serverKey: key, updatedAt: Date.now() }
  await db.cases.update(caseId, { storage: 'server', serverKey: key, updatedAt: updated.updatedAt })
  onProgress?.('removing browser copies…')
  await db.transaction('rw', [db.events, db.mails, db.mailBodies, db.attachments, db.urls, db.facets, db.iocs, db.findings], async () => {
    await db.events.where('caseId').equals(caseId).delete()
    const mailIds = await db.mails.where('caseId').equals(caseId).primaryKeys()
    if (mailIds.length) await db.mailBodies.where('mailId').anyOf(mailIds).delete()
    await db.mails.where('caseId').equals(caseId).delete()
    await db.attachments.where('caseId').equals(caseId).delete()
    await db.urls.where('caseId').equals(caseId).delete()
    await db.facets.where('caseId').equals(caseId).delete()
    await db.iocs.where('caseId').equals(caseId).delete()
    await db.findings.where('caseId').equals(caseId).delete()
  })
  useStore.getState().setCurrentCase(updated)
  useStore.getState().bumpRules()
  toast('ok', `case moved to the server store (${total.toLocaleString('en-US')} rows). Re-run the rules to rebuild findings.`, 8000)
  onProgress?.('done')
  return updated
}
