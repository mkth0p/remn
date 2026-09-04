import { createSHA256 } from 'hash-wasm'
import { uuid4 } from './uuid'
import { getDb, newServerKey, type Case, type Ioc, type MailBody } from '../db/schema'
import { API_HEADERS, readNdjsonBody } from '../api/client'

export function downloadBlob(name: string, blob: Blob): void {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  document.body.appendChild(a)
  a.click()
  setTimeout(() => {
    URL.revokeObjectURL(url)
    a.remove()
  }, 1000)
}

export function toCsv(rows: Record<string, unknown>[], columns?: string[]): string {
  if (!rows.length) return ''
  const cols = columns ?? Array.from(rows.reduce((s, r) => (Object.keys(r).forEach((k) => s.add(k)), s), new Set<string>()))
  const esc = (v: unknown) => {
    if (v == null) return ''
    const s = typeof v === 'object' ? JSON.stringify(v) : String(v)
    // Neutralise formula injection when the CSV is opened in Excel
    const safe = /^[=+\-@\t\r]/.test(s) ? "'" + s : s
    return /[",\n\r]/.test(safe) ? '"' + safe.replace(/"/g, '""') + '"' : safe
  }
  const lines = [cols.join(',')]
  for (const r of rows) lines.push(cols.map((c) => esc(r[c])).join(','))
  return lines.join('\r\n')
}

export function exportCsv(name: string, rows: Record<string, unknown>[], columns?: string[]): void {
  downloadBlob(name, new Blob(['﻿' + toCsv(rows, columns)], { type: 'text/csv;charset=utf-8' }))
}

export function exportJson(name: string, data: unknown): void {
  downloadBlob(name, new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }))
}

const STIX_TYPES: Record<string, (v: string) => string> = {
  ip: (v) => (v.includes(':') ? `[ipv6-addr:value = '${v}']` : `[ipv4-addr:value = '${v}']`),
  domain: (v) => `[domain-name:value = '${v}']`,
  url: (v) => `[url:value = '${v.replace(/'/g, "\\'")}']`,
  hash: (v) => (v.length === 64 ? `[file:hashes.'SHA-256' = '${v}']` : v.length === 40 ? `[file:hashes.'SHA-1' = '${v}']` : `[file:hashes.MD5 = '${v}']`),
  email: (v) => `[email-addr:value = '${v}']`,
}

export function iocsToStix(kase: Case, iocs: Ioc[]): Record<string, unknown> {
  const now = new Date().toISOString()
  const objects: Record<string, unknown>[] = []
  for (const i of iocs) {
    const pattern = STIX_TYPES[i.kind]?.(i.value)
    if (!pattern) continue
    objects.push({
      type: 'indicator',
      spec_version: '2.1',
      id: `indicator--${uuid4()}`,
      created: now,
      modified: now,
      name: `${i.kind}: ${i.value}`,
      description: `Seen ${i.count} time(s) in case "${kase.name}" (sources: ${i.sources.join(', ')})${i.verdict ? ` - reputation: ${i.verdict}` : ''}`,
      indicator_types: [i.verdict === 'malicious' ? 'malicious-activity' : i.verdict === 'suspicious' ? 'anomalous-activity' : 'unknown'],
      pattern,
      pattern_type: 'stix',
      valid_from: i.firstSeen ? new Date(i.firstSeen).toISOString() : now,
      labels: i.tags ?? [],
    })
  }
  return { type: 'bundle', id: `bundle--${uuid4()}`, objects }
}

export async function sha256Hex(text: string): Promise<string> {
  const h = await createSHA256()
  h.init()
  h.update(new TextEncoder().encode(text))
  return h.digest('hex')
}

/** Export the whole case (all tables) as one JSON bundle with a manifest hash. */
export async function exportCaseBundle(kase: Case, onProgress?: (msg: string) => void): Promise<void> {
  const db = getDb()
  const id = kase.id!
  const bundle: Record<string, unknown> = { format: 'remn-case', version: 1, exportedAt: new Date().toISOString(), case: kase }
  const isServer = kase.storage === 'server' && !!kase.serverKey
  const tables = ['evidence', 'events', 'mails', 'mailBodies', 'attachments', 'urls', 'findings', 'iocs', 'facets', 'aiSessions', 'savedSearches'] as const
  for (const t of tables) {
    onProgress?.(`reading ${t}…`)
    bundle[t] = await (db[t] as unknown as { where: (k: string) => { equals: (v: number) => { toArray: () => Promise<unknown[]> } } }).where('caseId').equals(id).toArray()
  }
  if (isServer) {
    // rows live in DuckDB, not IndexedDB: pull them from the export endpoint
    // in /import wire format ({type: evidence|event|mail, ...})
    onProgress?.('reading server store…')
    const serverRows: Record<string, unknown>[] = []
    const resp = await fetch(`/api/store/${kase.serverKey}/export`, { headers: API_HEADERS })
    if (!resp.ok) throw new Error(`server export failed (${resp.status})`)
    await readNdjsonBody(resp, (row) => {
      serverRows.push(row)
      if (serverRows.length % 20000 === 0) onProgress?.(`reading server store… ${serverRows.length.toLocaleString('en-US')} rows`)
    })
    bundle.serverRows = serverRows
  }
  const custom = await db.customRules.filter((c) => c.caseId === id).toArray()
  bundle.customRules = custom
  onProgress?.('hashing…')
  const payload = JSON.stringify(bundle)
  const hash = await sha256Hex(payload)
  const wrapper = `{"sha256":"${hash}","bundle":${payload}}`
  downloadBlob(`${kase.name.replace(/[^a-z0-9_-]+/gi, '_')}-${new Date().toISOString().slice(0, 10)}.remn.json`, new Blob([wrapper], { type: 'application/json' }))
  onProgress?.('done')
}

export async function importCaseBundle(file: File, onProgress?: (msg: string) => void): Promise<number> {
  const text = await file.text()
  const wrapper = JSON.parse(text) as { sha256: string; bundle: Record<string, unknown> }
  if (!wrapper?.bundle || (wrapper.bundle as { format?: string }).format !== 'remn-case') throw new Error('not an REMN case bundle')
  onProgress?.('verifying hash…')
  const payload = text.slice(text.indexOf('"bundle":') + 9, -1)
  const hash = await sha256Hex(payload)
  if (hash !== wrapper.sha256) throw new Error(`bundle hash mismatch (expected ${wrapper.sha256.slice(0, 12)}…, got ${hash.slice(0, 12)}…)`)
  const b = wrapper.bundle
  const db = getDb()
  const kase = { ...(b.case as Case) }
  delete kase.id
  kase.name = `${kase.name} (imported)`
  const serverRows = (b.serverRows as Record<string, unknown>[] | undefined) ?? []
  if (kase.storage === 'server') {
    if (serverRows.length) {
      kase.serverKey = newServerKey()
    } else {
      // bundle predates the server export path (or the store was empty): keep
      // the browser-side tables but do not point at a store we cannot rebuild
      kase.storage = 'browser'
      delete kase.serverKey
    }
  }
  const newId = await db.cases.add(kase)
  if (kase.storage === 'server' && kase.serverKey && serverRows.length) {
    onProgress?.('rebuilding server store…')
    // the first /import call creates the store (registry.get(create=True))
    const byEvidence = new Map<number, Record<string, unknown>[]>()
    for (const r of serverRows) {
      const eid = Number((r as { evidenceId?: number }).evidenceId ?? 0)
      const arr = byEvidence.get(eid) ?? []
      arr.push(r)
      byEvidence.set(eid, arr)
    }
    let sent = 0
    for (const [eid, rows] of byEvidence) {
      for (let i = 0; i < rows.length; i += 4000) {
        const body = rows.slice(i, i + 4000).map((r) => JSON.stringify(r)).join('\n')
        const resp = await fetch(`/api/store/${kase.serverKey}/import?evidenceId=${eid}`, { method: 'POST', headers: { ...API_HEADERS, 'Content-Type': 'application/x-ndjson' }, body })
        if (!resp.ok) throw new Error(`server import failed (${resp.status})`)
        sent += Math.min(4000, rows.length - i)
        onProgress?.(`rebuilding server store… ${sent.toLocaleString('en-US')} / ${serverRows.length.toLocaleString('en-US')} rows`)
      }
    }
  }
  const evidenceMap = new Map<number, number>()
  onProgress?.('evidence…')
  for (const e of (b.evidence as { id: number; caseId: number }[]) ?? []) {
    const { id, ...rest } = e
    const nid = await db.evidence.add({ ...rest, caseId: newId } as never)
    evidenceMap.set(id, nid)
  }
  const remap = (r: { id?: number; caseId: number; evidenceId?: number }) => {
    const { id, ...rest } = r
    void id
    return { ...rest, caseId: newId, evidenceId: r.evidenceId != null ? evidenceMap.get(r.evidenceId) ?? r.evidenceId : undefined }
  }
  onProgress?.('events…')
  const events = ((b.events as { id?: number; caseId: number; evidenceId?: number }[]) ?? []).map(remap)
  for (let i = 0; i < events.length; i += 5000) await db.events.bulkAdd(events.slice(i, i + 5000) as never[])
  onProgress?.('mails…')
  const mailMap = new Map<number, number>()
  for (const m of (b.mails as { id: number; caseId: number; evidenceId?: number }[]) ?? []) {
    const nid = await db.mails.add(remap(m) as never)
    mailMap.set(m.id, nid)
  }
  for (const body of (b.mailBodies as MailBody[]) ?? []) {
    const nid = mailMap.get(body.mailId)
    if (nid) await db.mailBodies.put({ ...body, mailId: nid, caseId: newId })
  }
  type AnyTable = { bulkAdd: (rows: unknown[]) => Promise<unknown> }
  for (const t of ['attachments', 'urls'] as const) {
    const rows = ((b[t] as { id?: number; caseId: number; evidenceId?: number; mailId: number }[]) ?? []).map((r) => ({ ...remap(r), mailId: mailMap.get(r.mailId) ?? r.mailId }))
    for (let i = 0; i < rows.length; i += 5000) await (db[t] as unknown as AnyTable).bulkAdd(rows.slice(i, i + 5000))
  }
  onProgress?.('findings, iocs, facets…')
  for (const t of ['findings', 'iocs', 'facets', 'aiSessions', 'savedSearches'] as const) {
    const rows = ((b[t] as { id?: number; caseId: number }[]) ?? []).map((r) => {
      const { id, ...rest } = r
      void id
      return { ...rest, caseId: newId }
    })
    for (let i = 0; i < rows.length; i += 5000) await (db[t] as unknown as AnyTable).bulkAdd(rows.slice(i, i + 5000))
  }
  for (const c of (b.customRules as { id?: number; caseId: number | null }[]) ?? []) {
    const { id, ...rest } = c
    void id
    await db.customRules.add({ ...rest, caseId: newId } as never)
  }
  onProgress?.('done')
  return newId
}
