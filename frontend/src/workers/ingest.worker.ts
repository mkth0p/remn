/// <reference lib="webworker" />
/**
 * Ingestion worker: hashes the file (SHA-256, streaming), uploads it, parses
 * the NDJSON stream and writes rows / facets / IOCs into IndexedDB.
 */
import { createSHA256 } from 'hash-wasm'
import { refKey, resolveEngineRefs, type EngineFinding } from '../data/engineFindings'
import { getDb, type AttachmentRow, type EventRow, type Facet, type Ioc, type MailBody, type MailRow, type UrlRow } from '../db/schema'
import { setApiToken, streamNdjson } from '../api/client'
import { isPublicIp } from '../util/format'
import { duplicateEvidence } from '../data/duplicateEvidence'

export interface IngestRequest {
  cmd: 'ingest'
  jobId: number
  caseId: number
  evidenceId: number
  file: File
  kind: 'evtx' | 'mail' | 'package'
  /** A completed chunked upload to parse instead of posting the file: set for large evidence. */
  uploadId?: string
  /** The digest computed during that upload, so the file is not read a second time. */
  uploadSha256?: string
  sourceName?: string
  includeRaw: boolean
  settings: { internalDomains: string[]; brands: string[]; vipNames: string[]; trustedSenders?: string[] }
  /** access token for remote deployments - the worker has its own api/client module instance */
  token?: string
}
export interface HashRequest {
  cmd: 'hash'
  jobId: number
  file: File
}
/** Recompute facets and indicators of a case from the rows still present (after evidence removal). */
export interface RebuildRequest {
  cmd: 'rebuild'
  caseId: number
}
export type WorkerRequest = IngestRequest | HashRequest | RebuildRequest

const ctx = self as unknown as DedicatedWorkerGlobalScope
const post = (msg: Record<string, unknown>) => ctx.postMessage(msg)

const EVENT_FACETS = [
  'eventId',
  'recordKind',
  'artifactType',
  'sourceFile',
  'channel',
  'provider',
  'computer',
  'targetUser',
  'subjectUser',
  'ipAddress',
  'logonType',
  'category',
  'levelName',
  'processName',
  'serviceName',
]
const MAIL_FACETS = ['fromDomain', 'fromAddr', 'fromNameNorm', 'folder', 'originIp', 'flags', 'sourceFormat', 'attExt', 'riskBand']
const FACET_CAP = 4000
const BATCH = 2000

class FacetCounter {
  counts = new Map<string, Map<string, number>>()
  add(field: string, value: unknown): void {
    if (value == null || value === '') return
    const vals = Array.isArray(value) ? value : [value]
    let m = this.counts.get(field)
    if (!m) this.counts.set(field, (m = new Map()))
    for (const v of vals) {
      const s = String(v).slice(0, 200)
      const cur = m.get(s)
      if (cur === undefined) {
        if (m.size >= FACET_CAP) continue
        m.set(s, 1)
      } else m.set(s, cur + 1)
    }
  }
}

class IocCounter {
  map = new Map<string, Ioc>()
  add(caseId: number, kind: Ioc['kind'], value: string | null | undefined, source: string, ts: number | null): void {
    if (!value) return
    const v = value.trim().toLowerCase().slice(0, 2048)
    if (!v) return
    const key = kind + ':' + v
    const cur = this.map.get(key)
    if (cur) {
      cur.count++
      if (!cur.sources.includes(source) && cur.sources.length < 8) cur.sources.push(source)
      if (ts != null) {
        cur.firstSeen = cur.firstSeen == null ? ts : Math.min(cur.firstSeen, ts)
        cur.lastSeen = cur.lastSeen == null ? ts : Math.max(cur.lastSeen, ts)
      }
    } else if (this.map.size < 50000) {
      this.map.set(key, { caseId, kind, value: v, sources: [source], firstSeen: ts, lastSeen: ts, count: 1 })
    }
  }
}

async function hashFile(file: File, onProgress?: (done: number) => void, signal?: { aborted: boolean }): Promise<string> {
  const hasher = await createSHA256()
  hasher.init()
  const chunk = 4 * 1024 * 1024
  let offset = 0
  while (offset < file.size) {
    if (signal?.aborted) throw new Error('aborted')
    const buf = await file.slice(offset, Math.min(offset + chunk, file.size)).arrayBuffer()
    hasher.update(new Uint8Array(buf))
    offset += buf.byteLength
    onProgress?.(offset)
  }
  return hasher.digest('hex')
}

async function flushFacets(caseId: number, source: 'events' | 'mails', fc: FacetCounter): Promise<void> {
  const db = getDb()
  for (const [field, m] of fc.counts) {
    const existing = await db.facets.where('[caseId+source+field]').equals([caseId, source, field]).toArray()
    const byVal = new Map(existing.map((f) => [f.value, f]))
    const puts: Facet[] = []
    for (const [value, count] of m) {
      const ex = byVal.get(value)
      if (ex) puts.push({ ...ex, count: ex.count + count })
      else puts.push({ caseId, source, field, value, count })
    }
    await db.facets.bulkPut(puts)
  }
}

async function flushIocs(caseId: number, ic: IocCounter): Promise<void> {
  const db = getDb()
  const items = Array.from(ic.map.values())
  for (let i = 0; i < items.length; i += 500) {
    const slice = items.slice(i, i + 500)
    const keys = slice.map((x) => [caseId, x.kind, x.value] as [number, string, string])
    const existing = await db.iocs.where('[caseId+kind+value]').anyOf(keys).toArray()
    const byKey = new Map(existing.map((e) => [e.kind + ':' + e.value, e]))
    const puts: Ioc[] = slice.map((x) => {
      const ex = byKey.get(x.kind + ':' + x.value)
      if (!ex) return x
      return {
        ...ex,
        count: ex.count + x.count,
        sources: Array.from(new Set([...ex.sources, ...x.sources])).slice(0, 8),
        firstSeen: ex.firstSeen == null ? x.firstSeen : x.firstSeen == null ? ex.firstSeen : Math.min(ex.firstSeen, x.firstSeen),
        lastSeen: ex.lastSeen == null ? x.lastSeen : x.lastSeen == null ? ex.lastSeen : Math.max(ex.lastSeen, x.lastSeen),
      }
    })
    await db.iocs.bulkPut(puts)
  }
}

function accumulateEvent(caseId: number, row: Record<string, unknown>, fc: FacetCounter, ic: IocCounter): void {
  for (const f of EVENT_FACETS) fc.add(f, row[f])
  const ts = typeof row.ts === 'number' ? row.ts : null
  const prov = String(row.provider ?? '')
  for (const f of ['ipAddress', 'destinationIp', 'sourceIp']) {
    const v = row[f]
    if (typeof v === 'string' && isPublicIp(v)) ic.add(caseId, 'ip', v, `event:${row.eventId}`, ts)
  }
  if (typeof row.query === 'string' && row.query.includes('.')) ic.add(caseId, 'domain', row.query, 'sysmon-dns', ts)
  if (typeof row.destinationHostname === 'string' && row.destinationHostname.includes('.')) ic.add(caseId, 'domain', row.destinationHostname, 'sysmon-net', ts)
  for (const h of hashesFromSysmon(row.hashes)) ic.add(caseId, 'hash', h, `sysmon:${row.eventId}`, ts)
  if (typeof row.url === 'string' && /^https?:\/\/(?![+*]|localhost|127\.)[a-z0-9.-]+(?::\d+)?(?:\/|$)/i.test(row.url)) ic.add(caseId, 'url', row.url, prov, ts)
}

function accumulateMail(caseId: number, m: MailRow, fc: FacetCounter, ic: IocCounter): void {
  for (const f of MAIL_FACETS) {
    if (f === 'attExt')
      fc.add(
        f,
        (m.attachments ?? []).map((a) => a.realExt || a.ext || '?'),
      )
    else if (f === 'riskBand') fc.add(f, m.risk >= 80 ? 'critical' : m.risk >= 60 ? 'high' : m.risk >= 40 ? 'medium' : m.risk >= 20 ? 'low' : 'clean')
    else fc.add(f, (m as Record<string, unknown>)[f])
  }
  const ts = m.date ?? null
  if (m.originIp && isPublicIp(m.originIp)) ic.add(caseId, 'ip', m.originIp, 'mail-origin', ts)
  if (m.fromAddr) ic.add(caseId, 'email', m.fromAddr, 'mail-from', ts)
  if (m.fromRegistrable) ic.add(caseId, 'domain', m.fromRegistrable, 'mail-from', ts)
  for (const u of m.urls ?? []) {
    if (u.scheme === 'http' || u.scheme === 'https' || !u.scheme) {
      ic.add(caseId, 'url', u.normalized || u.url, 'mail-url', ts)
      if (u.domain && !/^\d+\.\d+\.\d+\.\d+$/.test(u.domain)) ic.add(caseId, 'domain', u.domain, 'mail-url', ts)
      else if (u.domain && isPublicIp(u.domain)) ic.add(caseId, 'ip', u.domain, 'mail-url', ts)
    }
  }
  for (const a of m.attachments ?? []) if (a.sha256) ic.add(caseId, 'hash', a.sha256, 'attachment', ts)
}

/** Facets and indicators are accumulated during ingestion; after evidence removal they are recomputed
 * from the rows that remain, keeping the reputation results already obtained for surviving indicators. */
async function rebuild(caseId: number): Promise<void> {
  const db = getDb()
  const fcEvents = new FacetCounter()
  const fcMails = new FacetCounter()
  const ic = new IocCounter()
  let rows = 0
  await db.events
    .where('caseId')
    .equals(caseId)
    .each((row) => {
      accumulateEvent(caseId, row as unknown as Record<string, unknown>, fcEvents, ic)
      rows++
    })
  await db.mails
    .where('caseId')
    .equals(caseId)
    .each((m) => {
      accumulateMail(caseId, m, fcMails, ic)
      rows++
    })
  const old = await db.iocs.where('caseId').equals(caseId).toArray()
  const checked = new Map(old.filter((i) => i.checkedAt).map((i) => [i.kind + ':' + i.value, i]))
  for (const x of ic.map.values()) {
    const o = checked.get(x.kind + ':' + x.value)
    if (o) Object.assign(x, { reputation: o.reputation, verdict: o.verdict, tags: o.tags, checkedAt: o.checkedAt })
  }
  await db.transaction('rw', [db.facets, db.iocs], async () => {
    await db.facets.where('caseId').equals(caseId).delete()
    await db.iocs.where('caseId').equals(caseId).delete()
  })
  await flushFacets(caseId, 'events', fcEvents)
  await flushFacets(caseId, 'mails', fcMails)
  await flushIocs(caseId, ic)
  post({ type: 'rebuilt', rows, iocs: ic.map.size })
}

function hashesFromSysmon(h: unknown): string[] {
  if (typeof h !== 'string') return []
  const out: string[] = []
  for (const part of h.split(',')) {
    const [k, v] = part.split('=')
    if (k && v && (k.trim().toUpperCase() === 'SHA256' || k.trim().toUpperCase() === 'MD5' || k.trim().toUpperCase() === 'SHA1')) out.push(v.trim())
  }
  return out
}

async function ingest(req: IngestRequest): Promise<void> {
  const db = getDb()
  const { caseId, evidenceId, file, kind } = req
  const abort = { aborted: false }
  let lastReport = 0
  // A large file was uploaded in chunks before this worker started and hashed on the way, so it
  // is neither read nor sent a second time here.
  let sha256 = req.uploadSha256 ?? ''
  if (!sha256) {
    post({ type: 'phase', phase: 'hashing' })
    sha256 = await hashFile(
      file,
      (done) => {
        const now = Date.now()
        if (now - lastReport > 150 || done === file.size) {
          lastReport = now
          post({ type: 'hash-progress', done, total: file.size })
        }
      },
      abort,
    )
  }
  post({ type: 'hash', sha256 })
  const duplicate = await duplicateEvidence(caseId, evidenceId, req.sourceName ?? file.name, kind, sha256)
  if (duplicate) {
    await db.evidence.delete(evidenceId)
    post({ type: 'duplicate', evidenceId: duplicate.id })
    return
  }
  await db.evidence.update(evidenceId, { sha256Client: sha256, status: 'uploading' })

  post({ type: 'phase', phase: 'uploading' })
  const form = new FormData()
  if (req.uploadId) form.append('uploadId', req.uploadId)
  else form.append('file', file, file.name)
  form.append('sourceName', req.sourceName ?? file.name)
  form.append('raw', req.includeRaw ? '1' : '0')
  if (kind !== 'evtx')
    form.append(
      'settings',
      JSON.stringify({ internalDomains: req.settings.internalDomains, brands: req.settings.brands, vipNames: req.settings.vipNames, trustedSenders: req.settings.trustedSenders ?? [] }),
    )

  const fc = new FacetCounter()
  const mailFc = new FacetCounter()
  const ic = new IocCounter()
  let batch: Record<string, unknown>[] = []
  let batchType: 'event' | 'mail' = 'event'
  let inserted = 0
  const st = { meta: null as Record<string, unknown> | null, done: null as Record<string, unknown> | null, errorMsg: null as string | null }
  let lastProgress = 0

  // Findings an engine produced on the server name their rows by record identity; the ids those
  // rows get here are only known once they are inserted, so the index is built on the way in,
  // and only when the server said an engine would run.
  const engineFindings: EngineFinding[] = []
  const engineSummaries: Record<string, unknown>[] = []
  const refIndex = new Map<string, number>()
  const wantRefs = () => Array.isArray(st.meta?.engines) && (st.meta!.engines as unknown[]).length > 0
  const flushEvents = async () => {
    if (!batch.length) return
    const rows = batch as EventRow[]
    batch = []
    if (wantRefs()) {
      const ids = (await db.events.bulkAdd(rows, { allKeys: true })) as number[]
      rows.forEach((row, i) => {
        const r = row as unknown as Record<string, unknown>
        if (r.recordId != null) refIndex.set(refKey(r), ids[i])
      })
    } else {
      await db.events.bulkAdd(rows)
    }
    inserted += rows.length
  }
  const flushMails = async () => {
    if (!batch.length) return
    const rows = batch
    batch = []
    const mails: MailRow[] = []
    const bodies: Omit<MailBody, 'mailId'>[] = []
    for (const r of rows) {
      const { bodyText, bodyHtml, headersText, visibleText, ...rest } = r as Record<string, unknown>
      mails.push(rest as MailRow)
      bodies.push({
        caseId,
        bodyText: (bodyText as string) ?? null,
        bodyHtml: (bodyHtml as string) ?? null,
        headersText: (headersText as string) ?? null,
        visibleText: (visibleText as string) ?? null,
      })
    }
    const keys = (await db.mails.bulkAdd(mails, { allKeys: true })) as number[]
    const bodyRows: MailBody[] = bodies.map((b, i) => ({ ...b, mailId: keys[i] }))
    await db.mailBodies.bulkPut(bodyRows)
    const atts: AttachmentRow[] = []
    const urls: UrlRow[] = []
    mails.forEach((m, i) => {
      const mailId = keys[i]
      for (const a of m.attachments ?? []) {
        atts.push({ ...a, details: undefined, caseId, mailId, evidenceId, mailSubject: m.subject, fromAddr: m.fromAddr, date: m.date })
      }
      for (const u of m.urls ?? []) urls.push({ ...u, caseId, mailId, evidenceId })
    })
    if (atts.length) await db.attachments.bulkAdd(atts)
    if (urls.length) await db.urls.bulkAdd(urls)
    inserted += mails.length
  }

  const onRow = async (row: Record<string, unknown>) => {
    const type = row.type
    if (type === 'meta') {
      st.meta = row
      post({ type: 'meta', meta: row })
      await db.evidence.update(evidenceId, { status: 'parsing', format: String(row.format ?? ''), sha256Server: String(row.sha256 ?? '') })
      post({ type: 'phase', phase: 'parsing' })
      return
    }
    if (type === 'done') {
      st.done = row
      return
    }
    if (type === 'finding') {
      delete row.type
      engineFindings.push(row as unknown as EngineFinding)
      return
    }
    if (type === 'engine') {
      delete row.type
      engineSummaries.push(row)
      const status = String(row.status ?? '')
      post({ type: 'log', level: status === 'parsed' ? 'info' : 'warn', text: `${row.engine}: ${row.findings} finding(s) in ${row.seconds}s${row.reason ? ' - ' + row.reason : ''}` })
      return
    }
    if (type === 'error') {
      st.errorMsg = String(row.error ?? 'unknown error')
      post({ type: 'log', level: 'err', text: `server: ${st.errorMsg}` })
      return
    }
    delete row.type
    row.caseId = caseId
    row.evidenceId = evidenceId
    if (type === 'event' || type === 'mail') {
      if (batch.length && type !== batchType) {
        if (batchType === 'event') await flushEvents()
        else await flushMails()
      }
      batchType = type
    }
    if (type === 'event') {
      accumulateEvent(caseId, row, fc, ic)
      batch.push(row)
      if (batch.length >= BATCH) await flushEvents()
    } else if (type === 'mail') {
      accumulateMail(caseId, row as unknown as MailRow, mailFc, ic)
      batch.push(row)
      if (batch.length >= 200) await flushMails()
    }
    const now = Date.now()
    if (now - lastProgress > 200) {
      lastProgress = now
      post({ type: 'progress', rows: inserted + batch.length })
    }
  }

  try {
    await streamNdjson(`/api/ingest/${kind}`, form, onRow, { onBytes: (n) => post({ type: 'bytes', bytes: n }) })
    if (!st.done) throw new Error('Ingestion stream ended before its completion record; imported rows may be partial')
    if (batchType === 'event') await flushEvents()
    else await flushMails()
    post({ type: 'progress', rows: inserted })
    post({ type: 'log', level: 'info', text: 'writing facets and indicators…' })
    await flushFacets(caseId, 'events', fc)
    await flushFacets(caseId, 'mails', mailFc)
    await flushIocs(caseId, ic)
    const serverHash = (st.done?.sha256 as string) || (st.meta?.sha256 as string) || ''
    const integrity = serverHash ? (serverHash === sha256 ? 'verified' : 'mismatch') : 'pending'
    await db.evidence.update(evidenceId, {
      status: st.errorMsg ? 'error' : 'done',
      error: st.errorMsg ?? undefined,
      count: inserted,
      stats: (st.done?.stats as Record<string, unknown>) ?? undefined,
      sha256Server: serverHash || undefined,
      integrity,
      progress: 1,
    })
    if (engineFindings.length) {
      // resolved here, where the index is; stored by the main thread, which owns the case
      post({ type: 'findings', engine: String(engineFindings[0].engine ?? 'hayabusa'), findings: resolveEngineRefs(engineFindings, refIndex), summaries: engineSummaries })
    }
    post({ type: 'done', count: inserted, stats: st.done?.stats ?? null, sha256, sha256Server: serverHash, integrity, error: st.errorMsg })
  } catch (e) {
    const msg = (e as Error).message || String(e)
    try {
      if (batchType === 'event') await flushEvents()
      else await flushMails()
    } catch {
      /* ignore */
    }
    // A truncated stream still commits the rows it received, so the facets and indicators derived
    // from them have to be written too. Without this the rows exist while the facet and IOC tables
    // hold nothing for them, and no rebuild is scheduled. Failures here must not mask the original.
    try {
      await flushFacets(caseId, 'events', fc)
      await flushFacets(caseId, 'mails', mailFc)
      await flushIocs(caseId, ic)
    } catch {
      /* the original error is the one worth reporting */
    }
    await db.evidence.update(evidenceId, { status: 'error', error: msg, count: inserted })
    post({ type: 'error', error: msg, count: inserted })
  }
}

ctx.onmessage = async (ev: MessageEvent<WorkerRequest>) => {
  const req = ev.data
  try {
    if (req.cmd === 'hash') {
      const sha256 = await hashFile(req.file, (done) => post({ type: 'hash-progress', done, total: req.file.size }))
      post({ type: 'hash', sha256, jobId: req.jobId })
    } else if (req.cmd === 'ingest') {
      if (req.token) setApiToken(req.token)
      await ingest(req)
    } else if (req.cmd === 'rebuild') {
      await rebuild(req.caseId)
    }
  } catch (e) {
    post({ type: 'error', error: (e as Error).message || String(e) })
  }
}
