import { autoRunAfterIngest } from './findingsState'
import { apiPost, API_HEADERS } from '../api/client'
import { getDb, type Case, type Evidence } from '../db/schema'
import { log, toast, useStore } from '../state/store'
import type { IngestRequest } from '../workers/ingest.worker'
import { chunkedUpload } from './upload'
import { waitForJob } from './jobs'
import { getSource } from './source'

let jobSeq = 1

export function detectKind(file: File): 'evtx' | 'mail' {
  const n = file.name.toLowerCase()
  if (n.endsWith('.evtx')) return 'evtx'
  // Microsoft 365 audit / Entra sign-in exports ride the event pipeline (format sniffed server-side)
  if (/\.(csv|json|jsonl|ndjson)$/.test(n)) return 'evtx'
  if (isArchive(file) && /evtx|winevt|eventlog|event[-_ ]?logs?|sysmon|security[-_ ]?log/i.test(n)) return 'evtx'
  return 'mail'
}

export function isArchive(file: File): boolean {
  return /\.(zip|tar|tgz|tar\.gz|tar\.bz2|tbz2|tar\.xz|txz)$/i.test(file.name)
}

export function thresholdBytes(): number {
  const mb = useStore.getState().storeThresholdMb
  return Math.max(1, mb) * 1024 * 1024
}

/**
 * Entry point used by the drop zones. Large files dropped in a browser-stored
 * case are held back for the analyst's decision (convert the case or ingest anyway).
 */
export function requestIngest(files: File[], kase: Case, kindOverride?: 'evtx' | 'mail'): void {
  if (!files.length) return
  const big = kase.storage !== 'server' && files.some((f) => f.size > thresholdBytes())
  const archives = files.filter(isArchive)
  if (big || (archives.length && !kindOverride)) {
    useStore.getState().setPendingIngest({ files, kindOverride, reason: big ? 'big' : 'archive' })
    return
  }
  files.forEach((f) => ingestFile(f, kase, kindOverride ?? detectKind(f)))
}

export async function ingestFile(file: File, kase: Case, kind: 'evtx' | 'mail' = detectKind(file)): Promise<number> {
  if (kase.storage === 'server' && kase.serverKey) return ingestToServer(file, kase, kind)
  return ingestToBrowser(file, kase, kind)
}

async function createEvidence(file: File, kase: Case, kind: 'evtx' | 'mail'): Promise<number> {
  const evidence: Evidence = {
    caseId: kase.id!,
    name: file.name,
    size: file.size,
    kind,
    integrity: 'pending',
    addedAt: Date.now(),
    lastModified: file.lastModified,
    status: 'hashing',
    count: 0,
    analyst: kase.analyst,
  }
  return getDb().evidence.add(evidence)
}

// ---------------------------------------------------------------------------
// server store: chunked upload + ingestion job
// ---------------------------------------------------------------------------
export async function ingestToServer(file: File, kase: Case, kind: 'evtx' | 'mail'): Promise<number> {
  const db = getDb()
  const evidenceId = await createEvidence(file, kase, kind)
  const jobId = jobSeq++
  const s = useStore.getState()
  s.upsertJob({ id: jobId, evidenceId, name: file.name, kind, phase: 'hashing', progress: 0, rows: 0, bytes: 0, startedAt: Date.now() })
  log('info', `[${file.name}] evidence #${evidenceId} (${kind}) → server store ${kase.serverKey!.slice(0, 8)}…, uploading in chunks`)
  try {
    const up = await chunkedUpload(file, (p) => {
      useStore.getState().upsertJob({ id: jobId, phase: p.uploaded < p.total ? 'uploading' : 'hashing', progress: Math.min(p.uploaded, p.hashed) / Math.max(1, p.total), bytes: p.uploaded })
    })
    await db.evidence.update(evidenceId, { sha256Client: up.sha256Client, sha256Server: up.sha256Server, status: 'parsing', integrity: up.sha256Client === up.sha256Server ? 'verified' : 'mismatch' })
    log('ok', `[${file.name}] uploaded ${up.size} bytes, SHA-256 ${up.sha256Client}${up.sha256Client === up.sha256Server ? ' (server hash matches)' : ' (SERVER HASH DIFFERS)'}`)
    if (up.sha256Client !== up.sha256Server) toast('err', `${file.name}: the server received a file with a different hash`, 0)
    useStore.getState().upsertJob({ id: jobId, phase: 'parsing', progress: 0 })
    const { jobId: serverJob } = await apiPost<{ jobId: string }>(`/api/store/${kase.serverKey}/ingest`, {
      uploadId: up.uploadId,
      kind,
      evidence: { id: evidenceId, name: file.name, size: file.size, sha256Client: up.sha256Client, addedAt: Date.now() },
      options: {
        includeRaw: kase.settings.includeRaw !== false,
        keepBodies: kase.settings.keepBodies !== false,
        settings: {
          internalDomains: kase.settings.internalDomains,
          brands: kase.settings.brands,
          vipNames: kase.settings.vipNames,
          trustedSenders: kase.settings.trustedSenders ?? [],
          analyzeAttachments: kase.settings.deepAttachments !== false,
        },
      },
    })
    const job = await waitForJob(serverJob, (j) => {
      const p = j.progress as { rows?: number; format?: string }
      useStore.getState().upsertJob({ id: jobId, phase: 'parsing', rows: Number(p.rows ?? 0) })
    })
    const r = (job.result ?? {}) as { count?: number; stats?: Record<string, unknown>; format?: string; integrity?: string; seconds?: number }
    await db.evidence.update(evidenceId, { status: 'done', count: r.count ?? 0, stats: r.stats, format: r.format, progress: 1 })
    useStore.getState().upsertJob({ id: jobId, phase: 'done', rows: r.count ?? 0, progress: 1 })
    log('ok', `[${file.name}] ${r.count} rows stored on the server in ${r.seconds ?? '?'} s (format ${r.format})`)
    toast('ok', `${file.name}: ${(r.count ?? 0).toLocaleString('en-US')} rows ingested (server store)`)
  } catch (e) {
    const msg = (e as Error).message || String(e)
    await db.evidence.update(evidenceId, { status: 'error', error: msg })
    useStore.getState().upsertJob({ id: jobId, phase: 'error', error: msg })
    log('err', `[${file.name}] ${msg}`)
    toast('err', `${file.name}: ${msg}`, 0)
  } finally {
    setTimeout(() => useStore.getState().removeJob(jobId), 4000)
    refreshCounts(kase)
    autoRunAfterIngest(kase)
  }
  return evidenceId
}

// ---------------------------------------------------------------------------
// browser store: worker (hash + NDJSON stream + IndexedDB)
// ---------------------------------------------------------------------------
export async function ingestToBrowser(file: File, kase: Case, kind: 'evtx' | 'mail'): Promise<number> {
  const db = getDb()
  const evidenceId = await createEvidence(file, kase, kind)
  const jobId = jobSeq++
  const store = useStore.getState()
  store.upsertJob({ id: jobId, evidenceId, name: file.name, kind, phase: 'hashing', progress: 0, rows: 0, bytes: 0, startedAt: Date.now() })
  log('info', `[${file.name}] added as evidence #${evidenceId} (${kind}), hashing…`)

  const worker = new Worker(new URL('../workers/ingest.worker.ts', import.meta.url), { type: 'module' })
  const req: IngestRequest = {
    cmd: 'ingest',
    jobId,
    caseId: kase.id!,
    evidenceId,
    file,
    kind,
    includeRaw: kase.settings.includeRaw !== false,
    settings: { internalDomains: kase.settings.internalDomains, brands: kase.settings.brands, vipNames: kase.settings.vipNames, trustedSenders: kase.settings.trustedSenders ?? [] },
    token: API_HEADERS['X-Forensic-Client'],
  }
  return new Promise<number>((resolve) => {
    worker.onmessage = (ev: MessageEvent<Record<string, unknown>>) => {
      const m = ev.data
      const s = useStore.getState()
      switch (m.type) {
        case 'phase':
          s.upsertJob({ id: jobId, phase: m.phase as 'hashing' })
          break
        case 'hash-progress':
          s.upsertJob({ id: jobId, progress: Number(m.done) / Math.max(1, Number(m.total)) })
          break
        case 'hash':
          log('ok', `[${file.name}] SHA-256 ${m.sha256}`)
          break
        case 'meta':
          log('info', `[${file.name}] server format=${(m.meta as { format: string }).format} sha256=${(m.meta as { sha256: string }).sha256}`)
          break
        case 'bytes':
          s.upsertJob({ id: jobId, bytes: Number(m.bytes) })
          break
        case 'progress':
          s.upsertJob({ id: jobId, rows: Number(m.rows) })
          break
        case 'log':
          log(m.level as 'info', `[${file.name}] ${m.text}`)
          break
        case 'done': {
          const integ = m.integrity as string
          s.upsertJob({ id: jobId, phase: m.error ? 'error' : 'done', rows: Number(m.count), progress: 1, error: m.error ? String(m.error) : undefined })
          log(m.error ? 'warn' : 'ok', `[${file.name}] ${m.count} rows stored - integrity ${integ}${m.error ? ' - server error: ' + m.error : ''}`)
          if (integ === 'mismatch') toast('err', `${file.name}: server hash differs from the browser hash!`, 0)
          else toast(m.error ? 'warn' : 'ok', `${file.name}: ${m.count} rows ingested`)
          worker.terminate()
          setTimeout(() => useStore.getState().removeJob(jobId), 4000)
          refreshCounts(kase)
          autoRunAfterIngest(kase)
          resolve(evidenceId)
          break
        }
        case 'error':
          s.upsertJob({ id: jobId, phase: 'error', error: String(m.error) })
          log('err', `[${file.name}] ${m.error}`)
          toast('err', `${file.name}: ${m.error}`, 0)
          worker.terminate()
          resolve(evidenceId)
          break
      }
    }
    worker.onerror = (e) => {
      useStore.getState().upsertJob({ id: jobId, phase: 'error', error: e.message })
      log('err', `[${file.name}] worker error: ${e.message}`)
      db.evidence.update(evidenceId, { status: 'error', error: e.message })
      worker.terminate()
      resolve(evidenceId)
    }
    worker.postMessage(req)
  })
}

export async function hashOnly(file: File, onProgress?: (p: number) => void): Promise<string> {
  const worker = new Worker(new URL('../workers/ingest.worker.ts', import.meta.url), { type: 'module' })
  return new Promise((resolve, reject) => {
    worker.onmessage = (ev: MessageEvent<Record<string, unknown>>) => {
      if (ev.data.type === 'hash-progress') onProgress?.(Number(ev.data.done) / Math.max(1, Number(ev.data.total)))
      if (ev.data.type === 'hash') {
        worker.terminate()
        resolve(String(ev.data.sha256))
      }
      if (ev.data.type === 'error') {
        worker.terminate()
        reject(new Error(String(ev.data.error)))
      }
    }
    worker.postMessage({ cmd: 'hash', jobId: 0, file })
  })
}

/** Recompute a browser case's facets and indicators from the rows that remain (after evidence removal). */
export function rebuildDerived(caseId: number): Promise<{ rows: number; iocs: number }> {
  const worker = new Worker(new URL('../workers/ingest.worker.ts', import.meta.url), { type: 'module' })
  return new Promise((resolve, reject) => {
    worker.onmessage = (ev: MessageEvent<Record<string, unknown>>) => {
      if (ev.data.type === 'rebuilt') {
        worker.terminate()
        resolve({ rows: Number(ev.data.rows), iocs: Number(ev.data.iocs) })
      } else if (ev.data.type === 'error') {
        worker.terminate()
        reject(new Error(String(ev.data.error)))
      }
    }
    worker.onerror = (e) => {
      worker.terminate()
      reject(new Error(e.message))
    }
    worker.postMessage({ cmd: 'rebuild', caseId })
  })
}

export async function refreshCounts(kase: Case | number): Promise<void> {
  const db = getDb()
  const k = typeof kase === 'number' ? await db.cases.get(kase) : kase
  if (!k?.id) return
  const caseId = k.id
  const [findings, evidence] = await Promise.all([db.findings.where('caseId').equals(caseId).count(), db.evidence.where('caseId').equals(caseId).count()])
  if (k.storage === 'server' && k.serverKey) {
    try {
      const sum = (await getSource(k).summary()) as { counts?: { events?: number; mails?: number; iocs?: number } }
      useStore.getState().setCounts({ events: sum.counts?.events ?? 0, mails: sum.counts?.mails ?? 0, iocs: sum.counts?.iocs ?? 0, findings, evidence })
    } catch {
      useStore.getState().setCounts({ findings, evidence })
    }
    return
  }
  const [events, mails, iocs] = await Promise.all([db.events.where('caseId').equals(caseId).count(), db.mails.where('caseId').equals(caseId).count(), db.iocs.where('caseId').equals(caseId).count()])
  useStore.getState().setCounts({ events, mails, findings, iocs, evidence })
}
