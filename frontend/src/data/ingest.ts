import { persistEngineFindings, type EngineFinding } from './engineFindings'
import { autoRunAfterIngest } from './findingsState'
import { apiPost, API_HEADERS } from '../api/client'
import { getDb, requestPersistentStorage, type Case, type DateSetting, type Evidence } from '../db/schema'
import { log, toast, useStore } from '../state/store'
import type { IngestRequest } from '../workers/ingest.worker'
import { chunkedUpload, type UploadResult } from './upload'
import { waitForJob } from './jobs'
import { getSource } from './source'
import { duplicateEvidence } from './duplicateEvidence'
import { whileImporting } from './interruptedImports'
import { deployment } from './deployment'
import { datesRead, describeDates } from './dateSetting'

let jobSeq = 1

/**
 * The import behind each running job, so the Jobs panel can cancel it. The files of one drop share
 * one controller: cancelling stops the file being read and the files queued after it.
 */
const imports = new Map<number, AbortController>()

/** Cancel the import of a job; what it had written is removed as removing the evidence would. */
export function cancelImport(jobId: number): void {
  const ctrl = imports.get(jobId)
  if (!ctrl || ctrl.signal.aborted) return
  useStore.getState().upsertJob({ id: jobId, cancelling: true })
  ctrl.abort()
}

/**
 * The kind of a dropped file, from its name. A file in a dropped folder goes to the package reader,
 * which recognises each file by its content. A loose file whose name is none of these is unknown,
 * unless its start was read as mail when it was dropped: such a file used to be sent as mail
 * whatever it held, and the mail parser takes anything for a message.
 */
export function detectKind(file: File): 'evtx' | 'mail' | 'package' | 'unknown' {
  if (file.webkitRelativePath || isArchive(file)) return 'package'
  const n = file.name.toLowerCase()
  if (n.endsWith('.evtx')) return 'evtx'
  // Microsoft 365 audit / Entra sign-in exports ride the event pipeline (format sniffed server-side)
  if (/\.(csv|tsv|json|jsonl|ndjson|pf|cab|reg|hiv|xml|txt|log)$/.test(n)) return 'package'
  if (isArchive(file) && /evtx|winevt|eventlog|event[-_ ]?logs?|sysmon|security[-_ ]?log/i.test(n)) return 'evtx'
  if (/\.(eml|msg|mbox|mbx|pst|ost)$/.test(n)) return 'mail'
  return startsLikeMail.has(file) ? 'mail' : 'unknown'
}

/** Files of a drop whose name said nothing and whose start reads as mail (see requestIngest). */
const startsLikeMail = new WeakSet<File>()

// the start of a mail as the server's parser knows one: an mbox "From " line, or a header line
// with two of the usual mail headers in the first 4 KB
const HEADER_LINE = /^[A-Za-z][A-Za-z0-9-]{1,40}:\s/
const MAIL_MARKERS = ['\nFrom:', '\nSubject:', '\nReceived:', '\nMessage-ID:', '\nMessage-Id:', '\nTo:', '\nDate:', '\nReturn-Path:']

/** Whether a file whose name says nothing starts like mail: a mail client's mailbox file often has no extension. */
export async function looksLikeMail(file: File): Promise<boolean> {
  try {
    const head = new TextDecoder().decode(await file.slice(0, 4096).arrayBuffer()).trimStart()
    if (head.startsWith('From ') && head.includes('\n')) return true
    if (!HEADER_LINE.test(head.split('\n', 1)[0])) return false
    return MAIL_MARKERS.filter((m) => `\n${head}`.includes(m)).length >= 2
  } catch {
    // a file that cannot be read is not taken for mail
    return false
  }
}

/**
 * Whether this file is parsed in the browser rather than uploaded: an .evtx file, in a case kept
 * in this browser that asked for it. The header is checked again when the file is read.
 */
export function parsedInBrowser(file: File, kase: Case, kind: 'evtx' | 'mail' | 'package' | 'unknown' = detectKind(file)): boolean {
  return kase.storage !== 'server' && kase.settings.parseEvtxInBrowser === true && kind === 'evtx' && file.name.toLowerCase().endsWith('.evtx')
}

/** An EVTX file starts with "ElfFile\0". */
export async function hasEvtxHeader(file: File): Promise<boolean> {
  const head = new Uint8Array(await file.slice(0, 8).arrayBuffer())
  return head.length === 8 && String.fromCharCode(...head) === 'ElfFile\0'
}

export function isArchive(file: File): boolean {
  return /\.(zip|tar|tgz|tar\.gz|tar\.bz2|tbz2|tar\.xz|txz)$/i.test(file.name)
}

/**
 * Size above which a browser-store case uploads in chunks rather than one request.
 *
 * Nothing about the server requires it: this is about what sits in front of it. Reverse proxies
 * and CDNs cap a single request body far below the server's own limit, so a large file posted
 * whole is refused with a 413 that the analyst cannot act on.
 */
export const CHUNK_ABOVE_BYTES = 32 * 1024 * 1024

export function thresholdBytes(): number {
  const mb = useStore.getState().storeThresholdMb
  return Math.max(1, mb) * 1024 * 1024
}

/**
 * Entry point used by the drop zones. Large files dropped in a browser-stored
 * case are held back for the analyst's decision (convert the case or ingest anyway).
 */
export function requestIngest(files: File[], kase: Case, kindOverride?: 'evtx' | 'mail' | 'package', noticeRead = false): void {
  // A browser-store case sends each file to the parser, which refuses anything over its upload
  // limit. Say so before a file is hashed and uploaded, rather than failing twice after the wait.
  const health = useStore.getState().health
  // browser-only mode caps chunked uploads at the single-request limit; a full server stages up to maxChunkedGb
  const limitMb = health?.mode === 'browser-only' ? health.limits?.maxUploadMb : health?.limits?.maxChunkedGb ? health.limits.maxChunkedGb * 1024 : undefined
  if (kase.storage !== 'server' && limitMb) {
    // a file parsed here is never uploaded, so the server's limit does not apply to it
    const over = files.filter((f) => f.size > limitMb * 1024 * 1024 && !parsedInBrowser(f, kase, kindOverride ?? detectKind(f)))
    for (const f of over)
      toast(
        'err',
        `${f.name} is ${Math.round(f.size / 1024 / 1024)} MB, above this server's ${limitMb} MB limit per file. Split it (for example one mailbox folder or one event log per file), or run REMN on your own machine.`,
        0,
      )
    files = files.filter((f) => !over.includes(f))
  }
  if (!kindOverride) {
    const unknown = files.filter((f) => detectKind(f) === 'unknown')
    if (unknown.length) {
      // a file whose name says nothing is read by its start: one that starts like mail goes on as
      // mail, in the same drop as the others, and anything else is turned away
      const drop = files
      void Promise.all(unknown.map(looksLikeMail)).then((isMail) => {
        unknown.forEach((f, i) => {
          if (isMail[i]) startsLikeMail.add(f)
        })
        const refused = unknown.filter((_, i) => !isMail[i])
        if (refused.length) {
          const names = refused.slice(0, 5).map((f) => f.name)
          toast(
            'err',
            `${refused.length} file(s) not imported: their kind is unknown (${names.join(', ')}${refused.length > names.length ? `, and ${refused.length - names.length} more` : ''}). REMN reads event logs (.evtx), mail (.eml, .msg, .mbox, .pst, .ost, or a mailbox file that starts like mail), cloud and triage exports and archives; inside a dropped folder or an archive a file is recognised by its content.`,
            0,
          )
          for (const f of refused) log('warn', `[${f.name}] not imported: its kind is unknown`)
        }
        const rest = drop.filter((f) => !refused.includes(f))
        if (rest.length) requestIngest(rest, kase, undefined, noticeRead)
      })
      return
    }
  }
  if (!files.length) return
  // Before the server has answered, a page served from another host cannot tell what an upload
  // there means, so it asks first: a file dropped in the first moment, or while health failed,
  // used to go out without the notice.
  const notice = useStore.getState().dataNotice
  // files that are all parsed here go nowhere, so there is nothing to be told about first
  const uploads = files.some((f) => !parsedInBrowser(f, kase, kindOverride ?? detectKind(f)))
  if (uploads && !noticeRead && (notice === 'required' || (notice === 'unknown' && deployment(health).tier !== 'this-machine'))) {
    useStore.getState().setPendingIngest({ files, kindOverride, reason: 'notice' })
    return
  }
  const big = kase.storage !== 'server' && files.some((f) => f.size > thresholdBytes())
  const archives = files.filter(isArchive)
  if (big || (archives.length && !kindOverride)) {
    useStore.getState().setPendingIngest({ files, kindOverride, reason: big ? 'big' : 'archive' })
    return
  }
  void ingestFiles(files, kase, (f) => kindOverride ?? detectKind(f))
}

/** Keep folder imports bounded: one ingest worker / server job at a time. */
export async function ingestFiles(files: File[], kase: Case, kind: (file: File) => 'evtx' | 'mail' | 'package' | 'unknown' = detectKind): Promise<void> {
  if (files.length > 1) log('info', `${files.length} evidence files queued for import`)
  if (kase.storage !== 'server')
    void requestPersistentStorage().then((kept) => {
      if (kept === false) log('warn', 'the browser did not grant persistent storage: under storage pressure it may clear this site; export a case bundle to keep a copy')
    })
  const batchCase = files.length > 1 ? { ...kase, settings: { ...kase.settings, autoRunRules: false } } : kase
  const ctrl = new AbortController()
  let started = 0
  try {
    for (const file of files) {
      if (ctrl.signal.aborted) break
      started++
      const k = kind(file)
      // the drop turned these away with a message; nothing is guessed for one that comes another way
      if (k === 'unknown') log('warn', `[${file.name}] not imported: its kind is unknown`)
      else await ingestFile(file, batchCase, k, ctrl)
    }
    if (ctrl.signal.aborted && started < files.length) log('warn', `import cancelled: ${files.length - started} more file(s) of this drop were not imported`)
  } catch (error) {
    toast('err', `Import queue stopped: ${(error as Error).message}`, 0)
  } finally {
    if (files.length > 1) autoRunAfterIngest(kase)
  }
}

export async function ingestFile(file: File, kase: Case, kind: 'evtx' | 'mail' | 'package', ctrl?: AbortController, dates?: DateSetting): Promise<number> {
  if (kase.storage === 'server' && kase.serverKey) return ingestToServer(file, kase, kind, ctrl, dates)
  return ingestToBrowser(file, kase, kind, ctrl, dates)
}

/** How an evidence file's dates were read, said once it is read; nothing when there is nothing to say. */
function logDates(name: string, stats: unknown, dates: DateSetting | undefined): void {
  const st = stats && typeof stats === 'object' ? (stats as Record<string, unknown>) : undefined
  const read = datesRead({ stats: st, dates })
  if (!read) return
  // a guess, a zone assumed or a date the set order cannot read: the analyst can read it again otherwise
  const doubt = ['dateOrderGuessed', 'zoneAssumed', 'dateOrderContradicted'].some((k) => Number(st?.[k] ?? 0) > 0)
  const counts = read.counts.length ? `: ${read.counts.join('; ')}` : ''
  log(doubt ? 'warn' : 'info', `[${name}] ${read.setting}${counts}${doubt ? '. The evidence detail sets the date order and zone to read it again.' : ''}`)
}

/**
 * Read an evidence file again with another date order or time zone. The file dropped must be the
 * one the evidence was read from (its SHA-256 recorded at import); the evidence is removed, as
 * removing it would, and the file imported again with the setting. The analyst's note on the
 * evidence is kept. Returns the new evidence's id.
 */
export async function readAgain(evidence: Evidence, file: File, kase: Case, dates: DateSetting | undefined, hash: (file: File) => Promise<string> = hashOnly): Promise<number> {
  const sha256 = await hash(file)
  if (evidence.sha256Client && sha256 !== evidence.sha256Client) throw new Error(`${file.name} is not the file of this evidence: its SHA-256 is ${sha256}, the evidence's ${evidence.sha256Client}`)
  await getSource(kase).deleteEvidence(evidence.id!)
  log('info', `[${evidence.name}] evidence #${evidence.id} removed to be read again: ${describeDates(dates)}`)
  refreshCounts(kase)
  const id = await ingestFile(file, kase, evidence.kind, undefined, dates)
  if (evidence.note) await getDb().evidence.update(id, { note: evidence.note })
  return id
}

/**
 * Remove what a cancelled import left, as removing the evidence would: the rows it wrote, and with
 * them the findings, facets and indicators that may count them. An import cancelled before any
 * row was written only loses its evidence entry and the upload staged for it.
 */
async function dropCancelledImport(file: File, kase: Case, evidenceId: number, jobId: number, left: { uploadId?: string; serverJob?: string }): Promise<void> {
  const db = getDb()
  try {
    if (left.uploadId) await fetch(`/api/upload/${left.uploadId}`, { method: 'DELETE', headers: API_HEADERS }).catch(() => undefined)
    // the server job stops at its next check; its rows are removed once it has, or it would write after the removal
    if (left.serverJob && kase.serverKey) await waitForJob(left.serverJob, kase.serverKey).catch(() => undefined)
    const rows = left.serverJob
      ? null
      : (await db.events.where('[caseId+evidenceId]').equals([kase.id!, evidenceId]).count()) + (await db.mails.where('[caseId+evidenceId]').equals([kase.id!, evidenceId]).count())
    let cleared = 0
    if (rows === 0) await db.evidence.delete(evidenceId)
    else cleared = (await getSource(kase).deleteEvidence(evidenceId)).findings
    const what =
      rows == null ? 'the rows it had written were removed from the server store' : rows ? `the ${rows.toLocaleString('en-US')} row(s) it had written were removed` : 'nothing had been written'
    log('warn', `[${file.name}] import cancelled: ${what}${cleared ? `, and ${cleared} finding(s) cleared until the rules run again` : ''}`)
    toast('info', `${file.name}: import cancelled`)
    if (cleared) autoRunAfterIngest(kase)
  } catch (e) {
    const msg = (e as Error).message || String(e)
    log('err', `[${file.name}] import cancelled, but what it had written could not be removed (${msg}); remove evidence #${evidenceId} on the Evidence page`)
    toast('err', `${file.name}: import cancelled, but evidence #${evidenceId} could not be removed: ${msg}`, 0)
  } finally {
    imports.delete(jobId)
    useStore.getState().removeJob(jobId)
    void refreshCounts(kase)
  }
}

async function createEvidence(file: File, kase: Case, kind: 'evtx' | 'mail' | 'package', importLock?: string, dates?: DateSetting): Promise<number> {
  const evidence: Evidence = {
    caseId: kase.id!,
    name: file.webkitRelativePath || file.name,
    size: file.size,
    kind,
    integrity: 'pending',
    addedAt: Date.now(),
    lastModified: file.lastModified,
    status: 'hashing',
    count: 0,
    analyst: kase.analyst,
    importLock,
    ...(dates ? { dates } : {}),
  }
  return getDb().evidence.add(evidence)
}

// ---------------------------------------------------------------------------
// server store: chunked upload + ingestion job
// ---------------------------------------------------------------------------
export async function ingestToServer(file: File, kase: Case, kind: 'evtx' | 'mail' | 'package', ctrl = new AbortController(), dates?: DateSetting): Promise<number> {
  const db = getDb()
  const evidenceId = await createEvidence(file, kase, kind, undefined, dates)
  const jobId = jobSeq++
  imports.set(jobId, ctrl)
  const s = useStore.getState()
  s.upsertJob({ id: jobId, evidenceId, name: file.name, kind, phase: 'hashing', progress: 0, rows: 0, bytes: 0, startedAt: Date.now() })
  log('info', `[${file.name}] evidence #${evidenceId} (${kind}) → server store ${kase.serverKey!.slice(0, 8)}…, uploading in chunks`)
  let up: UploadResult | undefined
  let serverJob: string | undefined
  try {
    up = await chunkedUpload(
      file,
      (p) => {
        useStore.getState().upsertJob({ id: jobId, phase: p.uploaded < p.total ? 'uploading' : 'hashing', progress: Math.min(p.uploaded, p.hashed) / Math.max(1, p.total), bytes: p.uploaded })
      },
      ctrl.signal,
    )
    const duplicate = up.sha256Client === up.sha256Server ? await duplicateEvidence(kase.id!, evidenceId, file.webkitRelativePath || file.name, kind, up.sha256Client) : undefined
    if (duplicate) {
      await fetch(`/api/upload/${up.uploadId}`, { method: 'DELETE', headers: API_HEADERS })
      await db.evidence.delete(evidenceId)
      useStore.getState().upsertJob({ id: jobId, phase: 'done', progress: 1 })
      toast('info', `${file.name}: already imported as evidence #${duplicate.id}; skipped`)
      return duplicate.id!
    }
    await db.evidence.update(evidenceId, { sha256Client: up.sha256Client, sha256Server: up.sha256Server, status: 'parsing', integrity: up.sha256Client === up.sha256Server ? 'verified' : 'mismatch' })
    log('ok', `[${file.name}] uploaded ${up.size} bytes, SHA-256 ${up.sha256Client}${up.sha256Client === up.sha256Server ? ' (server hash matches)' : ' (SERVER HASH DIFFERS)'}`)
    if (up.sha256Client !== up.sha256Server) toast('err', `${file.name}: the server received a file with a different hash`, 0)
    useStore.getState().upsertJob({ id: jobId, phase: 'parsing', progress: 0 })
    // the request that starts the job is not aborted half-way, so a job the server started is always known
    if (ctrl.signal.aborted) throw new DOMException('aborted', 'AbortError')
    const submitted = await apiPost<{ jobId: string }>(`/api/store/${kase.serverKey}/ingest`, {
      uploadId: up.uploadId,
      kind,
      evidence: { id: evidenceId, name: file.webkitRelativePath || file.name, size: file.size, sha256Client: up.sha256Client, addedAt: Date.now() },
      options: {
        includeRaw: kase.settings.includeRaw !== false,
        keepBodies: kase.settings.keepBodies !== false,
        fileSystem: kase.settings.readFileSystem === true,
        ...(dates ? { dates } : {}),
        settings: {
          internalDomains: kase.settings.internalDomains,
          brands: kase.settings.brands,
          vipNames: kase.settings.vipNames,
          trustedSenders: kase.settings.trustedSenders ?? [],
          trustedArcSealers: kase.settings.trustedArcSealers ?? [],
          analyzeAttachments: kase.settings.deepAttachments !== false,
        },
      },
    })
    serverJob = submitted.jobId
    const job = await waitForJob(
      serverJob,
      kase.serverKey!,
      (j) => {
        const p = j.progress as { rows?: number; format?: string }
        useStore.getState().upsertJob({ id: jobId, phase: 'parsing', rows: Number(p.rows ?? 0) })
      },
      ctrl.signal,
    )
    const r = (job.result ?? {}) as { count?: number; stats?: Record<string, unknown>; format?: string; integrity?: string; seconds?: number; findings?: EngineFinding[] }
    await db.evidence.update(evidenceId, { status: 'done', count: r.count ?? 0, stats: r.stats, format: r.format, progress: 1 })
    if (r.findings?.length) {
      const engine = String(r.findings[0].engine ?? 'hayabusa')
      const n = await persistEngineFindings(kase.id!, evidenceId, engine, r.findings)
      log('ok', `[${file.name}] ${n} finding(s) from ${engine} stored`)
    }
    useStore.getState().upsertJob({ id: jobId, phase: 'done', rows: r.count ?? 0, progress: 1 })
    log('ok', `[${file.name}] ${r.count} rows stored on the server in ${r.seconds ?? '?'} s (format ${r.format})`)
    logDates(file.name, r.stats, dates)
    toast('ok', `${file.name}: ${(r.count ?? 0).toLocaleString('en-US')} rows ingested (server store)`)
  } catch (e) {
    if (ctrl.signal.aborted) {
      // an upload cancelled half-way discarded its own partial; a finished one is still staged
      await dropCancelledImport(file, kase, evidenceId, jobId, { uploadId: serverJob ? undefined : up?.uploadId, serverJob })
      return evidenceId
    }
    const msg = (e as Error).message || String(e)
    await db.evidence.update(evidenceId, { status: 'error', error: msg })
    useStore.getState().upsertJob({ id: jobId, phase: 'error', error: msg })
    log('err', `[${file.name}] ${msg}`)
    toast('err', `${file.name}: ${msg}`, 0)
  } finally {
    imports.delete(jobId)
    setTimeout(() => useStore.getState().removeJob(jobId), 4000)
    refreshCounts(kase)
    autoRunAfterIngest(kase)
  }
  return evidenceId
}

// ---------------------------------------------------------------------------
// browser store: worker (hash + NDJSON stream + IndexedDB)
// ---------------------------------------------------------------------------
export function ingestToBrowser(file: File, kase: Case, kind: 'evtx' | 'mail' | 'package', ctrl = new AbortController(), dates?: DateSetting): Promise<number> {
  // the lock is taken before the evidence exists, so no other tab ever sees it unlocked
  return whileImporting((lock) => importToBrowser(file, kase, kind, lock, ctrl, dates))
}

async function importToBrowser(file: File, kase: Case, kind: 'evtx' | 'mail' | 'package', lock: string | undefined, ctrl: AbortController, dates?: DateSetting): Promise<number> {
  const db = getDb()
  const evidenceId = await createEvidence(file, kase, kind, lock, dates)
  const jobId = jobSeq++
  imports.set(jobId, ctrl)
  const store = useStore.getState()
  store.upsertJob({ id: jobId, evidenceId, name: file.name, kind, phase: 'hashing', progress: 0, rows: 0, bytes: 0, startedAt: Date.now() })
  log('info', `[${file.name}] added as evidence #${evidenceId} (${kind}), hashing…`)

  const worker = new Worker(new URL('../workers/ingest.worker.ts', import.meta.url), { type: 'module' })
  const local = parsedInBrowser(file, kase, kind) && (await hasEvtxHeader(file))
  if (parsedInBrowser(file, kase, kind) && !local) log('warn', `[${file.name}] no EVTX header: sent to the server to be parsed`)
  if (local) log('info', `[${file.name}] parsed in this browser; the file is not uploaded`)
  // Beyond this, one request carrying the whole file is refused by proxies long before the
  // server's own limit, which is the 413 a browser-store case used to hit. The chunked path
  // sends fixed-size pieces instead and hashes on the way, so the file is read once.
  let upload: { uploadId: string; sha256Client: string } | undefined
  if (!local && file.size > CHUNK_ABOVE_BYTES) {
    try {
      useStore.getState().upsertJob({ id: jobId, phase: 'uploading', progress: 0 })
      upload = await chunkedUpload(file, (p) => useStore.getState().upsertJob({ id: jobId, phase: 'uploading', progress: p.uploaded / Math.max(1, p.total) }), ctrl.signal)
    } catch (e) {
      // A server without the chunked endpoints, or an interrupted upload: fall back to the
      // single request rather than failing the ingest outright.
      if (!ctrl.signal.aborted) log('warn', `[${file.name}] chunked upload unavailable (${(e as Error).message}); sending in one request`)
      upload = undefined
    }
  }
  if (ctrl.signal.aborted) {
    worker.terminate()
    await dropCancelledImport(file, kase, evidenceId, jobId, { uploadId: upload?.uploadId })
    return evidenceId
  }
  const req: IngestRequest = {
    cmd: 'ingest',
    jobId,
    caseId: kase.id!,
    evidenceId,
    file,
    uploadId: upload?.uploadId,
    uploadSha256: upload?.sha256Client,
    kind,
    sourceName: file.webkitRelativePath || file.name,
    includeRaw: kase.settings.includeRaw !== false,
    readFileSystem: kase.settings.readFileSystem === true,
    dates,
    settings: {
      internalDomains: kase.settings.internalDomains,
      brands: kase.settings.brands,
      vipNames: kase.settings.vipNames,
      trustedSenders: kase.settings.trustedSenders ?? [],
      trustedArcSealers: kase.settings.trustedArcSealers ?? [],
    },
    token: API_HEADERS['X-Forensic-Client'],
    parseInBrowser: local,
  }
  return new Promise<number>((resolve) => {
    // The worker is stopped where it is: a batch it was writing is rolled back with its
    // transaction, and the rows of the batches before it are removed with the evidence.
    const cancel = () => {
      worker.terminate()
      void dropCancelledImport(file, kase, evidenceId, jobId, { uploadId: upload?.uploadId }).finally(() => resolve(evidenceId))
    }
    const settled = () => {
      ctrl.signal.removeEventListener('abort', cancel)
      imports.delete(jobId)
    }
    ctrl.signal.addEventListener('abort', cancel, { once: true })
    worker.onmessage = (ev: MessageEvent<Record<string, unknown>>) => {
      const m = ev.data
      const s = useStore.getState()
      if (ctrl.signal.aborted) return
      switch (m.type) {
        case 'duplicate': {
          // the file was staged for a parse that will not happen: the server should not keep it
          if (upload?.uploadId) fetch(`/api/upload/${upload.uploadId}`, { method: 'DELETE', headers: API_HEADERS }).catch(() => undefined)
          const skipped = (m.skippedEngines as string[] | undefined) ?? []
          toast(
            skipped.length ? 'warn' : 'info',
            skipped.length
              ? `${file.name}: already imported as evidence #${m.evidenceId}, but its ${skipped.join(', ')} run was skipped then. To run it, remove evidence #${m.evidenceId} and add the file again; the rules and your decisions are rebuilt from the rows.`
              : `${file.name}: already imported as evidence #${m.evidenceId}; skipped`,
            skipped.length ? 0 : undefined,
          )
          worker.terminate()
          settled()
          s.removeJob(jobId)
          resolve(Number(m.evidenceId))
          break
        }
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
        case 'findings': {
          const findings = m.findings as EngineFinding[]
          persistEngineFindings(kase.id!, evidenceId, String(m.engine), findings)
            .then((n) => log('ok', `[${file.name}] ${n} finding(s) from ${m.engine} stored`))
            .catch((e: Error) => log('err', `[${file.name}] engine findings not stored: ${e.message}`))
          break
        }
        case 'done': {
          const integ = m.integrity as string
          s.upsertJob({ id: jobId, phase: m.error ? 'error' : 'done', rows: Number(m.count), progress: 1, error: m.error ? String(m.error) : undefined })
          const dup = Number(m.duplicates ?? 0)
          log(
            m.error ? 'warn' : 'ok',
            `[${file.name}] ${m.count} rows stored${dup ? `, ${dup} repeated record(s) not added again` : ''} - integrity ${integ}${m.error ? ' - server error: ' + m.error : ''}`,
          )
          logDates(file.name, m.stats, dates)
          if (integ === 'mismatch') toast('err', local ? `${file.name}: the file changed while it was read!` : `${file.name}: server hash differs from the browser hash!`, 0)
          else toast(m.error ? 'warn' : 'ok', `${file.name}: ${m.count} rows ingested`)
          worker.terminate()
          settled()
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
          settled()
          resolve(evidenceId)
          break
      }
    }
    worker.onerror = (e) => {
      if (ctrl.signal.aborted) return
      useStore.getState().upsertJob({ id: jobId, phase: 'error', error: e.message })
      log('err', `[${file.name}] worker error: ${e.message}`)
      db.evidence.update(evidenceId, { status: 'error', error: e.message })
      worker.terminate()
      settled()
      resolve(evidenceId)
    }
    worker.postMessage(req)
  })
}

/** SHA-256 of a file in a worker. Aborting the signal stops the worker and rejects. */
export async function hashOnly(file: File, onProgress?: (p: number) => void, signal?: AbortSignal): Promise<string> {
  const worker = new Worker(new URL('../workers/ingest.worker.ts', import.meta.url), { type: 'module' })
  return new Promise((resolve, reject) => {
    const stop = () => {
      worker.terminate()
      reject(new DOMException('aborted', 'AbortError'))
    }
    if (signal?.aborted) return stop()
    signal?.addEventListener('abort', stop, { once: true })
    worker.onerror = (e) => {
      worker.terminate()
      reject(new Error(e.message))
    }
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
