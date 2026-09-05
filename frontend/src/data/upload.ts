/**
 * Chunked upload for large evidence. The file is hashed in the ingest worker
 * while the chunks are uploaded from the main thread, so a multi-GB file
 * costs one read for the hash and one for the upload, with resumable offsets.
 *
 * Resume across reloads: the upload id and progress are persisted in kv keyed
 * by (name, size, lastModified). If the page dies mid-upload, dropping the
 * same file again continues from the server's received offset. The server
 * partial is only discarded on explicit cancel (abort) or success; stale
 * partials are pruned server-side after 24 h.
 */
import { API_HEADERS, apiGet, apiPost } from '../api/client'
import { getDb } from '../db/schema'
import { log } from '../state/store'
import { hashOnly } from './ingest'

export interface UploadResult {
  uploadId: string
  sha256Client: string
  sha256Server: string
  size: number
  resumedFrom?: number
}

export interface UploadProgress {
  uploaded: number
  hashed: number
  total: number
}

interface StoredUpload {
  uploadId: string
  name: string
  size: number
  lastModified: number
  received: number
}

const uploadKvKey = (file: File) => `upload-${file.name}-${file.size}-${file.lastModified}`

/** Drop the resume record of a file and the partial the server may still hold (evidence removal). */
export async function forgetUpload(file: { name: string; size: number; lastModified?: number | null }): Promise<boolean> {
  const db = getDb()
  const key = `upload-${file.name}-${file.size}-${file.lastModified ?? ''}`
  const rec = await db.kv.get(key).catch(() => undefined)
  const uploadId = (rec?.value as StoredUpload | undefined)?.uploadId
  if (uploadId) await fetch(`/api/upload/${uploadId}`, { method: 'DELETE', headers: API_HEADERS }).catch(() => undefined)
  await db.kv.delete(key).catch(() => undefined)
  return !!rec
}

async function findResumable(file: File): Promise<{ uploadId: string; received: number } | null> {
  try {
    const rec = await getDb().kv.get(uploadKvKey(file))
    const v = rec?.value as StoredUpload | undefined
    if (!v?.uploadId) return null
    const st = await apiGet<{ received: number; complete: boolean; size: number }>(`/api/upload/${v.uploadId}`)
    if (st.complete || st.size !== file.size || !(st.received > 0)) return null
    return { uploadId: v.uploadId, received: st.received }
  } catch {
    return null
  }
}

async function putChunk(uploadId: string, offset: number, blob: Blob, signal?: AbortSignal): Promise<number> {
  for (let attempt = 0; attempt < 3; attempt++) {
    const resp = await fetch(`/api/upload/${uploadId}/chunk?offset=${offset}`, { method: 'PUT', headers: { ...API_HEADERS, 'Content-Type': 'application/octet-stream' }, body: blob, signal })
    if (resp.ok) return (await resp.json()).received as number
    if (resp.status === 409) {
      // offset mismatch: resync with the server's view
      const body = await resp.json().catch(() => ({}))
      if (typeof body.received === 'number') return body.received
    }
    if (attempt === 2) throw new Error(`chunk upload failed (${resp.status})`)
    await new Promise((r) => setTimeout(r, 500 * (attempt + 1)))
  }
  throw new Error('chunk upload failed')
}

export async function chunkedUpload(file: File, onProgress?: (p: UploadProgress) => void, signal?: AbortSignal): Promise<UploadResult> {
  const db = getDb()
  const kvKey = uploadKvKey(file)
  const resume = await findResumable(file)
  let uploadId: string
  let chunkSize = 16 * 1024 * 1024
  let offset = 0
  if (resume) {
    uploadId = resume.uploadId
    offset = resume.received
    log('info', `[${file.name}] resuming interrupted upload at ${Math.round((offset / file.size) * 100)}% (${offset} bytes)`)
  } else {
    const init = await apiPost<{ uploadId: string; chunkSize: number }>('/api/upload/init', { name: file.name, size: file.size }, signal)
    uploadId = init.uploadId
    chunkSize = Math.max(1024 * 1024, init.chunkSize || chunkSize)
  }
  const persist = (received: number) =>
    db.kv.put({ key: kvKey, value: { uploadId, name: file.name, size: file.size, lastModified: file.lastModified, received } satisfies StoredUpload }).catch(() => undefined)
  await persist(offset)
  const progress: UploadProgress = { uploaded: offset, hashed: 0, total: file.size }
  const report = () => onProgress?.({ ...progress })
  const hashing = hashOnly(file, (p) => {
    progress.hashed = Math.round(p * file.size)
    report()
  })
  try {
    while (offset < file.size) {
      if (signal?.aborted) throw new DOMException('aborted', 'AbortError')
      const end = Math.min(offset + chunkSize, file.size)
      const received = await putChunk(uploadId, offset, file.slice(offset, end), signal)
      offset = received
      progress.uploaded = offset
      report()
      void persist(offset)
    }
    const done = await apiPost<{ sha256: string; size: number }>(`/api/upload/${uploadId}/complete`, {}, signal)
    const sha256Client = await hashing
    await db.kv.delete(kvKey).catch(() => undefined)
    return { uploadId, sha256Client, sha256Server: done.sha256, size: done.size, resumedFrom: resume?.received }
  } catch (e) {
    const cancelled = (e as Error).name === 'AbortError' || signal?.aborted
    if (cancelled) {
      // explicit cancel: throw away the server partial and the resume record
      fetch(`/api/upload/${uploadId}`, { method: 'DELETE', headers: API_HEADERS }).catch(() => undefined)
      db.kv.delete(kvKey).catch(() => undefined)
    } else {
      // transient failure (network drop, reload, server restart): keep both so
      // re-dropping the same file resumes from the received offset
      log('warn', `[${file.name}] upload interrupted at ${Math.round((offset / file.size) * 100)}% - drop the same file again to resume`)
    }
    throw e
  }
}
