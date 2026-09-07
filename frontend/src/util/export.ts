import { createSHA256 } from 'hash-wasm'
import { uuid4 } from './uuid'
import { type Case, type Ioc } from '../db/schema'
import { restoreCaseBundle, writeCaseBundle } from '../data/caseBundle'

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

/** Stream to a selected file, or a temporary browser file, without collecting the case in RAM. */
export async function exportCaseBundle(kase: Case, onProgress?: (msg: string) => void): Promise<void> {
  const name = `${kase.name.replace(/[^a-z0-9_-]+/gi, '_')}-${new Date().toISOString().slice(0, 10)}.remn.ndjson`
  const picker = (window as unknown as { showSaveFilePicker?: (opts: { suggestedName: string }) => Promise<FileSystemFileHandle> }).showSaveFilePicker
  if (picker) {
    const handle = await picker({ suggestedName: name })
    const sink = await handle.createWritable()
    try {
      await writeCaseBundle(kase, sink, onProgress)
      await sink.close()
    } catch (error) {
      await sink.abort()
      throw error
    }
  } else {
    if (!navigator.storage?.getDirectory) throw new Error('Streaming backups require a browser with file-system storage support.')
    const root = await navigator.storage.getDirectory()
    const temp = `remn-backup-${uuid4()}`
    const handle = await root.getFileHandle(temp, { create: true })
    const sink = await handle.createWritable()
    try {
      await writeCaseBundle(kase, sink, onProgress)
      await sink.close()
      downloadBlob(name, await handle.getFile())
      // Keep the backing file while the browser starts the download.
      setTimeout(() => {
        void root.removeEntry(temp).catch(() => undefined)
      }, 60_000)
    } catch (error) {
      await sink.abort().catch(() => undefined)
      await root.removeEntry(temp).catch(() => undefined)
      throw error
    }
  }
  onProgress?.('done')
}

export const importCaseBundle = restoreCaseBundle
