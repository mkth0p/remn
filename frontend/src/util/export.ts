import { createSHA1, createSHA256 } from 'hash-wasm'
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

/** A value inside a STIX pattern string literal: backslash and quote are the two characters to escape. */
const lit = (v: string) => `'${v.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}'`
const HASH_NAME: Record<number, string> = { 64: 'SHA-256', 40: 'SHA-1', 32: 'MD5' }

/** The STIX cyber-observable for an indicator value, and the pattern that matches it. */
function stixObservable(kind: string, v: string): { sco: Record<string, unknown>; pattern: string } | null {
  if (kind === 'ip') {
    const type = v.includes(':') ? 'ipv6-addr' : 'ipv4-addr'
    return { sco: { type, value: v }, pattern: `[${type}:value = ${lit(v)}]` }
  }
  if (kind === 'domain') return { sco: { type: 'domain-name', value: v }, pattern: `[domain-name:value = ${lit(v)}]` }
  if (kind === 'url') return { sco: { type: 'url', value: v }, pattern: `[url:value = ${lit(v)}]` }
  if (kind === 'email') return { sco: { type: 'email-addr', value: v }, pattern: `[email-addr:value = ${lit(v)}]` }
  if (kind === 'hash' && HASH_NAME[v.length]) {
    const name = HASH_NAME[v.length]
    return { sco: { type: 'file', hashes: { [name]: v } }, pattern: `[file:hashes.${lit(name)} = ${lit(v)}]` }
  }
  return null
}

/** UUID version 5 (RFC 9562), as STIX 2.1 defines deterministic identifiers. */
async function uuid5(namespace: string, name: string): Promise<string> {
  const ns = namespace.replace(/-/g, '')
  const bytes = new Uint8Array([...(ns.match(/../g) ?? []).map((x) => parseInt(x, 16)), ...new TextEncoder().encode(name)])
  const h = await createSHA1()
  h.init()
  h.update(bytes)
  const d = h.digest('binary')
  d[6] = (d[6] & 0x0f) | 0x50
  d[8] = (d[8] & 0x3f) | 0x80
  const x = Array.from(d.slice(0, 16), (b) => b.toString(16).padStart(2, '0')).join('')
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20)}`
}
/** the namespace STIX 2.1 gives for cyber-observable ids */
const STIX_SCO_NS = '00abedb4-aa42-466c-9c01-fed23315a9b7'
/** REMN's own namespace for the indicator and identity ids it derives, so an export re-imports without duplicates */
const REMN_NS = '5b3c6e0e-8f0e-5a6f-9d2c-2f1d7c9e4a10'
/** TLP:AMBER, a STIX 2.1 predefined marking: case indicators are for the recipient's organisation */
const TLP_AMBER = 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82'
const canonical = (o: Record<string, unknown>): string =>
  JSON.stringify(o, (_, v) => (v && typeof v === 'object' && !Array.isArray(v) ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => a.localeCompare(b))) : v))

/**
 * A STIX 2.1 bundle of the case's indicators. Every value is exported as a cyber-observable; only
 * the ones a reputation check flagged (malicious or suspicious) become indicator objects, since an
 * indicator says "look for this", and a mailbox holds thousands of ordinary senders and domains.
 * Identifiers are derived from the content, so the same export twice is the same objects.
 */
export async function iocsToStix(kase: Case, iocs: Ioc[]): Promise<Record<string, unknown>> {
  const now = new Date().toISOString()
  const identityId = `identity--${await uuid5(REMN_NS, `case:${kase.name}`)}`
  const objects: Record<string, unknown>[] = [{ type: 'identity', spec_version: '2.1', id: identityId, created: now, modified: now, name: `REMN case: ${kase.name}`, identity_class: 'system' }]
  for (const i of iocs) {
    const obs = stixObservable(i.kind, i.value)
    if (!obs) continue
    const scoKey = obs.sco.type === 'file' ? { hashes: obs.sco.hashes } : { value: obs.sco.value }
    const scoId = `${obs.sco.type}--${await uuid5(STIX_SCO_NS, canonical(scoKey))}`
    objects.push({ ...obs.sco, spec_version: '2.1', id: scoId, object_marking_refs: [TLP_AMBER] })
    if (i.verdict !== 'malicious' && i.verdict !== 'suspicious') continue
    objects.push({
      type: 'indicator',
      spec_version: '2.1',
      id: `indicator--${await uuid5(REMN_NS, obs.pattern)}`,
      created_by_ref: identityId,
      created: now,
      modified: now,
      name: `${i.kind}: ${i.value}`,
      description: `Seen ${i.count} time(s) in case "${kase.name}" (sources: ${i.sources.join(', ')}); reputation: ${i.verdict}.`,
      indicator_types: [i.verdict === 'malicious' ? 'malicious-activity' : 'anomalous-activity'],
      pattern: obs.pattern,
      pattern_type: 'stix',
      valid_from: i.firstSeen ? new Date(i.firstSeen).toISOString() : now,
      labels: i.tags ?? [],
      object_marking_refs: [TLP_AMBER],
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
