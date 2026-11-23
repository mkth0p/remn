/**
 * A row by its place in its own file, which a reader of the file can check without REMN. A row's
 * id is REMN's: removing evidence and adding it again renumbers its rows, and so does importing a
 * case bundle into another browser. The record's place in its file does not change: an event
 * log's record number (with the computer and channel, which a forwarded log needs), a mailbox's
 * message index, a cloud record's own id, with the SHA-256 of the file it was read from.
 *
 * The duplicate key is the same for the same record read from another file or export: the
 * computer, channel and EventRecordID of an event (the key the Hayabusa findings are joined by),
 * a message's Message-ID, a Unified Audit Log or sign-in record's id.
 */
import type { Evidence } from '../db/schema'
import { EN } from './reportText'

/** A record's place in its file, as values: record is its English writing, the report writes it in its own language. */
export type RecordPlace =
  | { kind: 'message'; n: number }
  | { kind: 'message-id'; id: string }
  | { kind: 'cloud'; what: string; id: string }
  | { kind: 'record'; n: number; channel?: string; computer?: string }
  | { kind: 'row'; n: number | string }

export interface RecordRef {
  /** the file as uploaded, and the archive or package member it was read from */
  file: string
  /** its place in that file, as a reader of the file finds it */
  record: string
  at: RecordPlace
  /** SHA-256 of the member (in a package) or of the upload */
  sha256?: string
  /** the same for the same record read from another file or export */
  duplicateKey?: string
  /** stable across removal and re-ingest of the file, and across bundle import */
  key: string
}

type Row = Record<string, unknown>

const text = (v: unknown) => (typeof v === 'string' && v.trim() ? v.trim() : null)
const int = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : typeof v === 'string' && /^\d+$/.test(v) ? Number(v) : null)

/** The event's identity outside its file: computer, channel and its own record number. */
export function eventDuplicateKey(row: Row): string | undefined {
  const rk = text(row.recordKey)
  if (rk) return rk
  const rid = int(row.recordId)
  const computer = text(row.computer)
  const channel = text(row.channel)
  return rid != null && computer && channel ? `${computer.toLowerCase()}|${channel.toLowerCase()}|${rid}` : undefined
}

export function recordRef(row: Row, source: 'events' | 'mails', evidence?: Evidence): RecordRef {
  const upload = evidence?.name ?? `evidence #${String(row.evidenceId ?? '?')}`
  const member = text(row.sourceFile)
  const inner = member && member !== upload ? member : null
  const file = inner ? `${upload} › ${inner}` : upload
  const sha256 = text(row.sourceSha256) ?? text(evidence?.sha256Server) ?? text(evidence?.sha256Client) ?? undefined
  const where = `${sha256 ?? upload}:${inner ?? ''}`
  const placed = (at: RecordPlace) => ({ file, record: EN.record(at), at, sha256 })
  if (source === 'mails') {
    const index = int(row.sourceIndex)
    const mid = text(row.messageId)
    const at: RecordPlace = index != null ? { kind: 'message', n: index + 1 } : mid ? { kind: 'message-id', id: mid } : { kind: 'row', n: String(row.id) }
    return { ...placed(at), duplicateKey: mid ? `mid:${mid.toLowerCase()}` : undefined, key: `${where}#${index != null ? `m${index}` : `mid:${mid ?? row.id}`}` }
  }
  const cloud = text(row.recordKey)
  if (cloud) {
    const [kind, id] = cloud.includes(':') ? [cloud.slice(0, cloud.indexOf(':')), cloud.slice(cloud.indexOf(':') + 1)] : ['record', cloud]
    return { ...placed({ kind: 'cloud', what: kind, id }), duplicateKey: cloud, key: `${where}#${cloud}` }
  }
  const dup = eventDuplicateKey(row)
  const rid = int(row.recordId)
  if (rid != null) {
    // a log forwarded from several machines numbers each machine's records apart
    const whose = text(row.computer) && text(row.channel) ? { channel: text(row.channel)!, computer: text(row.computer)! } : {}
    return { ...placed({ kind: 'record', n: rid, ...whose }), duplicateKey: dup, key: `${where}#${dup ?? rid}` }
  }
  const index = int(row.sourceIndex)
  return { ...placed({ kind: 'row', n: index != null ? index + 1 : String(row.id) }), duplicateKey: dup, key: `${where}#${index != null ? `i${index}` : `id${String(row.id)}`}` }
}

/** "Security.evtx record 4,200 (Security on DC01)", for the report. */
export const recordLabel = (r: RecordRef) => `${r.file} ${r.record}`
