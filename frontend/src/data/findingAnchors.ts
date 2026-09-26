/**
 * Findings tied to the records they cite, not to REMN's row ids.
 *
 * A finding cites its rows by id (`refs`), and a finding raised on one row is keyed by that id
 * (`rule|123`, `chain|alice|123`). Removing evidence and adding it again renumbers the rows, so the
 * rebuilt finding had another key and the analyst's decision, archived under the old one, never
 * came back. Each finding now also carries the record key of every row it cites (recordKeys.ts:
 * the file's SHA-256 and the record's place in it), and its decision is archived under a key built
 * from the record instead of the row id, which the same record read again gives back.
 */
import type { Table } from 'dexie'
import type { Evidence, Finding } from '../db/schema'
import { recordRef } from './recordKeys'

type Row = Record<string, unknown>
type Source = 'events' | 'mails'

/** Read rows of a case by id; a row that is gone is left out of the map. */
export type RowLoader = (source: Source, ids: number[]) => Promise<Map<number, Row>>

interface RowTable {
  bulkGet(ids: number[]): PromiseLike<(object | undefined)[]>
}

/** Rows kept in this browser (a browser case, or the Dexie upgrade's own transaction). */
export function tableRows(tables: Record<Source, RowTable>): RowLoader {
  return async (source, ids) => {
    const rows = (await tables[source].bulkGet(ids)) as (Row | undefined)[]
    return new Map(rows.filter((r): r is Row => !!r).map((r) => [Number(r.id), r]))
  }
}

type Cites = Pick<Finding, 'source' | 'refs'> & { recordKeys?: string[] }

/**
 * The record key of each row the findings cite, in the order of their refs; empty where the row
 * could not be read (a server case that is offline, a row removed since).
 */
export async function recordKeysFor(findings: Cites[], evidence: Evidence[], load: RowLoader): Promise<string[][]> {
  const wanted: Record<Source, Set<number>> = { events: new Set(), mails: new Set() }
  for (const f of findings) for (const id of f.refs ?? []) if (typeof id === 'number') wanted[f.source === 'mails' ? 'mails' : 'events'].add(id)
  const rows: Record<Source, Map<number, Row>> = { events: new Map(), mails: new Map() }
  for (const source of ['events', 'mails'] as const) {
    const ids = [...wanted[source]]
    for (let i = 0; i < ids.length; i += 2000) for (const [id, row] of await load(source, ids.slice(i, i + 2000))) rows[source].set(id, row)
  }
  const byId = new Map(evidence.map((e) => [e.id!, e]))
  const keys = new Map<string, string>()
  const keyOf = (source: Source, id: number): string => {
    const memo = `${source}:${id}`
    if (!keys.has(memo)) {
      const row = rows[source].get(id)
      keys.set(memo, row ? recordRef(row, source, byId.get(Number(row.evidenceId))).key : '')
    }
    return keys.get(memo)!
  }
  return findings.map((f) => (f.refs ?? []).map((id) => keyOf(f.source === 'mails' ? 'mails' : 'events', id)))
}

/**
 * The key a finding raised on one row keeps when that row is renumbered: its own key with the row
 * id replaced by the row's record key. Null for a finding whose key names no row (a group, a
 * burst), which is stable already, and for one whose record is unknown.
 */
export function anchorKey(f: Pick<Finding, 'key' | 'refs'> & { recordKeys?: string[] }): string | null {
  const first = f.refs?.[0]
  const record = f.recordKeys?.[0]
  if (first == null || !record) return null
  const cut = f.key.lastIndexOf('|')
  if (cut < 0 || f.key.slice(cut + 1) !== String(first)) return null
  return `${f.key.slice(0, cut + 1)}rk:${record}`
}

/** Where a finding's decision is archived: its record anchor when it has one, its key otherwise. */
export const reviewKey = (f: Pick<Finding, 'key' | 'refs'> & { recordKeys?: string[] }): string => anchorKey(f) ?? f.key

/** Attach the record keys of what each finding cites (a server case passes its own loader). */
export async function withRecordKeys<T extends Cites>(findings: T[], evidence: Evidence[], load: RowLoader): Promise<(T & { recordKeys: string[] })[]> {
  const keys = await recordKeysFor(findings, evidence, load)
  return findings.map((f, i) => ({ ...f, recordKeys: keys[i] }))
}

export interface MigrationTables {
  events: RowTable
  mails: RowTable
  evidence: Table<Evidence, number>
  findings: Table<Finding, number>
  kv: Table<{ key: string; value: unknown }, string>
}

/**
 * Give the findings of existing cases their record keys, and move each archived decision whose
 * key names a row to the key of that row's record. Only rows kept in this browser can be read,
 * so a server case's findings get theirs at the next rule run; their decisions stay under the
 * old key, where they are still found until the rows are renumbered.
 */
export async function anchorStoredFindings(t: MigrationTables, caseIds?: number[]): Promise<{ findings: number; reviews: number }> {
  const load = tableRows(t)
  const evidence = await t.evidence.toArray()
  const cases =
    caseIds ??
    [
      ...new Set([
        ...((await t.findings.orderBy('caseId').uniqueKeys()) as number[]),
        ...(await t.kv.where('key').startsWith('finding-reviews-').primaryKeys()).map((k) => Number(String(k).slice('finding-reviews-'.length))),
      ]),
    ].filter((id) => Number.isInteger(id))
  let findings = 0
  let reviews = 0
  for (const caseId of cases) {
    const own = evidence.filter((e) => e.caseId === caseId)
    const rows = (await t.findings.where('caseId').equals(caseId).toArray()).filter((f) => !f.recordKeys?.some(Boolean))
    const keyed = await recordKeysFor(rows, own, load)
    const updated = rows.map((f, i) => ({ ...f, recordKeys: keyed[i] })).filter((f) => f.recordKeys.some(Boolean))
    if (updated.length) await t.findings.bulkPut(updated)
    findings += updated.length
    const archiveKey = `finding-reviews-${caseId}`
    const archive = (await t.kv.get(archiveKey))?.value as Record<string, Pick<Finding, 'source' | 'refs' | 'ruleId'> & { recordKeys?: string[]; key?: string }> | undefined
    if (!archive) continue
    const legacy = Object.entries(archive).filter(([, r]) => r.source && r.refs?.length && !r.recordKeys?.some(Boolean))
    const archived = await recordKeysFor(
      legacy.map(([, r]) => r as Cites),
      own,
      load,
    )
    let moved = 0
    legacy.forEach(([key, r], i) => {
      const anchor = anchorKey({ key, refs: r.refs, recordKeys: archived[i] })
      if (!anchor) return
      delete archive[key]
      if (!archive[anchor]) archive[anchor] = { ...r, key, recordKeys: archived[i] }
      moved++
    })
    if (moved) await t.kv.put({ key: archiveKey, value: archive })
    reviews += moved
  }
  return { findings, reviews }
}
