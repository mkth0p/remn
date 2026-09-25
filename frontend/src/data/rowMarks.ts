import type { Table } from 'dexie'
import { getDb, type RowMark, type RowMarkVerdict, type RowProvenance } from '../db/schema'

/**
 * Analyst marks on individual event and mail rows.
 *
 * Marks live in their own table, never on the row: parsed rows are evidence and are rewritten
 * wholesale by a re-ingest or a rescore, so anything stored on them is not the analyst's. Mail
 * `flags` are analyzer-owned for exactly that reason and cannot carry a verdict.
 *
 * Each mark records the row id it applies to AND the provenance of that row. The id is what makes
 * lookups cheap today; the provenance is what a later pass can use to re-attach marks after
 * evidence is deleted and re-ingested, which renumbers every row. Capturing it costs nothing at
 * write time and means that improvement needs no migration.
 */

const CHUNK = 500

/** The stable identity of a row, as far as its source can express it. */
export function rowProvenance(row: Record<string, unknown>, source: 'events' | 'mails'): RowProvenance {
  const pick = (key: string): string | null => {
    const value = row[key]
    return typeof value === 'string' && value ? value : null
  }
  const num = (key: string): number | null => {
    const value = row[key]
    return typeof value === 'number' && Number.isFinite(value) ? value : null
  }
  return {
    sourceFile: pick('sourceFile') ?? pick('sourceName'),
    sourceSha256: pick('sourceSha256'),
    sourceIndex: num('sourceIndex'),
    recordId: num('recordId'),
    channel: source === 'events' ? pick('channel') : null,
    computer: source === 'events' ? pick('computer') : null,
    messageId: source === 'mails' ? pick('messageId') : null,
    ts: num(source === 'mails' ? 'date' : 'ts'),
  }
}

function table(): Table<RowMark, number> {
  return getDb().rowMarks
}

export async function loadRowMarks(caseId: number, source: 'events' | 'mails', rowIds: number[]): Promise<Map<number, RowMark>> {
  const found = new Map<number, RowMark>()
  for (let i = 0; i < rowIds.length; i += CHUNK) {
    const page = rowIds.slice(i, i + CHUNK)
    const marks = await table()
      .where('[caseId+source+rowId]')
      .anyOf(page.map((rowId) => [caseId, source, rowId] as [number, string, number]))
      .toArray()
    for (const mark of marks) found.set(mark.rowId, mark)
  }
  return found
}

export interface RowMarkPatch {
  verdict?: RowMarkVerdict
  addTags?: string[]
  removeTags?: string[]
  reason?: string
  by?: 'analyst' | 'ai'
}

/**
 * Apply one decision to a set of rows, creating or updating each mark.
 *
 * `rows` carries the row objects rather than ids alone so the provenance can be captured; a caller
 * that only has ids can pass `{id}` objects and the mark still works, with less to re-attach later.
 */
export async function markRows(caseId: number, source: 'events' | 'mails', rows: Record<string, unknown>[], patch: RowMarkPatch): Promise<number> {
  if (!rows.length) return 0
  const db = getDb()
  const now = Date.now()
  let written = 0
  for (let i = 0; i < rows.length; i += CHUNK) {
    const page = rows.slice(i, i + CHUNK)
    await db.transaction('rw', db.rowMarks, async () => {
      const ids = page.map((r) => Number(r.id)).filter((id) => Number.isFinite(id))
      const existing = await loadRowMarks(caseId, source, ids)
      const puts: RowMark[] = []
      for (const row of page) {
        const rowId = Number(row.id)
        if (!Number.isFinite(rowId)) continue
        const previous = existing.get(rowId)
        const tags = new Set(previous?.tags ?? [])
        for (const tag of patch.addTags ?? []) if (tag.trim()) tags.add(tag.trim())
        for (const tag of patch.removeTags ?? []) tags.delete(tag.trim())
        puts.push({
          ...(previous ?? {}),
          caseId,
          source,
          rowId,
          evidenceId: typeof row.evidenceId === 'number' ? row.evidenceId : (previous?.evidenceId ?? null),
          verdict: patch.verdict ?? previous?.verdict ?? 'relevant',
          tags: [...tags].sort(),
          reason: patch.reason ?? previous?.reason ?? '',
          provenance: previous?.provenance ?? rowProvenance(row, source),
          by: patch.by ?? 'analyst',
          createdAt: previous?.createdAt ?? now,
          updatedAt: now,
        })
      }
      if (puts.length) {
        await db.rowMarks.bulkPut(puts)
        written += puts.length
      }
    })
  }
  return written
}

export async function clearRowMarks(caseId: number, source: 'events' | 'mails', rowIds: number[]): Promise<number> {
  const db = getDb()
  let removed = 0
  for (let i = 0; i < rowIds.length; i += CHUNK) {
    const page = rowIds.slice(i, i + CHUNK)
    const keys = await db.rowMarks
      .where('[caseId+source+rowId]')
      .anyOf(page.map((rowId) => [caseId, source, rowId] as [number, string, number]))
      .primaryKeys()
    if (keys.length) {
      await db.rowMarks.bulkDelete(keys)
      removed += keys.length
    }
  }
  return removed
}

/** Row ids carrying a mark, for the "show what I marked" filter. Bounded, and says when it cut. */
export async function markedRowIds(caseId: number, source: 'events' | 'mails', where: { verdict?: RowMarkVerdict; tag?: string } = {}, limit = 5000): Promise<{ ids: number[]; truncated: boolean }> {
  let marks = await getDb()
    .rowMarks.where('[caseId+source]')
    .equals([caseId, source])
    .limit(limit + 1)
    .toArray()
  if (where.verdict) marks = marks.filter((m) => m.verdict === where.verdict)
  if (where.tag) marks = marks.filter((m) => m.tags.includes(where.tag!))
  return { ids: marks.slice(0, limit).map((m) => m.rowId), truncated: marks.length > limit }
}

/** Counts per verdict and per tag, for the facet panel and the report. */
export async function rowMarkSummary(caseId: number): Promise<{ verdicts: Record<string, number>; tags: Record<string, number>; total: number }> {
  const verdicts: Record<string, number> = {}
  const tags: Record<string, number> = {}
  let total = 0
  await getDb()
    .rowMarks.where('caseId')
    .equals(caseId)
    .each((mark) => {
      total++
      verdicts[mark.verdict] = (verdicts[mark.verdict] ?? 0) + 1
      for (const tag of mark.tags) tags[tag] = (tags[tag] ?? 0) + 1
    })
  return { verdicts, tags, total }
}

/** Every tag used in this case, for suggesting rather than retyping. */
export async function rowMarkTags(caseId: number): Promise<string[]> {
  const { tags } = await rowMarkSummary(caseId)
  return Object.keys(tags).sort()
}
