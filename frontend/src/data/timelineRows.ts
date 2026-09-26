/**
 * Every event a filter matches, in time order, for a timeline export. The Events table shows the
 * first rows of a search; a timeline handed to Timesketch or Timeline Explorer has to carry all of
 * them, so this pages through the matches by time instead of taking the rows on screen.
 */
import type { EventRow } from '../db/schema'
import type { Filter } from '../rules/filter'
import type { DataSource } from './source'

const PAGE = 20000
/** what one export holds at most, so a case of millions of rows cannot exhaust the tab */
export const TIMELINE_MAX = 250_000

export interface TimelineRows {
  rows: EventRow[]
  /** why the export stopped before the last match, when it did */
  cut: string | null
}

const toMs = (v: string | number | null | undefined): number | null => {
  if (v === null || v === undefined || v === '') return null
  const n = typeof v === 'number' ? v : Date.parse(v)
  return Number.isFinite(n) ? n : null
}

export async function timelineRows(ds: Pick<DataSource, 'searchEvents'>, filter: Filter, opts: { max?: number; page?: number; signal?: AbortSignal } = {}): Promise<TimelineRows> {
  const max = opts.max ?? TIMELINE_MAX
  const page = opts.page ?? PAGE
  const to = filter.timeRange?.to ?? null
  let from = toMs(filter.timeRange?.from)
  const rows: EventRow[] = []
  const seen = new Set<number>()
  for (;;) {
    // a page starts at the time the last one ended (inclusive), and the rows at that instant
    // already taken are skipped by id
    const res = await ds.searchEvents({ ...filter, sort: { field: 'ts', dir: 'asc' }, timeRange: { from, to } }, page, opts.signal)
    let added = 0
    for (const r of res.rows) {
      if (typeof r.ts !== 'number' || seen.has(r.id!)) continue
      seen.add(r.id!)
      rows.push(r)
      added++
      if (rows.length >= max) return { rows, cut: `stopped at ${max.toLocaleString('en-US')} rows; narrow the filter to export the rest` }
    }
    if (!res.truncated) return { rows, cut: null }
    const last = res.rows[res.rows.length - 1]?.ts
    if (!added || typeof last !== 'number') {
      // a whole page shares one instant already read: paging by time cannot get past it
      return { rows, cut: `more than ${page.toLocaleString('en-US')} rows share the time ${new Date(from ?? 0).toISOString()}; narrow the filter to export the rest` }
    }
    from = last
  }
}
