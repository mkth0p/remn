/**
 * Read queries over IndexedDB used by the views and by the AI tools.
 */
import Dexie from 'dexie'
import { getDb, type EventRow, type Facet, type MailBody, type MailRow } from '../db/schema'
import { compileFilter, extractEventIds, getPath, type Filter, type SettingsLike } from '../rules/filter'

export interface SearchResult<T> {
  rows: T[]
  truncated: boolean
  /** the sort ran over this many matching rows, taken in time order, not over every match */
  sampledFrom?: number
}

const HARD_CAP = 20000

function sortRows<T extends Record<string, unknown>>(rows: T[], field: string, dir: 'asc' | 'desc'): T[] {
  const mul = dir === 'asc' ? 1 : -1
  return rows.sort((a, b) => {
    const va = getPath(a, field)
    const vb = getPath(b, field)
    if (va == null && vb == null) return 0
    if (va == null) return 1
    if (vb == null) return -1
    if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * mul
    return String(va).localeCompare(String(vb)) * mul
  })
}

/**
 * The row ids a filter pins (an `id in [...]` or `id eq` condition under AND logic), or null. Opening
 * a finding filters on its rows this way: they are fetched by primary key, not found by reading
 * every row of the case and testing each against the list.
 */
function pinnedIds(filter: Filter): number[] | null {
  if (filter.logic === 'or') return null
  const c = (filter.conditions ?? []).find((x) => x.field === 'id' && (x.op === 'in' || x.op === 'eq'))
  if (!c) return null
  const ids = (Array.isArray(c.value) ? c.value : [c.value]).map(Number).filter((n) => Number.isInteger(n))
  return ids.length ? ids : null
}

export async function searchEvents(caseId: number, filter: Filter, opts: { limit?: number; settings?: SettingsLike; signal?: AbortSignal; cap?: number } = {}): Promise<SearchResult<EventRow>> {
  const db = getDb()
  // how many matches a sort other than the index's own reads at most (lowered by the tests)
  const cap = opts.cap ?? HARD_CAP
  const limit = Math.min(opts.limit ?? 2000, cap)
  const pred = compileFilter(filter, { source: 'events', settings: opts.settings })
  const sort = filter.sort ?? { field: 'ts', dir: 'desc' }
  const ids = extractEventIds(filter.conditions, filter.logic)
  let rows: EventRow[]
  let truncated: boolean
  const pinned = pinnedIds(filter)
  if (pinned) {
    rows = (await db.events.bulkGet(pinned)).filter((r): r is EventRow => !!r && r.caseId === caseId && pred(r as Record<string, unknown>))
    sortRows(rows as Record<string, unknown>[], sort.field, sort.dir)
    truncated = rows.length > limit
    return { rows: rows.slice(0, limit), truncated }
  }
  if (ids && ids.length && ids.length <= 50) {
    const keys = ids.map((id) => [caseId, id] as [number, number])
    // The event-ID index gives rows in ingestion order. Sorting the first 20,000 of them showed a
    // "newest" that was not the newest once a log held more. When every match fits, all are read and
    // sorted; when not, a time sort walks the time index instead, which yields the true order.
    const matching = await db.events.where('[caseId+eventId]').anyOf(keys).count()
    if (matching <= cap || sort.field !== 'ts') {
      rows = await db.events
        .where('[caseId+eventId]')
        .anyOf(keys)
        .filter((r) => pred(r as Record<string, unknown>))
        .limit(cap)
        .toArray()
      const sampled = matching > cap
      truncated = rows.length >= cap
      sortRows(rows as Record<string, unknown>[], sort.field, sort.dir)
      if (rows.length > limit) {
        rows = rows.slice(0, limit)
        truncated = true
      }
      return { rows, truncated, ...(sampled ? { sampledFrom: cap } : {}) }
    }
  }
  const from = pred.from ?? Dexie.minKey
  const to = pred.to ?? Dexie.maxKey
  let coll = db.events.where('[caseId+ts]').between([caseId, from], [caseId, to], true, true)
  if (sort.field === 'ts' && sort.dir === 'desc') coll = coll.reverse()
  if (sort.field === 'ts') {
    rows = await coll
      .filter((r) => pred(r as Record<string, unknown>))
      .limit(limit + 1)
      .toArray()
    truncated = rows.length > limit
    rows = rows.slice(0, limit)
    const undated = await undatedEvents(caseId, pred, limit)
    return { rows: rows.concat(undated as typeof rows), truncated }
  }
  rows = await coll
    .filter((r) => pred(r as Record<string, unknown>))
    .limit(cap)
    .toArray()
  rows = rows.concat((await undatedEvents(caseId, pred, cap - rows.length)) as typeof rows)
  truncated = rows.length >= cap
  // sorting by a column other than time reads at most cap matches first: say so when it did
  const sampled = truncated
  sortRows(rows as Record<string, unknown>[], sort.field, sort.dir)
  if (rows.length > limit) {
    rows = rows.slice(0, limit)
    truncated = true
  }
  return { rows, truncated, ...(sampled ? { sampledFrom: cap } : {}) }
}

/**
 * Collection snapshots (autoruns, services, installed programs) have no event time, and Dexie
 * omits rows with a null key from the [caseId+ts] index, so they are invisible to every read
 * that walks it. They are still counted in the case totals, so without this they read as missing
 * evidence. Only meaningful when no time range is set: an undated row cannot be inside one.
 */
function undatedEventCollection(caseId: number, pred: (r: Record<string, unknown>) => boolean) {
  return getDb()
    .events.where('caseId')
    .equals(caseId)
    .filter((r) => (r as { ts?: number | null }).ts == null && pred(r as Record<string, unknown>))
}

async function undatedEvents(caseId: number, pred: { from?: number | null; to?: number | null } & ((r: Record<string, unknown>) => boolean), limit: number) {
  if (pred.from != null || pred.to != null || limit <= 0) return []
  return undatedEventCollection(caseId, pred).limit(limit).toArray()
}

export async function countEvents(caseId: number, filter: Filter, settings?: SettingsLike): Promise<number> {
  const db = getDb()
  const pred = compileFilter(filter, { source: 'events', settings })
  const hasConds = !!(filter.conditions?.length || filter.regex?.pattern || filter.text || filter.hourRange)
  const ids = extractEventIds(filter.conditions, filter.logic)
  if (ids && ids.length && ids.length <= 50) {
    return db.events
      .where('[caseId+eventId]')
      .anyOf(ids.map((id) => [caseId, id] as [number, number]))
      .filter((r) => pred(r as Record<string, unknown>))
      .count()
  }
  const from = pred.from ?? Dexie.minKey
  const to = pred.to ?? Dexie.maxKey
  const coll = db.events.where('[caseId+ts]').between([caseId, from], [caseId, to], true, true)
  const dated = hasConds ? await coll.filter((r) => pred(r as Record<string, unknown>)).count() : await coll.count()
  if (pred.from != null || pred.to != null) return dated
  return dated + (await undatedEventCollection(caseId, pred).count())
}

export interface AggGroup {
  value: string
  count: number
  first: number | null
  last: number | null
}

async function eachEvent(caseId: number, filter: Filter, settings: SettingsLike | undefined, fn: (r: EventRow) => void): Promise<number> {
  const db = getDb()
  const pred = compileFilter(filter, { source: 'events', settings })
  const ids = extractEventIds(filter.conditions, filter.logic)
  let n = 0
  const visit = (r: EventRow) => {
    if (pred(r as Record<string, unknown>)) {
      n++
      fn(r)
    }
  }
  if (ids && ids.length && ids.length <= 50) {
    await db.events
      .where('[caseId+eventId]')
      .anyOf(ids.map((id) => [caseId, id] as [number, number]))
      .each(visit)
  } else {
    const from = pred.from ?? Dexie.minKey
    const to = pred.to ?? Dexie.maxKey
    await db.events.where('[caseId+ts]').between([caseId, from], [caseId, to], true, true).each(visit)
    if (pred.from == null && pred.to == null) await undatedEventCollection(caseId, pred).each(visit)
  }
  return n
}

/** Group label of one value: addresses ({name, addr}) group by address, other objects by their JSON. */
function groupKey(x: unknown): string {
  if (x == null || x === '') return '(empty)'
  if (typeof x === 'object') {
    const o = x as Record<string, unknown>
    const addr = o.addr ?? o.address ?? o.email
    return typeof addr === 'string' && addr ? addr.toLowerCase() : JSON.stringify(x)
  }
  return String(x)
}

export async function aggregateEvents(caseId: number, filter: Filter, field: string, limit = 25, settings?: SettingsLike): Promise<{ groups: AggGroup[]; total: number; distinct: number }> {
  const map = new Map<string, AggGroup>()
  const total = await eachEvent(caseId, filter, settings, (r) => {
    const v = getPath(r, field)
    const vals = Array.isArray(v) ? v : [v]
    for (const x of vals) {
      const key = groupKey(x)
      const g = map.get(key)
      const ts = r.ts ?? null
      if (g) {
        g.count++
        if (ts != null) {
          g.first = g.first == null ? ts : Math.min(g.first, ts)
          g.last = g.last == null ? ts : Math.max(g.last, ts)
        }
      } else if (map.size < 100000) map.set(key, { value: key, count: 1, first: ts, last: ts })
    }
  })
  const groups = Array.from(map.values()).sort((a, b) => b.count - a.count)
  return { groups: groups.slice(0, limit), total, distinct: map.size }
}

/**
 * Stacking (least-frequency analysis): the event fields an analyst stacks, the same list as
 * STACK_FIELDS in backend/services/store/queries.py. Windows names paths, programs, services and
 * accounts without regard to case, so those group case-insensitively; a command line keeps its case
 * (an encoded argument is case-sensitive). providerEventId is the pair "provider / event id".
 */
export const STACK_FIELDS = [
  'image',
  'parentImage',
  'processName',
  'parentProcessName',
  'commandLine',
  'parentCommandLine',
  'path',
  'serviceName',
  'serviceFile',
  'taskName',
  'objectName',
  'targetFilename',
  'imageLoaded',
  'subjectUser',
  'targetUser',
  'workstation',
  'ipAddress',
  'destinationIp',
  'query',
  'providerEventId',
] as const
export type StackField = (typeof STACK_FIELDS)[number]
const STACK_CASE_SENSITIVE = new Set<string>(['commandLine', 'parentCommandLine'])

export interface StackRow {
  /** the value as the evidence spells it (the first spelling in sort order when case is folded) */
  value: string
  count: number
  /** distinct hosts it was seen on */
  hosts: number
  /** those hosts, when five or fewer */
  hostList: string[] | null
  first: number | null
  last: number | null
}
export interface Stack {
  field: string
  order: 'rare' | 'common'
  rows: StackRow[]
  /** events with a value in the field, and those without */
  events: number
  blank: number
  /** every value, not only those returned */
  distinct: number
  /** hosts among the events with a value: the N of "on 1 of N hosts" */
  hosts: number
  truncated: boolean
}

/** A host as the stories count it (lineage.host_key): lower case, without its domain; an address stays whole. */
function stackHost(v: unknown): string | null {
  if (v == null || v === '') return null
  const h = String(v).toLowerCase()
  const k = /^[0-9.]+$/.test(h) ? h : h.split('.')[0]
  return k || null
}

function stackValue(r: EventRow, field: string): string | null {
  if (field === 'providerEventId') return r.provider != null && r.provider !== '' && r.eventId != null ? `${r.provider} / ${r.eventId}` : null
  const v = r[field]
  return v == null || v === '' ? null : String(v)
}

/** Binary order, as DuckDB sorts text: the two stores return the same rows in the same order. */
const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0)

export async function stackEvents(caseId: number, filter: Filter, field: string, order: 'rare' | 'common' = 'rare', limit = 500, settings?: SettingsLike): Promise<Stack> {
  if (!(STACK_FIELDS as readonly string[]).includes(field)) throw new Error(`cannot stack on '${field}'`)
  const fold = field !== 'providerEventId' && !STACK_CASE_SENSITIVE.has(field)
  const groups = new Map<string, { value: string; count: number; hosts: Set<string>; first: number | null; last: number | null }>()
  const allHosts = new Set<string>()
  let events = 0
  const total = await eachEvent(caseId, filter, settings, (r) => {
    const v = stackValue(r, field)
    if (v == null) return
    events++
    const key = fold ? v.toLowerCase() : v
    const h = stackHost(r.computer)
    const ts = r.ts ?? null
    let g = groups.get(key)
    if (!g) {
      g = { value: v, count: 0, hosts: new Set(), first: ts, last: ts }
      groups.set(key, g)
    } else if (v < g.value) g.value = v
    g.count++
    if (h) {
      g.hosts.add(h)
      allHosts.add(h)
    }
    if (ts != null) {
      g.first = g.first == null ? ts : Math.min(g.first, ts)
      g.last = g.last == null ? ts : Math.max(g.last, ts)
    }
  })
  const dir = order === 'common' ? -1 : 1
  const sorted = Array.from(groups.entries()).sort(([ka, a], [kb, b]) => (a.hosts.size - b.hosts.size) * dir || (a.count - b.count) * dir || cmp(ka, kb))
  const n = Math.max(1, Math.min(Math.floor(limit), 5000))
  const rows = sorted.slice(0, n).map(([, g]) => ({
    value: g.value,
    count: g.count,
    hosts: g.hosts.size,
    hostList: g.hosts.size <= 5 ? Array.from(g.hosts).sort(cmp) : null,
    first: g.first,
    last: g.last,
  }))
  return { field, order: order === 'common' ? 'common' : 'rare', rows, events, blank: total - events, distinct: groups.size, hosts: allHosts.size, truncated: groups.size > rows.length }
}

export type Bucket = 'minute' | 'hour' | 'day'
const bucketMs: Record<Bucket, number> = { minute: 60_000, hour: 3_600_000, day: 86_400_000 }

export async function timelineEvents(caseId: number, filter: Filter, bucket: Bucket, settings?: SettingsLike): Promise<{ t: number; count: number }[]> {
  const size = bucketMs[bucket]
  const map = new Map<number, number>()
  await eachEvent(caseId, filter, settings, (r) => {
    if (r.ts == null) return
    const b = Math.floor(r.ts / size) * size
    map.set(b, (map.get(b) ?? 0) + 1)
  })
  return Array.from(map.entries())
    .map(([t, count]) => ({ t, count }))
    .sort((a, b) => a.t - b.t)
}

// ---- mails -----------------------------------------------------------------
/**
 * The browser store keeps a mail's full body apart from its row (the mailBodies table), so a
 * predicate over the row sees only the 400-character preview. Free text and bodyText conditions are
 * resolved against the bodies first: a bodyText condition becomes the set of mail ids it matches,
 * and free text also matches a mail whose body holds it. Before this, the search box that says
 * "body" searched the preview only, and a bodyText condition never matched.
 */
async function mailPredicate(caseId: number, filter: Filter, settings?: SettingsLike) {
  const db = getDb()
  const conds = filter.conditions ?? []
  const needsBodies = conds.some((c) => c.field === 'bodyText') || !!filter.text?.trim()
  if (!needsBodies) return compileFilter(filter, { source: 'mails', settings })
  const bodies = await db.mailBodies.where('caseId').equals(caseId).toArray()
  const bodyOf = (b: MailBody) => b.bodyText ?? b.visibleText ?? ''
  const resolved = conds.map((c) => {
    if (c.field !== 'bodyText') return c
    const one = compileFilter({ conditions: [c] }, { source: 'mails', settings })
    return { field: 'id', op: 'in' as const, value: bodies.filter((b) => one({ bodyText: bodyOf(b) })).map((b) => b.mailId) }
  })
  const pred = compileFilter({ ...filter, conditions: resolved }, { source: 'mails', settings })
  const text = filter.text?.trim().toLowerCase()
  if (!text) return pred
  const inBody = new Set(bodies.filter((b) => bodyOf(b).toLowerCase().includes(text)).map((b) => b.mailId))
  const rest = compileFilter({ ...filter, conditions: resolved, text: '' }, { source: 'mails', settings })
  return Object.assign((r: Record<string, unknown>) => pred(r) || (inBody.has(r.id as number) && rest(r)), { from: pred.from, to: pred.to, tsField: pred.tsField })
}

export async function searchMails(caseId: number, filter: Filter, opts: { limit?: number; settings?: SettingsLike } = {}): Promise<SearchResult<MailRow>> {
  const db = getDb()
  const limit = Math.min(opts.limit ?? 2000, HARD_CAP)
  const pred = await mailPredicate(caseId, filter, opts.settings)
  const sort = filter.sort ?? { field: 'date', dir: 'desc' }
  const pinned = pinnedIds(filter)
  if (pinned) {
    const hit = (await db.mails.bulkGet(pinned)).filter((r): r is MailRow => !!r && r.caseId === caseId && pred(r as Record<string, unknown>))
    sortRows(hit as unknown as Record<string, unknown>[], sort.field, sort.dir)
    return { rows: hit.slice(0, limit), truncated: hit.length > limit }
  }
  const from = pred.from ?? Dexie.minKey
  const to = pred.to ?? Dexie.maxKey
  let coll = db.mails.where('[caseId+date]').between([caseId, from], [caseId, to], true, true)
  if (sort.field === 'date' && sort.dir === 'desc') coll = coll.reverse()
  let rows = await coll
    .filter((r) => pred(r as Record<string, unknown>))
    .limit(sort.field === 'date' ? limit + 1 : HARD_CAP)
    .toArray()
  // mails without a date are not in the [caseId+date] index: append them when no time range is set
  if (pred.from == null && pred.to == null) {
    const undated = await db.mails
      .where('caseId')
      .equals(caseId)
      .filter((r) => r.date == null && pred(r as Record<string, unknown>))
      .toArray()
    rows = rows.concat(undated)
  }
  if (sort.field !== 'date') sortRows(rows as Record<string, unknown>[], sort.field, sort.dir)
  const truncated = rows.length > limit
  return { rows: rows.slice(0, limit), truncated }
}

export async function countMails(caseId: number, filter: Filter, settings?: SettingsLike): Promise<number> {
  const db = getDb()
  const pred = await mailPredicate(caseId, filter, settings)
  return db.mails
    .where('caseId')
    .equals(caseId)
    .filter((r) => pred(r as Record<string, unknown>))
    .count()
}

export async function aggregateMails(caseId: number, filter: Filter, field: string, limit = 25, settings?: SettingsLike): Promise<{ groups: AggGroup[]; total: number; distinct: number }> {
  const db = getDb()
  const pred = compileFilter(filter, { source: 'mails', settings })
  const map = new Map<string, AggGroup>()
  let total = 0
  await db.mails
    .where('caseId')
    .equals(caseId)
    .each((r) => {
      if (!pred(r as Record<string, unknown>)) return
      total++
      const v = getPath(r, field)
      const vals = Array.isArray(v) ? v : [v]
      for (const x of vals) {
        const key = groupKey(x)
        const g = map.get(key)
        const ts = r.date ?? null
        if (g) {
          g.count++
          if (ts != null) {
            g.first = g.first == null ? ts : Math.min(g.first, ts)
            g.last = g.last == null ? ts : Math.max(g.last, ts)
          }
        } else if (map.size < 100000) map.set(key, { value: key, count: 1, first: ts, last: ts })
      }
    })
  const groups = Array.from(map.values()).sort((a, b) => b.count - a.count)
  return { groups: groups.slice(0, limit), total, distinct: map.size }
}

export async function timelineMails(caseId: number, filter: Filter, bucket: Bucket, settings?: SettingsLike): Promise<{ t: number; count: number }[]> {
  const db = getDb()
  const pred = compileFilter(filter, { source: 'mails', settings })
  const size = bucketMs[bucket]
  const map = new Map<number, number>()
  await db.mails
    .where('caseId')
    .equals(caseId)
    .each((r) => {
      if (r.date == null || !pred(r as Record<string, unknown>)) return
      const b = Math.floor(r.date / size) * size
      map.set(b, (map.get(b) ?? 0) + 1)
    })
  return Array.from(map.entries())
    .map(([t, count]) => ({ t, count }))
    .sort((a, b) => a.t - b.t)
}

// ---- facets / pivots ----------------------------------------------------------
export async function getFacets(caseId: number, source: 'events' | 'mails', field: string, limit = 50, q = ''): Promise<Facet[]> {
  const db = getDb()
  const needle = q.trim().toLowerCase()
  // a search reaches every stored value, not only the most frequent ones already loaded
  const rows = await db.facets
    .where('[caseId+source+field]')
    .equals([caseId, source, field])
    .filter((f) => !needle || f.value.toLowerCase().includes(needle))
    .toArray()
  rows.sort((a, b) => b.count - a.count)
  return rows.slice(0, limit)
}

export interface PivotResult {
  value: string
  events: {
    count: number
    first: number | null
    last: number | null
    byEventId: Record<string, number>
    fields: Record<string, number>
    /** the scan stopped here: counts are over the first this-many events of the case */
    scannedOf?: { scanned: number; total: number }
  }
  mails: { count: number; first: number | null; last: number | null; fields: Record<string, number> }
}

export async function pivot(caseId: number, value: string, maxScan = 400000): Promise<PivotResult> {
  const db = getDb()
  const needle = value.trim().toLowerCase()
  const res: PivotResult = {
    value,
    events: { count: 0, first: null, last: null, byEventId: {}, fields: {} },
    mails: { count: 0, first: null, last: null, fields: {} },
  }
  if (!needle) return res
  const EV_FIELDS = [
    'ipAddress',
    'targetUser',
    'subjectUser',
    'computer',
    'workstation',
    'destinationIp',
    'sourceIp',
    'processName',
    'serviceName',
    'image',
    'query',
    'commandLine',
    'targetFilename',
    'hashes',
    'message',
    'scriptBlockText',
    'memberName',
    'objectName',
  ]
  let scanned = 0
  // A pivot over millions of rows stops at maxScan and says so, rather than keep walking without
  // counting and report partial numbers as the whole.
  await db.events
    .where('caseId')
    .equals(caseId)
    .until(() => scanned >= maxScan)
    .each((r) => {
      scanned++
      let hit = false
      for (const f of EV_FIELDS) {
        const v = r[f]
        if (typeof v === 'string' && v.toLowerCase().includes(needle)) {
          hit = true
          res.events.fields[f] = (res.events.fields[f] ?? 0) + 1
        }
      }
      if (!hit && typeof r.raw === 'string' && r.raw.toLowerCase().includes(needle)) {
        hit = true
        res.events.fields.raw = (res.events.fields.raw ?? 0) + 1
      }
      if (!hit) return
      res.events.count++
      const k = String(r.eventId)
      res.events.byEventId[k] = (res.events.byEventId[k] ?? 0) + 1
      if (r.ts != null) {
        res.events.first = res.events.first == null ? r.ts : Math.min(res.events.first, r.ts)
        res.events.last = res.events.last == null ? r.ts : Math.max(res.events.last, r.ts)
      }
    })
  if (scanned >= maxScan) res.events.scannedOf = { scanned, total: await db.events.where('caseId').equals(caseId).count() }
  const M_FIELDS = ['fromAddr', 'fromName', 'fromDomain', 'subject', 'originIp', 'returnPath', 'messageId', 'textPreview']
  await db.mails
    .where('caseId')
    .equals(caseId)
    .each((r) => {
      let hit = false
      for (const f of M_FIELDS) {
        const v = r[f]
        if (typeof v === 'string' && v.toLowerCase().includes(needle)) {
          hit = true
          res.mails.fields[f] = (res.mails.fields[f] ?? 0) + 1
        }
      }
      if (!hit && r.urls?.some((u) => (u.url || '').toLowerCase().includes(needle))) {
        hit = true
        res.mails.fields.urls = (res.mails.fields.urls ?? 0) + 1
      }
      if (!hit && r.attachments?.some((a) => (a.sha256 || '').toLowerCase() === needle || (a.md5 || '').toLowerCase() === needle || (a.name || '').toLowerCase().includes(needle))) {
        hit = true
        res.mails.fields.attachments = (res.mails.fields.attachments ?? 0) + 1
      }
      if (!hit && (r.replyTo ?? []).some((x) => (x.addr || '').toLowerCase().includes(needle))) {
        hit = true
        res.mails.fields.replyTo = (res.mails.fields.replyTo ?? 0) + 1
      }
      if (!hit) return
      res.mails.count++
      if (r.date != null) {
        res.mails.first = res.mails.first == null ? r.date : Math.min(res.mails.first, r.date)
        res.mails.last = res.mails.last == null ? r.date : Math.max(res.mails.last, r.date)
      }
    })
  return res
}

export async function caseSummary(caseId: number): Promise<Record<string, unknown>> {
  const db = getDb()
  const evidence = await db.evidence.where('caseId').equals(caseId).toArray()
  const events = await db.events.where('caseId').equals(caseId).count()
  const mails = await db.mails.where('caseId').equals(caseId).count()
  const findings = await db.findings.where('caseId').equals(caseId).toArray()
  const iocs = await db.iocs.where('caseId').equals(caseId).count()
  const topEventIds = (await getFacets(caseId, 'events', 'eventId', 15)).map((f) => ({ eventId: f.value, count: f.count }))
  const topComputers = (await getFacets(caseId, 'events', 'computer', 10)).map((f) => ({ computer: f.value, count: f.count }))
  const topSenders = (await getFacets(caseId, 'mails', 'fromAddr', 10)).map((f) => ({ from: f.value, count: f.count }))
  const topFlags = (await getFacets(caseId, 'mails', 'flags', 15)).map((f) => ({ flag: f.value, count: f.count }))
  const bySeverity: Record<string, number> = {}
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1
  const evRange = { first: null as number | null, last: null as number | null }
  const mailRange = { first: null as number | null, last: null as number | null }
  for (const e of evidence) {
    const s = e.stats as { firstTs?: number; lastTs?: number; eventRange?: { firstTs?: number; lastTs?: number }; mailRange?: { firstTs?: number; lastTs?: number } } | undefined
    if (!s) continue
    if (e.kind === 'package') {
      for (const [range, target] of [
        [s.eventRange, evRange],
        [s.mailRange, mailRange],
      ] as const) {
        if (range?.firstTs != null) target.first = target.first == null ? range.firstTs : Math.min(target.first, range.firstTs)
        if (range?.lastTs != null) target.last = target.last == null ? range.lastTs : Math.max(target.last, range.lastTs)
      }
      continue
    }
    const tgt = e.kind === 'evtx' ? evRange : mailRange
    if (s.firstTs != null) tgt.first = tgt.first == null ? s.firstTs : Math.min(tgt.first, s.firstTs)
    if (s.lastTs != null) tgt.last = tgt.last == null ? s.lastTs : Math.max(tgt.last, s.lastTs)
  }
  return {
    evidence: evidence.map((e) => ({ id: e.id, name: e.name, kind: e.kind, format: e.format, size: e.size, count: e.count, sha256: e.sha256Client, integrity: e.integrity, status: e.status })),
    counts: { events, mails, findings: findings.length, iocs },
    eventsTimeRange: { firstIso: evRange.first ? new Date(evRange.first).toISOString() : null, lastIso: evRange.last ? new Date(evRange.last).toISOString() : null },
    mailsTimeRange: { firstIso: mailRange.first ? new Date(mailRange.first).toISOString() : null, lastIso: mailRange.last ? new Date(mailRange.last).toISOString() : null },
    topEventIds,
    topComputers,
    topSenders,
    topMailFlags: topFlags,
    findingsBySeverity: bySeverity,
    topFindings: findings
      .sort((a, b) => ['info', 'low', 'medium', 'high', 'critical'].indexOf(b.severity) - ['info', 'low', 'medium', 'high', 'critical'].indexOf(a.severity))
      .slice(0, 15)
      .map((f) => ({ id: f.id, ruleId: f.ruleId, title: f.title, severity: f.severity, count: f.count, entities: f.entities, tsIso: f.ts ? new Date(f.ts).toISOString() : null })),
  }
}
