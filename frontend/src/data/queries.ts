/**
 * Read queries over IndexedDB used by the views and by the AI tools.
 */
import Dexie from 'dexie'
import { getDb, type EventRow, type Facet, type MailRow } from '../db/schema'
import { compileFilter, extractEventIds, getPath, type Filter, type SettingsLike } from '../rules/filter'

export interface SearchResult<T> {
  rows: T[]
  truncated: boolean
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

export async function searchEvents(caseId: number, filter: Filter, opts: { limit?: number; settings?: SettingsLike; signal?: AbortSignal } = {}): Promise<SearchResult<EventRow>> {
  const db = getDb()
  const limit = Math.min(opts.limit ?? 2000, HARD_CAP)
  const pred = compileFilter(filter, { source: 'events', settings: opts.settings })
  const sort = filter.sort ?? { field: 'ts', dir: 'desc' }
  const ids = extractEventIds(filter.conditions, filter.logic)
  let rows: EventRow[]
  let truncated: boolean
  if (ids && ids.length && ids.length <= 50) {
    rows = await db.events
      .where('[caseId+eventId]')
      .anyOf(ids.map((id) => [caseId, id] as [number, number]))
      .filter((r) => pred(r as Record<string, unknown>))
      .limit(HARD_CAP)
      .toArray()
    truncated = rows.length >= HARD_CAP
    sortRows(rows as Record<string, unknown>[], sort.field, sort.dir)
    if (rows.length > limit) {
      rows = rows.slice(0, limit)
      truncated = true
    }
    return { rows, truncated }
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
    .limit(HARD_CAP)
    .toArray()
  rows = rows.concat((await undatedEvents(caseId, pred, HARD_CAP - rows.length)) as typeof rows)
  truncated = rows.length >= HARD_CAP
  sortRows(rows as Record<string, unknown>[], sort.field, sort.dir)
  if (rows.length > limit) {
    rows = rows.slice(0, limit)
    truncated = true
  }
  return { rows, truncated }
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
export async function searchMails(caseId: number, filter: Filter, opts: { limit?: number; settings?: SettingsLike } = {}): Promise<SearchResult<MailRow>> {
  const db = getDb()
  const limit = Math.min(opts.limit ?? 2000, HARD_CAP)
  const pred = compileFilter(filter, { source: 'mails', settings: opts.settings })
  const sort = filter.sort ?? { field: 'date', dir: 'desc' }
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
  const pred = compileFilter(filter, { source: 'mails', settings })
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
export async function getFacets(caseId: number, source: 'events' | 'mails', field: string, limit = 50): Promise<Facet[]> {
  const db = getDb()
  const rows = await db.facets.where('[caseId+source+field]').equals([caseId, source, field]).toArray()
  rows.sort((a, b) => b.count - a.count)
  return rows.slice(0, limit)
}

export interface PivotResult {
  value: string
  events: { count: number; first: number | null; last: number | null; byEventId: Record<string, number>; fields: Record<string, number> }
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
  await db.events
    .where('caseId')
    .equals(caseId)
    .each((r) => {
      if (scanned++ > maxScan) return
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
