/// <reference lib="webworker" />
/**
 * Rule worker: runs the YAML rules against IndexedDB and stores findings.
 */
import { getDb, type Finding, type MailRow } from '../db/schema'
import { compileCond, ruleEventIds, ruleFields, runRule, type Rule, type RuleDiag } from '../rules/engine'
import type { Row, SettingsLike } from '../rules/filter'

export interface RunRequest {
  cmd: 'run'
  caseId: number
  rules: Rule[]
  settings: SettingsLike
}

const ctx = self as unknown as DedicatedWorkerGlobalScope
const post = (msg: Record<string, unknown>) => ctx.postMessage(msg)

const BODY_FIELDS = new Set(['bodyText', 'bodyHtml', 'headersText', 'visibleText'])

interface Keep {
  raw: boolean
  data: boolean
}

async function fetchEvents(caseId: number, ids: number[] | null, pred: (r: Row) => boolean, keep: Keep): Promise<Row[]> {
  const db = getDb()
  const out: Row[] = []
  const strip = (r: Row) => {
    if (!keep.raw) delete r.raw
    if (!keep.data) delete r.data
    return r
  }
  if (ids && ids.length) {
    const keys = ids.map((id) => [caseId, id] as [number, number])
    await db.events
      .where('[caseId+eventId]')
      .anyOf(keys)
      .each((r) => {
        if (pred(r as Row)) out.push(strip(r as Row))
      })
  } else {
    await db.events
      .where('caseId')
      .equals(caseId)
      .each((r) => {
        if (pred(r as Row)) out.push(strip(r as Row))
      })
  }
  return out
}

let mailCache: { caseId: number; rows: MailRow[] } | null = null
async function allMails(caseId: number): Promise<MailRow[]> {
  if (mailCache && mailCache.caseId === caseId) return mailCache.rows
  const db = getDb()
  const rows = await db.mails.where('caseId').equals(caseId).toArray()
  mailCache = { caseId, rows }
  return rows
}
let joinedCache: { caseId: number; rows: Row[] } | null = null
const JOIN_CACHE_MAX = 50_000
async function mailsWithBodies(caseId: number): Promise<Row[]> {
  if (joinedCache && joinedCache.caseId === caseId) return joinedCache.rows
  const db = getDb()
  const rows = await allMails(caseId)
  const bodies = await db.mailBodies.where('caseId').equals(caseId).toArray()
  const byId = new Map(bodies.map((b) => [b.mailId, b]))
  const joined = rows.map((m) => {
    const b = byId.get(m.id as number)
    return { ...m, bodyText: b?.bodyText ?? null, bodyHtml: b?.bodyHtml ?? null, headersText: b?.headersText ?? null, visibleText: b?.visibleText ?? null }
  })
  // keep the join for the rest of the run when it is small enough to hold (hundreds of body rules share it)
  joinedCache = joined.length <= JOIN_CACHE_MAX ? { caseId, rows: joined } : null
  return joined
}

/** Which heavy columns the rules pinned to one eventId set actually read. */
function keepFor(fields: Set<string>): Keep {
  let raw = false
  let data = false
  for (const f of fields) {
    if (f === 'raw' || f.startsWith('raw')) raw = true
    if (f === 'data' || f.startsWith('data.') || f === 'dataList') data = true
  }
  return { raw, data }
}

/** Cache key of the event subset a rule reads: its pinned eventIds, or '*' for a full scan. */
function subsetKey(rule: Rule): string | null {
  if (rule.source !== 'events') return null
  const ids = ruleEventIds(rule.where)
  return ids ? ids.slice().sort((a, b) => a - b).join(',') : '*'
}

const CACHE_ROWS = 250_000

async function run(req: RunRequest): Promise<void> {
  const db = getDb()
  const { caseId, rules, settings } = req
  mailCache = null
  joinedCache = null
  const ruleIds = new Set(rules.map((r) => r.id))
  // preserve analyst decisions on findings that still exist after the re-run
  const old = await db.findings.where('caseId').equals(caseId).filter((f) => ruleIds.has(f.ruleId)).toArray()
  const oldByKey = new Map(old.map((f) => [f.key, f]))
  await db.findings.where('caseId').equals(caseId).filter((f) => ruleIds.has(f.ruleId)).delete()
  let total = 0
  const byRule: Record<string, number> = {}
  const diagnostics: RuleDiag[] = []
  const now = Date.now()
  // Rules that read the same event subset (same pinned eventIds) run back to back and share one
  // IndexedDB read: with the community packs, ~1,500 process-creation rules would otherwise each
  // re-read every Sysmon 1 / 4688 row. Heavy columns (raw XML, EventData) are kept only when a
  // rule of the group reads them.
  const keepByKey = new Map<string, Keep>()
  for (const rule of rules) {
    const k = subsetKey(rule)
    if (k === null) continue
    const need = keepFor(ruleFields(rule.where))
    const cur = keepByKey.get(k) ?? { raw: false, data: false }
    keepByKey.set(k, { raw: cur.raw || need.raw, data: cur.data || need.data })
  }
  const order = rules.map((rule, i) => ({ rule, i, k: subsetKey(rule) ?? '' })).sort((a, b) => (a.k < b.k ? -1 : a.k > b.k ? 1 : a.i - b.i))
  const eventCount = keepByKey.has('*') ? await db.events.where('caseId').equals(caseId).count() : 0
  const cache = new Map<string, Row[]>()
  let cached = 0
  const subset = async (k: string, ids: number[] | null, pred: (r: Row) => boolean): Promise<Row[]> => {
    if (k === '*' && eventCount > CACHE_ROWS) return fetchEvents(caseId, null, pred, keepByKey.get(k)!) // too big to hold: stream per rule
    let rows = cache.get(k)
    if (!rows) {
      rows = await fetchEvents(caseId, ids, () => true, keepByKey.get(k)!)
      if (cached + rows.length > CACHE_ROWS) {
        cache.clear()
        cached = 0
      }
      cache.set(k, rows)
      cached += rows.length
    }
    return rows
  }
  for (let n = 0; n < order.length; n++) {
    const { rule, k: key } = order[n]
    const i = n
    if (rule.enabled === false) continue
    const t0 = Date.now()
    try {
      let rows: Row[]
      let thenRows: (() => Row[]) | undefined
      const fields = ruleFields(rule.where)
      if (rule.source === 'events') {
        const pred = compileCond(rule.where, settings)
        rows = await subset(key, ruleEventIds(rule.where), pred)
        if (rule.then?.where) {
          const thenPred = compileCond(rule.then.where, settings)
          const pre = await fetchEvents(caseId, ruleEventIds(rule.then.where), thenPred, { raw: false, data: false })
          thenRows = () => pre
        }
      } else {
        const needBodies = Array.from(fields).some((f) => BODY_FIELDS.has(f))
        rows = needBodies ? await mailsWithBodies(caseId) : ((await allMails(caseId)) as unknown as Row[])
        if (rule.then?.where) {
          const all = rows
          thenRows = () => all
        }
      }
      const found = runRule(rule, { rows, settings, thenRows: thenRows ? () => thenRows!() : undefined, onDiag: (d) => diagnostics.push(d) })
      const toAdd: Finding[] = found.map((f) => {
        const prev = oldByKey.get(f.key)
        return { ...f, caseId, createdAt: prev?.createdAt ?? now, status: prev?.status ?? 'new', notes: prev?.notes }
      })
      if (toAdd.length) await db.findings.bulkAdd(toAdd)
      byRule[rule.id] = toAdd.length
      total += toAdd.length
      post({ type: 'progress', index: i + 1, total: rules.length, ruleId: rule.id, findings: toAdd.length, ms: Date.now() - t0, rows: rows.length })
    } catch (e) {
      post({ type: 'rule-error', ruleId: rule.id, error: (e as Error).message || String(e), index: i + 1, total: rules.length })
    }
  }
  mailCache = null
  joinedCache = null
  cache.clear()
  post({ type: 'done', total, byRule, diagnostics })
}

ctx.onmessage = async (ev: MessageEvent<RunRequest>) => {
  try {
    if (ev.data.cmd === 'run') await run(ev.data)
  } catch (e) {
    post({ type: 'error', error: (e as Error).message || String(e) })
  }
}
