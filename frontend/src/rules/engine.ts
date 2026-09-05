/**
 * Rule engine for the YAML DSL (see rules/*.yaml). Pure functions: the worker
 * feeds rows, the engine returns findings.
 */
import { compileRegex, getPath, isOutsideHours, localHourAndDay, matchCondition, settingList, type Condition, type Op, type Row, type SettingsLike } from './filter'
import type { Finding, Severity } from '../db/schema'

export interface RuleThen {
  where?: RuleCond
  join?: string[]
  within?: string
  severity?: Severity
  title?: string
}
export interface RuleTime {
  outside_business_hours?: boolean
  weekend?: boolean
  hours?: [number, number]
  field?: string
}
export type RuleCond = Record<string, unknown>
export interface Rule {
  id: string
  title: string
  description?: string
  severity: Severity
  confidence?: 'low' | 'medium' | 'high'
  source: 'events' | 'mails'
  attack?: string[]
  tags?: string[]
  enabled?: boolean
  where?: RuleCond
  group_by?: string[]
  window?: string
  threshold?: string | number
  distinct?: string
  then?: RuleThen
  time?: RuleTime
  exclude?: RuleCond
  entities?: string[]
  then_flags?: Record<string, Severity>[]
  require_setting?: string
  any_in_group?: RuleCond
  max_findings?: number
  /** per-row rules matching more rows than this are collapsed into per-entity findings (default 200) */
  collapse_after?: number
}

export const SEVERITIES: Severity[] = ['info', 'low', 'medium', 'high', 'critical']
export const COLLAPSE_AFTER = 200
const GROUPABLE: Record<string, string[]> = {
  events: ['computer', 'targetUser', 'subjectUser', 'ipAddress', 'processName', 'serviceName', 'memberName', 'groupName', 'shareName', 'image', 'destinationIp', 'query'],
  mails: ['fromAddr', 'fromDomain', 'fromRegistrable', 'fromNameNorm', 'originIp', 'replyToDomain', 'folder'],
}
export const sevRank = (s: Severity | string | undefined): number => Math.max(0, SEVERITIES.indexOf((s || 'info') as Severity))
export const maxSeverity = (a: Severity, b: Severity | undefined): Severity => (b && sevRank(b) > sevRank(a) ? b : a)

const OPS = new Set<string>(['eq', 'ne', 'in', 'nin', 'contains', 'not_contains', 'contains_any', 'contains_all', 'startswith', 'not_startswith', 'endswith', 'not_endswith', 're', 'not_re', 'gt', 'gte', 'lt', 'lte', 'exists', 'empty', 'in_setting', 'nin_setting', 'levenshtein', 'length', 'contains_cs', 'startswith_cs', 'endswith_cs'])

type Pred = (row: Row) => boolean

/** Compile the YAML "where" object: keys `field|op`, `any_of[_N]`, `all_of`, `not`. */
export function compileCond(cond: RuleCond | undefined | null, settings?: SettingsLike): Pred {
  if (!cond || typeof cond !== 'object') return () => true
  const preds: Pred[] = []
  for (const [key, value] of Object.entries(cond)) {
    if (/^any_of(_\d+)?$/.test(key)) {
      const alts = Array.isArray(value) ? value : [value]
      const sub = alts.map((a) => compileCond(a as RuleCond, settings))
      preds.push((row) => sub.some((p) => p(row)))
      continue
    }
    if (/^all_of(_\d+)?$/.test(key)) {
      const alts = Array.isArray(value) ? value : [value]
      const sub = alts.map((a) => compileCond(a as RuleCond, settings))
      preds.push((row) => sub.every((p) => p(row)))
      continue
    }
    if (key === 'not') {
      const sub = compileCond(value as RuleCond, settings)
      preds.push((row) => !sub(row))
      continue
    }
    const [field, opRaw] = key.split('|')
    let op: Op
    if (opRaw && OPS.has(opRaw)) op = opRaw as Op
    else if (opRaw) throw new Error(`unknown operator "${opRaw}" in "${key}"`)
    else op = Array.isArray(value) ? 'in' : 'eq'
    const c: Condition = { field, op, value }
    if (op === 'contains' && Array.isArray(value)) c.op = 'contains_any'
    preds.push((row) => matchCondition(row, c, settings))
  }
  if (!preds.length) return () => true
  return (row) => preds.every((p) => p(row))
}

export function parseDuration(s: string | number | undefined): number | null {
  if (s == null || s === '') return null
  if (typeof s === 'number') return s * 1000
  const m = /^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)?\s*$/i.exec(String(s))
  if (!m) return null
  const n = Number(m[1])
  const unit = (m[2] || 's').toLowerCase()
  const mult: Record<string, number> = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000, w: 604_800_000 }
  return n * mult[unit]
}

export function parseThreshold(t: string | number | undefined): ((n: number) => boolean) | null {
  if (t == null || t === '') return null
  if (typeof t === 'number') return (n) => n >= t
  const m = /^\s*(>=|<=|==|=|>|<|!=)?\s*(\d+)\s*$/.exec(String(t))
  if (!m) return null
  const v = Number(m[2])
  switch (m[1] || '>=') {
    case '>=': return (n) => n >= v
    case '>': return (n) => n > v
    case '<=': return (n) => n <= v
    case '<': return (n) => n < v
    case '==': case '=': return (n) => n === v
    case '!=': return (n) => n !== v
    default: return (n) => n >= v
  }
}

const str = (v: unknown): string => (v == null ? '' : Array.isArray(v) ? v.map(String).join(',') : typeof v === 'object' ? JSON.stringify(v) : String(v))

function groupKey(row: Row, fields: string[]): string {
  return fields.map((f) => str(getPath(row, f)).toLowerCase()).join('')
}

function defaultEntityFields(rule: Rule): string[] {
  if (rule.entities?.length) return rule.entities
  if (rule.group_by?.length) return rule.group_by
  return rule.source === 'mails' ? ['fromAddr', 'fromDomain', 'subject', 'originIp'] : ['computer', 'targetUser', 'subjectUser', 'ipAddress', 'processName', 'serviceName']
}

function entitiesOf(row: Row, fields: string[]): Record<string, string> {
  const out: Record<string, string> = {}
  for (const f of fields) {
    const v = getPath(row, f)
    if (v != null && v !== '' && !(Array.isArray(v) && !v.length)) out[f] = str(v).slice(0, 200)
  }
  return out
}

function timePred(rule: Rule, settings: SettingsLike | undefined, tsField: string): Pred | null {
  const t = rule.time
  if (!t || (!t.outside_business_hours && !t.weekend && !t.hours)) return null
  const bh = settings?.businessHours ?? { start: 8, end: 19, tz: 'UTC' }
  const [start, end] = t.hours ?? [bh.start, bh.end]
  const weekend = settings?.weekendDays ?? [0, 6]
  const field = t.field || tsField
  return (row) => {
    const ts = row[field]
    if (typeof ts !== 'number') return false
    const { hour, day } = localHourAndDay(ts, bh.tz || 'UTC')
    let ok = false
    if (t.outside_business_hours && isOutsideHours(hour, start, end)) ok = true
    if (t.weekend && weekend.includes(day)) ok = true
    if (!t.outside_business_hours && !t.weekend && t.hours) ok = isOutsideHours(hour, start, end)
    return ok
  }
}

/** Why a rule produced zero findings (emitted through RunOptions.onDiag). */
export interface RuleDiag {
  ruleId: string
  reason: 'missing_setting' | 'no_selector_match' | 'all_excluded' | 'outside_time_window' | 'below_threshold'
  detail?: string
  matched: number
  afterExclude: number
  afterTime: number
}

/** Settings names referenced by AND-position `in_setting` conditions whose lists are empty (rule can never match). */
export function emptyPositiveSettings(cond: RuleCond | undefined, settings: SettingsLike | undefined, acc: string[] = []): string[] {
  if (!cond) return acc
  for (const [key, value] of Object.entries(cond)) {
    if (/^any_of(_\d+)?$/.test(key) || key === 'not') continue // OR / negated context: not necessarily blocking
    if (/^all_of(_\d+)?$/.test(key)) {
      for (const alt of Array.isArray(value) ? value : [value]) emptyPositiveSettings(alt as RuleCond, settings, acc)
      continue
    }
    const op = key.split('|')[1]
    if (op === 'in_setting' && !settingList(settings, String(value)).length && !acc.includes(String(value))) acc.push(String(value))
  }
  return acc
}

export interface RunOptions {
  settings?: SettingsLike
  /** rows of the rule's source, any order (sorted internally) */
  rows: Row[]
  /** lookup for `then` follow-ups: returns candidate rows of the same source */
  thenRows?: (cond: RuleCond) => Row[]
  now?: number
  idField?: string
  /** called once when the rule yields zero findings, with the reason */
  onDiag?: (d: RuleDiag) => void
}

/** Run one rule and return findings (without caseId/createdAt/status - the worker completes them). */
export function runRule(rule: Rule, opts: RunOptions): Omit<Finding, 'caseId' | 'createdAt' | 'status'>[] {
  const settings = opts.settings
  const tsField = rule.source === 'mails' ? 'date' : 'ts'
  const idField = opts.idField ?? 'id'
  if (rule.require_setting && !((settings?.[rule.require_setting] as unknown[] | undefined)?.length || (settings?.[rule.require_setting.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase())] as unknown[] | undefined)?.length)) {
    opts.onDiag?.({ ruleId: rule.id, reason: 'missing_setting', detail: `setting "${rule.require_setting}" is empty`, matched: 0, afterExclude: 0, afterTime: 0 })
    return []
  }
  const missingSettings = emptyPositiveSettings(rule.where, settings)
  const where = compileCond(rule.where, settings)
  const exclude = rule.exclude ? compileCond(rule.exclude, settings) : null
  const tp = timePred(rule, settings, tsField)
  const entityFields = defaultEntityFields(rule)
  const maxFindings = rule.max_findings ?? 2000
  const thenFlags = (rule.then_flags ?? []).flatMap((o) => Object.entries(o)) as [string, Severity][]

  const matches: Row[] = []
  let nWhere = 0
  let nExcl = 0
  for (const row of opts.rows) {
    if (!where(row)) continue
    nWhere++
    if (exclude && exclude(row)) continue
    nExcl++
    if (tp && !tp(row)) continue
    matches.push(row)
  }
  matches.sort((a, b) => (Number(a[tsField]) || 0) - (Number(b[tsField]) || 0))
  const findings: Omit<Finding, 'caseId' | 'createdAt' | 'status'>[] = []
  const emitZeroDiag = () => {
    if (!opts.onDiag || findings.length) return
    let reason: RuleDiag['reason']
    let detail: string | undefined
    if (nWhere === 0 && missingSettings.length) {
      reason = 'missing_setting'
      detail = `empty setting(s): ${missingSettings.join(', ')}`
    } else if (nWhere === 0) reason = 'no_selector_match'
    else if (nExcl === 0) reason = 'all_excluded'
    else if (matches.length === 0) reason = 'outside_time_window'
    else {
      reason = 'below_threshold'
      detail = `${matches.length} row(s) matched but no group met ${rule.threshold ?? 'the threshold'}${rule.window ? ` within ${rule.window}` : ''}`
    }
    opts.onDiag({ ruleId: rule.id, reason, detail, matched: nWhere, afterExclude: nExcl, afterTime: matches.length })
  }
  const base = () => ({ ruleId: rule.id, title: rule.title, description: rule.description, severity: rule.severity, confidence: rule.confidence, source: rule.source, attack: rule.attack ?? [], tags: rule.tags ?? [] })
  const escalationFor = (rows: Row[]) => {
    let severity = rule.severity
    let escalation: string | undefined
    for (const [flag, s] of thenFlags) {
      if (sevRank(s) > sevRank(severity) && rows.some((r) => Array.isArray(r.flags) && r.flags.includes(flag))) {
        severity = s
        escalation = flag
      }
    }
    let refs = rows.slice(0, 500).map(idOf)
    if (escalation) {
      const supporting = rows.find((r) => Array.isArray(r.flags) && r.flags.includes(escalation))!
      if (!refs.includes(idOf(supporting))) refs = [...refs.slice(0, 499), idOf(supporting)]
    }
    return { severity, escalation, refs }
  }
  const idOf = (r: Row) => Number(r[idField])

  const threshold = parseThreshold(rule.threshold)
  const groupBy = rule.group_by ?? []
  const windowMs = parseDuration(rule.window)

  if (!groupBy.length && !threshold) {
    const collapseAfter = rule.collapse_after ?? COLLAPSE_AFTER
    if (matches.length > collapseAfter) {
      // too many per-row alerts: collapse into one finding per entity combination
      const groupable = GROUPABLE[rule.source] ?? entityFields
      const keyFields = entityFields.filter((f) => groupable.includes(f))
      const grouped: Rule = { ...rule, group_by: keyFields.length ? keyFields : entityFields.slice(0, 2), threshold: '>= 1' }
      const out = runRule(grouped, opts)
      for (const f of out) f.escalation = f.escalation || `collapsed: ${matches.length.toLocaleString('en-US')} matching rows`
      return out
    }
    // one finding per matching row
    for (const row of matches) {
      if (findings.length >= maxFindings) break
      let sev = rule.severity
      let escalation: string | undefined
      const flags = Array.isArray(row.flags) ? (row.flags as string[]) : []
      for (const [flag, s] of thenFlags) {
        if (flags.includes(flag) && sevRank(s) > sevRank(sev)) {
          sev = s
          escalation = flag
        }
      }
      findings.push({ ...base(), severity: sev, key: `${rule.id}|${idOf(row)}`, ts: (row[tsField] as number) ?? null, entities: entitiesOf(row, entityFields), count: 1, refs: [idOf(row)], escalation })
    }
    emitZeroDiag()
    return findings
  }

  // grouped / thresholded rules
  const groups = new Map<string, Row[]>()
  for (const row of matches) {
    const k = groupBy.length ? groupKey(row, groupBy) : '*'
    if (groupBy.length && k.split('').every((x) => !x)) continue // all group fields empty
    let g = groups.get(k)
    if (!g) groups.set(k, (g = []))
    g.push(row)
  }
  const anyInGroup = rule.any_in_group ? compileCond(rule.any_in_group, settings) : null
  const distinctOf = (rows: Row[]) => (rule.distinct ? new Set(rows.map((r) => str(getPath(r, rule.distinct!)).toLowerCase()).filter(Boolean)).size : rows.length)

  for (const [, rows] of groups) {
    if (anyInGroup && !rows.some((r) => anyInGroup(r))) continue
    if (!windowMs) {
      const n = distinctOf(rows)
      if (threshold && !threshold(n)) continue
      if (!threshold && n < 1) continue
      const first = rows[0]
      const last = rows[rows.length - 1]
      const ent = entitiesOf(first, entityFields)
      if (rule.distinct) ent[rule.distinct] = Array.from(new Set(rows.map((r) => str(getPath(r, rule.distinct!))).filter(Boolean))).slice(0, 8).join(', ')
      findings.push({ ...base(), ...escalationFor(rows), key: `${rule.id}|${groupKey(first, groupBy)}`, ts: (first[tsField] as number) ?? null, tsEnd: (last[tsField] as number) ?? null, entities: ent, count: rows.length })
      if (findings.length >= maxFindings) break
      continue
    }
    // sliding window: detect bursts
    let i = 0
    let open: { rows: Row[]; start: number; last: number } | null = null
    const win: Row[] = []
    for (const row of rows) {
      const t = Number(row[tsField]) || 0
      win.push(row)
      while (win.length && t - (Number(win[0][tsField]) || 0) > windowMs) win.shift()
      if (open) {
        if (t - open.last <= windowMs) {
          open.rows.push(row)
          open.last = t
          continue
        }
        // close the burst
        findings.push(makeBurst(open))
        open = null
      }
      const n = distinctOf(win)
      if (threshold ? threshold(n) : n >= 1) {
        open = { rows: [...win], start: Number(win[0][tsField]) || 0, last: t }
      }
      i++
    }
    if (open) findings.push(makeBurst(open))
    if (findings.length >= maxFindings) break
  }

  function makeBurst(b: { rows: Row[]; start: number; last: number }) {
    const first = b.rows[0]
    const ent = entitiesOf(first, entityFields)
    if (rule.distinct) ent[rule.distinct] = Array.from(new Set(b.rows.map((r) => str(getPath(r, rule.distinct!))).filter(Boolean))).slice(0, 8).join(', ')
    return { ...base(), ...escalationFor(b.rows), key: `${rule.id}|${groupKey(first, groupBy)}|${Math.floor(b.start / 60000)}`, ts: b.start, tsEnd: b.last, entities: ent, count: b.rows.length }
  }

  // follow-up ("then"): escalate when a matching event follows within `within`
  if (rule.then?.where && opts.thenRows) {
    const within = parseDuration(rule.then.within) ?? 0
    const thenPred = compileCond(rule.then.where, settings)
    const candidates = opts.thenRows(rule.then.where).filter(thenPred)
    const join = rule.then.join ?? groupBy
    for (const f of findings) {
      const end = f.tsEnd ?? f.ts ?? 0
      const hit = candidates.find((r) => {
        const t = Number(r[tsField]) || 0
        if (t < (f.ts ?? 0) || t > end + within) return false
        return join.every((j) => {
          const [a, b] = j.includes('=') ? j.split('=') : [j, j]
          const want = f.entities[a] ?? ''
          return want !== '' && str(getPath(r, b)).toLowerCase() === want.toLowerCase()
        })
      })
      if (hit) {
        f.severity = maxSeverity(f.severity, rule.then.severity)
        f.escalation = rule.then.title || 'follow-up matched'
        if (rule.then.title) f.title = `${rule.title} → ${rule.then.title}`
        f.refs = [...f.refs, idOf(hit)]
        f.tsEnd = Math.max(end, Number(hit[tsField]) || 0)
      }
    }
  }
  emitZeroDiag()
  return findings
}

/** Collect the eventIds a rule's `where` pins down (for Dexie index pre-selection). */
export function ruleEventIds(cond: RuleCond | undefined): number[] | null {
  if (!cond) return null
  const direct: number[] = []
  for (const [key, value] of Object.entries(cond)) {
    if (key === 'eventId' || key === 'eventId|eq' || key === 'eventId|in') {
      for (const v of Array.isArray(value) ? value : [value]) {
        const n = Number(v)
        if (Number.isFinite(n)) direct.push(n)
      }
    }
  }
  if (direct.length) return Array.from(new Set(direct))
  // any_of where every alternative pins eventIds
  for (const [key, value] of Object.entries(cond)) {
    if (/^any_of(_\d+)?$/.test(key) && Array.isArray(value)) {
      const all: number[] = []
      for (const alt of value) {
        const ids = ruleEventIds(alt as RuleCond)
        if (!ids) return null
        all.push(...ids)
      }
      if (all.length) return Array.from(new Set(all))
    }
  }
  // all_of: every member must hold, so any member that pins ids bounds the rule (intersect when several do)
  for (const [key, value] of Object.entries(cond)) {
    if (/^all_of(_\d+)?$/.test(key) && Array.isArray(value)) {
      const pinned = value.map((m) => ruleEventIds(m as RuleCond)).filter((ids): ids is number[] => !!ids && ids.length > 0)
      if (pinned.length) {
        const inter = pinned[0].filter((id) => pinned.every((set) => set.includes(id)))
        return inter.length ? inter : pinned[0]
      }
    }
  }
  return null
}

/** Fields a rule reads (to decide whether mail bodies must be joined). */
export function ruleFields(cond: RuleCond | undefined, acc: Set<string> = new Set()): Set<string> {
  if (!cond) return acc
  for (const [key, value] of Object.entries(cond)) {
    if (/^(any_of|all_of)(_\d+)?$/.test(key)) {
      for (const alt of Array.isArray(value) ? value : [value]) ruleFields(alt as RuleCond, acc)
    } else if (key === 'not') ruleFields(value as RuleCond, acc)
    else acc.add(key.split('|')[0])
  }
  return acc
}

export function validateRule(r: unknown): { ok: true; rule: Rule } | { ok: false; error: string } {
  if (!r || typeof r !== 'object') return { ok: false, error: 'rule must be a mapping' }
  const rule = r as Rule
  if (!rule.id || typeof rule.id !== 'string') return { ok: false, error: 'missing id' }
  if (!rule.title) return { ok: false, error: `${rule.id}: missing title` }
  if (!SEVERITIES.includes(rule.severity)) return { ok: false, error: `${rule.id}: severity must be one of ${SEVERITIES.join(', ')}` }
  if (rule.source !== 'events' && rule.source !== 'mails') return { ok: false, error: `${rule.id}: source must be events or mails` }
  try {
    compileCond(rule.where)
    if (rule.exclude) compileCond(rule.exclude)
    if (rule.then?.where) compileCond(rule.then.where)
    if (rule.any_in_group) compileCond(rule.any_in_group)
  } catch (e) {
    return { ok: false, error: `${rule.id}: ${(e as Error).message}` }
  }
  if (rule.threshold != null && !parseThreshold(rule.threshold)) return { ok: false, error: `${rule.id}: invalid threshold` }
  if (rule.window && !parseDuration(rule.window)) return { ok: false, error: `${rule.id}: invalid window` }
  // regex sanity
  const walk = (c: RuleCond | undefined) => {
    if (!c) return
    for (const [k, v] of Object.entries(c)) {
      if (/^(any_of|all_of)(_\d+)?$/.test(k)) for (const alt of Array.isArray(v) ? v : [v]) walk(alt as RuleCond)
      else if (k === 'not') walk(v as RuleCond)
      else if (k.endsWith('|re') || k.endsWith('|not_re')) for (const p of Array.isArray(v) ? v : [v]) if (!compileRegex(String(p))) throw new Error(`${rule.id}: invalid regex ${p}`)
    }
  }
  try {
    walk(rule.where)
    walk(rule.exclude)
  } catch (e) {
    return { ok: false, error: (e as Error).message }
  }
  return { ok: true, rule }
}
