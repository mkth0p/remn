/**
 * Filter DSL shared by the search UI, the AI tools and the rule engine.
 * Pure functions - no DOM, no Dexie - so it runs in workers and in tests.
 */
import { BUILTIN_LISTS } from '../reference/lists'

export type Op =
  | 'eq' | 'ne' | 'in' | 'nin' | 'contains' | 'not_contains' | 'contains_any' | 'contains_all'
  | 'startswith' | 'not_startswith' | 'endswith' | 'not_endswith' | 're' | 'not_re'
  | 'gt' | 'gte' | 'lt' | 'lte' | 'exists' | 'empty' | 'in_setting' | 'nin_setting' | 'levenshtein' | 'length'

export interface Condition {
  field: string
  op: Op
  value?: unknown
}

export interface Filter {
  conditions?: Condition[]
  logic?: 'and' | 'or'
  timeRange?: { from?: string | number | null; to?: string | number | null }
  hourRange?: { from: number; to: number; outside?: boolean; tz?: string }
  regex?: { field: string; pattern: string; flags?: string }
  text?: string
  sort?: { field: string; dir: 'asc' | 'desc' }
  limit?: number
}

export interface SettingsLike {
  internal_domains?: string[]
  expected_countries?: string[]
  expectedCountries?: string[]
  internalDomains?: string[]
  vip_names?: string[]
  vipNames?: string[]
  admin_accounts?: string[]
  adminAccounts?: string[]
  service_accounts?: string[]
  serviceAccounts?: string[]
  internal_ips?: string[]
  internalIps?: string[]
  brands?: string[]
  businessHours?: { start: number; end: number; tz: string }
  weekendDays?: number[]
  [k: string]: unknown
}

export type Row = Record<string, unknown>

/** A property of a row, plus the derived url fields the SQL engine also exposes (subdomain, fragment). */
function derived(obj: Row, key: string): unknown {
  const v = obj[key]
  if (v !== undefined) return v
  if (key === 'subdomain' && typeof obj.host === 'string' && typeof obj.domain === 'string') {
    const h = obj.host.toLowerCase()
    const d = obj.domain.toLowerCase()
    return d && h !== d && h.endsWith('.' + d) ? h.slice(0, h.length - d.length - 1) : null
  }
  if (key === 'fragment' && typeof obj.url === 'string') {
    const i = obj.url.indexOf('#')
    return i >= 0 ? obj.url.slice(i + 1) : null
  }
  return undefined
}

const camel = (s: string) => s.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase())

/** Resolve a dotted path; arrays are flattened (attachments.flags -> all flags of all attachments). */
export function getPath(row: unknown, path: string): unknown {
  if (row == null) return undefined
  if (!path.includes('.')) return derived(row as Row, path)
  const parts = path.split('.')
  let cur: unknown[] = [row]
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i]
    // flat dotted keys ("Role.DisplayName" inside data) take precedence over nesting
    const rest = parts.slice(i).join('.')
    const next: unknown[] = []
    for (const c of cur) {
      if (c == null) continue
      if (Array.isArray(c)) {
        for (const item of c) {
          if (item != null && typeof item === 'object') next.push(derived(item as Row, p))
        }
      } else if (typeof c === 'object') {
        if (i > 0 && rest !== p && Object.prototype.hasOwnProperty.call(c, rest)) {
          const flat = (c as Row)[rest]
          return Array.isArray(flat) && flat.length === 1 ? flat[0] : flat
        }
        next.push(derived(c as Row, p))
      }
    }
    cur = next.flatMap((v) => (Array.isArray(v) ? v : [v])).filter((v) => v !== undefined)
    if (!cur.length) return undefined
  }
  if (cur.length === 1) return cur[0]
  return cur
}

const norm = (v: unknown): string => (v == null ? '' : typeof v === 'object' ? JSON.stringify(v).toLowerCase() : String(v).toLowerCase())

/** Edit distance (insert / delete / substitute), used by the `levenshtein` operator. */
export function levenshtein(a: string, b: string): number {
  if (a === b) return 0
  if (!a.length) return b.length
  if (!b.length) return a.length
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i)
  for (let i = 1; i <= a.length; i++) {
    const cur = [i]
    for (let j = 1; j <= b.length; j++) cur.push(Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)))
    prev = cur
  }
  return prev[b.length]
}

function toArray(v: unknown): unknown[] {
  if (v === undefined || v === null) return []
  return Array.isArray(v) ? v : [v]
}

function numeric(v: unknown): number | null {
  if (typeof v === 'number') return v
  if (typeof v === 'string') {
    const s = v.trim()
    if (/^0x[0-9a-f]+$/i.test(s)) return parseInt(s, 16)
    const n = Number(s)
    return Number.isFinite(n) && s !== '' ? n : null
  }
  if (typeof v === 'boolean') return v ? 1 : 0
  return null
}

const regexCache = new Map<string, RegExp | null>()
export function compileRegex(pattern: string, flags = 'i'): RegExp | null {
  const key = flags + '/' + pattern
  if (regexCache.has(key)) return regexCache.get(key) ?? null
  let re: RegExp | null = null
  try {
    // Python-style inline flags (?i) -> JS flags
    let p = pattern
    let f = flags
    const m = /^\(\?([ims]+)\)/.exec(p)
    if (m) {
      p = p.slice(m[0].length)
      for (const c of m[1]) if (!f.includes(c)) f += c
    }
    re = new RegExp(p, f.replace(/[^gimsuy]/g, ''))
  } catch {
    re = null
  }
  if (regexCache.size > 500) regexCache.clear()
  regexCache.set(key, re)
  return re
}

// --- CIDR helpers ---------------------------------------------------------
function ipToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim())
  if (!m) return null
  const parts = m.slice(1).map(Number)
  if (parts.some((p) => p > 255)) return null
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
}
export function ipInCidr(ip: string, cidr: string): boolean {
  const c = cidr.trim().toLowerCase()
  const v = ip.trim().toLowerCase()
  if (!c) return false
  if (!c.includes('/')) return v === c
  const [net, bitsStr] = c.split('/')
  const bits = Number(bitsStr)
  if (net.includes(':')) {
    // IPv6: prefix comparison on the expanded hex form (good enough for fe80::/10, fc00::/7)
    const exp = (a: string) => {
      const parts = a.split('::')
      const head = parts[0] ? parts[0].split(':') : []
      const tail = parts[1] ? parts[1].split(':') : []
      const fill = 8 - head.length - tail.length
      return [...head, ...Array(Math.max(fill, 0)).fill('0'), ...tail].map((h) => h.padStart(4, '0')).join('')
    }
    if (!v.includes(':')) return false
    const a = parseInt(exp(v).slice(0, 4), 16)
    const b = parseInt(exp(net).slice(0, 4), 16)
    const mask = bits >= 16 ? 0xffff : (0xffff << (16 - bits)) & 0xffff
    return (a & mask) === (b & mask)
  }
  const ipN = ipToInt(v)
  const netN = ipToInt(net)
  if (ipN === null || netN === null || !Number.isFinite(bits)) return false
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0
  return ((ipN & mask) >>> 0) === ((netN & mask) >>> 0)
}

/** A case-settings list by snake or camel name, else a built-in reference list of that name (tranco_10k). */
export function settingList(settings: SettingsLike | undefined, name: string): string[] {
  const v = settings ? (settings[name] ?? settings[camel(name)]) : undefined
  if (Array.isArray(v) && v.length) return v.map((x) => String(x))
  const builtin = BUILTIN_LISTS[name] ?? BUILTIN_LISTS[camel(name)]
  return builtin ? builtin() : []
}

function normalizeNameLike(s: string): string {
  return s
    .normalize('NFKD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase()
    .replace(/<[^>]*>/g, ' ')
    .replace(/[^a-z0-9 ]+/g, ' ')
    .split(/\s+/)
    .filter(Boolean)
    .sort()
    .join(' ')
}

function inSetting(value: unknown, settings: SettingsLike | undefined, name: string): boolean {
  const list = settingList(settings, name)
  if (!list.length) return false
  const vals = toArray(value).map(norm).filter(Boolean)
  if (!vals.length) return false
  if (name === 'internal_ips' || name === 'internalIps') {
    return vals.some((v) => list.some((c) => ipInCidr(v, c)))
  }
  if (name === 'vip_names' || name === 'vipNames' || name === 'org_display_names' || name === 'orgDisplayNames') {
    const set = new Set(list.map(normalizeNameLike))
    return vals.some((v) => set.has(normalizeNameLike(v)))
  }
  if (name === 'internal_domains' || name === 'internalDomains' || name === 'trusted_senders' || name === 'trustedSenders') {
    const doms = list.map((d) => d.toLowerCase().replace(/^@/, '').trim())
    return vals.some((v) => doms.some((d) => v === d || v.endsWith('.' + d)))
  }
  const set = new Set(list.map((x) => x.toLowerCase().trim()))
  return vals.some((v) => set.has(v))
}

/** Evaluate one condition against a row. Strings compare case-insensitively. */
export function matchCondition(row: Row, c: Condition, settings?: SettingsLike): boolean {
  const actual = getPath(row, c.field)
  const op = c.op
  let wanted = c.value
  // LLM-built filters often pass "a,b,c" instead of ["a","b","c"] for list operators
  if (typeof wanted === 'string' && wanted.includes(',') && (op === 'in' || op === 'nin' || op === 'contains_any' || op === 'contains_all')) {
    wanted = wanted.split(',').map((s) => s.trim()).filter(Boolean)
  }
  const actArr = toArray(actual)
  const actStr = actArr.map(norm)
  const wantArr = toArray(wanted)
  const wantStr = wantArr.map(norm)
  switch (op) {
    case 'exists':
      return wanted === false ? actual == null || actual === '' : actual != null && actual !== '' && !(Array.isArray(actual) && !actual.length)
    case 'empty':
      return actual == null || actual === '' || (Array.isArray(actual) && !actual.length)
    case 'eq':
      if (actual == null) return wanted == null || wanted === ''
      if (wantArr.length > 1) return actStr.some((a) => wantStr.includes(a))
      if (typeof wanted === 'number' && typeof actual !== 'number') {
        const n = numeric(actual)
        return n !== null && n === wanted
      }
      return actStr.some((a) => a === norm(wanted))
    case 'ne':
      if (actual == null) return !(wanted == null || wanted === '')
      if (typeof wanted === 'number') {
        const n = numeric(actual)
        return n === null || n !== wanted
      }
      return !actStr.some((a) => wantStr.includes(a))
    case 'in':
      if (actual == null) return false
      return actStr.some((a) => wantStr.includes(a)) || actArr.some((a) => typeof a === 'number' && wantArr.includes(a))
    case 'nin':
      if (actual == null) return true
      return !actStr.some((a) => wantStr.includes(a)) && !actArr.some((a) => typeof a === 'number' && wantArr.includes(a))
    case 'contains':
    case 'contains_any':
      if (actual == null) return false
      if (Array.isArray(actual)) return actStr.some((a) => wantStr.some((w) => a === w || a.includes(w)))
      return wantStr.some((w) => actStr.some((a) => a.includes(w)))
    case 'contains_all':
      if (actual == null) return false
      return wantStr.every((w) => actStr.some((a) => a === w || a.includes(w)))
    case 'not_contains':
      if (actual == null) return true
      return !wantStr.some((w) => actStr.some((a) => a.includes(w)))
    case 'startswith':
      return actStr.some((a) => wantStr.some((w) => a.startsWith(w)))
    case 'not_startswith':
      return !actStr.some((a) => wantStr.some((w) => a.startsWith(w)))
    case 'endswith':
      return actStr.some((a) => wantStr.some((w) => a.endsWith(w)))
    case 'not_endswith':
      return !actStr.some((a) => wantStr.some((w) => a.endsWith(w)))
    case 'levenshtein': {
      // wanted = [needle, maxDistance]
      if (!Array.isArray(wanted) || wanted.length !== 2 || actual == null) return false
      const needle = norm(wanted[0])
      const max = numeric(wanted[1])
      if (max === null) return false
      return actStr.some((a) => levenshtein(a, needle) <= max)
    }
    case 'length': {
      // wanted = threshold string ("< 500", ">= 3") or a number (exact); characters of a text, items of a list
      if (actual == null) return false
      const m = /^\s*(>=|<=|==|=|!=|>|<)?\s*(\d+)\s*$/.exec(String(wanted))
      if (!m) return false
      const n = Number(m[2])
      const sym = m[1] || '='
      const len = Array.isArray(actual) ? actual.length : Array.from(typeof actual === 'string' ? actual : String(actual)).length
      return sym === '>' ? len > n : sym === '>=' ? len >= n : sym === '<' ? len < n : sym === '<=' ? len <= n : sym === '!=' ? len !== n : len === n
    }
    case 're':
    case 'not_re': {
      const patterns = wantArr.map((w) => compileRegex(String(w), 'i')).filter((r): r is RegExp => !!r)
      const hit = actArr.some((a) => {
        const s = a == null ? '' : typeof a === 'object' ? JSON.stringify(a) : String(a)
        return patterns.some((r) => r.test(s))
      })
      return op === 're' ? hit : !hit
    }
    case 'gt':
    case 'gte':
    case 'lt':
    case 'lte': {
      const w = numeric(wanted)
      if (w === null) return false
      return actArr.some((a) => {
        const n = numeric(a)
        if (n === null) return false
        return op === 'gt' ? n > w : op === 'gte' ? n >= w : op === 'lt' ? n < w : n <= w
      })
    }
    case 'in_setting':
      return inSetting(actual, settings, String(wanted))
    case 'nin_setting':
      return !inSetting(actual, settings, String(wanted))
    default:
      return false
  }
}

const TEXT_FIELDS_EVENTS = ['summary', 'targetUser', 'subjectUser', 'ipAddress', 'computer', 'commandLine', 'processName', 'serviceName', 'serviceFile', 'scriptBlockText', 'message', 'workstation', 'provider', 'channel', 'taskName', 'objectName', 'image', 'query', 'destinationIp', 'targetFilename', 'targetObject']
const TEXT_FIELDS_MAILS = ['subject', 'fromName', 'fromAddr', 'fromDomain', 'originIp', 'textPreview', 'messageId', 'folder', 'flags', 'returnPath']

export function toMs(v: string | number | null | undefined): number | null {
  if (v == null || v === '') return null
  if (typeof v === 'number') return v
  const n = Date.parse(v)
  return Number.isFinite(n) ? n : null
}

export function localHourAndDay(ts: number, tz: string): { hour: number; day: number } {
  try {
    const fmt = new Intl.DateTimeFormat('en-US', { timeZone: tz, hour: 'numeric', hour12: false, weekday: 'short' })
    const parts = fmt.formatToParts(new Date(ts))
    const hour = Number(parts.find((p) => p.type === 'hour')?.value ?? 0) % 24
    const wd = parts.find((p) => p.type === 'weekday')?.value ?? 'Mon'
    const day = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(wd)
    return { hour, day: day < 0 ? 1 : day }
  } catch {
    const d = new Date(ts)
    return { hour: d.getUTCHours(), day: d.getUTCDay() }
  }
}

export function isOutsideHours(hour: number, start: number, end: number): boolean {
  if (start === end) return false
  if (start < end) return hour < start || hour >= end
  return hour >= end && hour < start // overnight window (e.g. 22 -> 6)
}

export interface CompiledFilter {
  (row: Row): boolean
  tsField: string
  from: number | null
  to: number | null
}

/** Compile a Filter into a predicate. `tsField` is 'ts' for events and 'date' for mails. */
export function compileFilter(f: Filter | null | undefined, opts: { tsField?: string; settings?: SettingsLike; source?: 'events' | 'mails' } = {}): CompiledFilter {
  const tsField = opts.tsField ?? (opts.source === 'mails' ? 'date' : 'ts')
  const conds = (f?.conditions ?? []).filter((c) => c && c.field && c.op)
  const logic = f?.logic === 'or' ? 'or' : 'and'
  const from = toMs(f?.timeRange?.from)
  const to = toMs(f?.timeRange?.to)
  const regex = f?.regex?.pattern ? compileRegex(f.regex.pattern, f.regex.flags || 'i') : null
  const regexField = f?.regex?.field || ''
  const text = (f?.text || '').trim().toLowerCase()
  const textFields = opts.source === 'mails' ? TEXT_FIELDS_MAILS : TEXT_FIELDS_EVENTS
  const hr = f?.hourRange
  const tz = hr?.tz || opts.settings?.businessHours?.tz || 'UTC'
  const pred = ((row: Row): boolean => {
    if (from !== null || to !== null) {
      const t = row[tsField]
      if (typeof t !== 'number') return false
      if (from !== null && t < from) return false
      if (to !== null && t > to) return false
    }
    if (hr) {
      const t = row[tsField]
      if (typeof t !== 'number') return false
      const { hour } = localHourAndDay(t, tz)
      const outside = isOutsideHours(hour, hr.from, hr.to)
      if (hr.outside ? !outside : outside) return false
    }
    if (conds.length) {
      if (logic === 'and') {
        for (const c of conds) if (!matchCondition(row, c, opts.settings)) return false
      } else if (!conds.some((c) => matchCondition(row, c, opts.settings))) return false
    }
    if (regex) {
      if (regexField && regexField !== '*') {
        const v = getPath(row, regexField)
        const s = v == null ? '' : typeof v === 'object' ? JSON.stringify(v) : String(v)
        if (!regex.test(s)) return false
      } else {
        const raw = typeof row.raw === 'string' ? row.raw : JSON.stringify(row)
        if (!regex.test(raw)) return false
      }
    }
    if (text) {
      let hit = false
      for (const fld of textFields) {
        const v = row[fld]
        if (v == null) continue
        const s = Array.isArray(v) ? v.join(' ') : String(v)
        if (s.toLowerCase().includes(text)) {
          hit = true
          break
        }
      }
      if (!hit && typeof row.raw === 'string' && row.raw.toLowerCase().includes(text)) hit = true
      if (!hit && row.data && JSON.stringify(row.data).toLowerCase().includes(text)) hit = true
      if (!hit) return false
    }
    return true
  }) as CompiledFilter
  pred.tsField = tsField
  pred.from = from
  pred.to = to
  return pred
}

/** Extract the eventId values a filter/condition set pins down (for index pre-selection), or null. */
export function extractEventIds(conds: Condition[] | undefined, logic: 'and' | 'or' = 'and'): number[] | null {
  if (!conds?.length) return null
  const sets: number[][] = []
  for (const c of conds) {
    if (c.field !== 'eventId') continue
    if (c.op === 'eq' || c.op === 'in') {
      const ids = toArray(c.value).map(numeric).filter((n): n is number => n !== null)
      if (ids.length) sets.push(ids)
    }
  }
  if (!sets.length) return null
  if (logic === 'or') return sets.length === conds.length ? Array.from(new Set(sets.flat())) : null
  // AND: the intersection of all eventId sets (usually a single set)
  let res = new Set(sets[0])
  for (const s of sets.slice(1)) res = new Set(s.filter((x) => res.has(x)))
  return Array.from(res)
}

export function describeFilter(f: Filter | null | undefined): string {
  if (!f) return ''
  const parts: string[] = []
  for (const c of f.conditions ?? []) parts.push(`${c.field} ${c.op}${c.value !== undefined ? ' ' + JSON.stringify(c.value) : ''}`)
  if (f.timeRange?.from || f.timeRange?.to) parts.push(`time ${f.timeRange.from ?? '…'} → ${f.timeRange.to ?? '…'}`)
  if (f.hourRange) parts.push(`${f.hourRange.outside ? 'outside' : 'within'} ${f.hourRange.from}h-${f.hourRange.to}h`)
  if (f.regex?.pattern) parts.push(`/${f.regex.pattern}/${f.regex.flags ?? 'i'} on ${f.regex.field || '*'}`)
  if (f.text) parts.push(`"${f.text}"`)
  return parts.join(` ${f.logic === 'or' ? 'OR' : 'AND'} `)
}
