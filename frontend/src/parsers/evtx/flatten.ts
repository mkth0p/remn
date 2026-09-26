/**
 * EVTX records to rows, ported from the server (backend/services/parsers/evtx_parser.py `flatten`,
 * backend/services/reference/eventids.py, and the timestamp and address helpers of
 * backend/services/common.py). The event arrives as the JSON pyevtx-rs gives the server, from the
 * same Rust decoder compiled to WebAssembly, and leaves as the same row: the golden corpus pins
 * both to the same digests (parity.test.ts).
 */
import { ACCESS_NAMES, EVENTS, FIELD_MAP, GROUP_EVENTS, INT_FIELDS, KERBEROS_FAILURES, LEVELS, LOGON_TYPES, LONG_FIELDS, LONG_LIMIT, STATUS_CODES, TICKET_ENCRYPTION } from './reference.gen'
import { BigInteger, dumps, inValues, isDict, or, pyInt, pyLen, pySlice, pyStr, strip, truthy, type Json, type PyInt } from './py'

export type Row = Record<string, unknown>

// ---------------------------------------------------------------------------
// services.common
// ---------------------------------------------------------------------------
const ISO_RE = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:[.,](\d+))?\s*(Z|UTC|[+-]\d{2}:?\d{2})?$/

/**
 * (epoch ms, ISO UTC) for the ISO times an event log holds, as parse_timestamp gives them. The
 * server's fallbacks for RFC 2822 dates and other ISO spellings are not needed by EVTX, whose
 * times are always written this way, and are not ported.
 */
export function parseTimestamp(value: unknown): [number | null, string | null] {
  if (value === null || value === undefined || value === '') return [null, null]
  const s = strip(pyStr(value))
  const m = ISO_RE.exec(s)
  if (!m) return [null, null]
  const [, date, time, fracRaw, tz] = m
  const frac = (fracRaw ?? '0').slice(0, 6).padEnd(6, '0')
  const [y, mo, d] = date.split('-').map(Number)
  const [h, mi, se] = time.split(':').map(Number)
  const micro = Number(frac)
  // datetime() refuses what does not exist: month 13, 30 February, hour 24, second 60
  if (y < 1 || mo < 1 || mo > 12 || d < 1 || d > daysIn(y, mo) || h > 23 || mi > 59 || se > 59) return [null, null]
  let offsetMin = 0
  if (tz && tz !== 'Z' && tz !== 'UTC') {
    const sign = tz[0] === '+' ? 1 : -1
    const hh = Number(tz.slice(1, 3))
    const mm = Number(tz.slice(-2))
    offsetMin = sign * (hh * 60 + mm)
    // timezone() takes an offset under 24 hours; past it the server's row fails, and so does this one
    if (Math.abs(offsetMin) >= 24 * 60) throw new Error('offset must be a timedelta strictly between -timedelta(hours=24) and timedelta(hours=24)')
  }
  // exact integer microseconds since the epoch, divided and scaled as Python's timestamp() does
  const days = daysFromCivil(y, mo, d)
  const secs = days * 86400 + h * 3600 + mi * 60 + se - offsetMin * 60
  const totalMicros = secs * 1_000_000 + micro
  const ms = Math.trunc((totalMicros / 1e6) * 1000)
  // isoformat(timespec="milliseconds") of the UTC time: microseconds cut, not rounded
  const utcSecs = Math.floor(totalMicros / 1_000_000)
  const utcDays = Math.floor(utcSecs / 86400)
  const rem = utcSecs - utcDays * 86400
  const [uy, um, ud] = civilFromDays(utcDays)
  if (uy < 1 || uy > 9999) return [null, null]
  const msPart = Math.floor((totalMicros - utcSecs * 1_000_000) / 1000)
  const iso = `${String(uy).padStart(4, '0')}-${p2(um)}-${p2(ud)}T${p2(Math.floor(rem / 3600))}:${p2(Math.floor((rem % 3600) / 60))}:${p2(rem % 60)}.${String(msPart).padStart(3, '0')}Z`
  return [ms, iso]
}

const p2 = (n: number) => String(n).padStart(2, '0')

function daysIn(y: number, m: number): number {
  if (m === 2) return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0 ? 29 : 28
  return [4, 6, 9, 11].includes(m) ? 30 : 31
}

// Howard Hinnant's days-from-civil: proleptic Gregorian, valid for every year datetime accepts
function daysFromCivil(y: number, m: number, d: number): number {
  y -= m <= 2 ? 1 : 0
  const era = Math.floor(y / 400)
  const yoe = y - era * 400
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy
  return era * 146097 + doe - 719468
}

function civilFromDays(z: number): [number, number, number] {
  z += 719468
  const era = Math.floor(z / 146097)
  const doe = z - era * 146097
  const yoe = Math.floor((doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146096)) / 365)
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100))
  const mp = Math.floor((5 * doy + 2) / 153)
  const d = doy - Math.floor((153 * mp + 2) / 5) + 1
  const m = mp + (mp < 10 ? 3 : -9)
  return [yoe + era * 400 + (m <= 2 ? 1 : 0), m, d]
}

function ipv4(s: string): boolean {
  const parts = s.split('.')
  if (parts.length !== 4) return false
  return parts.every((p) => /^[0-9]{1,3}$/.test(p) && !(p.length > 1 && p[0] === '0') && Number(p) <= 255)
}

// ipaddress.IPv6Address's reading, scope id included
function ipv6(s: string): boolean {
  const pct = s.indexOf('%')
  if (pct >= 0) {
    const scope = s.slice(pct + 1)
    if (!scope || scope.includes('%')) return false
    s = s.slice(0, pct)
  }
  if (!s) return false
  let parts = s.split(':')
  if (parts.length < 3) return false
  if (parts[parts.length - 1].includes('.')) {
    if (!ipv4(parts[parts.length - 1])) return false
    parts = [...parts.slice(0, -1), 'ffff', 'ffff']
  }
  if (parts.length > 9) return false
  let skip: number | null = null
  for (let i = 1; i < parts.length - 1; i++) {
    if (!parts[i]) {
      if (skip !== null) return false
      skip = i
    }
  }
  if (skip !== null) {
    let hi = skip
    let lo = parts.length - skip - 1
    if (!parts[0]) {
      hi -= 1
      if (hi) return false
    }
    if (!parts[parts.length - 1]) {
      lo -= 1
      if (lo) return false
    }
    if (8 - (hi + lo) < 1) return false
  } else {
    if (parts.length !== 8) return false
    if (!parts[0] || !parts[parts.length - 1]) return false
  }
  return parts.every((p, i) => (skip !== null && !p && (i === skip || (i === 0 && skip === 1) || (i === parts.length - 1 && skip === parts.length - 2)) ? true : /^[0-9a-fA-F]{1,4}$/.test(p)))
}

export function normalizeIp(value: unknown): string | null {
  if (value === null || value === undefined) return null
  let s = strip(pyStr(value))
  if (!s || s === '-' || s === '::' || s === '::0' || s === '0.0.0.0') return null
  if (s.toLowerCase().startsWith('::ffff:')) s = s.slice(7)
  if (s === '::1') s = '127.0.0.1'
  return ipv4(s) || ipv6(s) ? s : null
}

// ---------------------------------------------------------------------------
// services.reference.eventids
// ---------------------------------------------------------------------------
export function describe(provider: string | null | undefined, eventId: PyInt | null): [string, string] | null {
  if (eventId === null || eventId instanceof BigInteger) return null
  const prov = (provider ?? '').toLowerCase()
  let best: [string, string] | null = null
  let bestLen = -1
  for (const [frag, eid, desc, cat] of EVENTS) {
    if (eid !== eventId) continue
    const f = frag.toLowerCase()
    if (f && !prov.includes(f)) continue
    if (f.length > bestLen) {
      best = [desc, cat]
      bestLen = f.length
    }
  }
  return best
}

function description(provider: string | null | undefined, eventId: PyInt | null): string | null {
  return describe(provider, eventId)?.[0] ?? null
}

export function logonTypeName(value: unknown): string | null {
  const n = typeof value === 'number' ? value : typeof value === 'string' ? pyInt(value, 10) : null
  return typeof n === 'number' ? (LOGON_TYPES[n] ?? null) : null
}

function hexNorm(code: unknown): string | null {
  if (code === null || code === undefined) return null
  let s = strip(pyStr(code)).toLowerCase()
  if (!s) return null
  if (s.startsWith('0x')) {
    const n = pyInt(s, 16)
    if (n !== null) s = '0x' + BigInt(String(n)).toString(16)
  }
  return s
}

const lookup = (table: Record<string, string>, code: unknown): string | null => {
  const s = hexNorm(code)
  return s ? (Object.hasOwn(table, s) ? table[s] : null) : null
}
export const statusText = (code: unknown) => lookup(STATUS_CODES, code)
export const kerberosFailureText = (code: unknown) => lookup(KERBEROS_FAILURES, code)
export const ticketEncryptionName = (code: unknown) => lookup(TICKET_ENCRYPTION, code)

function user(ev: Row, prefix: string): string | null {
  const name = ev[`${prefix}User`]
  if (!truthy(name) || name === '-') return null
  const dom = ev[`${prefix}Domain`]
  if (truthy(dom) && dom !== '-') return `${pyStr(dom)}\\${pyStr(name)}`
  return pyStr(name)
}

// f"{x}" of a row value
const f = (v: unknown) => pyStr(v)
// f"{x or ''}"
const fo = (v: unknown) => (truthy(v) ? pyStr(v) : '')

/** One-line human summary built from the flattened event fields (eventids.summarize). */
export function summarize(ev: Row): string {
  const eid = ev.eventId as PyInt | null
  const prov = (ev.provider as string | null) || ''
  const provL = prov.toLowerCase()
  const desc = description(prov, eid) || ''
  const parts: string[] = []
  const tgt = user(ev, 'target')
  const sub = user(ev, 'subject')
  const ip = ev.ipAddress
  const ws = ev.workstation
  const lt = ev.logonType
  const ltn = lt !== null && lt !== undefined ? logonTypeName(lt) : null
  const isSecurity = provL.includes('security-auditing')
  const isSysmon = provL.includes('sysmon')
  const has = (k: string) => truthy(ev[k])
  const one = (...ids: number[]) => typeof eid === 'number' && ids.includes(eid)

  if (isSecurity && one(4624)) {
    parts.push(strip(`Logon ${fo(or(ltn, or(lt, '')))}`))
    if (tgt) parts.push(`as ${tgt}`)
    if (truthy(ip)) parts.push(`from ${f(ip)}`)
    else if (truthy(ws)) parts.push(`from ${f(ws)}`)
    if (has('authPackage')) parts.push(`(${f(ev.authPackage)})`)
  } else if (isSecurity && one(4625)) {
    parts.push(strip(`Failed logon ${fo(or(ltn, or(lt, '')))}`))
    if (tgt) parts.push(`as ${tgt}`)
    if (truthy(ip)) parts.push(`from ${f(ip)}`)
    else if (truthy(ws)) parts.push(`from ${f(ws)}`)
    const reason = statusText(ev.subStatus) || statusText(ev.status)
    if (reason) parts.push(`- ${reason}`)
  } else if (isSecurity && one(4634, 4647)) {
    parts.push('Logoff')
    if (tgt) parts.push(tgt)
  } else if (isSecurity && one(4648)) {
    parts.push('Explicit credentials')
    if (sub) parts.push(`by ${sub}`)
    if (tgt) parts.push(`as ${tgt}`)
    if (has('targetServer')) parts.push(`to ${f(ev.targetServer)}`)
    if (has('processName')) parts.push(`via ${f(ev.processName)}`)
  } else if (isSecurity && one(4672)) {
    parts.push('Special privileges')
    if (sub) parts.push(`for ${sub}`)
  } else if (isSecurity && one(4688)) {
    parts.push('Process')
    parts.push(has('processName') ? f(ev.processName) : '?')
    if (has('commandLine')) parts.push(`- ${f(ev.commandLine)}`)
    if (sub) parts.push(`by ${sub}`)
  } else if (one(4697, 7045) && (isSecurity || provL.includes('service control'))) {
    parts.push('Service installed')
    if (has('serviceName')) parts.push(f(ev.serviceName))
    if (has('serviceFile')) parts.push(`-> ${f(ev.serviceFile)}`)
  } else if ((isSecurity && one(4698, 4699, 4700, 4701, 4702)) || (provL.includes('taskscheduler') && one(106, 140, 141))) {
    parts.push(desc)
    if (has('taskName')) parts.push(f(ev.taskName))
    if (sub) parts.push(`by ${sub}`)
  } else if (isSecurity && one(4720, 4722, 4725, 4726, 4738, 4740, 4767, 4781)) {
    parts.push(desc)
    if (tgt) parts.push(tgt)
    if (sub) parts.push(`by ${sub}`)
  } else if (isSecurity && one(4728, 4729, 4732, 4733, 4756, 4757)) {
    parts.push(desc)
    if (has('memberName')) parts.push(f(ev.memberName))
    if (has('groupName')) parts.push(`-> ${f(ev.groupName)}`)
    if (sub) parts.push(`by ${sub}`)
  } else if (isSecurity && one(4768, 4769, 4770, 4771, 4772, 4773)) {
    parts.push(desc)
    if (tgt) parts.push(tgt)
    if (has('serviceName')) parts.push(`svc ${f(ev.serviceName)}`)
    if (truthy(ip)) parts.push(`from ${f(ip)}`)
    const enc = ticketEncryptionName(ev.ticketEncryption)
    if (enc) parts.push(`[${enc}]`)
    const fail = kerberosFailureText(ev.status)
    if (fail) parts.push(`- ${fail}`)
  } else if (isSecurity && one(4776)) {
    parts.push('NTLM validation')
    if (tgt) parts.push(tgt)
    if (truthy(ws)) parts.push(`from ${f(ws)}`)
    const reason = statusText(ev.status)
    if (reason) parts.push(`- ${reason}`)
  } else if (isSecurity && one(5140, 5145)) {
    parts.push('Share access')
    if (has('shareName')) parts.push(f(ev.shareName))
    if (has('relativeTargetName')) parts.push(`/ ${f(ev.relativeTargetName)}`)
    if (sub) parts.push(`by ${sub}`)
    if (truthy(ip)) parts.push(`from ${f(ip)}`)
  } else if ((isSecurity && one(1102)) || (provL.includes('eventlog') && one(104))) {
    parts.push(desc)
    if (sub) parts.push(`by ${sub}`)
    if (has('channelCleared')) parts.push(`(${f(ev.channelCleared)})`)
  } else if (provL.includes('powershell') && one(4104)) {
    parts.push('Script block')
    const txt = has('scriptBlockText') ? f(ev.scriptBlockText) : ''
    parts.push(pySlice(txt, 160).replaceAll('\n', ' '))
  } else if (provL.includes('terminalservices') && one(21, 22, 23, 24, 25, 39, 40, 41, 1149)) {
    parts.push(desc)
    if (has('targetUser')) parts.push(f(ev.targetUser))
    if (truthy(ip)) parts.push(`from ${f(ip)}`)
  } else if (provL.includes('defender') && one(1116, 1006)) {
    parts.push('Malware detected')
    if (has('threatName')) parts.push(f(ev.threatName))
    if (has('path')) parts.push(`at ${f(ev.path)}`)
  } else if (isSecurity && one(6416)) {
    parts.push('New device')
    if (has('deviceDescription')) parts.push(f(ev.deviceDescription))
  } else if (isSecurity && one(4616)) {
    parts.push('Time changed')
    if (has('previousTime') && has('newTime')) parts.push(`${f(ev.previousTime)} -> ${f(ev.newTime)}`)
  } else if (isSysmon) {
    parts.push(desc || `Sysmon ${f(eid)}`)
    if (one(1)) parts.push(fo(or(ev.commandLine, or(ev.image, ''))))
    else if (one(3)) parts.push(`${fo(ev.image)} -> ${fo(ev.destinationIp)}:${fo(ev.destinationPort)}`)
    else if (one(22)) parts.push(`${fo(ev.image)} ? ${fo(ev.query)}`)
    else if (one(7)) parts.push(fo(ev.imageLoaded))
    else if (one(11, 23, 26)) parts.push(fo(ev.targetFilename))
    else if (one(12, 13, 14)) parts.push(fo(ev.targetObject))
    else if (one(10)) parts.push(`${fo(ev.sourceImage)} -> ${fo(ev.targetImage)} (${fo(ev.grantedAccess)})`)
    else parts.push(fo(ev.image))
  } else {
    parts.push(desc || `Event ${f(eid)}`)
    if (tgt) parts.push(tgt)
    else if (sub) parts.push(sub)
  }
  return strip(parts.filter((p) => p).join(' '))
}

// ---------------------------------------------------------------------------
// services.parsers.evtx_parser
// ---------------------------------------------------------------------------
/** Collapse pyevtx-rs JSON structures ({'#text':..., '#attributes':...}) into scalars. */
export function scalar(value: Json | undefined): Json | undefined {
  if (isDict(value)) {
    if (Object.hasOwn(value, '#text')) return scalar(value['#text'])
    const attrs = value['#attributes']
    const rest = Object.keys(value).filter((k) => k !== '#attributes')
    if (!rest.length && truthy(attrs) && isDict(attrs)) return mapObject(Object.keys(attrs), (k) => scalar(attrs[k]) as Json)
    return mapObject(rest, (k) => scalar(value[k]) as Json)
  }
  if (Array.isArray(value)) return value.map((v) => scalar(v) as Json)
  return value
}

/** A plain object built key by key, safe for any key an event carries (even "__proto__"). */
function mapObject(keys: string[], fn: (k: string) => Json): Record<string, Json> {
  const out: Record<string, Json> = {}
  for (const k of keys) Object.defineProperty(out, k, { value: fn(k), enumerable: true, writable: true, configurable: true })
  return out
}

function setKey(obj: Record<string, unknown>, k: string, v: unknown): void {
  if (k === '__proto__') Object.defineProperty(obj, k, { value: v, enumerable: true, writable: true, configurable: true })
  else obj[k] = v
}

function get(obj: Json | undefined, key: string): Json | undefined {
  return isDict(obj) && Object.hasOwn(obj, key) ? obj[key] : undefined
}

export function str(value: unknown, limit = 4000): string | null {
  if (value === null || value === undefined) return null
  let s = Array.isArray(value) || isDict(value) ? dumps(value) : pyStr(value)
  s = strip(s)
  if (!s || s === '-') return null
  return pyLen(s) <= limit ? s : pySlice(s, limit) + '…'
}

export function toInt(value: unknown): PyInt | null {
  if (value === null || value === undefined || value === '') return null
  if (typeof value === 'boolean') return value ? 1 : 0
  if (typeof value === 'number') return Number.isInteger(value) ? value : null
  if (value instanceof BigInteger) return value
  if (typeof value !== 'string') return null
  const s = strip(value)
  return s.toLowerCase().startsWith('0x') ? pyInt(s, 16) : pyInt(s, 10)
}

/** '%%4416 %%4417' -> the codes, then a line with their names. */
export function renderAccessList(value: string | null): string | null {
  if (!value || !value.includes('%%')) return value
  const names = [...value.matchAll(/%%(\d+)/g)]
    .map((m) => m[1])
    .filter((c) => Object.hasOwn(ACCESS_NAMES, c))
    .map((c) => ACCESS_NAMES[c])
  return names.length ? `${value}\n${names.join(' ')}` : value
}

/** The record header's write time, without the zero FILETIME filtered exports write (header_time). */
export function headerTime(t: string | null | undefined): string | null {
  let value = t ?? null
  if (typeof value === 'string' && value.endsWith(' UTC')) value = value.slice(0, -4)
  if (typeof value === 'string' && value.startsWith('1601-01-01T00:00:00')) return null
  return value
}

const IP_KEYS = new Set(['ipAddress', 'sourceIp', 'destinationIp'])
const SERVICE_EVENTS = [7036, 7040, 7035, 7000, 7031, 7034, 7023, 7024]
const RDP_USER_EVENTS = [21, 22, 23, 24, 25, 39, 40]
const KERBEROS_EVENTS = [4768, 4769, 4771, 4772, 4773]

export interface RecordHeader {
  id: number | null
  t: string | null
}

/** One event (the decoder's JSON) to one row, as the server's flatten() makes it. */
// PowerShell module logging (4103) and pipeline execution details (800) log each command of a
// pipeline as CommandInvocation(name) followed by one ParameterBinding(name) line per parameter.
const PS_INVOCATION = /^CommandInvocation\(([^)]*)\): "/
const PS_ERROR = /^(?:Non)?TerminatingError\(/
const PS_BINDING = /^ParameterBinding\(([^)]*)\): name="([^"]*)"; value="(.*)$/s
// what the host adds to every interactive pipeline, not what the user ran
const PS_HOST_COMMANDS = new Set(['out-default', 'psconsolehostreadline'])

/** The commands a 4103 / 800 payload records, written back as PowerShell: Get-ADGroupMember -Identity 'Administrators'. */
export function psPipeline(payload: string): string | null {
  const commands: [string, [string, string][]][] = []
  let inValue = false // inside a parameter value that goes on over several lines
  for (const raw of payload.split('\n')) {
    const line = raw.replace(/\r+$/, '')
    const inv = PS_INVOCATION.exec(line)
    if (inv) {
      commands.push([inv[1], []])
      inValue = false
      continue
    }
    const bind = PS_BINDING.exec(line)
    const last = commands.length ? commands[commands.length - 1][1] : null
    if (bind && last) {
      const value = bind[3]
      inValue = !value.endsWith('"') // the closing quote ends the value
      last.push([bind[2], inValue ? value : value.slice(0, -1)])
    } else if (PS_ERROR.test(line)) {
      inValue = false
    } else if (inValue && last && last.length) {
      inValue = !line.endsWith('"')
      last[last.length - 1][1] += '\n' + (inValue ? line : line.slice(0, -1))
    }
  }
  const quote = (v: string) => "'" + v.replaceAll("'", "''") + "'"
  const parts: string[] = []
  for (const [name, bindings] of commands) {
    if (PS_HOST_COMMANDS.has(name.toLowerCase())) continue
    const words = [name]
    for (const [pname, value] of bindings) {
      if (pname && value === 'True') words.push(`-${pname}`)
      else if (pname) words.push(`-${pname} ${quote(value)}`)
      else words.push(quote(value))
    }
    parts.push(words.join(' '))
  }
  return parts.join(' | ') || null
}

/** The command a 4103 / 800 event records (as typed when 800 has it, else rebuilt), who ran it and from which script. */
function psCommand(row: Row, payload: string, context: string, typed: string | null): void {
  const fields = new Map<string, string>()
  for (const line of context.split('\n')) {
    const i = line.indexOf('=')
    if (i < 0) continue
    const name = strip(line.slice(0, i)).replaceAll(' ', '').toLowerCase()
    if (!fields.has(name)) fields.set(name, strip(line.slice(i + 1)))
  }
  const command = strip(typed || '') || psPipeline(payload)
  if (command && !truthy(row.commandLine)) row.commandLine = str(command, LONG_LIMIT)
  const user = fields.get('user') || fields.get('userid') || ''
  if (user && !truthy(row.subjectUser)) {
    const i = user.indexOf('\\')
    if (i >= 0) {
      row.subjectDomain = str(user.slice(0, i))
      row.subjectUser = str(user.slice(i + 1))
    } else row.subjectUser = str(user)
  }
  const script = fields.get('scriptname') || ''
  if (script && !truthy(row.path)) row.path = str(script)
}

export function flatten(event: Json, record: RecordHeader | null = null, includeRaw = true): Row {
  const ev = (isDict(event) && Object.hasOwn(event, 'Event') ? event.Event : event) as Json
  const system = (or(get(ev, 'System'), {}) as Json) ?? {}
  const provider = or(scalar(get(system, 'Provider')), {}) as Json
  let providerName: Json | undefined
  let providerGuid: Json | undefined
  if (isDict(provider)) {
    providerName = or(get(provider, 'Name'), get(provider, 'EventSourceName'))
    providerGuid = get(provider, 'Guid')
  } else {
    providerName = str(provider)
    providerGuid = null
  }
  const eventIdRaw = get(system, 'EventID')
  const eventId = toInt(scalar(eventIdRaw))
  let qualifiers: PyInt | null = null
  if (isDict(eventIdRaw)) qualifiers = toInt(get(or(get(eventIdRaw, '#attributes'), {}) as Json, 'Qualifiers'))
  const timeCreated = or(scalar(get(system, 'TimeCreated')), {}) as Json
  const systemTime = isDict(timeCreated) ? get(timeCreated, 'SystemTime') : timeCreated
  let [ts, tsIso] = parseTimestamp(systemTime)
  if (ts === null && record !== null) [ts, tsIso] = parseTimestamp(headerTime(record.t))
  const execution = or(scalar(get(system, 'Execution')), {}) as Json
  const security = or(scalar(get(system, 'Security')), {}) as Json
  const correlation = or(scalar(get(system, 'Correlation')), {}) as Json
  const level = toInt(scalar(get(system, 'Level')))

  const row: Row = {
    recordId: or(toInt(scalar(get(system, 'EventRecordID'))), record?.id ?? null),
    ts,
    tsIso,
    eventId,
    qualifiers,
    version: toInt(scalar(get(system, 'Version'))),
    level,
    levelName: typeof level === 'number' && Object.hasOwn(LEVELS, level) ? LEVELS[level] : level !== null ? String(level) : null,
    task: toInt(scalar(get(system, 'Task'))),
    opcode: toInt(scalar(get(system, 'Opcode'))),
    keywords: str(scalar(get(system, 'Keywords'))),
    provider: str(providerName, 200),
    providerGuid: str(providerGuid, 64),
    channel: str(scalar(get(system, 'Channel')), 200),
    computer: str(scalar(get(system, 'Computer')), 200),
    userSid: str(isDict(security) ? get(security, 'UserID') : security, 100),
    processId: isDict(execution) ? toInt(get(execution, 'ProcessID')) : null,
    threadId: isDict(execution) ? toInt(get(execution, 'ThreadID')) : null,
    activityId: str(isDict(correlation) ? get(correlation, 'ActivityID') : null, 64),
  }

  const data: Record<string, Json> = {}
  for (const section of ['EventData', 'UserData']) {
    let payload = get(ev, section)
    if (payload === null || payload === undefined) continue
    payload = scalar(payload)
    if (isDict(payload)) {
      // UserData wraps content in one named element (EventXML, LogFileCleared, ...)
      const keys = Object.keys(payload)
      if (section === 'UserData' && keys.length === 1 && isDict(payload[keys[0]])) {
        setKey(data, '_userDataType', keys[0])
        payload = payload[keys[0]] as Record<string, Json>
      }
      for (const k of Object.keys(payload)) {
        const v = payload[k]
        if (k === '#attributes') {
          if (isDict(v)) for (const ak of Object.keys(v)) setKey(data, `@${ak}`, scalar(v[ak]) as Json)
          continue
        }
        setKey(data, k, v)
      }
    } else if (Array.isArray(payload)) {
      data.Data = payload
    } else if (payload !== null && payload !== undefined) {
      data.Data = payload
    }
  }

  for (const k of Object.keys(data)) {
    if (!Object.hasOwn(FIELD_MAP, k)) continue
    const key = FIELD_MAP[k]
    const v = data[k]
    if (IP_KEYS.has(key)) {
      row[key] = or(normalizeIp(v), !inValues(v, [null, '-', '::', '0.0.0.0']) ? str(v, 100) : null)
      continue
    }
    if (INT_FIELDS.has(key)) {
      row[key] = toInt(v)
      continue
    }
    if (key === 'dataList') {
      if (Array.isArray(v)) {
        row.message = str(
          v
            .filter((x) => x !== null)
            .map((x) => pyStr(scalar(x)))
            .join('\n'),
          4000,
        )
      } else row.message = str(v, 4000)
      continue
    }
    if (Object.hasOwn(row, key) && !inValues(row[key], [null, ''])) continue // first mapping wins
    row[key] = str(v, LONG_FIELDS.has(key) ? LONG_LIMIT : 4000)
  }

  // Event-specific fix-ups
  if (truthy(row.accessList)) row.accessList = renderAccessList(row.accessList as string)
  const eid = typeof eventId === 'number' ? eventId : null
  if (eid !== null && GROUP_EVENTS.has(eid) && truthy(row.targetUser)) {
    row.groupName = row.targetUser
    row.groupDomain = row.targetDomain ?? null
  }
  const d = (k: string) => (Object.hasOwn(data, k) ? data[k] : undefined)
  if (eid === 1149 && truthy(d('Param1'))) {
    row.targetUser = str(d('Param1'))
    row.targetDomain = str(d('Param2'))
    row.ipAddress = or(normalizeIp(d('Param3')), str(d('Param3'), 100))
  }
  if (eid !== null && SERVICE_EVENTS.includes(eid) && truthy(d('param1'))) {
    row.serviceName = str(d('param1'))
    row.serviceState = str(d('param2'))
  }
  if (eid !== null && RDP_USER_EVENTS.includes(eid) && truthy(d('User')) && !truthy(row.targetUser)) row.targetUser = str(d('User'))
  const providerL = ((row.provider as string | null) || '').toLowerCase()
  const dataList = d('Data')
  if (eid === 4103 && providerL.includes('powershell') && truthy(d('Payload'))) {
    psCommand(row, pyStr(scalar(d('Payload'))), truthy(scalar(d('ContextInfo'))) ? pyStr(scalar(d('ContextInfo'))) : '', null)
  } else if (eid === 800 && row.channel === 'Windows PowerShell' && Array.isArray(dataList) && dataList.length >= 3) {
    const [typed, context, payload] = dataList.slice(0, 3).map((x) => (x === null || x === undefined ? '' : pyStr(scalar(x))))
    psCommand(row, payload, context, typed)
  }
  if (truthy(row.user) && !truthy(row.subjectUser) && ((row.provider as string | null) || '').toLowerCase().includes('sysmon')) {
    const u = row.user as string
    const i = u.indexOf('\\')
    if (i >= 0) {
      row.subjectDomain = u.slice(0, i)
      row.subjectUser = u.slice(i + 1)
    } else row.subjectUser = u
  }
  if ((row.logonType === null || row.logonType === undefined) && d('LogonType') !== null && d('LogonType') !== undefined) row.logonType = toInt(d('LogonType'))

  const desc = describe(row.provider as string | null, eventId)
  row.category = desc ? desc[1] : null
  row.description = desc ? desc[0] : null
  if (row.logonType !== null && row.logonType !== undefined) row.logonTypeName = logonTypeName(row.logonType)
  if (truthy(row.subStatus) || truthy(row.status)) {
    const reason = statusText(row.subStatus) || statusText(row.status)
    if (reason) row.statusText = reason
    else if (eid !== null && KERBEROS_EVENTS.includes(eid)) {
      const k = kerberosFailureText(row.status)
      if (k) row.statusText = k
    }
  }
  row.summary = summarize(row)
  row.data = mapObject(Object.keys(data), (k) => scalar(data[k]) as Json)
  if (includeRaw) row.raw = dumps(ev)
  return row
}
