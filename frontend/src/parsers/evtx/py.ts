/**
 * The few Python behaviours the server's EVTX flattening relies on, reproduced so the rows the
 * browser makes are the rows the server makes, value for value: str(), str.strip(), len() and
 * slicing by code point, int(), truthiness, and json.dumps with ensure_ascii=False.
 */

/** An integer past 2^53, kept as its digits: JavaScript numbers would silently change it. */
export class BigInteger {
  constructor(readonly digits: string) {}
  toString(): string {
    return this.digits
  }
}

/** JSON.parse that keeps the decoder's `{"$big":"<digits>"}` integers exact. */
export function parseDecoded(text: string): unknown {
  return JSON.parse(text, (_k, v) => {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      const keys = Object.keys(v)
      if (keys.length === 1 && keys[0] === '$big' && typeof v.$big === 'string') return new BigInteger(v.$big)
    }
    return v
  })
}

export type Json = null | boolean | number | string | BigInteger | Json[] | { [k: string]: Json }

export function isDict(v: unknown): v is Record<string, Json> {
  return v !== null && typeof v === 'object' && !Array.isArray(v) && !(v instanceof BigInteger)
}

/** Python truthiness for the values JSON can hold. */
export function truthy(v: unknown): boolean {
  if (v === null || v === undefined || v === false || v === 0 || v === '') return false
  if (Array.isArray(v)) return v.length > 0
  if (isDict(v)) return Object.keys(v).length > 0
  return true
}

/** Python's `a or b`. */
export function or<T, U>(a: T, b: U): T | U {
  return truthy(a) ? a : b
}

// the characters str.isspace() accepts, which str.strip() removes
const WS = '\\t\\n\\x0b\\x0c\\r\\x1c-\\x1f \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000'
const STRIP = new RegExp(`^[${WS}]+|[${WS}]+$`, 'g')

export function strip(s: string): string {
  return s.replace(STRIP, '')
}

/** len() counts code points, JavaScript counts UTF-16 units. */
export function pyLen(s: string): number {
  let n = s.length
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1)
      if (d >= 0xdc00 && d <= 0xdfff) {
        n--
        i++
      }
    }
  }
  return n
}

/** s[:n] by code point. */
export function pySlice(s: string, n: number): string {
  if (s.length <= n) return s
  let units = 0
  for (let cp = 0; cp < n && units < s.length; cp++) {
    const c = s.charCodeAt(units)
    const pair = c >= 0xd800 && c <= 0xdbff && units + 1 < s.length && (s.charCodeAt(units + 1) & 0xfc00) === 0xdc00
    units += pair ? 2 : 1
  }
  return s.slice(0, units)
}

/** json.dumps(value, ensure_ascii=False, separators=(",", ":")), with sort_keys when asked. */
export function dumps(value: unknown, sortKeys = false): string {
  if (value === null || value === undefined) return 'null'
  if (value instanceof BigInteger) return value.digits
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : value !== value ? 'NaN' : value > 0 ? 'Infinity' : '-Infinity'
  if (typeof value === 'string') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map((v) => dumps(v, sortKeys)).join(',') + ']'
  if (typeof value === 'object') {
    const keys = Object.keys(value)
    if (sortKeys) keys.sort(comparePy)
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + dumps((value as Record<string, unknown>)[k], sortKeys)).join(',') + '}'
  }
  return JSON.stringify(String(value))
}

/** Python orders strings by code point, JavaScript's < by UTF-16 unit. */
function comparePy(a: string, b: string): number {
  if (a === b) return 0
  const x = Array.from(a)
  const y = Array.from(b)
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    if (x[i] !== y[i]) return x[i].codePointAt(0)! - y[i].codePointAt(0)!
  }
  return x.length - y.length
}

/** str(value) for the values JSON holds. */
export function pyStr(value: unknown): string {
  if (value === null || value === undefined) return 'None'
  if (value === true) return 'True'
  if (value === false) return 'False'
  if (typeof value === 'string') return value
  if (typeof value === 'number' || value instanceof BigInteger) return String(value)
  return reprish(value)
}

// str() of a dict or list: repr of its items, as Python writes them
function reprish(value: unknown): string {
  if (value === null || value === undefined) return 'None'
  if (value === true) return 'True'
  if (value === false) return 'False'
  if (typeof value === 'number' || value instanceof BigInteger) return String(value)
  if (typeof value === 'string') return pyRepr(value)
  if (Array.isArray(value)) return '[' + value.map(reprish).join(', ') + ']'
  if (typeof value === 'object')
    return (
      '{' +
      Object.entries(value as Record<string, unknown>)
        .map(([k, v]) => `${pyRepr(k)}: ${reprish(v)}`)
        .join(', ') +
      '}'
    )
  return String(value)
}

function pyRepr(s: string): string {
  const quote = s.includes("'") && !s.includes('"') ? '"' : "'"
  let out = quote
  for (const ch of s) {
    const c = ch.codePointAt(0)!
    if (ch === '\\') out += '\\\\'
    else if (ch === quote) out += '\\' + quote
    else if (ch === '\n') out += '\\n'
    else if (ch === '\r') out += '\\r'
    else if (ch === '\t') out += '\\t'
    else if (c < 0x20 || c === 0x7f) out += '\\x' + c.toString(16).padStart(2, '0')
    else out += ch
  }
  return out + quote
}

/** An integer as Python's int() reads it, or null where int() raises. */
export type PyInt = number | BigInteger

function fromBig(b: bigint): PyInt {
  return b <= BigInt(Number.MAX_SAFE_INTEGER) && b >= -BigInt(Number.MAX_SAFE_INTEGER) ? Number(b) : new BigInteger(b.toString())
}

export function pyInt(s: string, base: 10 | 16): PyInt | null {
  const t = strip(s)
  if (base === 16) {
    const m = /^([+-]?)(?:0[xX])?_?([0-9a-fA-F]+(?:_[0-9a-fA-F]+)*)$/.exec(t)
    if (!m) return null
    const b = BigInt('0x' + m[2].replace(/_/g, ''))
    return fromBig(m[1] === '-' ? -b : b)
  }
  const m = /^([+-]?)([0-9]+(?:_[0-9]+)*)$/.exec(t)
  if (!m) return null
  const digits = m[2].replace(/_/g, '')
  // int() refuses a leading zero only in literals; int("007") is 7
  const b = BigInt(digits)
  return fromBig(m[1] === '-' ? -b : b)
}

/** Python equality between a JSON value and a string or null, for `v in (None, "-", ...)`. */
export function inValues(v: unknown, values: readonly (string | null)[]): boolean {
  return values.some((x) => (x === null ? v === null || v === undefined : v === x))
}
