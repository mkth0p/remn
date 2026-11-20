import type { Severity } from '../db/schema'

let useLocalTime = false
export function setLocalTime(v: boolean): void {
  useLocalTime = v
}
export function getLocalTime(): boolean {
  return useLocalTime
}

const pad = (n: number, w = 2) => String(n).padStart(w, '0')

function formatTime(ms: number | null | undefined, local: boolean, opts: { ms?: boolean; date?: boolean }): string {
  if (ms == null || !Number.isFinite(ms)) return ''
  const d = new Date(ms)
  if (Number.isNaN(d.getTime())) return ''
  // a local time is the UTC time moved by the offset of the zone at that moment, and it says that
  // offset as a UTC time says Z: a time copied into a note or a message keeps its zone
  const offset = local ? -d.getTimezoneOffset() : 0
  const w = new Date(ms + offset * 60_000)
  let out = `${w.getUTCFullYear()}-${pad(w.getUTCMonth() + 1)}-${pad(w.getUTCDate())}`
  if (opts.date) return out
  out += ` ${pad(w.getUTCHours())}:${pad(w.getUTCMinutes())}:${pad(w.getUTCSeconds())}`
  if (opts.ms) out += `.${pad(w.getUTCMilliseconds(), 3)}`
  if (!local) return out + 'Z'
  const abs = Math.abs(offset)
  return `${out}${offset < 0 ? '-' : '+'}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`
}

/** The width of a table column of times: a local time is longer by its offset from UTC. */
export function timeColumnWidth(utc: number): number {
  return useLocalTime ? utc + 36 : utc
}

/** The zone the screen shows times in, for column headers: "UTC", or "local" when the analyst chose it. */
export function tzLabel(): string {
  return useLocalTime ? 'local' : 'UTC'
}

/** A time as the analyst chose to see it on screen: UTC by default, local time when set. */
export function fmtTs(ms: number | null | undefined, opts: { ms?: boolean; date?: boolean } = {}): string {
  return formatTime(ms, useLocalTime, opts)
}

/**
 * A time for what is printed or handed over: always UTC. The report says "Times are UTC", and a
 * report must read the same whoever prints it; the display setting printed Paris times under
 * that line.
 */
export function fmtUtc(ms: number | null | undefined, opts: { ms?: boolean; date?: boolean } = {}): string {
  return formatTime(ms, false, opts)
}

export function fmtBytes(n: number | null | undefined): string {
  if (n == null || !Number.isFinite(n)) return ''
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v < 10 ? v.toFixed(2) : v < 100 ? v.toFixed(1) : Math.round(v)} ${units[i]}`
}

export function fmtNum(n: number | null | undefined): string {
  if (n == null || !Number.isFinite(n)) return ''
  return n.toLocaleString('en-US')
}

export function fmtDuration(ms: number | null | undefined): string {
  if (ms == null || !Number.isFinite(ms)) return ''
  const s = Math.round(ms / 1000)
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ${s % 60}s`
  const h = Math.floor(m / 60)
  if (h < 48) return `${h}h ${m % 60}m`
  return `${Math.floor(h / 24)}d ${h % 24}h`
}

export function riskClass(r: number | null | undefined): string {
  const v = r ?? 0
  return v >= 80 ? 'r4' : v >= 60 ? 'r3' : v >= 40 ? 'r2' : v >= 20 ? 'r1' : 'r0'
}

export function severityOfRisk(r: number | null | undefined): Severity {
  const v = r ?? 0
  return v >= 85 ? 'critical' : v >= 65 ? 'high' : v >= 40 ? 'medium' : v >= 20 ? 'low' : 'info'
}

/**
 * The stored form of an indicator. Only a URL's scheme and host are case-insensitive: its path and
 * query name another resource when their case changes, so they keep it. Every other kind folds.
 */
export function iocValue(kind: string, value: string): string {
  const v = value.trim().slice(0, 2048)
  if (kind !== 'url') return v.toLowerCase()
  const m = /^((?:[a-z][a-z0-9+.-]*:)?\/\/)?([^/?#]*)(.*)$/is.exec(v)!
  // credentials before the host keep their case
  const at = m[2].lastIndexOf('@')
  return (m[1] ?? '').toLowerCase() + m[2].slice(0, at + 1) + m[2].slice(at + 1).toLowerCase() + m[3]
}

export function defang(s: string | null | undefined): string {
  if (!s) return ''
  return s
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/^ftp:\/\//i, 'fxp://')
    .replace(/(^[a-z]+:\/\/[^/?#]*)|(^[^/?#]*)/i, (m) => m.replace(/\./g, '[.]'))
}

export function truncate(s: string | null | undefined, n: number): string {
  if (!s) return ''
  return s.length > n ? s.slice(0, n - 1) + '…' : s
}

export function classNames(...xs: (string | false | null | undefined)[]): string {
  return xs.filter(Boolean).join(' ')
}

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] as string)
}

/** Minimal markdown -> HTML (headings, lists, code, bold, tables). Output is escaped first. */
export function renderMarkdown(md: string): string {
  const esc = escapeHtml(md)
  const lines = esc.split('\n')
  const out: string[] = []
  let inCode = false
  let inList: 'ul' | 'ol' | null = null
  let inTable = false
  const closeList = () => {
    if (inList) {
      out.push(`</${inList}>`)
      inList = null
    }
  }
  const closeTable = () => {
    if (inTable) {
      out.push('</table>')
      inTable = false
    }
  }
  const inline = (s: string) =>
    s
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
      .replace(/(^|[^*])\*([^*\n]+)\*/g, '$1<em>$2</em>')
  for (const raw of lines) {
    const line = raw.replace(/\r$/, '')
    if (line.startsWith('```')) {
      closeList()
      closeTable()
      out.push(inCode ? '</pre>' : '<pre>')
      inCode = !inCode
      continue
    }
    if (inCode) {
      out.push(line)
      continue
    }
    if (/^\|.*\|\s*$/.test(line)) {
      closeList()
      if (/^\|\s*:?-+/.test(line)) continue
      const cells = line
        .slice(1, -1)
        .split('|')
        .map((c) => c.trim())
      if (!inTable) {
        out.push('<table>')
        inTable = true
        out.push('<tr>' + cells.map((c) => `<th>${inline(c)}</th>`).join('') + '</tr>')
      } else out.push('<tr>' + cells.map((c) => `<td>${inline(c)}</td>`).join('') + '</tr>')
      continue
    }
    closeTable()
    const h = /^(#{1,3})\s+(.*)$/.exec(line)
    if (h) {
      closeList()
      out.push(`<h${h[1].length}>${inline(h[2])}</h${h[1].length}>`)
      continue
    }
    const ul = /^\s*[-*]\s+(.*)$/.exec(line)
    const ol = /^\s*\d+[.)]\s+(.*)$/.exec(line)
    if (ul || ol) {
      const kind = ul ? 'ul' : 'ol'
      if (inList !== kind) {
        closeList()
        out.push(`<${kind}>`)
        inList = kind
      }
      out.push(`<li>${inline((ul || ol)![1])}</li>`)
      continue
    }
    closeList()
    if (!line.trim()) continue
    out.push(`<p>${inline(line)}</p>`)
  }
  closeList()
  closeTable()
  if (inCode) out.push('</pre>')
  return out.join('\n')
}

export function highlightJson(value: unknown): string {
  const json = typeof value === 'string' ? value : JSON.stringify(value, null, 2)
  return escapeHtml(json).replace(/("(?:\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g, (m) => {
    let cls = 'n'
    if (m.startsWith('"')) cls = m.endsWith(':') ? 'k' : 's'
    else if (/true|false/.test(m)) cls = 'b'
    else if (m === 'null') cls = 'z'
    return `<span class="${cls}">${m}</span>`
  })
}

export function shortHash(h: string | null | undefined, n = 12): string {
  return h ? h.slice(0, n) + '…' : ''
}

export function isPublicIp(ip: string | null | undefined): boolean {
  if (!ip) return false
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip)
  if (m) {
    const [a, b] = [Number(m[1]), Number(m[2])]
    if (a === 10 || a === 127 || a === 0 || a >= 224) return false
    if (a === 172 && b >= 16 && b <= 31) return false
    if (a === 192 && b === 168) return false
    if (a === 169 && b === 254) return false
    if (a === 100 && b >= 64 && b <= 127) return false
    return true
  }
  if (ip.includes(':')) {
    const low = ip.toLowerCase()
    if (low === '::1' || low.startsWith('fe80') || low.startsWith('fc') || low.startsWith('fd') || low === '::') return false
    return true
  }
  return false
}
