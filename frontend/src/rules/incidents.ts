import type { Finding, Severity } from '../db/schema'

/**
 * Incidents: findings grouped around what an analyst actually reviews.
 *
 * - every finding on one mail (rules, score bands, the attack chain seeded by it) is one incident;
 * - event findings about the same user / host / IP within a time gap (6 h by default) are one
 *   incident, the way Sentinel and Elastic group alerts on shared entities;
 * - grouped findings without a usable entity (bursts keyed by something else) stay on their own.
 *
 * Nothing is stored: incidents are derived from the findings table, and an incident's status is
 * derived from its members (setting it writes to every member).
 */

export type IncidentKind = 'mail' | 'entity' | 'group'
export type Status = Finding['status']

export interface Incident {
  id: string
  kind: IncidentKind
  title: string
  subtitle: string
  severity: Severity
  source: 'events' | 'mails' | 'mixed'
  ts: number | null
  tsEnd: number | null
  entities: Record<string, string>
  findings: Finding[]
  rules: string[]
  refs: number[]
  attack: string[]
  status: Status
  /** the member that gives the incident its severity and its headline */
  lead: Finding
}

export const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
export const DEFAULT_GAP_MS = 6 * 3_600_000
const USER_FIELDS = ['targetUser', 'subjectUser', 'user', 'upn', 'memberName', 'userPrincipalName']
const HOST_FIELDS = ['computer', 'host', 'workstation']
const IP_FIELDS = ['ipAddress', 'sourceIp', 'clientIp', 'ip']
const MAX_REFS = 5000

const rank = (s: Severity) => ORDER.indexOf(s)

/** The entity an event finding is about, in priority order user > host > ip. */
export function primaryEntity(f: Finding): { field: string; value: string } | null {
  for (const fields of [USER_FIELDS, HOST_FIELDS, IP_FIELDS]) {
    for (const k of fields) {
      const v = f.entities[k]
      if (v && !v.includes(',') && v !== '-') return { field: k, value: v }
    }
  }
  return null
}

/** Derived status: all false positive → false positive; any escalated → escalated; all handled → reviewed; else new. */
export function deriveStatus(members: Finding[]): Status {
  if (members.every((f) => f.status === 'false_positive')) return 'false_positive'
  if (members.some((f) => f.status === 'escalated')) return 'escalated'
  if (members.every((f) => f.status === 'reviewed' || f.status === 'false_positive')) return 'reviewed'
  return 'new'
}

function sortMembers(members: Finding[]): Finding[] {
  return [...members].sort((a, b) => rank(a.severity) - rank(b.severity) || b.count - a.count || (a.ts ?? 0) - (b.ts ?? 0))
}

function finish(id: string, kind: IncidentKind, members: Finding[], title?: string, subtitle?: string): Incident {
  const findings = sortMembers(members)
  const lead = findings[0]
  const entities: Record<string, string> = {}
  for (const f of findings) for (const [k, v] of Object.entries(f.entities)) if (!(k in entities) && v) entities[k] = v
  const rules = Array.from(new Set(findings.map((f) => f.ruleId)))
  const refs = Array.from(new Set(findings.flatMap((f) => f.refs))).slice(0, MAX_REFS)
  const attack = Array.from(new Set(findings.flatMap((f) => f.attack)))
  const times = findings.map((f) => f.ts).filter((t): t is number => t != null)
  const ends = findings.map((f) => f.tsEnd ?? f.ts).filter((t): t is number => t != null)
  const sources = new Set(findings.map((f) => f.source))
  const n = findings.length
  const sub = subtitle ?? `${n} finding${n === 1 ? '' : 's'} from ${rules.length} rule${rules.length === 1 ? '' : 's'}`
  return {
    id,
    kind,
    title: title ?? lead.title,
    subtitle: sub,
    severity: lead.severity,
    source: sources.size === 1 ? findings[0].source : 'mixed',
    ts: times.length ? Math.min(...times) : null,
    tsEnd: ends.length ? Math.max(...ends) : null,
    entities,
    findings,
    rules,
    refs,
    attack,
    status: deriveStatus(findings),
    lead,
  }
}

/** Group findings into incidents. Pure; the order is severity, then breadth (rules), then recency. */
export function buildIncidents(findings: Finding[], opts: { gapMs?: number } = {}): Incident[] {
  const gap = opts.gapMs ?? DEFAULT_GAP_MS
  const mail = new Map<number, Finding[]>()
  const byEntity = new Map<string, { field: string; value: string; items: Finding[] }>()
  const groups: Finding[][] = []
  for (const f of findings) {
    if (f.source === 'mails' && f.refs.length === 1) {
      const id = f.refs[0]
      const arr = mail.get(id) ?? []
      arr.push(f)
      mail.set(id, arr)
      continue
    }
    if (f.source === 'events') {
      const pe = primaryEntity(f)
      if (pe) {
        const key = `${pe.field === 'computer' || pe.field === 'host' || pe.field === 'workstation' ? 'host' : IP_FIELDS.includes(pe.field) ? 'ip' : 'user'}:${pe.value.toLowerCase()}`
        const e = byEntity.get(key) ?? { field: pe.field, value: pe.value, items: [] }
        e.items.push(f)
        byEntity.set(key, e)
        continue
      }
    }
    groups.push([f])
  }
  const out: Incident[] = []
  for (const [id, members] of mail) {
    const withSubject = members.find((f) => f.entities.subject)
    const from = members.find((f) => f.entities.fromAddr)?.entities.fromAddr
    const title = withSubject?.entities.subject || sortMembers(members)[0].title
    const n = members.length
    const rules = new Set(members.map((f) => f.ruleId)).size
    out.push(finish(`mail:${id}`, 'mail', members, title, `${from ? `from ${from} · ` : ''}${n} finding${n === 1 ? '' : 's'} from ${rules} rule${rules === 1 ? '' : 's'}`))
  }
  for (const [key, e] of byEntity) {
    const timed = e.items.filter((f) => f.ts != null).sort((a, b) => a.ts! - b.ts!)
    const untimed = e.items.filter((f) => f.ts == null)
    let cluster: { items: Finding[]; end: number } | null = null
    let n = 0
    const flush = () => {
      if (!cluster) return
      const items = cluster.items
      const rules = new Set(items.map((f) => f.ruleId)).size
      out.push(finish(`${key}|${n++}`, 'entity', items, e.value, `${sortMembers(items)[0].title} · ${items.length} finding${items.length === 1 ? '' : 's'} from ${rules} rule${rules === 1 ? '' : 's'}`))
      cluster = null
    }
    for (const f of timed) {
      const end = f.tsEnd ?? f.ts!
      if (cluster && f.ts! <= cluster.end + gap) {
        cluster.items.push(f)
        cluster.end = Math.max(cluster.end, end)
      } else {
        flush()
        cluster = { items: [f], end }
      }
    }
    flush()
    if (untimed.length) out.push(finish(`${key}|untimed`, 'entity', untimed, e.value))
  }
  for (const members of groups) {
    const f = members[0]
    out.push(finish(`group:${f.ruleId}|${f.key}`, 'group', members, f.title, Object.entries(f.entities).slice(0, 3).map(([k, v]) => `${k}=${v}`).join(' · ') || `${f.count} row(s)`))
  }
  return out.sort((a, b) => rank(a.severity) - rank(b.severity) || b.rules.length - a.rules.length || (b.ts ?? 0) - (a.ts ?? 0))
}

/** Counts per severity (findings or incidents alike). */
export function sevCounts(rows: { severity: Severity }[]): Record<string, number> {
  const c: Record<string, number> = {}
  for (const r of rows) c[r.severity] = (c[r.severity] ?? 0) + 1
  return c
}
