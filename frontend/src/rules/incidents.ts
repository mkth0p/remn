import type { Finding, Severity } from '../db/schema'
import type { Chain } from '../data/chains'

/**
 * Incidents: findings grouped around what an analyst actually reviews.
 *
 * - an attack chain and every finding whose rows are steps of it (the seed mail's findings, the
 *   findings on its events) are one incident, so a step never shows up twice; a finding the analyst
 *   unlinks leaves the chain and is decided on its own again;
 * - every finding on one mail (rules, score bands) is one incident;
 * - event findings about the same user / host / IP within a time gap (6 h by default) are one
 *   incident, the way Sentinel and Elastic group alerts on shared entities;
 * - grouped findings without a usable entity (bursts keyed by something else) stay on their own.
 *
 * Nothing is stored: incidents are derived from the findings table, and an incident's status is
 * derived from its members (setting it writes to every member).
 */

export type IncidentKind = 'chain' | 'mail' | 'entity' | 'group'
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
  /** chain incidents: the chain itself */
  chain?: Chain
}

export interface IncidentOptions {
  gapMs?: number
  /** attack chains: their member findings become one incident per chain */
  chains?: Chain[]
  /** severity of a chain incident (the Review page passes the analyst's override); default the chain's */
  severityOf?: (c: Chain) => Severity
}

export const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
export const DEFAULT_GAP_MS = 6 * 3_600_000
const USER_FIELDS = ['targetUser', 'subjectUser', 'user', 'upn', 'memberName', 'userPrincipalName']
const HOST_FIELDS = ['computer', 'host', 'workstation']
const IP_FIELDS = ['ipAddress', 'sourceIp', 'clientIp', 'ip']
const MAX_REFS = 5000
/** a finding with more rows than this describes a pattern, not steps of a chain */
const MAX_MEMBER_REFS = 500

const rank = (s: Severity) => ORDER.indexOf(s)
/** the analyst's rescoring wins over the rule's severity */
export const effectiveSeverity = (f: Pick<Finding, 'severity' | 'severityOverride'>): Severity => f.severityOverride ?? f.severity

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

/** The finding row that mirrors a chain (see data/chains.ts persistChainFindings). */
export const chainFindingKey = (c: Chain) => `chain|${c.identity}|${c.seed.id}`

/** Row ids a chain is made of: its seed mail(s) and every step (folded runs carry their rows in refs). */
export function chainCoverage(c: Chain): { mails: Set<number>; events: Set<number> } {
  const mails = new Set<number>([c.seed.id, ...(c.relatedSeeds ?? []).map((x) => x.id)])
  const events = new Set<number>()
  for (const s of c.steps) {
    const set = s.source === 'mails' ? mails : events
    if (s.id != null) set.add(s.id)
    for (const r of s.refs ?? []) set.add(r)
  }
  return { mails, events }
}

/**
 * Which chain each finding belongs to: the chain's own row, and every finding whose rows are all
 * steps (or the seed mail) of the chain. Unlinked findings stay out; when chains overlap the one
 * with the higher score takes the finding.
 */
export function chainMembership(findings: Finding[], chains: Chain[]): Map<number, string> {
  const out = new Map<number, string>()
  if (!chains.length) return out
  const cov = [...chains].sort((a, b) => b.score - a.score).map((c) => ({ c, key: chainFindingKey(c), ...chainCoverage(c) }))
  for (const f of findings) {
    if (f.id == null) continue
    if (f.ruleId === 'chain') {
      const hit = cov.find((x) => x.key === f.key)
      if (hit) out.set(f.id, hit.c.id)
      continue
    }
    if (f.chainUnlinked || !f.refs.length || f.refs.length > MAX_MEMBER_REFS) continue
    for (const x of cov) {
      const set = f.source === 'mails' ? x.mails : x.events
      if (f.refs.every((r) => set.has(r))) {
        out.set(f.id, x.c.id)
        break
      }
    }
  }
  return out
}

/** Derived status: all false positive → false positive; any escalated → escalated; all handled → reviewed; else new. */
export function deriveStatus(members: Finding[]): Status {
  if (members.every((f) => f.status === 'false_positive')) return 'false_positive'
  if (members.some((f) => f.status === 'escalated')) return 'escalated'
  if (members.every((f) => f.status === 'reviewed' || f.status === 'false_positive')) return 'reviewed'
  return 'new'
}

function sortMembers(members: Finding[]): Finding[] {
  return [...members].sort((a, b) => rank(effectiveSeverity(a)) - rank(effectiveSeverity(b)) || b.count - a.count || (a.ts ?? 0) - (b.ts ?? 0))
}

function finish(id: string, kind: IncidentKind, members: Finding[], title?: string, subtitle?: string): Incident {
  const findings = sortMembers(members)
  // a member marked false positive no longer decides the severity or the headline
  const active = findings.filter((f) => f.status !== 'false_positive')
  const lead = (active.length ? active : findings)[0]
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
    severity: effectiveSeverity(lead),
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
export function buildIncidents(findings: Finding[], opts: IncidentOptions = {}): Incident[] {
  const gap = opts.gapMs ?? DEFAULT_GAP_MS
  const mail = new Map<number, Finding[]>()
  const byEntity = new Map<string, { field: string; value: string; items: Finding[] }>()
  const groups: Finding[][] = []
  const chains = opts.chains ?? []
  const membership = chainMembership(findings, chains)
  const byChain = new Map<string, Finding[]>()
  for (const f of findings) {
    const chainId = f.id != null ? membership.get(f.id) : undefined
    if (chainId) {
      const arr = byChain.get(chainId) ?? []
      arr.push(f)
      byChain.set(chainId, arr)
      continue
    }
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
  for (const c of chains) {
    const members = byChain.get(c.id)
    if (!members) continue
    const own = members.find((f) => f.ruleId === 'chain')
    const n = members.length - (own ? 1 : 0)
    const inc = finish(`chain:${c.id}`, 'chain', members, `Attack chain · ${c.identityLabel}`, `score ${c.score} · ${c.steps.length} step${c.steps.length === 1 ? '' : 's'} · ${n} linked finding${n === 1 ? '' : 's'}`)
    inc.chain = c
    inc.severity = opts.severityOf ? opts.severityOf(c) : c.severity
    if (own) inc.lead = own
    out.push(inc)
  }
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
export function sevCounts(rows: { severity: Severity; severityOverride?: Severity }[]): Record<string, number> {
  const c: Record<string, number> = {}
  for (const r of rows) {
    const s = r.severityOverride ?? r.severity
    c[s] = (c[s] ?? 0) + 1
  }
  return c
}
