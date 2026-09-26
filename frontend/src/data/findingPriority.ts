/**
 * What to look at first: a priority score for each finding, and the reasons that make it.
 *
 * Deterministic and explainable, in the way THOR and Cyber Triage rank what they find: no model,
 * only the finding, its rule's measure and the rest of the case. A finding weighs
 *
 *   severity points x confidence x rule trust x rarity  + corroboration + escalated before
 *
 * and a finding whose same rule and same entities an analyst marked false positive before (in this
 * case or another one of this browser) keeps a quarter of that. Findings already decided (reviewed,
 * false positive) sort below the others whatever their score. Every weight is in PRIORITY below.
 */
import { getDb, type Finding, type Severity } from '../db/schema'
import { effectiveSeverity, HOST_FIELDS, IP_FIELDS, USER_FIELDS } from '../rules/incidents'
import { fmtTs } from '../util/format'
import { ruleTrust, type RuleTrust } from './ruleMeasures'
import { findingPhase, hostKey, PHASE_LABEL } from './stories'

/** The weights of the score, in one place to tune them. */
export const PRIORITY = {
  /** points of a finding by its severity, the analyst's override first (as the stories weigh a finding) */
  severity: { critical: 10, high: 6, medium: 3, low: 1, info: 0 } as Record<Severity, number>,
  /** the rule's own confidence; a rule that does not say one is taken at its word */
  confidence: { high: 1, medium: 0.85, low: 0.7 } as Record<NonNullable<Finding['confidence']>, number>,
  // rule trust is the precision of the rule's measure (ruleMeasures.ruleTrust, as the stories weigh it)
  /** a rule that fired on one host (or for one user) of the case, when the case has at least `rarityMin` */
  rare: 1.5,
  /** a rule that fired on at least `commonShare` of them */
  common: 0.75,
  commonShare: 0.5,
  rarityMin: 3,
  /** other rules on the same host or for the same user within this long of the finding */
  windowMs: 24 * 3_600_000,
  /** points per other rule, and more per other tactic among them, up to the cap */
  perRule: 1,
  perTactic: 1,
  corroborationCap: 6,
  /** an analyst escalated the same rule on the same entities before */
  escalatedBefore: 5,
  /** an analyst marked the same rule on the same entities false positive before: what the score keeps */
  falsePositiveBefore: 0.25,
}

export interface PriorityReason {
  kind: 'severity' | 'confidence' | 'trust' | 'rarity' | 'corroboration' | 'memory' | 'decided'
  /** whether it raised the score, lowered it, or only says what the score started from */
  tone: 'up' | 'down' | 'neutral'
  /** a word or two for the list */
  short: string
  /** the reason in a sentence */
  text: string
}
export interface Priority {
  score: number
  /** reviewed or false positive: sorts below the findings still to look at */
  decided: boolean
  reasons: PriorityReason[]
}

/** An analyst's decision on a finding, remembered across the cases of this browser. */
export interface PastDecision {
  caseId: number
  caseName: string
  findingId?: number
  signature: string
  status: 'false_positive' | 'escalated'
  /** when it was decided, when the decision says */
  at: number | null
}

export interface PriorityOptions {
  /** each rule's trust (ruleMeasures.ruleTrust of its measure); a rule it does not know is unmeasured */
  trust?: (ruleId: string) => RuleTrust | undefined
  /** analysts' decisions of this case and the others (loadPastDecisions) */
  memory?: PastDecision[]
}

const DECIDED: Finding['status'][] = ['reviewed', 'false_positive']
/** entity fields that say where or who, not what: the same rule on the same program elsewhere is the same decision */
const WHERE_FIELDS = new Set([...HOST_FIELDS, ...USER_FIELDS, ...IP_FIELDS, 'hostname', 'originIp'].map((k) => k.toLowerCase()))
const SERVICE_ACCOUNTS = new Set(['system', 'local service', 'network service', 'anonymous logon', 'localsystem'])
const num = (x: number) => String(Math.round(x * 100) / 100)
const plural = (n: number, one: string, many = `${one}s`) => (n === 1 ? one : many)

/** alice for alice, CONTOSO\alice and alice@contoso.com; empty for a machine or service account or a SID (after lineage._user_key). */
export function userKey(v: unknown): string {
  const s = String(v ?? '')
    .trim()
    .toLowerCase()
    .split('\\')
    .pop()!
    .split('@')[0]
  return !s || s === '-' || s.startsWith('s-1-') || s.endsWith('$') || SERVICE_ACCOUNTS.has(s) ? '' : s
}
const hostOf = (f: Finding) => hostKey(f.entities.computer || f.entities.host)
const usersOf = (f: Finding) => [...new Set(USER_FIELDS.map((k) => userKey(f.entities[k])).filter(Boolean))]

/**
 * What a decision on a finding is about: its rule and the entities that say what it found (the
 * program, the command line, the service), not the host, account or address it was found on, so
 * a benign program marked false positive on one host is known on the next. A rule whose entities
 * are only hosts, accounts and addresses keeps them all. Null when the finding names nothing.
 */
export function decisionSignature(f: Pick<Finding, 'ruleId' | 'entities'>): string | null {
  const all = Object.entries(f.entities ?? {}).filter(([, v]) => v != null && String(v).trim() !== '')
  const what = all.filter(([k]) => !WHERE_FIELDS.has(k.toLowerCase()))
  const pick = what.length ? what : all
  if (!pick.length) return null
  return [f.ruleId, ...pick.map(([k, v]) => `${k}=${String(v).trim().toLowerCase()}`).sort()].join('\u0000')
}

/** The analysts' false positives and escalations among these findings: the model's own decisions do not count. */
export function pastDecisions(findings: Finding[], caseNames: Map<number, string>): PastDecision[] {
  const out: PastDecision[] = []
  for (const f of findings) {
    if ((f.status !== 'false_positive' && f.status !== 'escalated') || f.decidedBy === 'ai' || f.ruleId === 'chain') continue
    const signature = decisionSignature(f)
    if (signature) out.push({ caseId: f.caseId, caseName: caseNames.get(f.caseId) ?? `#${f.caseId}`, findingId: f.id, signature, status: f.status, at: f.decidedAt ?? null })
  }
  return out
}

/** Every analyst decision of every case in this browser (nothing leaves it). */
export async function loadPastDecisions(): Promise<PastDecision[]> {
  const db = getDb()
  const [decided, cases] = await Promise.all([db.findings.where('status').anyOf(['false_positive', 'escalated']).toArray(), db.cases.toArray()])
  return pastDecisions(decided, new Map(cases.map((c) => [c.id!, c.name])))
}

function trustReason(t: RuleTrust): PriorityReason {
  const x = `x${num(t.precision)}`
  const clean = t.noisy ? `, and it fired on ${t.machines ?? 0} of ${t.of ?? 0} clean machines` : ''
  const tone = t.precision < 1 ? 'down' : 'neutral'
  if (t.verdict === 'detects')
    return t.noisy
      ? { kind: 'trust', tone, short: 'noisy rule', text: `Its rule detects what it looks for on recorded attacks${clean}: ${x}.` }
      : { kind: 'trust', tone, short: 'measured rule', text: 'Its rule detects what it looks for on recorded attacks and never fired on clean machines.' }
  if (t.verdict === 'lead') return { kind: 'trust', tone, short: 'lead', text: `Its rule is a lead, never seen to detect what it looks for${clean}: ${x}.` }
  if (t.verdict === 'misses') return { kind: 'trust', tone, short: 'misses sample', text: `Its rule does not fire on its own SigmaHQ sample${clean}: ${x}.` }
  return { kind: 'trust', tone, short: 'unmeasured', text: `Its rule was not measured on recorded attacks${clean}: ${x}.` }
}

/** The findings of each host or user, oldest first, for the other rules around a finding. */
function peersBy(findings: Finding[]): Map<string, Finding[]> {
  const by = new Map<string, Finding[]>()
  const add = (k: string, f: Finding) => (by.get(k) ?? by.set(k, []).get(k)!).push(f)
  for (const f of findings) {
    if (f.ts == null || f.ruleId === 'chain' || f.status === 'false_positive') continue
    const h = hostOf(f)
    if (h) add(`h:${h}`, f)
    for (const u of usersOf(f)) add(`u:${u}`, f)
  }
  for (const list of by.values()) list.sort((a, b) => a.ts! - b.ts!)
  return by
}

/** The first index of a list sorted by time whose finding is at or after `ts`. */
function firstAt(list: Finding[], ts: number): number {
  let lo = 0
  let hi = list.length
  while (lo < hi) {
    const mid = (lo + hi) >> 1
    if (list[mid].ts! < ts) lo = mid + 1
    else hi = mid
  }
  return lo
}

/**
 * Each finding's priority, by its key. The rarity and the other rules around a finding are read
 * from these findings, so pass the whole case.
 */
export function scoreFindings(findings: Finding[], opts: PriorityOptions = {}): Map<string, Priority> {
  const W = PRIORITY
  // which hosts and users each rule fired on, of those the case's findings name
  const caseHosts = new Set<string>()
  const caseUsers = new Set<string>()
  const ruleHosts = new Map<string, Set<string>>()
  const ruleUsers = new Map<string, Set<string>>()
  for (const f of findings) {
    if (f.ruleId === 'chain') continue
    const h = hostOf(f)
    if (h) {
      caseHosts.add(h)
      ;(ruleHosts.get(f.ruleId) ?? ruleHosts.set(f.ruleId, new Set()).get(f.ruleId)!).add(h)
    }
    for (const u of usersOf(f)) {
      caseUsers.add(u)
      ;(ruleUsers.get(f.ruleId) ?? ruleUsers.set(f.ruleId, new Set()).get(f.ruleId)!).add(u)
    }
  }
  const peers = peersBy(findings)
  const memory = new Map<string, PastDecision[]>()
  for (const d of opts.memory ?? []) (memory.get(d.signature) ?? memory.set(d.signature, []).get(d.signature)!).push(d)

  const out = new Map<string, Priority>()
  for (const f of findings) {
    const reasons: PriorityReason[] = []
    const sev = effectiveSeverity(f)
    let weight = W.severity[sev]
    reasons.push({
      kind: 'severity',
      tone: 'neutral',
      short: sev,
      text: `${sev[0].toUpperCase()}${sev.slice(1)} severity${f.severityOverride ? ` (the review's override; the rule says ${f.severity})` : ''}: ${weight} ${plural(weight, 'point')}.`,
    })
    if (f.confidence && W.confidence[f.confidence] !== 1) {
      weight *= W.confidence[f.confidence]
      reasons.push({ kind: 'confidence', tone: 'down', short: `${f.confidence} confidence`, text: `Its rule's confidence is ${f.confidence}: x${num(W.confidence[f.confidence])}.` })
    }

    // how far the rule can be believed; the chains' own rows are built from ties, not a rule
    if (f.ruleId !== 'chain') {
      const t = opts.trust?.(f.ruleId) ?? ruleTrust(undefined)
      weight *= t.precision
      reasons.push(trustReason(t))
    }

    // a rule that fired on one host of many before one that fires everywhere
    const h = hostOf(f)
    const users = usersOf(f)
    const [unit, of, seen, on] = h
      ? ['host', caseHosts.size, ruleHosts.get(f.ruleId)?.size ?? 0, 'on']
      : users.length
        ? ['user', caseUsers.size, ruleUsers.get(f.ruleId)?.size ?? 0, 'for']
        : ['', 0, 0, '']
    if (f.ruleId !== 'chain' && unit && of >= W.rarityMin && seen) {
      if (seen === 1) {
        weight *= W.rare
        reasons.push({ kind: 'rarity', tone: 'up', short: `1 of ${of} ${unit}s`, text: `Its rule fired ${on} 1 of the ${of} ${unit}s of the case's findings (${h || users[0]}): x${num(W.rare)}.` })
      } else if (seen / of >= W.commonShare) {
        weight *= W.common
        reasons.push({ kind: 'rarity', tone: 'down', short: `${seen} of ${of} ${unit}s`, text: `Its rule fired ${on} ${seen} of the ${of} ${unit}s of the case's findings: x${num(W.common)}.` })
      }
    }

    // other rules on the same host or for the same user around it, more of other tactics
    let points = weight
    if (f.ts != null && f.ruleId !== 'chain') {
      const from = f.ts - W.windowMs
      const to = (f.tsEnd ?? f.ts) + W.windowMs
      const others = new Map<string, { f: Finding; phase: string | null; where: string }>()
      const keys = [...(h ? [`h:${h}`] : []), ...users.map((u) => `u:${u}`)]
      for (const k of keys) {
        const list = peers.get(k) ?? []
        for (let i = firstAt(list, from); i < list.length && list[i].ts! <= to && others.size < 50; i++) {
          const o = list[i]
          if (o.ruleId === f.ruleId || others.has(o.ruleId)) continue
          others.set(o.ruleId, { f: o, phase: findingPhase(o), where: k.startsWith('h:') ? `on ${k.slice(2)}` : `for ${k.slice(2)}` })
        }
      }
      if (others.size) {
        const own = findingPhase(f)
        const tactics = new Set([...others.values()].map((o) => o.phase).filter((p): p is string => !!p && p !== own))
        const add = Math.min(W.corroborationCap, others.size * W.perRule + tactics.size * W.perTactic)
        points += add
        const list = [...others.values()]
        const where = [...new Set(list.map((o) => o.where))].join(' and ')
        const named = list
          .slice(0, 3)
          .map((o) => `${o.f.title}${o.phase ? ` (${PHASE_LABEL[o.phase].toLowerCase()})` : ''}`)
          .join(', ')
        reasons.push({
          kind: 'corroboration',
          tone: 'up',
          short: `+${others.size} ${plural(others.size, 'rule')}${tactics.size ? `, ${tactics.size} ${plural(tactics.size, 'tactic')}` : ''}`,
          text: `${others.size} other ${plural(others.size, 'rule')} ${where} within ${W.windowMs / 3_600_000} hours${tactics.size ? `, ${tactics.size} of another tactic` : ''}: ${named}${list.length > 3 ? ` and ${list.length - 3} more` : ''}: +${num(add)}.`,
        })
      }
    }

    // what an analyst decided before on the same rule and the same entities
    const signature = f.ruleId === 'chain' ? null : decisionSignature(f)
    const before = (signature ? (memory.get(signature) ?? []) : []).filter((d) => !(d.caseId === f.caseId && d.findingId === f.id))
    if (before.length) {
      const last = before.reduce((a, b) => ((b.at ?? 0) > (a.at ?? 0) ? b : a))
      const where = last.caseId === f.caseId ? 'in this case' : `in case ${last.caseName}`
      const when = last.at ? ` on ${fmtTs(last.at, { date: true })}` : ''
      const more = before.length > 1 ? ` (${before.length} decisions on it in all)` : ''
      if (last.status === 'false_positive') {
        points *= W.falsePositiveBefore
        reasons.push({
          kind: 'memory',
          tone: 'down',
          short: 'false positive before',
          text: `The same rule on the same entities was marked false positive ${where}${when}${more}: x${num(W.falsePositiveBefore)}.`,
        })
      } else {
        points += W.escalatedBefore
        reasons.push({ kind: 'memory', tone: 'up', short: 'escalated before', text: `The same rule on the same entities was escalated ${where}${when}${more}: +${W.escalatedBefore}.` })
      }
    }

    const decided = DECIDED.includes(f.status)
    if (decided)
      reasons.push({
        kind: 'decided',
        tone: 'down',
        short: 'decided',
        text: `Already ${f.status === 'reviewed' ? 'reviewed' : 'marked false positive'}: it sorts below the findings still to look at.`,
      })
    out.set(f.key, { score: Math.round(points * 10) / 10, decided, reasons })
  }
  return out
}

/** Findings to look at first: undecided before decided, then the higher score, then the latest. */
export function byPriority(scores: Map<string, Priority>): (a: Finding, b: Finding) => number {
  return (a, b) => {
    const pa = scores.get(a.key)
    const pb = scores.get(b.key)
    return Number(!!pa?.decided) - Number(!!pb?.decided) || (pb?.score ?? 0) - (pa?.score ?? 0) || (b.ts ?? 0) - (a.ts ?? 0)
  }
}

/** The reasons that moved the score, for a list: the severity is shown beside it. */
export const shortReasons = (p: Priority | undefined): string =>
  (p?.reasons ?? [])
    .filter((r) => r.tone !== 'neutral' && r.kind !== 'decided')
    .map((r) => r.short)
    .join(' · ')
