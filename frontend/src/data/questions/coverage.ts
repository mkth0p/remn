/**
 * Whether a question can be answered from this case's evidence: what kinds of evidence the case
 * holds, read from the channel and category facets of its events and from its mail count (both kept
 * up to date by ingestion, so reading them costs no scan), matched against the evidence each
 * question lists (catalog.ts). The check is at the level of a log or an artefact kind: a case that
 * holds the Security log covers a question about accounts created, whether or not account
 * management auditing was on; the question's note says what else it takes.
 */
import type { Finding } from '../../db/schema'
import { effectiveSeverity } from '../../rules/incidents'
import { fmtNum } from '../../util/format'
import type { DataSource } from '../source'
import { CATALOG, type EvidenceKind, type Question } from './catalog'

/** What the case holds: event counts by channel and by category, and its mails. */
export interface EvidenceProfile {
  channels: Map<string, number>
  categories: Map<string, number>
  mails: number
}

export interface HeldEvidence {
  id: string
  label: string
  count: number
}

export interface Coverage {
  covered: boolean
  /** the evidence kinds the question lists that the case holds, with their row counts */
  held: HeldEvidence[]
  /** the ones it does not hold */
  missing: { id: string; label: string }[]
  /** "covered by the Security log (1,204 rows)" or "not covered: no Sysmon log or Security log in this case" */
  text: string
}

const lower = (items: { value: string; count: number }[]) => {
  const m = new Map<string, number>()
  for (const i of items) if (i.value) m.set(i.value.toLowerCase(), (m.get(i.value.toLowerCase()) ?? 0) + i.count)
  return m
}

export function evidenceProfile(channels: { value: string; count: number }[], categories: { value: string; count: number }[], mails: number): EvidenceProfile {
  return { channels: lower(channels), categories: lower(categories), mails }
}

/** The case's profile from its facets; a facet that cannot be read counts as nothing held. */
export async function loadEvidenceProfile(source: DataSource, mails: number): Promise<EvidenceProfile> {
  const [channels, categories] = await Promise.all([source.facets('events', 'channel', 1000).catch(() => []), source.facets('events', 'category', 1000).catch(() => [])])
  return evidenceProfile(channels, categories, mails)
}

function sum(map: Map<string, number>, exact: string[] = [], prefixes: string[] = []): number {
  let n = 0
  for (const e of exact) n += map.get(e.toLowerCase()) ?? 0
  if (prefixes.length) {
    const p = prefixes.map((x) => x.toLowerCase())
    for (const [k, v] of map) if (p.some((x) => k.startsWith(x))) n += v
  }
  return n
}

/** How many rows of the case are of this kind of evidence. */
export function heldCount(kind: EvidenceKind, profile: EvidenceProfile): number {
  return sum(profile.channels, kind.channels, kind.channelPrefixes) + sum(profile.categories, kind.categories, kind.categoryPrefixes) + (kind.mails ? profile.mails : 0)
}

const list = (labels: string[], join: string) => (labels.length <= 2 ? labels.join(` ${join} `) : `${labels.slice(0, -1).join(', ')} ${join} ${labels[labels.length - 1]}`)

export function coverage(q: Pick<Question, 'evidence'>, profile: EvidenceProfile, kinds: Record<string, EvidenceKind> = CATALOG.evidence): Coverage {
  const held: HeldEvidence[] = []
  const missing: { id: string; label: string }[] = []
  for (const id of q.evidence) {
    const kind = kinds[id]
    if (!kind) continue
    const count = heldCount(kind, profile)
    if (count > 0) held.push({ id, label: kind.label, count })
    else missing.push({ id, label: kind.label })
  }
  const text = held.length
    ? `covered by the ${list(
        held.map((h) => `${h.label} (${fmtNum(h.count)} ${h.count === 1 ? 'row' : 'rows'})`),
        'and',
      )}`
    : `not covered: no ${list(
        missing.map((m) => m.label),
        'or',
      )} in this case`
  return { covered: held.length > 0, held, missing, text }
}

/** Findings that point at the attacker: medium severity or more, not decided false positive, with a time. */
export function attackerFindings(findings: Finding[]): Finding[] {
  return findings.filter((f) => f.ts != null && f.status !== 'false_positive' && ['medium', 'high', 'critical'].includes(effectiveSeverity(f)))
}

/** The first and the last of them, by event time. */
export function activitySpan(findings: Finding[]): { first: Finding | null; last: Finding | null } {
  const hits = attackerFindings(findings)
  if (!hits.length) return { first: null, last: null }
  const firstOf = (list: Finding[]) => list.reduce((a, b) => ((b.ts ?? 0) < (a.ts ?? 0) ? b : a))
  const lastOf = (list: Finding[]) => list.reduce((a, b) => ((b.tsEnd ?? b.ts ?? 0) > (a.tsEnd ?? a.ts ?? 0) ? b : a))
  return { first: firstOf(hits), last: lastOf(hits) }
}
