/** What the Findings page's parts share: its vocabularies, the last rule run as stored, and the texts read from them. */
import type { Finding, Severity } from '../../db/schema'
import type { Incident } from '../../rules/incidents'
import type { RuleDiag } from '../../rules/engine'
import type { Staleness } from '../../data/findingsState'

export const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
export const STATUSES = ['new', 'reviewed', 'escalated', 'false_positive'] as const
export type Status = (typeof STATUSES)[number]
export type Group = 'incident' | '' | 'ruleId' | 'entity' | 'source'
export type Sort = 'priority' | 'severity' | 'time'
export const SORT_LABEL: Record<Sort, string> = { priority: 'priority', severity: 'severity', time: 'newest' }
/** the rows a finding or an incident opens on the Events or Mails page at most */
export const REFS_OPEN = 2000

export const STATUS_LABEL: Record<Status, string> = { new: 'new', reviewed: 'reviewed', escalated: 'escalated', false_positive: 'false positive' }
export const STATUS_SEV: Record<Status, string> = { new: 'accent', reviewed: 'ok', escalated: 'critical', false_positive: 'info' }
export const KIND_LABEL: Record<Incident['kind'], string> = { chain: 'chain', mail: 'mail', entity: 'entity', group: 'grouped' }

export interface LastRun {
  ts: number
  byRule: Record<string, number>
  errors?: string[]
  diagnostics?: RuleDiag[]
}

/** Findings referencing the same seed mail or the same identity as this one. */
export function relatedChains(f: Finding, all: Finding[]): Finding[] {
  if (f.ruleId === 'chain') return []
  const ents = new Set(Object.values(f.entities).map((v) => String(v).toLowerCase()))
  return all.filter((c) => c.ruleId === 'chain' && (c.refs.some((r) => f.refs.includes(r)) || Object.values(c.entities).some((v) => ents.has(String(v).toLowerCase()))))
}

/** Rules that found more than their cap in the last run: the findings they left out are not listed. */
export function cutRules(lastRun: LastRun | null): RuleDiag[] {
  return (lastRun?.diagnostics ?? []).filter((d) => d.reason === 'truncated')
}

/** Why the findings are behind the evidence, one part per reason; empty when they are not. */
export function staleParts(stale: Staleness | null, findings: number): string[] {
  const parts: string[] = []
  if (stale) {
    if (stale.lastRun == null && findings === 0 && stale.evidenceAfter > 0) parts.push('rules have not run on this evidence yet')
    else if (stale.evidenceAfter > 0) parts.push(`${stale.evidenceAfter} evidence file${stale.evidenceAfter === 1 ? '' : 's'} added since the last run`)
    if (stale.rescoreIncomplete) parts.push('mail scores changed but the findings refresh did not finish')
    if (stale.baselineAfter) parts.push('sender baseline ran after the last run')
  }
  return parts
}

/** The prompt that asks the AI analyst about one finding. */
export function explainFindingPrompt(f: Finding): string {
  return `Explain this finding and propose the next investigation steps. Rule ${f.ruleId} (${f.severity}): ${f.title}. ${f.description ?? ''} Entities: ${JSON.stringify(f.entities)}. ${f.count} matching row(s) in ${f.source}, first ${f.ts ? new Date(f.ts).toISOString() : 'n/a'}. Use the tools to look at the referenced rows (ids ${f.refs.slice(0, 20).join(', ')}).`
}

/** The prompt that asks the AI analyst about one incident. */
export function explainIncidentPrompt(i: Incident): string {
  return `Assess this incident and propose the next investigation steps. ${i.kind === 'mail' ? 'Mail' : 'Entity'} "${i.title}" (${i.severity}), ${i.findings.length} finding(s) from ${i.rules.length} rule(s), ${i.ts ? new Date(i.ts).toISOString() : 'n/a'} to ${i.tsEnd ? new Date(i.tsEnd).toISOString() : 'n/a'}. Entities: ${JSON.stringify(i.entities)}. Findings: ${i.findings
    .slice(0, 20)
    .map((f) => `${f.severity} ${f.ruleId}: ${f.title}`)
    .join(' | ')}. Referenced rows (${i.source}): ${i.refs.slice(0, 20).join(', ')}.`
}
