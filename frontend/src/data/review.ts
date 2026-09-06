import { getDb, type Finding, type Severity } from '../db/schema'
import type { Chain, ChainStep } from './chains'
import { effectiveSeverity, ORDER, type Incident } from '../rules/incidents'

/**
 * Review decisions and report selection.
 *
 * Findings carry their own decisions (status, notes, severityOverride, reportExclude). Chains are
 * not rows, so their review (verdict, narrative, override, include) lives in kv `chain-reviews-<case>`.
 * The report settings (severity floor, chain detail level, sections) live in kv `report-settings-<case>`.
 * `selectForReport` is the single place that decides what the report contains.
 */

export { effectiveSeverity }
export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const rank = (s: Severity) => ORDER.indexOf(s)

export type ChainDetail = 'linked' | 'weighted' | 'all'
export type Verdict = 'confirmed' | 'benign' | 'unsure'

export interface ReportSettings {
  /** findings and incidents below this severity stay out of the report */
  minSeverity: Severity
  includeChains: boolean
  /** which chain steps the report prints: tied to the mail or carrying a finding / plus weighted steps / every step */
  chainDetail: ChainDetail
  includeTimeline: boolean
  includeTasks: boolean
  includeNotes: boolean
  includeIocs: boolean
  includeEvidence: boolean
  includeFp: boolean
  /** only findings an analyst has looked at (status not new) */
  onlyReviewed: boolean
}

export const DEFAULT_REPORT: ReportSettings = { minSeverity: 'medium', includeChains: true, chainDetail: 'weighted', includeTimeline: true, includeTasks: true, includeNotes: true, includeIocs: true, includeEvidence: true, includeFp: false, onlyReviewed: false }

export interface ChainReview {
  verdict?: Verdict
  narrative?: string
  include?: boolean
  severityOverride?: Severity
  reviewedAt?: number
}

export async function loadReportSettings(caseId: number): Promise<ReportSettings> {
  const v = (await getDb().kv.get(`report-settings-${caseId}`))?.value as Partial<ReportSettings> | undefined
  return { ...DEFAULT_REPORT, ...(v ?? {}) }
}
export async function saveReportSettings(caseId: number, s: ReportSettings): Promise<void> {
  await getDb().kv.put({ key: `report-settings-${caseId}`, value: s })
}
export async function loadChainReviews(caseId: number): Promise<Record<string, ChainReview>> {
  return ((await getDb().kv.get(`chain-reviews-${caseId}`))?.value as Record<string, ChainReview> | undefined) ?? {}
}
export async function saveChainReview(caseId: number, chainId: string, patch: Partial<ChainReview>): Promise<Record<string, ChainReview>> {
  const all = await loadChainReviews(caseId)
  all[chainId] = { ...(all[chainId] ?? {}), ...patch, reviewedAt: Date.now() }
  await getDb().kv.put({ key: `chain-reviews-${caseId}`, value: all })
  return all
}

export const chainSeverity = (c: Chain, r?: ChainReview): Severity => r?.severityOverride ?? c.severity
export const chainIncluded = (_c: Chain, r?: ChainReview): boolean => r?.include ?? r?.verdict !== 'benign'

/** Is a chain step printed at this detail level? */
export function stepVisible(s: ChainStep, detail: ChainDetail): boolean {
  if (detail === 'all') return true
  const linked = s.artifacts.length > 0 || s.findings.length > 0
  if (detail === 'linked') return linked
  return linked || s.weight >= 2
}

export function findingInReport(f: Finding, s: ReportSettings): boolean {
  if (f.reportExclude) return false
  if (f.status === 'false_positive' && !s.includeFp) return false
  if (s.onlyReviewed && f.status === 'new') return false
  return rank(effectiveSeverity(f)) <= rank(s.minSeverity)
}

export function selectForReport(findings: Finding[], chains: Chain[], reviews: Record<string, ChainReview>, s: ReportSettings): { findings: Finding[]; chains: Chain[] } {
  return {
    findings: findings.filter((f) => findingInReport(f, s)),
    chains: s.includeChains ? chains.filter((c) => chainIncluded(c, reviews[c.id]) && rank(chainSeverity(c, reviews[c.id])) <= rank(s.minSeverity)) : [],
  }
}

export interface ReviewItem {
  id: string
  kind: 'chain' | 'incident'
  title: string
  sub: string
  severity: Severity
  done: boolean
  chain?: Chain
  incident?: Incident
}

/** The order an analyst clears the case in: chains by score, then incidents by severity. */
export function reviewQueue(incidents: Incident[], chains: Chain[], reviews: Record<string, ChainReview>): ReviewItem[] {
  const cs: ReviewItem[] = [...chains].sort((a, b) => b.score - a.score).map((c) => ({ id: `chain:${c.id}`, kind: 'chain', title: c.identityLabel, sub: `chain · score ${c.score} · ${c.steps.length} steps`, severity: chainSeverity(c, reviews[c.id]), done: !!reviews[c.id]?.verdict, chain: c }))
  const is: ReviewItem[] = incidents.map((i) => ({ id: `incident:${i.id}`, kind: 'incident', title: i.title, sub: i.subtitle, severity: i.severity, done: i.status !== 'new', incident: i }))
  return [...cs, ...is]
}

/**
 * Rescore an incident: members more severe than the target take the override, and when the
 * target is above every member the lead takes it, so the incident's severity becomes the target.
 */
export function overridesForIncident(inc: Incident, target: Severity | null): { id: number; severityOverride: Severity | undefined }[] {
  if (target == null) return inc.findings.map((f) => ({ id: f.id!, severityOverride: undefined }))
  const out: { id: number; severityOverride: Severity | undefined }[] = []
  let raised = false
  for (const f of inc.findings) {
    if (f.status === 'false_positive') continue
    const cur = effectiveSeverity(f)
    if (rank(cur) < rank(target)) out.push({ id: f.id!, severityOverride: target })
    else if (rank(cur) === rank(target)) raised = true
  }
  if (!raised && !out.length) out.push({ id: inc.lead.id!, severityOverride: target })
  return out
}
