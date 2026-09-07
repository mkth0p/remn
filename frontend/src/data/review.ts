import { getDb, type Finding, type Severity } from '../db/schema'
import type { Chain, ChainStep } from './chains'
import { chainMembership, effectiveSeverity, ORDER, type Incident } from '../rules/incidents'

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
  /** the swimlane graph of each chain (and the shared-entity graph when several) as pictures */
  includeGraphs: boolean
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

export const DEFAULT_REPORT: ReportSettings = { minSeverity: 'medium', includeChains: true, includeGraphs: true, chainDetail: 'weighted', includeTimeline: true, includeTasks: true, includeNotes: true, includeIocs: true, includeEvidence: true, includeFp: false, onlyReviewed: false }

export interface ChainReview {
  verdict?: Verdict
  narrative?: string
  include?: boolean
  severityOverride?: Severity
  reviewedAt?: number
  /** who set the verdict */
  by?: 'analyst' | 'ai'
  /** the model's reason when it decided */
  aiReason?: string
}

export type Status = Finding['status']

/** The status a chain verdict writes to the chain's linked findings. */
export const verdictStatus = (v: Verdict): Status => (v === 'confirmed' ? 'escalated' : v === 'benign' ? 'false_positive' : 'reviewed')

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

/**
 * What the report contains. A finding linked to a chain follows its chain: printed with it when the
 * chain is, left out when the chain is; every other finding passes the floor and the flags on its own.
 */
export function selectForReport(findings: Finding[], chains: Chain[], reviews: Record<string, ChainReview>, s: ReportSettings): { findings: Finding[]; chains: Chain[] } {
  const selected = s.includeChains ? chains.filter((c) => chainIncluded(c, reviews[c.id]) && rank(chainSeverity(c, reviews[c.id])) <= rank(s.minSeverity)) : []
  const printed = new Set(selected.map((c) => c.id))
  const membership = chainMembership(findings, chains)
  return {
    findings: findings.filter((f) => {
      const chainId = f.id != null ? membership.get(f.id) : undefined
      if (chainId) return printed.has(chainId) && !f.reportExclude
      return findingInReport(f, s)
    }),
    chains: selected,
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

/**
 * The order an analyst clears the case in: chains by score (each with the incident that holds its
 * linked findings, when the incidents were built with the chains), then the other incidents by severity.
 */
export function reviewQueue(incidents: Incident[], chains: Chain[], reviews: Record<string, ChainReview>): ReviewItem[] {
  const byChain = new Map(incidents.filter((i) => i.kind === 'chain' && i.chain).map((i) => [i.chain!.id, i]))
  const cs: ReviewItem[] = [...chains].sort((a, b) => b.score - a.score).map((c) => ({ id: `chain:${c.id}`, kind: 'chain', title: c.identityLabel, sub: `chain · score ${c.score} · ${c.steps.length} steps${byChain.get(c.id) ? ` · ${byChain.get(c.id)!.findings.length} findings` : ''}`, severity: chainSeverity(c, reviews[c.id]), done: !!reviews[c.id]?.verdict, chain: c, incident: byChain.get(c.id) }))
  const is: ReviewItem[] = incidents.filter((i) => i.kind !== 'chain').map((i) => ({ id: `incident:${i.id}`, kind: 'incident', title: i.title, sub: i.subtitle, severity: i.severity, done: i.status !== 'new', incident: i }))
  return [...cs, ...is]
}

/** The findings a chain verdict decides on: the chain's linked findings, its own row included. */
export const chainMembers = (inc: Incident | undefined): Finding[] => (inc?.kind === 'chain' ? inc.findings : [])

/** Set a chain's verdict and write the matching status to its linked findings. */
export async function applyChainVerdict(caseId: number, chain: Chain, members: Finding[], verdict: Verdict, by: 'analyst' | 'ai' = 'analyst', aiReason?: string): Promise<Record<string, ChainReview>> {
  const db = getDb()
  const status = verdictStatus(verdict)
  await Promise.all(members.filter((f) => f.id != null).map((f) => db.findings.update(f.id!, { status, decidedBy: by, ...(by === 'ai' && aiReason ? { aiReason } : {}) })))
  return saveChainReview(caseId, chain.id, { verdict, by, ...(by === 'ai' ? { aiReason } : { aiReason: undefined }) })
}

/** Take findings out of their chain (or put them back): unlinked findings are decided on their own. */
export async function setChainUnlinked(ids: number[], on: boolean): Promise<void> {
  const db = getDb()
  await Promise.all(ids.map((id) => db.findings.update(id, { chainUnlinked: on || undefined })))
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
