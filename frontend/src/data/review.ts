import { getDb, type Finding, type Severity } from '../db/schema'
import type { Chain, ChainStep } from './chains'
import { buildIncidents, chainMembership, effectiveSeverity, ORDER, type Incident } from '../rules/incidents'
import { logoImage, type ReportLanguage } from './reportText'

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
  /** what the analyst writes for a client: the engagement, the scope, the conclusion, the recommendations and the handling */
  client: ClientReport
  /** the language the report is written in; the interface stays English */
  language: ReportLanguage
  /** the firm the report goes out under; REMN's own look when nothing is set */
  branding: ReportBranding
}

/** The firm's name, a line for the cover, and its logo as a PNG or JPEG data URL (reportText.ts LOGO_MAX_BYTES at most). */
export interface ReportBranding {
  firmName: string
  coverLine: string
  logo: string
}

export const EMPTY_BRANDING: ReportBranding = { firmName: '', coverLine: '', logo: '' }

/** A row of the report's version history. */
export interface ReportVersion {
  version: string
  /** yyyy-mm-dd */
  date: string
  author: string
  note: string
}

/** A containment or eradication action taken, with its date. */
export interface ContainmentAction {
  /** yyyy-mm-dd */
  date: string
  action: string
  by: string
}

export type Tlp = '' | 'clear' | 'green' | 'amber' | 'amber+strict' | 'red'
export const TLP_LEVELS: Exclude<Tlp, ''>[] = ['clear', 'green', 'amber', 'amber+strict', 'red']
export type AnalyticConfidence = '' | 'low' | 'moderate' | 'high'

/**
 * What makes the report a document an outside responder can hand to a client: who it is for, what
 * was examined, what the analyst concludes and recommends, and how it is to be handled. The analyst
 * writes all of it; a part left empty is left out of the report, and the scope falls back to what
 * the evidence holds, labelled so. Dates are yyyy-mm-dd; lists are one entry a line.
 */
export interface ClientReport {
  client: string
  engagementRef: string
  engagementStart: string
  engagementEnd: string
  requestedBy: string
  distribution: string
  versions: ReportVersion[]
  objectives: string
  periodFrom: string
  periodTo: string
  systemsIn: string
  systemsOut: string
  accountsIn: string
  accountsOut: string
  /** how the attacker got in, and why it was possible: the analyst's conclusion */
  initialAccess: string
  rootCause: string
  /**
   * the text last offered from a story's spine as a starting point: while the initial access still
   * reads exactly this, it is a draft the analyst has not made their own, and it is not printed
   */
  initialAccessDraft: string
  /** the analyst's own confidence in the conclusion, printed as theirs; empty when they gave none */
  analyticConfidence: AnalyticConfidence
  confidenceBasis: string
  /** what the attacker reached or took and what it did to the business, beyond the accounts and hosts the report lists */
  impact: string
  containment: ContainmentAction[]
  recShort: string
  recMedium: string
  recLong: string
  tlp: Tlp
  confidentiality: string
}

export const EMPTY_CLIENT: ClientReport = {
  client: '',
  engagementRef: '',
  engagementStart: '',
  engagementEnd: '',
  requestedBy: '',
  distribution: '',
  versions: [],
  objectives: '',
  periodFrom: '',
  periodTo: '',
  systemsIn: '',
  systemsOut: '',
  accountsIn: '',
  accountsOut: '',
  initialAccess: '',
  rootCause: '',
  initialAccessDraft: '',
  analyticConfidence: '',
  confidenceBasis: '',
  impact: '',
  containment: [],
  recShort: '',
  recMedium: '',
  recLong: '',
  tlp: '',
  confidentiality: '',
}

export const DEFAULT_REPORT: ReportSettings = {
  minSeverity: 'medium',
  includeChains: true,
  includeGraphs: true,
  chainDetail: 'weighted',
  includeTimeline: true,
  includeTasks: true,
  includeNotes: true,
  includeIocs: true,
  includeEvidence: true,
  includeFp: false,
  onlyReviewed: false,
  client: EMPTY_CLIENT,
  language: 'en',
  branding: EMPTY_BRANDING,
}

const str = (v: unknown): string => (typeof v === 'string' ? v : '')
const rowsOf = <T extends object>(v: unknown, keys: (keyof T)[]): T[] =>
  Array.isArray(v) ? v.filter((r): r is Record<string, unknown> => !!r && typeof r === 'object').map((r) => Object.fromEntries(keys.map((k) => [k, str(r[k as string])])) as T) : []

/**
 * The client part of stored settings, every field of the type it should be: a case made before
 * it existed has none, and a bundle from elsewhere may hold anything.
 */
export function clientReport(v: unknown): ClientReport {
  const r = (v && typeof v === 'object' ? v : {}) as Record<string, unknown>
  const out = { ...EMPTY_CLIENT }
  for (const k of Object.keys(EMPTY_CLIENT) as (keyof ClientReport)[]) if (typeof EMPTY_CLIENT[k] === 'string') (out as Record<string, unknown>)[k] = str(r[k])
  out.versions = rowsOf<ReportVersion>(r.versions, ['version', 'date', 'author', 'note'])
  out.containment = rowsOf<ContainmentAction>(r.containment, ['date', 'action', 'by'])
  out.tlp = (TLP_LEVELS as string[]).includes(out.tlp) ? out.tlp : ''
  out.analyticConfidence = (['low', 'moderate', 'high'] as string[]).includes(out.analyticConfidence) ? out.analyticConfidence : ''
  return out
}

/** The branding of stored settings, every field a string, and the logo only when it is an image the report can embed. */
export function reportBranding(v: unknown): ReportBranding {
  const r = (v && typeof v === 'object' ? v : {}) as Record<string, unknown>
  return { firmName: str(r.firmName), coverLine: str(r.coverLine), logo: logoImage(r.logo) ? str(r.logo) : '' }
}

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
  /** who wrote the narrative last */
  narrativeBy?: 'analyst' | 'ai'
}

export type Status = Finding['status']

/** The status a chain verdict writes to the chain's linked findings. */
export const verdictStatus = (v: Verdict): Status => (v === 'confirmed' ? 'escalated' : v === 'benign' ? 'false_positive' : 'reviewed')

export async function loadReportSettings(caseId: number): Promise<ReportSettings> {
  const v = (await getDb().kv.get(`report-settings-${caseId}`))?.value as Partial<ReportSettings> | undefined
  return { ...DEFAULT_REPORT, ...(v ?? {}), client: clientReport(v?.client), language: v?.language === 'fr' ? 'fr' : 'en', branding: reportBranding(v?.branding) }
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

/**
 * Confirmed chains and incidents of the whole case that the printed selection leaves out. The
 * report's verdict is about the case, so they count there; the Report and Review pages both use
 * this, so the cover reads the same on both.
 */
export function unprintedConfirmed(
  findings: Finding[],
  chains: Chain[],
  reviews: Record<string, ChainReview>,
  selection: { findings: Finding[]; chains: Chain[] },
): { severity: Severity; findings: Finding[] }[] {
  const printed = new Set(selection.findings.map((f) => f.id))
  return buildIncidents(findings, { chains, severityOf: (c) => chainSeverity(c, reviews[c.id]) })
    .filter((i) =>
      i.kind === 'chain' && i.chain
        ? reviews[i.chain.id]?.verdict === 'confirmed' && !selection.chains.some((c) => c.id === i.chain!.id)
        : i.status === 'escalated' && !i.findings.some((f) => printed.has(f.id)),
    )
    .map((i) => ({ severity: i.kind === 'chain' && i.chain ? chainSeverity(i.chain, reviews[i.chain.id]) : i.severity, findings: i.findings }))
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
  const cs: ReviewItem[] = [...chains]
    .sort((a, b) => b.score - a.score)
    .map((c) => ({
      id: `chain:${c.id}`,
      kind: 'chain',
      title: c.identityLabel,
      sub: `chain · score ${c.score} · ${c.steps.length} steps${byChain.get(c.id) ? ` · ${byChain.get(c.id)!.findings.length} findings` : ''}`,
      severity: chainSeverity(c, reviews[c.id]),
      done: !!reviews[c.id]?.verdict,
      chain: c,
      incident: byChain.get(c.id),
    }))
  const is: ReviewItem[] = incidents
    .filter((i) => i.kind !== 'chain')
    .map((i) => ({ id: `incident:${i.id}`, kind: 'incident', title: i.title, sub: i.subtitle, severity: i.severity, done: i.status !== 'new', incident: i }))
  return [...cs, ...is]
}

/** The findings a chain verdict decides on: the chain's linked findings, its own row included. */
export const chainMembers = (inc: Incident | undefined): Finding[] => (inc?.kind === 'chain' ? inc.findings : [])

/** Set a chain's verdict and write the matching status to its linked findings. */
export async function applyChainVerdict(caseId: number, chain: Chain, members: Finding[], verdict: Verdict, by: 'analyst' | 'ai' = 'analyst', aiReason?: string): Promise<Record<string, ChainReview>> {
  const db = getDb()
  const status = verdictStatus(verdict)
  await Promise.all(members.filter((f) => f.id != null).map((f) => db.findings.update(f.id!, { status, decidedBy: by, decidedAt: Date.now(), ...(by === 'ai' && aiReason ? { aiReason } : {}) })))
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
