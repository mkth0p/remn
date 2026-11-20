import type { Case, CaseNote, Evidence, Finding, Ioc, Severity } from '../db/schema'
import type { Chain, ChainStep } from './chains'
import { groupByIncident, storyCoverageWarnings, storyOwnGaps, type ReportStory, type StoryIncident, type StoryResult } from './stories'
import type { DecidedStory } from './storyDecisions'
import { spineBasis, spineSteps } from './storyFlow'
import type { ChainReview, ClientReport, ReportSettings } from './review'
import { chainSeverity, effectiveSeverity, stepVisible } from './review'
import { HOST_FIELDS, USER_FIELDS, type Incident } from '../rules/incidents'
import type { Rule } from '../rules/engine'
import type { RelationshipReview } from './relationshipReviews'
import { packageCoverageIssues } from './packageCoverage'
import { defang, escapeHtml, isPublicIp, renderMarkdown } from '../util/format'
import { userKey } from './findingPriority'
import { hostKey } from './stories'
import type { FacetItem } from './source'
import type { GapStatement } from './evidenceGaps'
import { isLead, type MeasureReading } from './ruleMeasures'
import { CHECKED_ROWS, type ClaimCheck, type ReportClaims, type TextStatus } from './claims'
import type { ReportQuestion, ReportQuestions } from './questions/answers'
// every word, number and time the report prints comes from the dictionary of its language; every time is UTC
import { EN, logoImage, reportText, type ReportText } from './reportText'

/**
 * The printed report: one self-contained HTML file laid out for A4 and the browser's print-to-PDF.
 *
 * It opens on a verdict, not on a table: a seal that says what the review concluded, the threat
 * profile as badges (which tactics were confirmed, which only observed), a scorecard, and the
 * bottom line. Then what happened in time order, the chains and incidents with their decisions,
 * the evidence, the indicators, and an appendix that groups findings by rule so a burst of ninety
 * identical rows is one line with a count and a span. It closes on how the analysis was done and
 * where it stops, because a reader should know what was not looked at.
 *
 * Every string from the case goes through escapeHtml; markdown fields go through renderMarkdown;
 * the graph pictures are PNG data URLs this app drew itself.
 */

export interface ReportData {
  kase: Case
  /** when the report was made; now when left out */
  generatedAt?: number
  settings: ReportSettings
  summary: string
  /** who wrote the executive summary last, when known */
  summaryBy?: 'analyst' | 'ai'
  /** when the summary was last written; older than the newest finding means it may describe another state of the case */
  summaryAt?: number
  /** false positives decided across the whole case, printed or not (the incidents list only carries what prints) */
  falsePositives?: number
  evidence: Evidence[]
  chains: Chain[]
  reviews: Record<string, ChainReview>
  /** findings linked to each chain (the chain's own row excluded) */
  membersOf: Map<string, Finding[]>
  /** PNG data URLs by chain id, plus 'campaign' */
  graphs: Record<string, string>
  campaignInsights: string[]
  coverageWarnings?: string[]
  relationships?: RelationshipReview[]
  /** incidents other than chains */
  incidents: Incident[]
  /** every finding the report carries */
  findings: Finding[]
  iocs: Ioc[]
  timeline: CaseNote[]
  tasks: CaseNote[]
  notes: CaseNote[]
  undecided: number
  /**
   * Confirmed chains and incidents that the printed selection leaves out (below the severity floor,
   * excluded, or a chain switched off). The verdict is about the case, not about what prints, so
   * they still count; the cover says how many are not printed.
   */
  unprintedConfirmed?: { severity: Severity; findings: Finding[] }[]
  /** the state of the last rule run, when known: the report's confidence depends on it */
  rules?: { lastRun: number | null; evidenceAfter: number; errors: number }
  /**
   * Whether the report was issued as final (every preflight check passed or waived with a reason)
   * or is a draft, and what is open or waived; see data/reportPreflight.ts.
   */
  issue?: { status: 'draft' | 'final'; finalAt?: number; open: { label: string; detail: string }[]; waived: { label: string; reason: string }[] }
  /** indicators in the case, and how many were actually checked against a reputation service */
  iocsTotal?: number
  iocsChecked?: number
  /** base64 woff2 of the display face for the wordmark, when it could be loaded */
  fontData?: string
  /** what the case's AI ledger records (ai/ledger.ts summariseLedger), when a model was used */
  ai?: AiUsage
  /** what the evidence cannot show (data/evidenceGaps.ts), printed first under "Where it stops" */
  gaps?: GapStatement[]
  /** each rule's measure (data/ruleMeasures.ts): a finding of a rule never seen to detect what it looks for is marked a lead */
  measures?: Record<string, MeasureReading>
  /** what the rules were measured on, in a sentence */
  measuredOn?: string
  /** the printed findings and texts checked against the rows they cite (data/claims.ts) */
  claims?: ReportClaims
  /** the stories printed (data/stories.ts reportStories), each with the analyst's note */
  stories?: ReportStory[]
  /** the case's stories not printed: below the severity floor, without a note when only reviewed items print, or past the first twenty */
  storiesLeft?: number
  /** the story build's incidents: the printed stories of one are printed together, under one heading */
  storyIncidents?: StoryIncident[]
  /** the stats of the story build: what it could not read (data/stories.ts storyCoverageWarnings) */
  storyStats?: StoryResult['stats']
  /** why the stories no longer read the case as it is (data/stories.ts storiesStaleness); empty or absent when they do */
  storiesStale?: string[]
  /** analyst notes whose story the build no longer holds (listed on the Stories page) */
  storyNotesOrphaned?: number
  /**
   * Every story of the case the analyst decided (data/storyDecisions.ts storiesForReport), printed or
   * not: a confirmed story counts in the verdict as a confirmed incident does, a reviewed one as a
   * reviewed item, a benign or false positive one as a false positive.
   */
  decidedStories?: DecidedStory[]
  /** stories decided benign or false positive: not printed */
  storiesDismissed?: number
  /** decisions on stories the build no longer holds (listed on the Stories page) */
  storyDecisionsOrphaned?: number
  /** the investigative questions chosen for the case and the analyst's answers (data/questions/answers.ts questionsForReport) */
  questions?: ReportQuestions
  /** the hosts and accounts the evidence's records name, for the scope when the analyst wrote none */
  scope?: EvidenceScope
  /** the author each rule names, by rule id (ruleAuthors): the Detection Rule License of the Sigma rules asks that a match keeps it */
  ruleAuthors?: Record<string, string>
}

/**
 * The author each rule names, by rule id. A rule converted from SigmaHQ keeps its Sigma header,
 * author included; REMN's own rules name none.
 */
export function ruleAuthors(rules: Iterable<Rule>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const rule of rules) {
    const sigma = 'sigma' in rule ? rule.sigma : undefined
    const author = sigma && typeof sigma === 'object' && 'author' in sigma ? sigma.author : undefined
    if (typeof author === 'string' && author.trim()) out[rule.id] = author.trim()
  }
  return out
}

/** The model's part in the case, as the report prints it. */
export interface AiUsage {
  runs: number
  toolCalls: number
  proposals: number
  accepted: number
  rejected: number
  undone: number
  notices: number
  models: string[]
  transports: string[]
  first: number | null
  last: number | null
  byProposalKind: Record<string, { proposed: number; accepted: number; rejected: number }>
  check: { entries: number; intact: boolean; brokenAt?: number; head: string | null }
}

/** The model's part in the case in plain sentences and rows: the HTML and the Word report print the same. */
export function aiTexts(a: AiUsage, t: ReportText = EN): { intro: string; facts: string; rows: string[][]; none: string; decisions: string; ledger: string; ledgerScope: string } {
  const where = a.transports.map((x) => t.transport[x] ?? x)
  // the whole head: a shortened one could not be matched against the hash of an entry in a later copy
  const ledger = a.check.intact ? `${t.ai.ledgerIntact(a.check.entries)} ${a.check.head ?? ''}` : `${t.ai.ledgerBroken(a.check.entries, a.check.brokenAt ?? 0)}${t.ai.ledgerBrokenWhy}`
  return {
    intro: t.ai.intro,
    facts: t.ai.facts(a.runs, a.toolCalls, a.first && a.last ? `${t.ts(a.first)} ${t.to} ${t.ts(a.last)}` : '', a.models, where),
    rows: Object.entries(a.byProposalKind).map(([k, v]) => [k.replace('_', ' '), t.num(v.proposed), t.num(v.accepted), t.num(v.rejected)]),
    none: t.ai.none,
    decisions: t.ai.decisions(a.accepted, a.rejected, a.undone, a.notices),
    ledger,
    ledgerScope: t.ai.ledgerScope,
  }
}

function aiSection(t: ReportText, a: AiUsage): string {
  const x = aiTexts(a, t)
  return (
    `<p class="intro">${h(x.intro)}</p>` +
    `<div class="settings">${h(x.facts)}</div>` +
    (x.rows.length
      ? table(
          t.ai.head,
          x.rows.map((r) => r.map(h)),
        )
      : `<div class="empty">${h(x.none)}</div>`) +
    `<div class="settings">${h(x.decisions)}</div>` +
    `<div class="settings">${a.check.intact ? `${h(t.ai.ledgerIntact(a.check.entries))} <code>${h(a.check.head ?? '')}</code>` : `<b>${h(t.ai.ledgerBroken(a.check.entries, a.check.brokenAt ?? 0))}</b>${h(t.ai.ledgerBrokenWhy)}`}</div>` +
    `<div class="cap">${h(x.ledgerScope)}</div>`
  )
}

const ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const
const rank = (s: string) => Math.max(0, ORDER.length - 1 - ORDER.indexOf(s as never))
const worstOf = (xs: string[]): Severity => (xs.length ? (ORDER.find((s) => xs.includes(s)) ?? 'info') : 'info')
const h = escapeHtml
const md = (text: string) => renderMarkdown(text)
const pill = (t: ReportText, sev: string) => `<span class="pill ${ORDER.includes(sev as never) ? sev : 'info'}">${h(t.sev[sev] ?? sev)}</span>`
const statusPill = (t: ReportText, s: string) => `<span class="pill st-${h(s)}">${h(t.status[s] ?? s)}</span>`
const verdictPill = (t: ReportText, v?: string) => (v ? `<span class="pill verdict-${h(v)}">${h(t.chainVerdict[v] ?? v)}</span>` : '')
const chip = (text: string) => `<span class="chip">${h(text)}</span>`
const rows = (xs: string[][]) => xs.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('')
/** a table whose header row repeats on every printed page */
const table = (head: string[], body: string[][]) => `<table><thead><tr>${head.map((x) => `<th>${h(x)}</th>`).join('')}</tr></thead><tbody>${rows(body)}</tbody></table>`
/** only a PNG data URL this app produced itself is embedded */
/** a graph legend entry: the shape (a CSS class of the report) and the colour the graph draws it in */
type KeyItem = [shape: 'diamond' | 'box' | 'dot' | 'ring' | 'line', color: string, label: string]
const chainKey = (t: ReportText): KeyItem[] => [
  ['diamond', 'var(--critical)', t.chain.key[0]],
  ['box', 'var(--high)', t.chain.key[1]],
  ['ring', 'var(--ink-3)', t.chain.key[2]],
  ['line', 'var(--accent)', t.chain.key[3]],
]
const campaignKey = (t: ReportText): KeyItem[] => [
  ['box', 'var(--high)', t.chain.campaignKey[0]],
  ['dot', 'var(--high)', t.chain.campaignKey[1]],
  ['dot', 'var(--low)', t.chain.campaignKey[2]],
  ['dot', 'var(--ink-3)', t.chain.campaignKey[3]],
]
const img = (src: string | undefined, alt: string, caption?: string, key?: KeyItem[]) =>
  src && /^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(src)
    ? `<figure><img src="${src}" alt="${h(alt)}">${
        caption || key
          ? `<figcaption>${key ? key.map(([shape, color, label]) => `<span class="gk"><i class="gk-${shape}" style="--k:${color}"></i>${h(label)}</span>`).join('') : ''}${caption ? h(caption) : ''}</figcaption>`
          : ''
      }</figure>`
    : ''
const span = (t: ReportText, from: number | null | undefined, to: number | null | undefined) => (from && to && to !== from ? `${t.ts(from)} <span class="dim">${t.to}</span> ${t.ts(to)}` : t.ts(from))
const firstSentence = (text: string | undefined) => {
  const t = (text ?? '').replace(/\s+/g, ' ').trim()
  const m = /^(.+?[.!?])(\s|$)/.exec(t)
  return (m ? m[1] : t).slice(0, 220)
}

// ---------------------------------------------------------------------------
// verdict, confidence, threat profile
// ---------------------------------------------------------------------------

export type VerdictKind = 'compromise' | 'suspicious' | 'unwanted' | 'unconfirmed' | 'pending' | 'clean'
export interface Verdict {
  kind: VerdictKind
  /** the words on the seal */
  label: string
  /** one sentence under the seal */
  detail: string
  /** the worst severity among confirmed items, when any */
  severity: Severity | null
  confirmed: number
  reviewed: number
  falsePositives: number
}

const isUnwanted = (f: Finding) => /(^|-)(pua|adware|unwanted)($|-)/i.test(f.ruleId) || (f.tags ?? []).some((t) => /^(pua|adware|unwanted)$/i.test(t)) || /potentially unwanted|\bPUA:/i.test(f.title)
/** a finding that only says the user ran something (ATT&CK T1204) below high: the runs of an unwanted program, not a second threat */
const userExecution = (f: Finding) => rank(effectiveSeverity(f)) < rank('high') && f.attack.length > 0 && f.attack.every((t) => t.toUpperCase().startsWith('T1204'))

/**
 * What the review concluded, from the decisions on chains, incidents and stories. Findings decide
 * nothing on their own. The one place the verdict is read: the report's cover and the Review page's
 * both come from here.
 */
export function computeVerdict(d: ReportData, t: ReportText = EN): Verdict {
  const confirmedChains = d.chains.filter((c) => d.reviews[c.id]?.verdict === 'confirmed')
  const escalated = d.incidents.filter((i) => i.status === 'escalated')
  // a story the analyst decided counts as an incident with the same decision would
  const stories = d.decidedStories ?? []
  const confirmedStories = stories.filter((s) => s.verdict === 'confirmed')
  const reviewed =
    d.chains.filter((c) => d.reviews[c.id]?.verdict === 'unsure').length + d.incidents.filter((i) => i.status === 'reviewed').length + stories.filter((s) => s.verdict === 'reviewed').length
  const falsePositives = (d.falsePositives ?? d.incidents.filter((i) => i.status === 'false_positive').length) + stories.filter((s) => s.verdict === 'benign' || s.verdict === 'false_positive').length
  // a confirmed item the print settings leave out is still confirmed: a presentation filter must not
  // turn "Compromise confirmed" into "Nothing confirmed"
  const unprinted = d.unprintedConfirmed ?? []
  const confirmed = confirmedChains.length + escalated.length + unprinted.length + confirmedStories.length
  const base = { confirmed, reviewed, falsePositives }
  const hidden = unprinted.length + confirmedStories.filter((s) => !s.printed).length
  const notPrinted = hidden ? t.verdict.notPrinted(hidden) : ''
  if (confirmed) {
    const sevs = [
      ...confirmedChains.map((c) => chainSeverity(c, d.reviews[c.id])),
      ...escalated.map((i) => i.severity),
      ...unprinted.map((u) => u.severity),
      ...confirmedStories.map((s) => s.severity),
    ]
    const severity = worstOf(sevs)
    const confirmedFindings = [
      ...escalated.flatMap((i) => i.findings),
      ...confirmedChains.flatMap((c) => d.membersOf.get(c.id) ?? []),
      ...unprinted.flatMap((u) => u.findings),
      ...confirmedStories.flatMap((s) => s.findings),
    ]
    // unwanted software is the verdict when a confirmed item names it and nothing confirmed rises above medium:
    // the runs of the same browser from a user profile are the same thing, not a second threat
    const unwantedPresent = confirmedFindings.some(isUnwanted)
    const onlyUnwanted = unwantedPresent && confirmedFindings.every((f) => isUnwanted(f) || userExecution(f))
    if (onlyUnwanted)
      return {
        ...base,
        kind: 'unwanted',
        severity,
        label: t.verdict.unwanted,
        detail: `${t.verdict.unwantedDetail(confirmed, severity)}${notPrinted}`,
      }
    if (rank(severity) >= rank('high'))
      return {
        ...base,
        kind: 'compromise',
        severity,
        label: t.verdict.compromise,
        detail: `${t.verdict.compromiseDetail(confirmed, severity)}${notPrinted}`,
      }
    return {
      ...base,
      kind: 'suspicious',
      severity,
      label: t.verdict.suspicious,
      detail: `${t.verdict.suspiciousDetail(confirmed, severity)}${notPrinted}`,
    }
  }
  if (reviewed)
    return {
      ...base,
      kind: 'unconfirmed',
      severity: null,
      label: t.verdict.unconfirmed,
      detail: t.verdict.unconfirmedDetail(reviewed, d.undecided),
    }
  if (d.undecided) return { ...base, kind: 'pending', severity: null, label: t.verdict.pending, detail: t.verdict.pendingDetail(d.undecided) }
  if (!d.findings.length && !d.chains.length && !d.incidents.length) return { ...base, kind: 'clean', severity: null, label: t.verdict.clean, detail: t.verdict.cleanEmpty }
  return { ...base, kind: 'clean', severity: null, label: t.verdict.clean, detail: t.verdict.cleanDetail(falsePositives) }
}

/** Why a non-package evidence file was not read completely, or '' when it was. */
export function evidenceIssue(e: Evidence, t: ReportText = EN): string {
  const stats = (e.stats ?? {}) as Record<string, unknown>
  if (e.status === 'error') return t.evidenceIssue.stopped(e.error ?? '')
  const errors = Number(stats.errors ?? 0)
  // a member skipped as out of scope ("not a mail file") was not evidence of this kind; one skipped
  // for a size limit, encryption or a compression method was, and was not read
  const members = (Array.isArray(stats.members) ? stats.members : Array.isArray(stats.files) ? stats.files : []) as { status?: string; reason?: string }[]
  const unread = members.filter((m) => m.status === 'skipped' && !/^not (a|an) /i.test(String(m.reason ?? ''))).length
  const bits: string[] = []
  if (errors > 0) bits.push(t.evidenceIssue.errors(errors))
  if (unread) bits.push(t.evidenceIssue.unread(unread))
  if (e.error) bits.push(e.error)
  return bits.join('; ')
}

export interface Confidence {
  level: 'high' | 'medium' | 'low'
  reasons: string[]
}

/**
 * How complete the review behind the report is: decisions made, evidence intact, analysis complete.
 * It says nothing of how sure the conclusion is, and the report prints it as completeness.
 */
export function computeConfidence(d: ReportData, t: ReportText = EN): Confidence {
  const reasons: string[] = []
  const w = t.completeness
  const decided = d.chains.filter((c) => d.reviews[c.id]?.verdict).length + d.incidents.filter((i) => i.status !== 'new').length
  const ratio = decided + d.undecided ? decided / (decided + d.undecided) : 1
  if (d.undecided) reasons.push(w.undecided(d.undecided))
  const unverified = d.evidence.filter((e) => e.integrity !== 'verified').length
  if (unverified) reasons.push(w.unverified(unverified))
  const issues = d.evidence.filter((e) => e.kind === 'package').flatMap((e) => packageCoverageIssues(e))
  if (issues.length) reasons.push(w.packages(issues.length))
  // a parse that failed, stopped at a limit, or skipped members read less than the file holds
  const incomplete = d.evidence.filter((e) => e.kind !== 'package' && evidenceIssue(e)).length
  if (incomplete) reasons.push(w.incomplete(incomplete))
  if (d.coverageWarnings?.length) reasons.push(w.chains(d.coverageWarnings.length))
  const rules = d.rules
  const rulesIssue = !!rules && (rules.lastRun == null || rules.evidenceAfter > 0 || rules.errors > 0)
  if (rules?.lastRun == null && rules) reasons.push(w.rulesNotRun)
  else if (rules?.evidenceAfter) reasons.push(w.evidenceAfter(rules.evidenceAfter))
  if (rules?.errors) reasons.push(w.rulesFailed(rules.errors))
  if (!(d.iocsChecked ?? 0)) reasons.push(w.notEnriched)
  const complete = !issues.length && !incomplete && !d.coverageWarnings?.length && !rulesIssue
  const level: Confidence['level'] = ratio >= 0.95 && !unverified && complete ? 'high' : ratio >= 0.7 && !unverified ? 'medium' : 'low'
  if (level === 'high') reasons.unshift(w.complete)
  return { level, reasons }
}

interface BadgeDef {
  id: string
  code: string
  label: string
  /** ATT&CK technique prefixes */
  tech: string[]
  /** rule tags */
  tags: string[]
  /** words in the rule id or title */
  words?: RegExp
}
/** The threat profile the cover shows: ATT&CK tactics, plus unwanted software, which ATT&CK has no tactic for. */
export const BADGES: BadgeDef[] = [
  { id: 'initial-access', code: 'IA', label: 'Initial access', tech: ['T1566', 'T1190', 'T1133', 'T1199'], tags: ['phishing', 'initial-access', 'mail-led'] },
  { id: 'execution', code: 'EX', label: 'Execution', tech: ['T1059', 'T1204', 'T1047', 'T1106', 'T1129'], tags: ['execution'] },
  { id: 'persistence', code: 'PE', label: 'Persistence', tech: ['T1543', 'T1547', 'T1053', 'T1136', 'T1098', 'T1505', 'T1137', 'T1546'], tags: ['persistence', 'account'] },
  { id: 'privilege', code: 'PR', label: 'Privilege escalation', tech: ['T1548', 'T1134', 'T1068', 'T1484'], tags: ['privilege'] },
  {
    // ATT&CK v19 split Defense Evasion into Stealth (TA0005) and Defense Impairment (TA0112) and
    // moved Impair Defenses (T1562) and event-log clearing to T1685-T1690; the badge reads both
    id: 'defense-evasion',
    code: 'DE',
    label: 'Defense evasion',
    tech: ['T1562', 'T1070', 'T1027', 'T1218', 'T1036', 'T1112', 'T1197', 'T1553', 'T1685', 'T1686', 'T1688', 'T1689', 'T1690'],
    tags: ['defense-evasion', 'log-tampering', 'defender', 'blocked'],
  },
  { id: 'credential', code: 'CA', label: 'Credential access', tech: ['T1003', 'T1110', 'T1555', 'T1558', 'T1556', 'T1187', 'T1552'], tags: ['credential', 'brute-force', 'authentication'] },
  { id: 'discovery', code: 'DI', label: 'Discovery', tech: ['T1087', 'T1082', 'T1018', 'T1016', 'T1069', 'T1083', 'T1049', 'T1033'], tags: ['discovery'] },
  { id: 'lateral', code: 'LM', label: 'Lateral movement', tech: ['T1021', 'T1569', 'T1570', 'T1550', 'T1080'], tags: ['lateral-movement'] },
  { id: 'collection', code: 'CO', label: 'Collection', tech: ['T1114', 'T1005', 'T1074', 'T1560', 'T1039', 'T1113'], tags: ['collection', 'mailbox'] },
  { id: 'c2', code: 'C2', label: 'Command and control', tech: ['T1071', 'T1105', 'T1568', 'T1572', 'T1090', 'T1219', 'T1102', 'T1573'], tags: ['c2', 'network'] },
  { id: 'exfil', code: 'EF', label: 'Exfiltration', tech: ['T1041', 'T1048', 'T1567', 'T1020', 'T1029'], tags: ['exfiltration', 'forwarding'] },
  { id: 'impact', code: 'IM', label: 'Impact', tech: ['T1486', 'T1490', 'T1489', 'T1529', 'T1485', 'T1491'], tags: ['impact', 'ransomware'] },
  { id: 'unwanted', code: 'PU', label: 'Unwanted software', tech: [], tags: ['pua', 'adware', 'unwanted'], words: /pua|adware|unwanted/i },
]

export interface BadgeState {
  def: BadgeDef
  state: 'confirmed' | 'observed' | 'none'
  findings: number
  techniques: string[]
}

const badgesOf = (f: Finding): BadgeDef[] =>
  BADGES.filter(
    (b) =>
      f.attack.some((t) => b.tech.some((p) => t.toUpperCase().startsWith(p))) ||
      (f.tags ?? []).some((t) => b.tags.includes(t.toLowerCase())) ||
      (b.words ? b.words.test(f.ruleId) || b.words.test(f.title) : false),
  )

/** Each tactic with what the report has for it: confirmed when a confirmed item carries it, observed when any printed finding does. */
export function threatProfile(d: ReportData): BadgeState[] {
  const confirmedIds = new Set<number>()
  for (const i of d.incidents) if (i.status === 'escalated') for (const f of i.findings) if (f.id != null) confirmedIds.add(f.id)
  for (const c of d.chains) if (d.reviews[c.id]?.verdict === 'confirmed') for (const f of d.membersOf.get(c.id) ?? []) if (f.id != null) confirmedIds.add(f.id)
  for (const s of d.decidedStories ?? []) if (s.verdict === 'confirmed') for (const f of s.findings) if (f.id != null) confirmedIds.add(f.id)
  const printed = d.findings.filter((f) => f.status !== 'false_positive')
  return BADGES.map((def) => {
    const mine = printed.filter((f) => badgesOf(f).includes(def))
    const confirmed = mine.some((f) => f.id != null && confirmedIds.has(f.id)) || (def.id === 'initial-access' && d.chains.some((c) => d.reviews[c.id]?.verdict === 'confirmed'))
    const techniques = [...new Set(mine.flatMap((f) => f.attack.filter((t) => def.tech.some((p) => t.toUpperCase().startsWith(p)))))].sort().slice(0, 6)
    return { def, state: confirmed ? 'confirmed' : mine.length ? 'observed' : 'none', findings: mine.length, techniques }
  })
}

// ---------------------------------------------------------------------------
// what a client report adds: the scope, the impact, the indicators, the techniques
// ---------------------------------------------------------------------------

/** What the case's evidence covers, for the scope: the hosts its records come from and the accounts they name, the most frequent first. */
export interface EvidenceScope {
  hosts: string[]
  /** the evidence names more hosts than were read: the list holds the most frequent ones */
  hostsCapped: boolean
  accounts: string[]
  accountsCapped: boolean
}

/** how many hosts and accounts the scope reads from the evidence; past it the report says the evidence names more */
export const SCOPE_READ = 500

/** The hosts the evidence's records come from and the user accounts they name (machine, service and built-in accounts left out), the most frequent first. */
export function evidenceScope(hosts: FacetItem[], userFields: FacetItem[][]): EvidenceScope {
  const accounts = new Map<string, { value: string; count: number }>()
  for (const u of userFields.flat()) {
    if (!userKey(u.value)) continue
    const k = u.value.toLowerCase()
    const a = accounts.get(k)
    if (a) a.count += u.count
    else accounts.set(k, { value: u.value, count: u.count })
  }
  return {
    hosts: hosts.map((x) => x.value).filter((x) => x.trim()),
    hostsCapped: hosts.length >= SCOPE_READ,
    accounts: [...accounts.values()].sort((a, b) => b.count - a.count).map((a) => a.value),
    accountsCapped: userFields.some((xs) => xs.length >= SCOPE_READ),
  }
}

/** The first and last event or message time the evidence holds, from each file's own range. */
export function evidencePeriod(evidence: Evidence[]): { from: number | null; to: number | null } {
  let from: number | null = null
  let to: number | null = null
  const take = (r?: { firstTs?: number | null; lastTs?: number | null }) => {
    if (r?.firstTs != null && Number.isFinite(r.firstTs)) from = from == null ? r.firstTs : Math.min(from, r.firstTs)
    if (r?.lastTs != null && Number.isFinite(r.lastTs)) to = to == null ? r.lastTs : Math.max(to, r.lastTs)
  }
  for (const e of evidence) {
    const s = e.stats as { firstTs?: number; lastTs?: number; eventRange?: { firstTs?: number; lastTs?: number }; mailRange?: { firstTs?: number; lastTs?: number } } | undefined
    if (!s) continue
    if (e.kind === 'package') {
      take(s.eventRange)
      take(s.mailRange)
    } else take(s)
  }
  return { from, to }
}

/** The items the analyst confirmed, printed or not, each with what it names: what the impact and the indicators are drawn from. */
interface ConfirmedItem {
  label: string
  severity: Severity
  start: number | null
  end: number | null
  findings: Finding[]
  accounts: string[]
  hosts: string[]
  addresses: string[]
}

function confirmedItems(d: ReportData, t: ReportText): ConfirmedItem[] {
  const out: ConfirmedItem[] = []
  for (const c of d.chains) {
    if (d.reviews[c.id]?.verdict !== 'confirmed') continue
    out.push({
      label: t.client.item.chain(c.identityLabel),
      severity: chainSeverity(c, d.reviews[c.id]),
      start: c.start,
      end: c.end,
      findings: d.membersOf.get(c.id) ?? [],
      accounts: [c.identityLabel],
      hosts: c.entities.hosts,
      addresses: [...c.entities.attackerAddresses, ...(c.seed.fromAddr ? [c.seed.fromAddr] : []), ...c.entities.ips, ...c.entities.domains],
    })
  }
  for (const i of d.incidents)
    if (i.status === 'escalated') out.push({ label: t.client.item.incident(i.title), severity: i.severity, start: i.ts, end: i.tsEnd, findings: i.findings, accounts: [], hosts: [], addresses: [] })
  for (const u of d.unprintedConfirmed ?? [])
    out.push({
      label: t.client.item.unprinted(u.findings[0]?.title ?? ''),
      severity: u.severity,
      start: null,
      end: null,
      findings: u.findings,
      accounts: [],
      hosts: [],
      addresses: [],
    })
  for (const st of d.decidedStories ?? []) {
    if (st.verdict !== 'confirmed') continue
    out.push({
      label: t.client.item.story(st.title),
      severity: st.severity,
      start: st.start,
      end: st.end,
      findings: st.findings,
      accounts: st.subject?.kind === 'person' ? [st.subject.label] : [],
      hosts: [...(st.subject?.kind === 'host' ? [st.subject.label] : []), ...st.hosts],
      addresses: st.attackerAddresses ?? [],
    })
  }
  return out
}

/** An account or host a confirmed item names: when, how bad at worst, and which items name it. */
export interface AffectedAsset {
  name: string
  /** other ways the evidence writes the same host */
  aliases: string[]
  first: number | null
  last: number | null
  severity: Severity
  from: string[]
}

/**
 * The accounts and hosts the analyst's confirmed items name, printed or not: the people a confirmed
 * chain or story is about, the hosts it ran on, and the accounts and hosts of the findings confirmed
 * with it. Machine, service and well-known accounts are left out; nothing the analyst did not confirm is in it.
 */
export function impactInventory(d: ReportData, t: ReportText = EN): { accounts: AffectedAsset[]; hosts: AffectedAsset[] } {
  const accounts = new Map<string, AffectedAsset>()
  const hosts = new Map<string, AffectedAsset>()
  const add = (into: Map<string, AffectedAsset>, key: string, name: string, it: ConfirmedItem, first: number | null, last: number | null, severity: Severity) => {
    if (!key) return
    const a = into.get(key) ?? into.set(key, { name, aliases: [], first: null, last: null, severity, from: [] }).get(key)!
    if (name !== a.name && !a.aliases.includes(name) && a.aliases.length < 3) a.aliases.push(name)
    if (first != null) a.first = a.first == null ? first : Math.min(a.first, first)
    if (last != null) a.last = a.last == null ? last : Math.max(a.last, last)
    if (rank(severity) > rank(a.severity)) a.severity = severity
    if (!a.from.includes(it.label)) a.from.push(it.label)
  }
  for (const it of confirmedItems(d, t)) {
    for (const acc of it.accounts) add(accounts, acc.trim().toLowerCase(), acc.trim(), it, it.start, it.end, it.severity)
    for (const host of it.hosts) add(hosts, hostKey(host), host, it, it.start, it.end, it.severity)
    for (const f of it.findings) {
      const sev = effectiveSeverity(f)
      for (const k of USER_FIELDS) {
        const v = String(f.entities[k] ?? '').trim()
        if (v && userKey(v)) add(accounts, v.toLowerCase(), v, it, f.ts, f.tsEnd ?? f.ts, sev)
      }
      // the host a record was written on; a workstation field names where a logon came from, which may be the attacker's own
      for (const k of HOST_FIELDS.filter((x) => x !== 'workstation')) {
        const v = String(f.entities[k] ?? '').trim()
        add(hosts, hostKey(v), v, it, f.ts, f.tsEnd ?? f.ts, sev)
      }
    }
  }
  const order = (a: AffectedAsset, b: AffectedAsset) => rank(b.severity) - rank(a.severity) || (a.first ?? Infinity) - (b.first ?? Infinity) || a.name.localeCompare(b.name)
  return { accounts: [...accounts.values()].sort(order), hosts: [...hosts.values()].sort(order) }
}

export type IndicatorKind = 'ip' | 'domain' | 'email' | 'url' | 'hash'
/** An indicator the report lists, with where it comes from: a confirmed item, or a reputation service that flagged it. */
export interface IndicatorRow {
  kind: IndicatorKind
  value: string
  from: string[]
  /** a reputation verdict, when a lookup gave one */
  verdict: string | null
}
/** the most indicators the appendix lists; the report says how many more there are */
export const MAX_INDICATORS = 300

const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/
const IPV6 = /^[0-9a-f:]+$/i
const DOMAIN = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i
const EMAIL = /^[^@\s]+@([^@\s]+\.[a-z]{2,63})$/i
const URL_RE = /^(?:https?|ftp):\/\/\S+$/i
const HASHES = /(?:^|[^0-9a-f])([0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-f])/gi
const HASH_KEY = /hash|sha256|sha1|md5|imphash/i
const DOMAIN_KEY = /domain$|^query(name)?$|registrable/i

/** What kind of indicator a finding's field holds, if any, read from its value and, for hashes and domains, its name. */
function indicatorsOf(key: string, raw: unknown): { kind: IndicatorKind; value: string }[] {
  const values = (Array.isArray(raw) ? raw.map(String) : [String(raw ?? '')]).map((v) => v.trim()).filter(Boolean)
  const out: { kind: IndicatorKind; value: string }[] = []
  for (const v of values) {
    if (HASH_KEY.test(key)) {
      for (const m of v.matchAll(HASHES)) out.push({ kind: 'hash', value: m[1].toLowerCase() })
      continue
    }
    if (IPV4.test(v) || (v.includes(':') && IPV6.test(v))) out.push({ kind: 'ip', value: v.toLowerCase() })
    else if (URL_RE.test(v)) out.push({ kind: 'url', value: v })
    else if (EMAIL.test(v)) out.push({ kind: 'email', value: v.toLowerCase() })
    else if (DOMAIN_KEY.test(key) && DOMAIN.test(v)) out.push({ kind: 'domain', value: v.toLowerCase().replace(/\.$/, '') })
  }
  return out
}

/**
 * The indicators of the attack: the addresses, domains, mail senders, URLs and hashes the confirmed
 * chains, stories and findings name, whether or not a reputation lookup ran, and those a reputation
 * service flagged. Addresses that are not public and the case's own domains are left out: they are
 * the victim's, not the attacker's. Each says where it comes from.
 */
export function indicatorAppendix(d: ReportData, t: ReportText = EN): { rows: IndicatorRow[]; left: number } {
  const internal = d.kase.settings.internalDomains.map((x) => x.toLowerCase().replace(/^\.+/, '')).filter(Boolean)
  const isInternal = (domain: string) => internal.some((x) => domain === x || domain.endsWith(`.${x}`))
  const keep = (kind: IndicatorKind, value: string) => {
    if (kind === 'ip') return isPublicIp(value)
    if (kind === 'domain') return !isInternal(value)
    if (kind === 'email') return !isInternal(value.split('@')[1] ?? '')
    if (kind === 'url') return !isInternal((/^[a-z]+:\/\/([^/:?#]+)/i.exec(value)?.[1] ?? '').toLowerCase())
    return true
  }
  const rows = new Map<string, IndicatorRow>()
  const add = (kind: IndicatorKind, value: string, from: string, verdict: string | null = null) => {
    if (!keep(kind, value)) return
    const k = `${kind}:${value}`
    const r = rows.get(k) ?? rows.set(k, { kind, value, from: [], verdict: null }).get(k)!
    if (!r.from.includes(from)) r.from.push(from)
    if (verdict) r.verdict = verdict
  }
  for (const it of confirmedItems(d, t)) {
    for (const a of it.addresses) for (const x of indicatorsOf('address', a)) add(x.kind, x.value, it.label)
    for (const f of it.findings) for (const [k, v] of Object.entries(f.entities)) for (const x of indicatorsOf(k, v)) add(x.kind, x.value, t.client.item.finding(f.title, f.ruleId))
  }
  for (const i of d.iocs) {
    const kind: IndicatorKind | null = i.kind === 'ip' || i.kind === 'domain' || i.kind === 'url' || i.kind === 'hash' ? i.kind : i.kind === 'email' ? 'email' : null
    if (kind) add(kind, i.kind === 'url' ? i.value : i.value.toLowerCase(), t.client.item.lookup(i.sources), i.verdict ?? null)
  }
  const order: IndicatorKind[] = ['ip', 'domain', 'email', 'url', 'hash']
  const all = [...rows.values()].sort((a, b) => order.indexOf(a.kind) - order.indexOf(b.kind) || a.value.localeCompare(b.value))
  return { rows: all.slice(0, MAX_INDICATORS), left: Math.max(0, all.length - MAX_INDICATORS) }
}

/** An ATT&CK technique the printed or confirmed findings carry: its tactics, how many findings, which rules, and whether a confirmed item carries it. */
export interface TechniqueRow {
  id: string
  tactics: string[]
  findings: number
  rules: string[]
  confirmed: boolean
}

/** Every ATT&CK technique of the printed findings (false positives left out) and of the confirmed ones, in the tactics' order. */
export function techniqueTable(d: ReportData, t: ReportText = EN): TechniqueRow[] {
  const confirmed = new Set<Finding>(confirmedItems(d, t).flatMap((it) => it.findings))
  const confirmedIds = new Set([...confirmed].map((f) => f.id).filter((x) => x != null))
  const seen = new Map<number | string, Finding>()
  for (const f of [...d.findings.filter((x) => x.status !== 'false_positive'), ...confirmed]) seen.set(f.id ?? f.key, f)
  const rows = new Map<string, TechniqueRow & { order: number }>()
  for (const f of seen.values())
    for (const raw of f.attack) {
      const id = raw.trim().toUpperCase()
      if (!/^T\d{4}(\.\d{3})?$/.test(id)) continue
      const defs = BADGES.filter((b) => b.tech.some((p) => id.startsWith(p)))
      const r =
        rows.get(id) ??
        rows.set(id, { id, tactics: defs.map((b) => t.tactic[b.id] ?? b.label), findings: 0, rules: [], confirmed: false, order: defs.length ? BADGES.indexOf(defs[0]) : BADGES.length }).get(id)!
      r.findings++
      const rule = f.title.replace(/\s+→.*$/, '')
      if (!r.rules.includes(rule)) r.rules.push(rule)
      if (confirmed.has(f) || (f.id != null && confirmedIds.has(f.id))) r.confirmed = true
    }
  return [...rows.values()].sort((a, b) => a.order - b.order || a.id.localeCompare(b.id)).map(({ order: _order, ...r }) => r)
}

/**
 * A starting point for the initial access, drawn from a story's spine: the confirmed story first,
 * else the first printed. It is offered to the analyst to rewrite, never printed as it is.
 */
export function spineStartingPoint(stories: ReportStory[], t: ReportText = EN): string {
  const pick = stories.find((s) => s.decisions?.call?.verdict === 'confirmed' && storySpineRows(s.story)) ?? stories.find((s) => storySpineRows(s.story))
  const spine = pick && storySpineRows(pick.story, t)
  if (!pick || !spine) return ''
  const at = (r: SpineRow) => t.story.startAt(r.title, r.host, t.ts(r.ts))
  const anchor = spine.rows.find((r) => r.anchor)
  return [t.story.startFrom(pick.story.title, spine.rows.filter((r) => r.wayIn).map(at), at(spine.rows[0])), anchor ? t.story.startWorst(at(anchor)) : ''].filter(Boolean).join(' ')
}

const HEX = '<svg viewBox="0 0 100 100" aria-hidden="true"><polygon points="50,3 92,26.5 92,73.5 50,97 8,73.5 8,26.5"/></svg>'
const badge = (t: ReportText, b: BadgeState) => {
  const label = t.tactic[b.def.id] ?? b.def.label
  return `<div class="hex ${b.state}" title="${h(t.cover.badgeTitle(label, b.findings))}${b.techniques.length ? ' · ' + h(b.techniques.join(', ')) : ''}">${HEX}<span class="code">${h(b.def.code)}</span><span class="lbl">${h(label)}</span><span class="n">${b.state === 'none' ? '' : t.num(b.findings)}</span></div>`
}

/** The seal on the cover: a hexagon with the verdict, coloured by what it says. */
const seal = (t: ReportText, v: Verdict) =>
  `<div class="seal ${v.kind}">${HEX}<div class="seal-in"><span class="k">${h(t.cover.seal)}</span><span class="w">${h(v.label)}</span>${v.severity ? `<span class="s">${h(t.sev[v.severity] ?? v.severity)}</span>` : ''}</div></div>`

// ---------------------------------------------------------------------------
// chains
// ---------------------------------------------------------------------------

/** The most step rows a chain prints; the rest is summarised in one line. */
export const MAX_STEP_ROWS = 60

export interface FoldedStep {
  step: ChainStep
  /** rows folded into this one (the same step repeating in a run) */
  n: number
  ts: number
  tsEnd: number
  offsetMin: number
  offsetEnd: number
}

/** Consecutive steps that say the same thing (title, source, machine, ties) print as one row with a count and a time span. */
export function foldSteps(steps: ChainStep[]): FoldedStep[] {
  const key = (s: ChainStep) => [s.title, s.kind, s.origin ?? '', s.computer ?? '', s.ipAddress ?? '', [...s.artifacts, ...s.findings.map((f) => f.title)].join(';')].join('')
  const out: FoldedStep[] = []
  for (const s of steps) {
    const last = out[out.length - 1]
    if (last && key(last.step) === key(s)) {
      last.n += 1
      last.tsEnd = Math.max(last.tsEnd, s.tsEnd || s.ts)
      last.offsetEnd = Math.max(last.offsetEnd, s.offsetMin)
    } else out.push({ step: s, n: 1, ts: s.ts, tsEnd: s.tsEnd || s.ts, offsetMin: s.offsetMin, offsetEnd: s.offsetMin })
  }
  return out
}

function meter(t: ReportText, c: Chain): string {
  const b = c.scoreBreakdown
  const w = t.chain.scoreParts
  const parts: [string, number][] = b
    ? [
        [w.seed, b.seed],
        [w.links, b.links],
        [w.steps, b.steps],
        [w.findings, b.findings],
        [w.sources, b.sources],
      ]
    : [[w.score, c.score]]
  const total = Math.max(
    1,
    parts.reduce((s, [, v]) => s + v, 0),
  )
  const colours = ['#1b7f66', '#2fbf8f', '#2f6fdb', '#d9822b', '#8a95a3']
  const segs = parts.map(([k, v], i) => `<span title="${h(k)} ${v}" style="width:${((v / total) * 100).toFixed(1)}%;background:${colours[i % colours.length]}"></span>`).join('')
  return `<span class="meter" title="${h(parts.map(([k, v]) => `${k} ${v}`).join(' · '))}"><span class="bar">${segs}</span><span>${h(t.chain.score(c.score, b?.cap))}</span></span>`
}

function chainCard(t: ReportText, c: Chain, d: ReportData): string {
  const r = d.reviews[c.id]
  const visible = c.steps.filter((s) => stepVisible(s, d.settings.chainDetail))
  const hidden = c.steps.length - visible.length
  const folded = foldSteps(visible)
  const printed = folded.slice(0, MAX_STEP_ROWS)
  const left = folded.length - printed.length
  const members = d.membersOf.get(c.id) ?? []
  const offset = (f: FoldedStep) =>
    f.n > 1 && f.offsetEnd !== f.offsetMin
      ? `${f.offsetMin >= 0 ? '+' : ''}${Math.round(f.offsetMin)} → ${f.offsetEnd >= 0 ? '+' : ''}${Math.round(f.offsetEnd)} ${t.chain.minutes}`
      : `${f.offsetMin >= 0 ? '+' : ''}${Math.round(f.offsetMin)} ${t.chain.minutes}`
  const when = (f: FoldedStep) => (f.n > 1 && f.tsEnd !== f.ts ? `${t.ts(f.ts)}<span class="sub">${t.to} ${t.ts(f.tsEnd)}</span>` : t.ts(f.ts))
  const narrative = r?.narrative
    ? `<div class="narr">${md(r.narrative)}</div>${r.narrativeBy === 'ai' ? `<div class="cap ai">${h(t.chain.narrativeByAi)}</div>` : ''}${textNote(t, `chain:${c.id}`, d.claims)}`
    : `<div class="narr"><p>${h(c.summary)}</p></div>`
  const sev = chainSeverity(c, r)
  // the dictionary's words hold no markup: the subject and the sender go in escaped, the sender as code
  const seed = t.chain.seed(c.seed.source === 'events' ? 'event' : 'mail', h(c.seed.subject), `<code>${h(c.seed.fromAddr ?? '')}</code>`, t.ts(c.seed.ts), c.seed.risk)
  const lane = (s: ChainStep) => (s.kind === 'mail' ? 'mail' : s.origin === 'm365' ? 'm365' : 'host')
  return `<div class="card chain ${h(sev)}">
<div class="card-head">${pill(t, sev)}<h3>${h(c.identityLabel)}</h3>${verdictPill(t, r?.verdict)}${meter(t, c)}</div>
<div class="card-meta">${seed} · ${h(t.chain.steps(c.steps.length, t.ts(c.start), t.ts(c.end)))} · ${h(t.chain.ties(c.artifactLinks))}${c.entities.attackerAddresses.length ? ` · ${h(t.chain.attacker)} <code>${h(c.entities.attackerAddresses.join(', '))}</code>` : ''}${c.entities.ips.length ? ` · ${h(t.chain.ips)} <code>${h(c.entities.ips.join(', '))}</code>` : ''}${c.entities.hosts.length ? ` · ${h(t.chain.hosts)} <code>${h(c.entities.hosts.join(', '))}</code>` : ''}</div>
${narrative}
${d.settings.includeGraphs ? img(d.graphs[c.id], t.chain.graphAlt(c.identityLabel), t.chain.graphCaption, chainKey(t)) : ''}
${table(
  t.chain.head,
  printed.map((f) => {
    const s = f.step
    return [
      `<span class="nowrap">${when(f)}</span>`,
      `<span class="nowrap">${offset(f)}</span>`,
      `<span class="lane ${lane(s)}"></span>${h(t.lane[lane(s)])}`,
      h(s.title) +
        (f.n > 1 ? ` <span class="chip">×${f.n}</span>` : s.count > 1 ? ` <span class="chip">×${s.count}</span>` : '') +
        (s.computer || s.ipAddress ? `<span class="sub">${h([s.computer, s.ipAddress].filter(Boolean).join(' · '))}</span>` : ''),
      h([...s.artifacts, ...s.findings.map((x) => x.title)].join('; ')),
    ]
  }),
)}
${left || hidden ? `<div class="cap">${left ? h(t.chain.left(left)) : ''}${left && hidden ? ' · ' : ''}${hidden ? h(t.chain.hidden(hidden, d.settings.chainDetail)) : ''}.</div>` : ''}
${members.length ? `<div class="cap" style="margin-top:8px">${h(t.chain.members(members.length))}</div>${groupedFindings(t, members, {}, d.measures, d.claims, d.ruleAuthors)}` : ''}
${r?.by === 'ai' && r.aiReason ? `<div class="cap ai">${h(t.chain.triage(r.aiReason))}</div>` : ''}
</div>`
}

// ---------------------------------------------------------------------------
// stories
// ---------------------------------------------------------------------------

/**
 * The analyst's decisions on a story, one plain sentence each: the decision and its reason, what was
 * merged, split, taken out and disputed. The HTML and the Word report print the same sentences.
 */
export function storyDecisionTexts(dec: ReportStory['decisions'], t: ReportText = EN): string[] {
  if (!dec) return []
  const w = t.story
  return [
    dec.call ? w.decided(t.storyVerdict[dec.call.verdict] ?? dec.call.verdict, dec.call.reason ?? '') : '',
    ...dec.merged.map((m) => w.merged(m.title, m.orgs, m.reason)),
    dec.split ? w.split(dec.part === 'second', dec.split.title, t.ts(dec.split.ts), dec.split.reason) : '',
    ...dec.out.map((o) => w.out(o.title, o.count, o.reason)),
    ...dec.disputed.map((x) => w.disputed(x.title, t.ts(x.ts), x.reason ?? '')),
    dec.confirmedSteps ? w.confirmedSteps(dec.confirmedSteps) : '',
  ].filter(Boolean)
}
const storyDecisionLines = (t: ReportText, dec: ReportStory['decisions']): string =>
  storyDecisionTexts(dec, t)
    .map((l) => `<div class="cap">${h(l)}</div>`)
    .join('')

const STORY_PILL: Record<string, string> = { confirmed: 'confirmed', reviewed: 'unsure' }

/**
 * A story's spine (docs/stories.md, "Spine"): the steps that carry it from the way in to the worst of
 * it, in time order, each with the tie that put it in the story, and how the spine was drawn. Nothing
 * for a story built before spines.
 */
/** A row of a story's spine, in plain values: the HTML and the Word report lay it out each their way. */
export interface SpineRow {
  ts: number
  tsEnd: number
  /** the severity of the step's worst finding */
  severity: Severity | null
  phase: string
  title: string
  host: string | null
  wayIn: boolean
  anchor: boolean
  /** the title of the step's worst finding, and how many more it has */
  finding: string | null
  more: number
  why: string
}

/** A story's spine as rows, with how many of its steps it holds and how it was drawn; null for a story built before spines. */
export function storySpineRows(s: ReportStory['story'], t: ReportText = EN): { rows: SpineRow[]; of: number; basis: string | null } | null {
  const steps = spineSteps(s)
  if (!steps?.length) return null
  const basis = spineBasis(s)
  const ways = new Set(basis?.wayIn ?? [])
  const rows = steps.map((st) => {
    const f = [...st.findings].sort((a, b) => rank(b.severity) - rank(a.severity))[0]
    return {
      ts: st.ts,
      tsEnd: st.tsEnd,
      severity: f?.severity ?? null,
      phase: st.phase ? (t.phase[st.phase] ?? st.phase) : t.phase.context,
      title: st.title,
      host: st.host,
      wayIn: ways.has(st.id),
      anchor: st.id === basis?.anchor,
      finding: f?.title ?? null,
      more: Math.max(0, st.findings.length - 1),
      why: `${t.tie[st.tie.confidence] ?? st.tie.confidence}: ${st.tie.basis}`,
    }
  })
  return { rows, of: s.steps.length, basis: basis?.text ?? null }
}

function storySpine(t: ReportText, s: ReportStory['story']): string {
  const spine = storySpineRows(s, t)
  if (!spine) return ''
  return `<div class="story-part">${h(t.story.spine(spine.rows.length, spine.of))}</div>
${table(
  t.story.spineHead,
  spine.rows.map((r) => [
    `<span class="nowrap">${span(t, r.ts, r.tsEnd)}</span>`,
    `${r.severity ? pill(t, r.severity) + ' ' : ''}${h(r.phase)}`,
    `${h(r.title)}${r.host ? ` <span class="dim">${h(t.story.on)}</span> <code>${h(r.host)}</code>` : ''}${r.wayIn ? ' ' + chip(t.story.wayIn) : ''}${r.anchor ? ' ' + chip(t.story.anchor) : ''}${r.finding ? `<span class="sub">${h(r.finding)}${r.more ? ` +${t.num(r.more)}` : ''}</span>` : ''}`,
    h(r.why),
  ]),
)}
${spine.basis ? `<div class="cap">${h(spine.basis)}</div>` : ''}
<div class="story-part">${h(t.story.phases)}</div>`
}

/** A story: its spine, its phases in the order they happened, what marks each (its worst findings, else its first step), the analyst's decisions on it, and where its evidence stops. */
/**
 * A story's phases in the order they happened, each with what marks it: its worst findings, else its
 * first step (`step` set). A step the analyst disputed marks no phase.
 */
export function storyPhaseRows(
  s: ReportStory['story'],
  dec: ReportStory['decisions'],
  t: ReportText = EN,
): { severity: Severity | null; label: string; first: number; last: number; steps: number; marks: string; step: boolean }[] {
  const disputed = new Set((dec?.disputed ?? []).map((x) => x.id))
  return s.phases.map((p) => {
    const steps = s.steps.filter((st) => st.phase === p.phase && !disputed.has(st.id))
    const found = steps.flatMap((st) => st.findings).sort((a, b) => rank(b.severity) - rank(a.severity))
    const titles = [...new Set(found.map((f) => f.title))]
    const marks = titles.length ? titles.slice(0, 2).join('; ') + (titles.length > 2 ? ' …' : '') : (steps[0]?.title ?? '')
    return { severity: p.severity, label: t.phase[p.phase] ?? p.label, first: p.first, last: p.last, steps: p.steps, marks, step: !titles.length }
  })
}

/** Who a story is about, when, and where: hosts and the outside addresses it came from, the first six of each. */
export function storyWhere(s: ReportStory['story'], t: ReportText = EN): { who: string; hosts: string; hostsMore: number; from: string } {
  return {
    who: `${s.kind === 'host' ? t.story.host : t.story.person} ${s.subject.label}`,
    hosts: s.hosts.slice(0, 6).join(', '),
    hostsMore: Math.max(0, s.hosts.length - 6),
    from: s.attackerAddresses.slice(0, 6).join(', '),
  }
}

/** The part of a split story a card prints, after its title. */
export const storyPart = (dec: ReportStory['decisions'], t: ReportText = EN): string => (dec?.part === 'second' ? t.story.secondPart : dec?.part === 'first' ? t.story.firstPart : '')

function storyCard(t: ReportText, { story: s, key, note, decisions: dec }: ReportStory, d: ReportData): string {
  // the build's own limits are printed once, above the stories
  const gaps = storyOwnGaps(s)
  const w = storyWhere(s, t)
  const where = [w.hosts ? `${h(t.story.hosts)} <code>${h(w.hosts)}</code>${w.hostsMore ? ` +${w.hostsMore}` : ''}` : '', w.from ? `${h(t.story.from)} <code>${h(w.from)}</code>` : ''].filter(Boolean)
  return `<div class="card chain ${h(s.severity)}">
<div class="card-head">${pill(t, s.severity)}<h3>${h(s.title)}${h(storyPart(dec, t))}</h3>${dec?.call ? `<span class="pill verdict-${STORY_PILL[dec.call.verdict] ?? 'benign'}">${h(t.storyVerdict[dec.call.verdict] ?? dec.call.verdict)}</span>` : ''}${chip(t.story.confidence(t.level[s.confidence] ?? s.confidence))}</div>
<div class="card-meta">${h(w.who)} · ${span(t, s.start, s.end)} · ${h(t.story.records(s.records, s.steps.length))}${where.length ? ' · ' + where.join(' · ') : ''}</div>
${note ? `<div class="narr">${md(note)}</div><div class="cap">${h(t.story.note)}</div>${textNote(t, `story:${key}`, d.claims)}` : `<div class="narr"><p>${h(s.summary || s.headline)}</p></div>`}
${storySpine(t, s)}
${table(
  t.story.phaseHead,
  storyPhaseRows(s, dec, t).map((p) => [
    `${p.severity ? pill(t, p.severity) + ' ' : ''}${h(p.label)}`,
    `<span class="nowrap">${span(t, p.first, p.last)}</span>`,
    t.num(p.steps),
    p.step ? `<span class="dim">${h(p.marks)}</span>` : h(p.marks),
  ]),
)}
${storyDecisionLines(t, dec)}
${gaps.length ? `<div class="cap">${h(t.story.stops)} ${gaps.map((g) => h(g)).join(' ')}</div>` : ''}
</div>`
}

/**
 * The printed stories, each incident's together under one heading that says why they read as one
 * intrusion (the strong and medium links between them) and what of it is not printed.
 */
function storyCards(t: ReportText, d: ReportData): string {
  return groupByIncident(d.stories ?? [], (r) => r.story, d.storyIncidents)
    .map(({ incident: i, items }) => {
      const cards = items.map((st) => storyCard(t, st, d)).join('\n')
      if (!i) return cards
      const bases = incidentBases(items, t)
      const unprinted = i.stories.length - items.length
      return `<div class="story-inc">
<div class="card-head">${pill(t, i.severity)}<h3>${h(t.story.intrusion(i.label))}</h3>${chip(t.story.count(i.stories.length))}</div>
<div class="card-meta">${span(t, i.start, i.end)}${i.hosts.length ? ` · ${h(t.story.hosts)} <code>${h(i.hosts.slice(0, 6).join(', '))}</code>${i.hosts.length > 6 ? ` +${i.hosts.length - 6}` : ''}` : ''}</div>
${bases.length ? `<div class="cap">${h(t.story.whyOne(`${bases.slice(0, 4).join('; ')}${bases.length > 4 ? ` ${t.andMore(bases.length - 4)}` : ''}`))}.</div>` : ''}${
        unprinted > 0 ? `<div class="cap">${h(t.story.unprinted(unprinted))}</div>` : ''
      }${i.cut ? `<div class="cap warn">${h(t.story.cut(i.cut))}</div>` : ''}
${cards}
</div>`
    })
    .join('\n')
}

/** Why the printed stories of one incident read as one intrusion: the strong and medium links between them. */
export function incidentBases(items: ReportStory[], t: ReportText = EN): string[] {
  const inside = new Set(items.map((r) => r.story.id))
  const why = new Map<string, string>()
  for (const { story } of items)
    for (const l of story.links ?? []) if (l.confidence !== 'weak' && inside.has(l.story)) why.set([story.id, l.story].sort().join('|'), `${l.basis} (${t.tie[l.confidence] ?? l.confidence})`)
  return [...why.values()]
}

/** What the reader of the Stories section must know before any story: that they are out of date, and where the build stopped. */
export function storiesCaveatTexts(d: ReportData, t: ReportText = EN): { warn: boolean; text: string }[] {
  const stale = d.storiesStale ?? []
  const cut = storyCoverageWarnings(d.storyStats)
  const orphaned = d.storyNotesOrphaned ?? 0
  const lostDecisions = d.storyDecisionsOrphaned ?? 0
  return [
    stale.length ? { warn: true, text: t.story.stale(stale.join('; ')) } : null,
    cut.length ? { warn: true, text: t.story.cutBuild(cut.join(' ')) } : null,
    orphaned ? { warn: false, text: t.story.orphanedNotes(orphaned) } : null,
    lostDecisions ? { warn: true, text: t.story.orphanedDecisions(lostDecisions) } : null,
  ].filter((x): x is { warn: boolean; text: string } => !!x)
}
const storiesCaveats = (t: ReportText, d: ReportData): string =>
  storiesCaveatTexts(d, t)
    .map((c) => `<div class="cap${c.warn ? ' warn' : ''}">${h(c.text)}</div>`)
    .join('')

// ---------------------------------------------------------------------------
// findings, grouped by rule
// ---------------------------------------------------------------------------

interface RuleGroup {
  ruleId: string
  title: string
  severity: Severity
  ruleSeverity: Severity
  findings: number
  rows: number
  first: number | null
  last: number | null
  attack: string[]
  statuses: Record<string, number>
  /** the distinct matched values that are not already said by the incident */
  values: string[]
  escalations: string[]
  /** the findings of the group */
  ids: number[]
}

/** One line per rule: ninety firewall rows print as one row with a count and a span, and the distinct values they matched. */
export function groupByRule(findings: Finding[], said: Record<string, string> = {}): RuleGroup[] {
  const groups = new Map<string, RuleGroup>()
  for (const f of findings) {
    let g = groups.get(f.ruleId)
    if (!g) {
      g = {
        ruleId: f.ruleId,
        title: f.title.replace(/\s+→.*$/, ''),
        severity: effectiveSeverity(f),
        ruleSeverity: f.severity,
        findings: 0,
        rows: 0,
        first: null,
        last: null,
        attack: [],
        statuses: {},
        values: [],
        escalations: [],
        ids: [],
      }
      groups.set(f.ruleId, g)
    }
    if (f.id != null) g.ids.push(f.id)
    g.findings++
    g.rows += f.count
    if (rank(effectiveSeverity(f)) > rank(g.severity)) g.severity = effectiveSeverity(f)
    if (f.ts != null) {
      g.first = g.first == null ? f.ts : Math.min(g.first, f.ts)
      const end = f.tsEnd ?? f.ts
      g.last = g.last == null ? end : Math.max(g.last, end)
    }
    for (const t of f.attack) if (!g.attack.includes(t)) g.attack.push(t)
    g.statuses[f.status] = (g.statuses[f.status] ?? 0) + 1
    if (f.escalation && !g.escalations.includes(f.escalation)) g.escalations.push(f.escalation)
    for (const [k, v] of Object.entries(f.entities)) {
      const text = Array.isArray(v) ? (v as unknown[]).map(String).join(' | ') : String(v ?? '')
      if (!text || said[k] === text || /^(computer|host|subjectUser|targetUser|user|upn)$/.test(k)) continue
      if (!g.values.includes(text) && g.values.length < 40) g.values.push(text)
    }
  }
  return [...groups.values()].sort((a, b) => rank(b.severity) - rank(a.severity) || b.rows - a.rows || a.title.localeCompare(b.title))
}

const MAX_VALUES = 6

/** After a rule's id: whether it was ever seen to detect what it looks for, and whether benign activity matches it. */
/** What a rule's measure says about its findings, in words: a lead, a rule that also fires on clean machines, or nothing. */
export function measureWords(m: MeasureReading | undefined, t: ReportText = EN): { lead: boolean; text: string } | null {
  if (!m) return null
  if (isLead(m)) return { lead: true, text: t.finding.lead }
  if (m.noisy) return { lead: false, text: t.finding.noisy }
  return null
}

function measureMark(t: ReportText, m: MeasureReading | undefined): string {
  const w = measureWords(m, t)
  if (!w) return ''
  return w.lead ? ` · <b class="lead">${h(w.text)}</b>` : ` · <span class="dim">${h(w.text)}</span>`
}

/** Whether a rule's findings hold against the rows they cite, and where the first of those rows is in its file; null when none was checked. */
export function claimLine(ids: number[], claims?: ReportClaims, t: ReportText = EN): { status: ClaimCheck['status']; word: string; where: string; more: number; reasons: string[] } | null {
  if (!claims) return null
  const cs = ids.map((id) => claims.findings[id]).filter((c): c is ClaimCheck => !!c)
  if (!cs.length) return null
  const worst = cs.find((c) => c.status === 'contradicted') ?? cs.find((c) => c.status === 'unsupported') ?? cs[0]
  const rec = cs.find((c) => c.records.length)?.records[0]
  const cited = cs.reduce((t, c) => t + c.cited, 0)
  return { status: worst.status, word: t.claimWord[worst.status] ?? worst.status, where: rec ? `${rec.file} ${rec.record}` : '', more: rec && cited > 1 ? cited - 1 : 0, reasons: worst.reasons }
}

function claimNote(t: ReportText, ids: number[], claims?: ReportClaims): string {
  const c = claimLine(ids, claims, t)
  if (!c) return ''
  const where = c.where ? ` · ${h(c.where)}${c.more ? ` <span class="dim">${h(t.andMore(c.more))}</span>` : ''}` : ''
  return `<span class="sub claim ${c.status}" title="${h(c.reasons.join(' '))}">${h(c.word)}${where}</span>`
}

/** A text's check, to print under the text, when it names something its rows do not hold, or names nothing that could be checked; null otherwise. */
export function textCheck(key: string, claims?: ReportClaims, t: ReportText = EN): { status: Exclude<TextStatus, 'verified'>; text: string } | null {
  const x = claims?.texts.find((y) => y.key === key)
  if (!x || x.check.status === 'verified') return null
  if (x.check.status === 'nothing_to_check') return { status: 'nothing_to_check', text: t.finding.nothingToCheck }
  return { status: x.check.status, text: t.finding.checked(x.check.reasons.join(' ')) }
}

function textNote(t: ReportText, key: string, claims?: ReportClaims): string {
  const c = textCheck(key, claims, t)
  return c ? `<div class="cap claim ${c.status}">${h(c.text)}</div>` : ''
}

/** After a rule's id: who wrote it, when the rule says. */
const authorMark = (t: ReportText, author: string | undefined) => (author ? ` · ${h(t.finding.by(author))}` : '')

function groupedFindings(
  t: ReportText,
  findings: Finding[],
  said: Record<string, string>,
  measures: Record<string, MeasureReading> = {},
  claims?: ReportClaims,
  authors: Record<string, string> = {},
): string {
  const groups = groupByRule(findings, said)
  return table(
    t.finding.groupHead,
    groups.map((g) => [
      pill(t, g.severity) + (g.severity !== g.ruleSeverity ? `<span class="sub">${h(t.finding.ruleSeverity(g.ruleSeverity))}</span>` : ''),
      `${h(g.title)}<span class="sub"><code>${h(g.ruleId)}</code>${authorMark(t, authors[g.ruleId])}${measureMark(t, measures[g.ruleId])}${g.escalations.length ? ' · ' + h(g.escalations.slice(0, 2).join(' · ')) : ''}</span>${claimNote(t, g.ids, claims)}`,
      `<span class="nowrap">${t.num(g.findings)} · ${t.num(g.rows)}</span>`,
      `<span class="nowrap">${span(t, g.first, g.last)}</span>`,
      g.attack
        .slice(0, 4)
        .map((t) => chip(t))
        .join(''),
      g.values.length
        ? `<span class="vals">${g.values
            .slice(0, MAX_VALUES)
            .map((v) => `<code>${h(v.length > 90 ? v.slice(0, 89) + '…' : v)}</code>`)
            .join('')}${g.values.length > MAX_VALUES ? `<span class="dim"> ${h(t.plusMore(g.values.length - MAX_VALUES))}</span>` : ''}</span>`
        : '<span class="dim">–</span>',
    ]),
  )
}

function incidentCard(t: ReportText, i: Incident, measures: Record<string, MeasureReading> = {}, claims?: ReportClaims, authors: Record<string, string> = {}): string {
  const decidedByAi = i.lead.decidedBy === 'ai'
  return `<div class="card inc ${h(i.severity)}">
<div class="card-head">${pill(t, i.severity)}<h3>${h(i.title)}</h3><span class="stamp st-${h(i.status)}">${h(t.status[i.status] ?? i.status)}</span></div>
<div class="card-meta">${h(i.subtitle)} · ${span(t, i.ts, i.tsEnd)} · ${h(t.incident.rows(i.refs.length))}${
    Object.keys(i.entities).length
      ? ' · ' +
        Object.entries(i.entities)
          .slice(0, 6)
          .map(([k, v]) => chip(`${k}=${String(v)}`))
          .join('')
      : ''
  }</div>
${i.lead.notes ? `<div class="note">${md(i.lead.notes)}</div>${i.lead.notesBy === 'ai' ? `<div class="cap ai">${h(t.incident.noteByAi)}</div>` : ''}` : ''}${textNote(t, `incident:${i.lead.id ?? i.title}`, claims)}
${decidedByAi && i.lead.aiReason ? `<div class="cap ai">${h(t.chain.triage(i.lead.aiReason))}</div>` : ''}
${groupedFindings(t, i.findings, i.entities, measures, claims, authors)}
</div>`
}

// ---------------------------------------------------------------------------
// what happened
// ---------------------------------------------------------------------------

/** the time slot of a confirmed item that has no event time: after every timed one */
const UNTIMED = Number.MAX_SAFE_INTEGER
interface Moment {
  ts: number
  end: number | null
  severity: Severity
  title: string
  /** the decision in the report's words */
  decision: string
  confirmed: boolean
  entities: string[]
  note: string
  kind: 'chain' | 'incident' | 'story'
}

/** The decided items in time order: what a reader should know happened, in the order it happened. */
export const MAX_MOMENTS = 14

export function moments(d: ReportData, t: ReportText = EN): { items: Moment[]; decided: boolean; total: number } {
  const out: Moment[] = []
  for (const c of d.chains) {
    const r = d.reviews[c.id]
    if (!r?.verdict || r.verdict === 'benign') continue
    out.push({
      ts: c.start,
      end: c.end,
      severity: chainSeverity(c, r),
      title: `${c.identityLabel}: ${c.seed.subject || t.chain.fallbackTitle}`,
      decision: t.chainVerdict[r.verdict] ?? r.verdict,
      confirmed: r.verdict === 'confirmed',
      entities: [c.seed.fromAddr, ...c.entities.hosts.slice(0, 2), ...c.entities.ips.slice(0, 2)].filter((x): x is string => !!x),
      note: firstSentence(r.narrative || c.summary),
      kind: 'chain',
    })
  }
  for (const i of d.incidents) {
    if (i.status === 'new' || i.status === 'false_positive') continue
    // a collected artefact has no event time; it still happened, so it closes the list rather than dropping out of it
    out.push({
      ts: i.ts ?? UNTIMED,
      end: i.tsEnd,
      severity: i.severity,
      title: i.title,
      decision: t.status[i.status] ?? i.status,
      confirmed: i.status === 'escalated',
      entities: Object.values(i.entities).slice(0, 3).map(String),
      note: firstSentence(i.lead.notes || i.lead.aiReason),
      kind: 'incident',
    })
  }
  // a printed story the analyst confirmed or reviewed, with the analyst's reason
  for (const st of d.decidedStories ?? []) {
    if (!st.printed || (st.verdict !== 'confirmed' && st.verdict !== 'reviewed')) continue
    out.push({
      ts: st.start,
      end: st.end,
      severity: st.severity,
      title: t.story.title(st.title),
      // only confirmed and reviewed stories are here: they read as the same decisions on an incident
      decision: st.verdict === 'confirmed' ? t.status.escalated : t.status.reviewed,
      confirmed: st.verdict === 'confirmed',
      entities: st.hosts.slice(0, 3),
      note: firstSentence(st.reason),
      kind: 'story',
    })
  }
  const decided = out.length > 0
  const confirmed = out.filter((m) => m.confirmed)
  const chosen = (confirmed.length ? confirmed : out).sort((a, b) => a.ts - b.ts)
  return { items: chosen.slice(0, MAX_MOMENTS), decided, total: chosen.length }
}

const momentsList = (t: ReportText, ms: Moment[]) =>
  `<ol class="moments">${ms
    .map(
      (m) =>
        `<li class="${h(m.severity)}"><div class="t">${m.ts === UNTIMED ? `${h(t.noEventTime)}<span class="sub">${h(t.happened.collected)}</span>` : `${t.ts(m.ts)}${m.end && m.end !== m.ts ? `<span class="sub">${t.to} ${t.ts(m.end)}</span>` : ''}`}</div><div class="b"><div class="hd">${pill(t, m.severity)}<b>${h(m.title)}</b><span class="stamp ${m.confirmed ? 'st-escalated' : 'st-reviewed'}">${h(m.decision)}</span></div>${m.entities.length ? `<div class="ents">${m.entities.map((e) => chip(e)).join('')}</div>` : ''}${m.note ? `<div class="nt">${h(m.note)}</div>` : ''}</div></li>`,
    )
    .join('')}</ol>`

// ---------------------------------------------------------------------------
// the document
// ---------------------------------------------------------------------------

const CSS = `
:root{--accent:#1b7f66;--accent-dim:rgba(27,127,102,.10);--ink:#0f1720;--ink-2:#4f5b69;--ink-3:#8a95a3;--line:#e3e6ea;--line-2:#cfd5dc;--surface:#fff;--surface-2:#f7f8fa;--surface-3:#eef1f4;
--critical:#a8231f;--high:#d1403f;--medium:#d9822b;--low:#2f6fdb;--info:#8a95a3;--violet:#6b4fd6;
--critical-bg:rgba(168,35,31,.10);--high-bg:rgba(209,64,63,.10);--medium-bg:rgba(217,130,43,.12);--low-bg:rgba(47,111,219,.10);--info-bg:rgba(138,149,163,.14);
--sans:'Inter','Segoe UI',system-ui,-apple-system,sans-serif;--mono:'Cascadia Code','JetBrains Mono',Consolas,monospace;--display:'Gulax','Segoe UI',system-ui,sans-serif}
*{box-sizing:border-box}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{font:12px/1.5 var(--sans);color:var(--ink);background:var(--surface);margin:0;padding:30px 40px 60px}
@page{size:A4;margin:14mm 13mm 16mm}
@media print{body{padding:0}.no-print{display:none}.cover-page{break-after:page}}
a{color:var(--accent);text-decoration:none}
code,.mono{font-family:var(--mono);font-size:10.5px}
.muted{color:var(--ink-2)}.dim{color:var(--ink-3)}.lead{font-weight:600;color:var(--ink-2);text-transform:uppercase;letter-spacing:.04em;font-size:9px}
/* cover */
.cover-page{position:relative}
.brand{display:flex;align-items:baseline;justify-content:space-between;border-bottom:2px solid var(--ink);padding-bottom:10px}
.brand .l{display:flex;align-items:baseline;gap:14px}
.wordmark{font-family:var(--display);font-size:28px;letter-spacing:.24em;color:var(--ink);line-height:1}
.brand .logo{max-height:40px;max-width:180px;align-self:center}.brand .firm{font-size:20px;font-weight:700;letter-spacing:-.01em;color:var(--ink);line-height:1}
.tag{font-size:9.5px;letter-spacing:.18em;text-transform:uppercase;color:var(--ink-3)}
.brand .r{font-family:var(--mono);font-size:10px;color:var(--ink-3);text-align:right;line-height:1.5}
.cover h1{font-size:26px;font-weight:600;letter-spacing:-.01em;margin:18px 0 4px;line-height:1.15}
.cover .meta{font-size:11.5px;color:var(--ink-2)}
.hero{display:grid;grid-template-columns:168px 1fr;gap:22px;align-items:center;margin:20px 0 6px;padding:16px 18px;border:1px solid var(--line);border-radius:12px;background:var(--surface-2)}
.issue{display:inline-block;margin-top:4px;padding:1px 8px;border-radius:3px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;font-size:10px}.issue.draft{border:1.5px solid var(--medium);color:var(--medium)}.issue.final{border:1.5px solid var(--accent);color:var(--accent)}
.cover.draft{position:relative}.cover.draft::after{content:'DRAFT';position:absolute;top:38%;left:50%;transform:translate(-50%,-50%) rotate(-24deg);font-size:120px;font-weight:800;letter-spacing:.1em;color:var(--medium);opacity:.09;pointer-events:none}
.seal{position:relative;width:168px;height:168px}
.seal svg{position:absolute;inset:0;width:100%;height:100%}
.seal svg polygon{fill:var(--surface);stroke:var(--ink-3);stroke-width:3}
.seal-in{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:0 22px}
.seal .k{font-family:var(--mono);font-size:9px;letter-spacing:.22em;text-transform:uppercase;color:var(--ink-3)}
.seal .w{font-weight:700;font-size:14px;line-height:1.15;margin-top:4px;letter-spacing:-.01em}
.seal .s{margin-top:6px;font-family:var(--mono);font-size:9.5px;letter-spacing:.14em;text-transform:uppercase}
.seal.compromise svg polygon{stroke:var(--critical);fill:var(--critical-bg)}.seal.compromise .w,.seal.compromise .s{color:var(--critical)}
.seal.suspicious svg polygon{stroke:var(--medium);fill:var(--medium-bg)}.seal.suspicious .w,.seal.suspicious .s{color:var(--medium)}
.seal.unwanted svg polygon{stroke:var(--violet);fill:rgba(107,79,214,.10)}.seal.unwanted .w,.seal.unwanted .s{color:var(--violet)}
.seal.unconfirmed svg polygon{stroke:var(--low);fill:var(--low-bg)}.seal.unconfirmed .w{color:var(--low)}
.seal.pending svg polygon{stroke:var(--ink-3);fill:var(--surface-3);stroke-dasharray:6 4}.seal.pending .w{color:var(--ink-2)}
.seal.clean svg polygon{stroke:var(--accent);fill:var(--accent-dim)}.seal.clean .w{color:var(--accent)}
.bottom .k{font-family:var(--mono);font-size:9.5px;letter-spacing:.2em;text-transform:uppercase;color:var(--ink-3);margin-bottom:6px}
.bottom .line{font-size:14.5px;line-height:1.45;font-weight:500;color:var(--ink)}
.bottom .line p{margin:0}
.bottom .det{margin-top:8px;font-size:11.5px;color:var(--ink-2)}
.bottom .conf{margin-top:10px;font-size:11px;color:var(--ink-2)}
.bottom .conf b{font-family:var(--mono);letter-spacing:.08em;text-transform:uppercase;font-size:10px;padding:1px 7px;border-radius:4px;margin-right:6px}
.conf.high b{color:var(--accent);background:var(--accent-dim)}.conf.medium b{color:var(--medium);background:var(--medium-bg)}.conf.low b{color:var(--high);background:var(--high-bg)}
.scorecard{display:grid;grid-template-columns:repeat(6,1fr);gap:8px;margin:12px 0 14px}
.kpi{border:1px solid var(--line);border-radius:8px;padding:8px 10px;background:var(--surface)}
.kpi .v{font-size:20px;font-weight:600;line-height:1.1;font-family:var(--mono)}
.kpi .l{font-size:9.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--ink-3);margin-top:3px}
.kpi.accent .v{color:var(--accent)}.kpi.critical .v{color:var(--critical)}
.sevbar{display:flex;height:8px;border-radius:4px;overflow:hidden;background:var(--surface-3);margin:0 0 5px}
.sevbar span{display:block;height:100%}
.legend{display:flex;gap:12px;font-size:10.5px;color:var(--ink-2);flex-wrap:wrap}
.legend i{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:5px;vertical-align:middle}
/* threat profile */
.profile{margin:14px 0 4px}
.profile .k{font-family:var(--mono);font-size:9.5px;letter-spacing:.2em;text-transform:uppercase;color:var(--ink-3);margin-bottom:8px;display:flex;justify-content:space-between}
.hexes{display:grid;grid-template-columns:repeat(7,1fr);gap:8px 6px}
.hex{position:relative;height:74px;text-align:center}
.hex svg{position:absolute;left:50%;top:0;width:58px;height:58px;transform:translateX(-50%)}
.hex svg polygon{fill:var(--surface);stroke:var(--line-2);stroke-width:2.5}
.hex .code{position:absolute;left:0;right:0;top:17px;font-family:var(--mono);font-weight:700;font-size:13px;letter-spacing:.06em;color:var(--line-2)}
.hex .n{position:absolute;left:0;right:0;top:34px;font-family:var(--mono);font-size:9px;color:var(--ink-3)}
.hex .lbl{position:absolute;left:-4px;right:-4px;top:60px;font-size:8.5px;letter-spacing:.02em;color:var(--ink-3);line-height:1.1}
.hex.observed svg polygon{stroke:var(--accent);fill:var(--surface)}.hex.observed .code{color:var(--accent)}.hex.observed .lbl{color:var(--ink-2)}
.hex.confirmed svg polygon{stroke:var(--high);fill:var(--high)}.hex.confirmed .code{color:#fff}.hex.confirmed .n{color:#fff}.hex.confirmed .lbl{color:var(--ink);font-weight:600}
.ribbons{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0 0}
.ribbon{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--line-2);border-radius:6px;padding:4px 9px;font-size:10.5px;color:var(--ink-2);background:var(--surface)}
.ribbon i{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--ink-3)}
span.warn{color:var(--medium);font-weight:600}.ribbon.ok i{background:var(--accent)}.ribbon.warn i{background:var(--medium)}.ribbon.ai i{background:var(--violet)}
.ribbon b{color:var(--ink);font-weight:600}
/* contents */
.toc{columns:2;column-gap:28px;font-size:11.5px;margin:18px 0 8px;padding:0;list-style:none}
.toc li{margin:0 0 4px;break-inside:avoid}
.toc .n{font-family:var(--mono);color:var(--accent);margin-right:8px}
/* sections */
.s{margin-top:26px;break-inside:auto}
.s-head{display:flex;align-items:baseline;gap:12px;margin-bottom:10px;break-after:avoid;break-inside:avoid}
.s-head .num{font-family:var(--mono);font-size:11px;color:var(--accent);letter-spacing:.08em}
.s-head h2{font-size:16px;font-weight:600;margin:0;letter-spacing:-.01em}
.s-head .rule{flex:1;height:1px;background:var(--line);transform:translateY(-4px)}
.s-head .count{font-family:var(--mono);font-size:11px;color:var(--ink-3)}
.intro{font-size:11.5px;color:var(--ink-2);margin:0 0 10px}
/* pills, stamps, chips */
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:10px;font-weight:600;letter-spacing:.02em;white-space:nowrap;line-height:1.6;vertical-align:middle}
.pill.critical{color:var(--critical);background:var(--critical-bg)}.pill.high{color:var(--high);background:var(--high-bg)}.pill.medium{color:var(--medium);background:var(--medium-bg)}.pill.low{color:var(--low);background:var(--low-bg)}.pill.info{color:var(--info);background:var(--info-bg)}
.pill.st-escalated{color:var(--critical);background:var(--critical-bg)}.pill.st-reviewed{color:var(--accent);background:var(--accent-dim)}.pill.st-false_positive{color:var(--ink-3);background:var(--info-bg)}.pill.st-new{color:var(--ink-2);background:var(--surface-3)}
.pill.verdict-confirmed{color:#fff;background:var(--critical)}.pill.verdict-unsure{color:#fff;background:var(--medium)}.pill.verdict-benign{color:#fff;background:var(--accent)}
.stamp{display:inline-block;font-family:var(--mono);font-size:9.5px;letter-spacing:.14em;text-transform:uppercase;padding:2px 8px;border:1.5px solid currentColor;border-radius:4px;transform:rotate(-2deg);white-space:nowrap}
.stamp.st-escalated{color:var(--critical)}.stamp.st-reviewed{color:var(--accent)}.stamp.st-false_positive{color:var(--ink-3)}.stamp.st-new{color:var(--ink-3);border-style:dashed}
.chip{display:inline-block;border:1px solid var(--line-2);border-radius:4px;padding:0 5px;font-family:var(--mono);font-size:9.5px;color:var(--ink-2);margin:0 3px 2px 0;max-width:100%;overflow-wrap:anywhere}
.vals code{display:block;overflow-wrap:anywhere;color:var(--ink-2)}
/* cards */
.card{border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:0 0 12px;break-inside:auto;background:var(--surface)}
.card.chain{border-left:4px solid var(--accent)}
.card.inc{border-left:4px solid var(--line-2);break-inside:avoid}
.card.inc.critical,.card.chain.critical{border-left-color:var(--critical)}.card.inc.high,.card.chain.high{border-left-color:var(--high)}.card.inc.medium,.card.chain.medium{border-left-color:var(--medium)}.card.inc.low,.card.chain.low{border-left-color:var(--low)}
.card-head,.card-meta,.narr{break-inside:avoid}
.card-head{break-after:avoid;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.card-head h3{font-size:14px;font-weight:600;margin:0;flex:1;min-width:200px}
.card-meta{font-size:11px;color:var(--ink-2);margin:6px 0 8px}
.story-inc{border-left:2px solid var(--line-2);padding-left:12px;margin:0 0 14px}
.meter{display:inline-flex;align-items:center;gap:8px;font-family:var(--mono);font-size:10.5px;color:var(--ink-2)}
.meter .bar{display:flex;width:120px;height:8px;border-radius:4px;overflow:hidden;background:var(--surface-3)}
.meter .bar span{display:block;height:100%}
.narr{border-left:3px solid var(--accent);background:var(--surface-2);padding:8px 12px;margin:8px 0 10px;border-radius:0 6px 6px 0;font-size:12px}
.narr p{margin:0 0 6px}.narr p:last-child{margin:0}
.narr strong{color:var(--ink)}
.cap{font-size:10px;color:var(--ink-3);margin-top:4px}
.story-part{font-weight:600;color:var(--ink-2);text-transform:uppercase;letter-spacing:.06em;font-size:9px;margin:10px 0 4px;break-after:avoid}
.q{border-top:1px solid var(--line);padding:6px 0 4px;break-inside:avoid}.q-head{display:flex;gap:8px;align-items:baseline;flex-wrap:wrap}.q-name{flex:1;min-width:200px;font-weight:600}.q .narr{margin-top:3px}.cites{margin:3px 0 0 16px;padding:0;font-size:10.5px;color:var(--ink-2)}h4.facet{font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--ink-3);margin:10px 0 2px}
.cap.ai{color:var(--violet)}.cap.warn{color:var(--medium);font-weight:600}.claim.unsupported{color:var(--medium)}.claim.contradicted{color:var(--critical);font-weight:600}
.note{background:var(--surface-2);padding:8px 12px;border-radius:6px;margin:6px 0 8px;font-size:12px}
.note p{margin:0 0 6px}.note p:last-child{margin:0}
figure{margin:8px 0 10px;break-inside:avoid}
figure img{width:100%;max-height:120mm;object-fit:contain;border:1px solid var(--line);border-radius:8px;background:#fff;padding:6px;box-sizing:border-box}
figure figcaption{font-size:10px;color:var(--ink-3);margin-top:4px;display:flex;flex-wrap:wrap;align-items:center;gap:3px 14px}
.gk{display:inline-flex;align-items:center;gap:5px;color:var(--ink-2)}.gk i{display:inline-block;width:9px;height:9px;background:var(--k);-webkit-print-color-adjust:exact;print-color-adjust:exact}
.gk-dot,.gk-ring{border-radius:50%}.gk-box{border-radius:2px}.gk-diamond{transform:rotate(45deg) scale(.85)}.gk-ring{background:#fff!important;border:1.5px dashed var(--k)}.gk-line{width:14px!important;height:2px!important}
/* tables */
table{border-collapse:collapse;width:100%;font-size:11px;margin:4px 0 8px}
th{font-size:9.5px;letter-spacing:.08em;text-transform:uppercase;color:var(--ink-3);text-align:left;font-weight:600;padding:5px 7px;border-bottom:1px solid var(--line-2);background:var(--surface-2)}
td{padding:5px 7px;border-bottom:1px solid var(--line);vertical-align:top}
tr{break-inside:avoid}
thead{display:table-header-group}
td .sub{display:block;font-size:10px;color:var(--ink-3)}
.lane{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:6px;vertical-align:middle}
.lane.mail{background:var(--accent)}.lane.m365{background:var(--low)}.lane.host{background:var(--ink-3)}
.nowrap{white-space:nowrap}
/* what happened */
.moments{list-style:none;margin:0;padding:0 0 0 14px;border-left:2px solid var(--line)}
.moments li{position:relative;display:grid;grid-template-columns:120px 1fr;gap:12px;margin:0 0 10px;padding-left:12px;break-inside:avoid}
.moments li::before{content:'';position:absolute;left:-20px;top:6px;width:10px;height:10px;border-radius:50%;background:var(--ink-3);border:2px solid #fff;box-shadow:0 0 0 1px var(--line-2)}
.moments li.critical::before{background:var(--critical)}.moments li.high::before{background:var(--high)}.moments li.medium::before{background:var(--medium)}.moments li.low::before{background:var(--low)}
.moments .t{font-family:var(--mono);font-size:10.5px;color:var(--ink-3);padding-top:3px}
.moments .t .sub{display:block;font-size:9.5px}
.moments .hd{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.moments .ents{margin-top:3px}
.moments .nt{font-size:11.5px;color:var(--ink-2);margin-top:3px}
/* timeline, tasks, notes, method */
.tl{list-style:none;margin:0;padding:0 0 0 18px;border-left:2px solid var(--line)}
.tl li{position:relative;margin:0 0 10px;padding-left:12px;page-break-inside:avoid}
.tl li::before{content:'';position:absolute;left:-24px;top:5px;width:10px;height:10px;border-radius:50%;background:var(--ink-3);border:2px solid #fff;box-shadow:0 0 0 1px var(--line-2)}
.tl li.critical::before{background:var(--critical)}.tl li.high::before{background:var(--high)}.tl li.medium::before{background:var(--medium)}.tl li.low::before{background:var(--low)}
.tl .t{font-family:var(--mono);font-size:10.5px;color:var(--ink-3)}
.tasks li{list-style:none;margin:0 0 4px;padding:0}
.tasks .box{display:inline-block;width:12px;height:12px;border:1px solid var(--line-2);border-radius:3px;margin-right:8px;vertical-align:-2px;text-align:center;font-size:9px;line-height:11px}
.tasks .done{color:var(--ink-3);text-decoration:line-through}
.notes .n{border-bottom:1px solid var(--line);padding:6px 0 8px;margin:0 0 6px}
.notes .n:last-child{border:0}
.method{display:grid;grid-template-columns:1fr 1fr;gap:10px 22px}
.method h4{font-family:var(--mono);font-size:9.5px;letter-spacing:.18em;text-transform:uppercase;color:var(--ink-3);margin:0 0 4px}
.method ul{margin:0 0 8px;padding-left:16px;font-size:11.5px;color:var(--ink-2)}
.method li{margin:0 0 2px}
.settings{font-family:var(--mono);font-size:10.5px;color:var(--ink-2);background:var(--surface-2);padding:8px 12px;border-radius:6px}
.settings code{overflow-wrap:anywhere}
.foot{margin-top:40px;border-top:1px solid var(--line);padding-top:6px;font-size:10px;color:var(--ink-3);display:flex;justify-content:space-between}
.foot .wm{font-family:var(--display);letter-spacing:.2em;color:var(--ink-2)}
.foot .wm.firm{font-family:var(--sans);letter-spacing:.02em;font-weight:600}
.empty{color:var(--ink-3);font-size:11.5px}
/* client report */
.marking{display:flex;gap:10px;align-items:center;justify-content:center;font-family:var(--mono);font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--ink-2);margin:0 0 10px}
.foot+.marking{margin:8px 0 0}
.tlp{background:#000;padding:2px 8px;border-radius:3px;font-weight:700}.tlp.clear{color:#fff}.tlp.green{color:#33ff00}.tlp.amber{color:#ffc000}.tlp.red{color:#ff2b2b}
.cover .meta.for{font-size:13px;color:var(--ink);margin-bottom:2px}
.bottom .conf .sub{display:block;font-size:9.5px;color:var(--ink-3);margin-top:2px}
.conf.analyst b{color:var(--violet);background:rgba(107,79,214,.10)}
table.kv th{width:26%;text-transform:none;letter-spacing:0;font-size:11px;color:var(--ink-2);background:none;border-bottom:1px solid var(--line);vertical-align:top}
`

/** The paragraph the cover quotes: the "Bottom line" block of a structured summary, else the first paragraph that reads as prose rather than a heading. */
export function bottomLine(summary: string): string {
  const t = summary.trim()
  if (!t) return ''
  const m = /\*\*bottom line\*\*:?\s*([\s\S]*?)(?=\n\s*\n|\n\s*\*\*|$)/i.exec(t)
  const clean = (s: string) =>
    s
      .replace(/^#+\s*/, '')
      .replace(/^\*\*[^*]+\*\*:?\s*/, '')
      .replace(/^[-*]\s+/, '')
      .trim()
  if (m) return clean(m[1]).slice(0, 600)
  // "Executive Summary — Case 1" or "Summary" is a title, not the bottom line: the first paragraph that is a sentence
  const paras = t
    .split(/\n\s*\n/)
    .map(clean)
    .filter(Boolean)
  const prose = paras.find((p) => p.length >= 40 && /[.!?]/.test(p) && !/^[A-Z][^.!?]{0,60}$/.test(p)) ?? paras.find((p) => p.length >= 40) ?? paras[0] ?? ''
  return prose
    .replace(/^(summary|overview)\s*[:.]?\s*/i, '')
    .split(/\n/)[0]
    .slice(0, 600)
}

/** How the report was produced, one plain sentence each: what was read, what fired, what was checked, what a model wrote. */
export function producedLines(d: ReportData, v: Verdict, t: ReportText = EN): string[] {
  const rowsTotal = d.evidence.reduce((t, e) => t + (e.count ?? 0), 0)
  const kinds = [...new Set(d.evidence.map((e) => e.format || e.kind))]
  const rulesFired = new Set(d.findings.map((f) => f.ruleId)).size
  const engine = d.findings.filter((f) => f.ruleId.startsWith('engine:')).length
  const aiTexts =
    d.chains.filter((c) => d.reviews[c.id]?.narrativeBy === 'ai' || d.reviews[c.id]?.by === 'ai').length +
    d.incidents.filter((i) => i.lead.notesBy === 'ai' || i.lead.decidedBy === 'ai').length +
    (d.summaryBy === 'ai' ? 1 : 0)
  const printedRules = [...new Set(d.findings.map((f) => f.ruleId))]
  const readings = printedRules.map((r) => d.measures?.[r]).filter((m): m is MeasureReading => !!m?.label)
  const detects = readings.filter((m) => m.verdict === 'detects').length
  const leads = readings.filter(isLead).length
  // the printed findings and texts, read back against the rows they cite
  const checked = d.findings.map((f) => (f.id != null ? d.claims?.findings[f.id] : undefined)).filter((c): c is ClaimCheck => !!c)
  const claimCount = (s: ClaimCheck['status']) => checked.filter((c) => c.status === s).length
  const texts = d.claims?.texts ?? []
  const textCount = (s: TextStatus) => texts.filter((x) => x.check.status === s).length
  const w = t.produced
  return [
    w.evidence(d.evidence.length, kinds.join(', '), rowsTotal),
    w.rules(rulesFired, engine),
    ...(checked.length
      ? [
          w.claims(CHECKED_ROWS, claimCount('verified'), claimCount('unsupported'), claimCount('contradicted')) +
            (texts.length ? w.texts(texts.length, textCount('verified'), textCount('nothing_to_check'), textCount('unsupported')) : ''),
        ]
      : []),
    ...(readings.length ? [w.measures(detects, leads, d.measuredOn ?? '')] : []),
    w.floor(d.settings.minSeverity, d.settings.onlyReviewed, d.settings.includeFp, d.storiesDismissed ?? 0),
    w.decisions(v.confirmed, v.reviewed, v.falsePositives, d.undecided),
    w.aiTexts(aiTexts),
  ]
}

/**
 * Where the analysis stops, one plain sentence each: what is open before the report is final, what
 * the evidence cannot show, what does not hold against its rows, the leads, the cuts and the files
 * not read completely. The HTML and the Word report print the same list.
 */
export function limitLines(d: ReportData, conf: Confidence, t: ReportText = EN): string[] {
  const w = t.limit
  const issues = d.evidence.filter((e) => e.kind === 'package').flatMap((e) => packageCoverageIssues(e))
  const leadFindings = d.findings.filter((f) => {
    const m = d.measures?.[f.ruleId]
    return !!m && isLead(m)
  }).length
  const texts = d.claims?.texts ?? []
  const byId = new Map(d.findings.filter((f) => f.id != null).map((f) => [f.id!, f]))
  const claimLimits = [
    ...Object.entries(d.claims?.findings ?? {})
      .filter(([id, c]) => c.status !== 'verified' && byId.has(Number(id)))
      .sort((a, b) => (a[1].status === 'contradicted' ? 0 : 1) - (b[1].status === 'contradicted' ? 0 : 1))
      .map(([id, c]) => {
        const f = byId.get(Number(id))!
        return w.findingClaim(f.title, f.ruleId, c.status === 'contradicted', c.reasons.join('; '))
      }),
    ...texts.filter((x) => x.check.status === 'unsupported').map((x) => w.textClaim(x.what, x.check.reasons.join('; '))),
  ]
  const issue = d.issue
  return [
    ...(issue?.status === 'draft' ? [w.draft(issue.open.map((c) => `${c.label.toLowerCase()} (${c.detail})`).join('; '))] : []),
    ...(issue?.waived ?? []).map((x) => w.waived(x.label.toLowerCase(), x.reason)),
    ...clientLimits(d, computeVerdict(d, t), t),
    ...(d.gaps ?? []).map((g) => g.text),
    ...(d.questions?.counts.open ? [w.questionsOpen(d.questions.counts.open, d.questions.uncovered)] : []),
    ...(d.questions?.counts.cannot ? [w.questionsCannot(d.questions.counts.cannot)] : []),
    ...claimLimits.slice(0, 12),
    ...(claimLimits.length > 12 ? [w.moreClaims(claimLimits.length - 12)] : []),
    ...(leadFindings ? [w.leads(leadFindings)] : []),
    w.times,
    w.snapshots,
    ...(d.coverageWarnings ?? []).map((x) => w.chains(x)),
    ...(d.stories?.length && d.storiesStale?.length ? [w.storiesStale(d.storiesStale.join('; '))] : []),
    ...(d.stories?.length ? storyCoverageWarnings(d.storyStats).map((x) => w.storiesCut(x)) : []),
    ...issues.slice(0, 6).map((x) => w.packages(x)),
    d.iocsChecked ? w.iocsChecked(d.iocsChecked, d.iocsTotal ?? d.iocsChecked) : w.iocsNone,
    ...(d.rules && d.rules.lastRun == null ? [w.rulesNotRun] : []),
    ...(d.rules?.evidenceAfter ? [w.evidenceAfter(d.rules.evidenceAfter)] : []),
    ...d.evidence.filter((e) => e.kind !== 'package' && evidenceIssue(e)).map((e) => w.file(e.name, evidenceIssue(e, t))),
    ...conf.reasons.filter((r) => r !== t.completeness.complete).map((r) => w.completeness(r)),
  ]
}

function method(t: ReportText, d: ReportData, v: Verdict, conf: Confidence): string {
  const list = (xs: string[]) => xs.map((s) => `<li>${h(s)}</li>`).join('')
  return `<div class="method"><div><h4>${h(t.produced.title)}</h4><ul>${list(producedLines(d, v, t))}</ul></div><div><h4>${h(t.limit.title)}</h4><ul>${list(limitLines(d, conf, t))}</ul></div></div>`
}

// ---------------------------------------------------------------------------
// questions

const QUESTION_PILL: Record<string, string> = { answered: 'verdict-benign', cannot: 'st-false_positive', open: 'verdict-unsure' }

function questionRow(t: ReportText, q: ReportQuestion): string {
  const cites = q.citations.length
    ? `<ul class="cites">${q.citations.map((c) => `<li>${c.source === 'findings' ? `<span class="dim">${h(t.question.finding)}</span> ` : ''}${h(c.label)}${c.ts ? ` <span class="dim">· ${t.ts(c.ts)}</span>` : ''}</li>`).join('')}</ul>`
    : q.status === 'answered'
      ? `<div class="cap warn">${h(t.question.noCitation)}</div>`
      : ''
  const text = q.text.trim() ? `<div class="narr">${md(q.text)}</div>` : q.status === 'open' ? `<div class="cap warn">${h(t.question.unanswered)}</div>` : ''
  const cov = q.coverage && (q.status !== 'answered' || q.covered === false) ? `<div class="cap${q.covered === false ? ' warn' : ''}">${h(t.question.evidence(q.coverage))}</div>` : ''
  return `<div class="q ${h(q.status)}"><div class="q-head"><code>${h(q.id)}</code><span class="q-name">${h(q.name)}</span><span class="pill ${QUESTION_PILL[q.status] ?? 'info'}">${h(t.answer[q.status] ?? q.status)}</span></div>${text}${cites}${cov}</div>`
}

/** What the Questions section says first: where the questions come from, and how many are answered, cannot be, and are open. */
export function questionsIntro(q: ReportQuestions, t: ReportText = EN): string {
  return t.question.intro(q.counts.answered, q.counts.cannot, q.counts.open, q.uncovered)
}

/** The chosen scenarios, each facet's questions with the analyst's answer, what it cites, and the ones left open flagged. */
export function questionsSection(q: ReportQuestions, t: ReportText = EN): string {
  return (
    `<p class="intro">${h(questionsIntro(q, t))}</p>` +
    q.scenarios
      .map(
        (s) =>
          `<div class="card"><div class="card-head"><h3>${h(s.name)}</h3>${chip(s.id)}${chip(s.origin === 'dfiq' ? 'DFIQ' : 'REMN')}</div>${s.facets
            .map((f) => `<h4 class="facet">${h(f.name)}</h4>${f.questions.map((x) => questionRow(t, x)).join('')}`)
            .join('')}</div>`,
      )
      .join('')
  )
}

// ---------------------------------------------------------------------------
// the client parts, as plain text both reports print
// ---------------------------------------------------------------------------

const lines = (text: string) =>
  text
    .split(/\r?\n/)
    .map((x) => x.trim())
    .filter(Boolean)

/** The engagement block: who the report is for and on whose request, when, to whom it goes, and its versions; only what the analyst filled in. */
export function engagementFacts(c: ClientReport, t: ReportText = EN): { facts: [string, string][]; distribution: string[]; versions: string[][] } {
  const w = t.client
  const start = t.day(c.engagementStart)
  const end = t.day(c.engagementEnd)
  const dates = start && end ? w.between(start, end) : start ? w.from(start) : end ? w.until(end) : ''
  const facts: [string, string][] = [
    [w.client, c.client.trim()],
    [w.reference, c.engagementRef.trim()],
    [w.dates, dates],
    [w.requestedBy, c.requestedBy.trim()],
  ]
  return {
    facts: facts.filter(([, v]) => v),
    distribution: lines(c.distribution),
    versions: c.versions.filter((v) => v.version.trim() || v.note.trim()).map((v) => [v.version.trim(), t.day(v.date), v.author.trim(), v.note.trim()]),
  }
}

/** How many entries of a derived list the report prints; the rest is counted. */
const SCOPE_LIST = 40

/**
 * The scope: the period examined, the systems and accounts in and out of scope, and the objectives.
 * What the analyst wrote is printed as written; where they wrote nothing in scope, what the evidence
 * covers is printed instead, and says so. Nothing is out of scope unless the analyst says it is.
 */
export function scopeRows(d: ReportData, t: ReportText = EN): { label: string; items: string[]; note: string }[] {
  const c = d.settings.client
  const w = t.client
  const period = evidencePeriod(d.evidence)
  const derivedList = (xs: string[] | undefined, capped: boolean | undefined, what: string) => {
    const all = xs ?? []
    const more = all.length - SCOPE_LIST
    return {
      items: [...all.slice(0, SCOPE_LIST), ...(more > 0 ? [t.andMore(more)] : [])],
      note: all.length ? w.derived(what, capped ? all.length : 0) : '',
    }
  }
  const rows: { label: string; items: string[]; note: string }[] = []
  if (c.periodFrom || c.periodTo) rows.push({ label: w.period, items: [w.between(t.day(c.periodFrom) || '…', t.day(c.periodTo) || '…')], note: '' })
  else if (period.from != null) rows.push({ label: w.period, items: [w.between(t.ts(period.from), t.ts(period.to))], note: w.periodDerived })
  const own = (label: string, text: string) => (lines(text).length ? rows.push({ label, items: lines(text), note: '' }) : 0)
  if (lines(c.systemsIn).length) own(w.systemsIn, c.systemsIn)
  else {
    const x = derivedList(d.scope?.hosts, d.scope?.hostsCapped, w.systemsWhat)
    if (x.note) rows.push({ label: w.systemsIn, ...x })
  }
  own(w.systemsOut, c.systemsOut)
  if (lines(c.accountsIn).length) own(w.accountsIn, c.accountsIn)
  else {
    const x = derivedList(d.scope?.accounts, d.scope?.accountsCapped, w.accountsWhat)
    if (x.note) rows.push({ label: w.accountsIn, ...x })
  }
  own(w.accountsOut, c.accountsOut)
  rows.push({ label: w.evidence, items: [w.evidenceFiles(d.evidence.length)], note: '' })
  return rows
}

/** The containment actions the analyst recorded, in date order. */
export const containmentRows = (c: ClientReport, t: ReportText = EN): string[][] =>
  c.containment
    .filter((a) => a.action.trim())
    .sort((a, b) => (a.date || '9999').localeCompare(b.date || '9999'))
    .map((a) => [a.date ? t.day(a.date) : t.client.noDate, a.action.trim(), a.by.trim()])

/** The recommendations the analyst wrote, by term; a term left empty is left out. */
export const recommendationTerms = (c: ClientReport, t: ReportText = EN): [string, string][] =>
  (
    [
      [t.client.short, c.recShort],
      [t.client.medium, c.recMedium],
      [t.client.long, c.recLong],
    ] as [string, string][]
  ).filter(([, x]) => x.trim())

/** Whether the initial access still reads as the starting point offered from a story's spine: then it is not the analyst's conclusion yet. */
export const initialAccessIsDraft = (c: ClientReport) => !!c.initialAccessDraft.trim() && c.initialAccess.trim() === c.initialAccessDraft.trim()

/** The analyst's conclusion: the initial access (unless it is still the spine's draft), the root cause, and their confidence in it, in the report's words, when they gave one. */
export function conclusionParts(c: ClientReport, t: ReportText = EN): { initialAccess: string; rootCause: string; confidence: string; basis: string } {
  return {
    initialAccess: initialAccessIsDraft(c) ? '' : c.initialAccess.trim(),
    rootCause: c.rootCause.trim(),
    confidence: c.analyticConfidence ? (t.analytic[c.analyticConfidence] ?? c.analyticConfidence) : '',
    basis: c.confidenceBasis.trim(),
  }
}

/** The handling marking: the TLP level and the confidentiality line, as one line, or '' when neither is set. */
export const markingLine = (c: ClientReport) => [c.tlp ? `TLP:${c.tlp.toUpperCase()}` : '', c.confidentiality.trim()].filter(Boolean).join(' · ')

/** The first entries of a list, and how many more there are. */
const firstOf = (t: ReportText, xs: string[], k = 3) => `${xs.slice(0, k).join('; ')}${xs.length > k ? ` ${t.andMore(xs.length - k)}` : ''}`

/** An affected account or host as a table row: its name and other forms, when, how bad, and which confirmed items name it. */
export const assetRow = (a: AffectedAsset, t: ReportText = EN): string[] => [
  `${a.name}${a.aliases.length ? t.client.also(a.aliases.join(', ')) : ''}`,
  a.first != null ? t.ts(a.first) : t.noEventTime,
  a.last != null ? t.ts(a.last) : '',
  t.sev[a.severity] ?? a.severity,
  firstOf(t, a.from),
]

export const indicatorRow = (r: IndicatorRow, t: ReportText = EN): string[] => [
  t.indicatorKind[r.kind] ?? r.kind,
  r.kind === 'hash' ? r.value : defang(r.value),
  firstOf(t, r.from),
  r.verdict ?? t.indicator.notLookedUp,
]

export const techniqueRow = (r: TechniqueRow, t: ReportText = EN): string[] => [
  r.id,
  r.tactics.join(', ') || t.technique.unmapped,
  t.num(r.findings),
  firstOf(t, r.rules),
  r.confirmed ? t.technique.yes : t.technique.no,
]

/** The limits a client report adds under Where it stops: a conclusion not stated, or still the spine's draft. */
export function clientLimits(d: ReportData, v: Verdict, t: ReportText = EN): string[] {
  const c = d.settings.client
  const confirmed = v.kind === 'compromise' || v.kind === 'suspicious' || v.kind === 'unwanted'
  if (initialAccessIsDraft(c)) return [t.limit.initialAccessDraft]
  if (confirmed && !c.initialAccess.trim() && !c.rootCause.trim()) return [t.limit.noConclusion]
  return []
}

/** The records a reviewed relationship rests on: the file, the record, its time and the file's SHA-256. */
export function referenceRows(r: RelationshipReview, t: ReportText = EN): string[][] {
  return r.references.map((ref) => [
    ref.sourceFile ?? '',
    t.relationship.record(ref.source, ref.id, ref.evidenceId, (ref.sourceIndex ?? -1) + 1),
    ref.recordKind === 'observation' ? t.relationship.collected(t.ts(ref.observedAt)) : t.relationship.event(t.ts(ref.ts)),
    ref.sourceSha256 ?? '',
  ])
}

const kvTable = (rows: [string, string][]) => `<table class="kv"><tbody>${rows.map(([k, v]) => `<tr><th>${k}</th><td>${v}</td></tr>`).join('')}</tbody></table>`
const listItems = (xs: string[]) => xs.map((x) => h(x)).join('<br>')
const TLP_CLASS: Record<string, string> = { clear: 'clear', green: 'green', amber: 'amber', 'amber+strict': 'amber', red: 'red' }
/** The handling marking as the cover and the foot of the report print it. */
const marking = (c: ClientReport) =>
  markingLine(c)
    ? `<div class="marking">${c.tlp ? `<span class="tlp ${TLP_CLASS[c.tlp]}">TLP:${h(c.tlp.toUpperCase())}</span>` : ''}${c.confidentiality.trim() ? `<span>${h(c.confidentiality.trim())}</span>` : ''}</div>`
    : ''

/** The sections a client report adds, in the order they print; each is left out when it has nothing to say. */
function clientSections(t: ReportText, d: ReportData): { before: Section[]; afterHappened: Section[]; techniques: Section | null } {
  const c = d.settings.client
  const w = t.client
  const before: Section[] = []
  const e = engagementFacts(c, t)
  if (e.facts.length || e.distribution.length || e.versions.length)
    before.push({
      id: 'engagement',
      title: t.section.engagement,
      body:
        (e.facts.length ? kvTable(e.facts.map(([k, v]) => [h(k), h(v)])) : '') +
        (e.distribution.length ? `<h4 class="facet">${h(w.distribution)}</h4><div>${listItems(e.distribution)}</div>` : '') +
        (e.versions.length
          ? `<h4 class="facet">${h(w.versions)}</h4>${table(
              w.versionHead,
              e.versions.map((r) => r.map(h)),
            )}`
          : ''),
    })
  const scope = scopeRows(d, t)
  const objectives = c.objectives.trim()
  const scopeBody = `${objectives ? `<div class="narr">${md(objectives)}</div>` : ''}${kvTable(scope.map((r) => [h(r.label), `${listItems(r.items)}${r.note ? `<span class="sub">${h(r.note)}</span>` : ''}`]))}`
  const conclusion = conclusionParts(c, t)
  const after: Section[] = []
  const conclusionBody = [
    conclusion.initialAccess ? `<h4 class="facet">${h(w.initialAccess)}</h4><div class="narr">${md(conclusion.initialAccess)}</div>` : '',
    conclusion.rootCause ? `<h4 class="facet">${h(w.rootCause)}</h4><div class="narr">${md(conclusion.rootCause)}</div>` : '',
    conclusion.confidence
      ? `<div class="conf analyst"><b>${h(t.cover.analystConfidence(conclusion.confidence))}</b>${conclusion.basis ? h(conclusion.basis) : ''}</div><div class="cap">${h(t.cover.analystConfidenceSub)}</div>`
      : '',
  ].join('')
  const impact = impactInventory(d, t)
  const note = c.impact.trim()
  if (impact.accounts.length || impact.hosts.length || note)
    after.push({
      id: 'impact',
      title: t.section.impact,
      count: impact.accounts.length + impact.hosts.length,
      body:
        `<p class="intro">${h(w.impactIntro)}</p>` +
        (note ? `<div class="narr">${md(note)}</div><div class="cap">${h(w.impactNote)}</div>` : '') +
        (impact.accounts.length
          ? table(
              [w.account, ...w.impactHead.slice(1)],
              impact.accounts.map((a) => assetRow(a, t).map(h)),
            )
          : '') +
        (impact.hosts.length
          ? table(
              [w.host, ...w.impactHead.slice(1)],
              impact.hosts.map((a) => assetRow(a, t).map(h)),
            )
          : '') +
        (!impact.accounts.length && !impact.hosts.length ? `<div class="empty">${h(w.impactNone)}</div>` : ''),
    })
  const actions = containmentRows(c, t)
  if (actions.length)
    after.push({
      id: 'containment',
      title: t.section.containment,
      count: actions.length,
      body: `<p class="intro">${h(w.containmentIntro)}</p>${table(
        w.containmentHead,
        actions.map((r) => r.map(h)),
      )}`,
    })
  const terms = recommendationTerms(c, t)
  if (terms.length)
    after.push({ id: 'recommendations', title: t.section.recommendations, body: terms.map(([term, text]) => `<h4 class="facet">${h(term)}</h4><div class="narr">${md(text)}</div>`).join('') })
  const techniques = techniqueTable(d, t)
  return {
    before: [
      ...before,
      // the summary sits between the engagement and the scope; buildReportHtml puts it there
      { id: 'scope', title: t.section.scope, body: scopeBody },
      ...(conclusionBody ? [{ id: 'conclusion', title: t.section.conclusion, body: conclusionBody }] : []),
    ],
    afterHappened: after,
    techniques: techniques.length
      ? {
          id: 'techniques',
          title: t.section.techniques,
          count: techniques.length,
          body: `<p class="intro">${h(t.technique.intro)}</p>${table(
            t.technique.head,
            techniques.map((r) => techniqueRow(r, t).map(h)),
          )}`,
        }
      : null,
  }
}

interface Section {
  id: string
  title: string
  count?: number
  body: string
}

/** A string as CSS writes it, quoted: nothing in it can close the string or the style element. */
const cssString = (s: string) => {
  // a backslash and a quote are escaped as themselves; control characters and the angle brackets by their code
  const esc = (c: string) => (c === '\\' || c === '"' ? `\\${c}` : c < ' ' || c === '\u007f' || c === '<' || c === '>' ? `\\${c.charCodeAt(0).toString(16)} ` : c)
  return `"${[...s].map(esc).join('')}"`
}

/**
 * What prints in the page margins, where the browser draws margin boxes (Chromium does; others print
 * without them): the brand, the case and the marking at the top of every page but the cover, and the
 * page number and count at the foot of every page. The draft watermark speaks the report's language.
 */
function printCss(t: ReportText, brand: string, caseName: string, mark: string): string {
  const box = 'font-family:Inter,"Segoe UI",system-ui,sans-serif;font-size:8.5px;color:#8a95a3'
  return (
    `.cover.draft::after{content:${cssString(t.cover.draftMark)}}` +
    `@page{@top-left{content:${cssString(`${brand} · ${caseName}`)};${box}}` +
    (mark ? `@top-right{content:${cssString(mark)};${box};font-weight:700}` : '') +
    `@bottom-right{content:${cssString(t.print.page)} counter(page) ${cssString(t.print.of)} counter(pages);${box}}}` +
    `@page:first{@top-left{content:none}@top-right{content:none}}`
  )
}

export function buildReportHtml(d: ReportData): string {
  const { kase, settings } = d
  const t = reportText(settings.language)
  const branding = settings.branding
  const firm = branding.firmName.trim()
  const logo = logoImage(branding.logo)
  const bySev: Record<string, number> = {}
  for (const f of d.findings) bySev[effectiveSeverity(f)] = (bySev[effectiveSeverity(f)] ?? 0) + 1
  const total = Math.max(1, d.findings.length)
  const verdict = computeVerdict(d, t)
  const confidence = computeConfidence(d, t)
  const profile = threatProfile(d)
  const happened = moments(d, t)
  const rowsTotal = d.evidence.reduce((x, e) => x + (e.count ?? 0), 0)
  const verified = d.evidence.filter((e) => e.integrity === 'verified').length
  const aiUsed =
    d.summaryBy === 'ai' || d.chains.some((c) => d.reviews[c.id]?.narrativeBy === 'ai' || d.reviews[c.id]?.by === 'ai') || d.incidents.some((i) => i.lead.notesBy === 'ai' || i.lead.decidedBy === 'ai')
  const line = bottomLine(d.summary)

  const client = clientSections(t, d)
  const sections: Section[] = []
  const [engagement, ...rest] = client.before[0]?.id === 'engagement' ? client.before : [null, ...client.before]
  if (engagement) sections.push(engagement)
  if (d.summary)
    sections.push({
      id: 'summary',
      title: t.section.summary,
      body: `<div class="narr">${md(d.summary)}</div>${d.summaryBy === 'ai' ? `<div class="cap ai">${h(t.summary.byAi)}</div>` : ''}${textNote(t, 'summary', d.claims)}${
        d.summaryAt && d.findings.some((f) => f.createdAt > d.summaryAt!) ? `<div class="cap">${h(t.summary.stale)}</div>` : ''
      }`,
    })
  for (const x of rest) if (x) sections.push(x)
  const anyConfirmed = happened.items.some((m) => m.confirmed)
  sections.push({
    id: 'happened',
    title: t.section.happened,
    count: happened.total,
    body: happened.items.length
      ? `<p class="intro">${h(anyConfirmed ? t.happened.confirmed : t.happened.reviewed)} ${h(t.happened.times)}${happened.total > happened.items.length ? ` ${h(t.happened.first(happened.items.length, happened.total))}` : ''}</p>${momentsList(t, happened.items)}`
      : `<div class="empty">${h(happened.decided ? t.happened.noDated : t.happened.noDecision)}</div>`,
  })
  sections.push(...client.afterHappened)
  if (d.questions)
    sections.push({
      id: 'questions',
      title: t.section.questions,
      count: d.questions.counts.answered + d.questions.counts.cannot + d.questions.counts.open,
      body: questionsSection(d.questions, t),
    })
  if (d.stories?.length) {
    const left = d.storiesLeft ?? 0
    const dismissedStories = d.storiesDismissed ?? 0
    sections.push({
      id: 'stories',
      title: t.section.stories,
      count: d.stories.length,
      body: `<p class="intro">${h(t.story.intro)}</p>${storiesCaveats(t, d)}${storyCards(t, d)}${left ? `<div class="cap">${h(t.story.left(left, settings.onlyReviewed))}</div>` : ''}${dismissedStories ? `<div class="cap">${h(t.story.dismissed(dismissedStories))}</div>` : ''}`,
    })
  }
  if (d.chains.length) {
    const campaign =
      settings.includeGraphs && d.chains.length > 1 && d.graphs.campaign
        ? `<div class="card"><div class="card-head"><h3>${h(t.chain.shared)}</h3></div>${img(d.graphs.campaign, t.chain.campaignAlt, t.chain.campaignCaption, campaignKey(t))}<div class="cap">${d.campaignInsights.length ? d.campaignInsights.map((x) => h(x)).join(' · ') : h(t.chain.nothingShared)}</div></div>`
        : ''
    sections.push({
      id: 'chains',
      title: t.section.chains,
      count: d.chains.length,
      body: `<p class="intro">${h(t.chain.intro)}</p>${campaign}${d.chains.map((c) => chainCard(t, c, d)).join('\n')}`,
    })
  }
  sections.push({
    id: 'incidents',
    title: t.section.incidents,
    count: d.incidents.length,
    body: `<p class="intro">${h(t.incident.intro)}</p>${d.incidents.length ? d.incidents.map((i) => incidentCard(t, i, d.measures, d.claims, d.ruleAuthors)).join('\n') : `<div class="empty">${h(t.incident.none)}</div>`}`,
  })
  if (settings.includeEvidence) {
    const packages = d.evidence.filter((e) => e.kind === 'package')
    sections.push({
      id: 'evidence',
      title: t.section.evidence,
      count: d.evidence.length,
      body:
        (d.evidence.length
          ? table(
              t.evidence.head,
              d.evidence.map((e) => {
                // the digest says the file is the one received; this says whether all of it was read
                const issue = e.kind === 'package' ? packageCoverageIssues(e).join('; ') : evidenceIssue(e, t)
                return [
                  h(e.name),
                  h(e.format || e.kind),
                  t.bytes(e.size),
                  t.num(e.count),
                  `<code>${h(e.sha256Client ?? '')}</code>`,
                  h(t.integrity[e.integrity] ?? e.integrity),
                  issue ? `<span class="warn">${h(t.evidence.incomplete(issue))}</span>` : h(t.evidence.complete),
                  `<span class="nowrap">${t.ts(e.addedAt)}</span>`,
                ]
              }),
            )
          : `<div class="empty">${h(t.evidence.none)}</div>`) +
        (packages.length
          ? `<h4 class="mono dim" style="margin:10px 0 4px;letter-spacing:.14em;text-transform:uppercase;font-size:9.5px">${h(t.evidence.packages)}</h4>${table(
              t.evidence.packageHead,
              packages.map((e) => [h(e.name), h(packageCoverageIssues(e).join('; ') || t.evidence.noIssues)]),
            )}`
          : ''),
    })
  }
  const relationships = (d.relationships ?? []).filter((r) => r.status === 'accepted' && r.includeInReport)
  if (relationships.length)
    sections.push({
      id: 'relationships',
      title: t.section.relationships,
      count: relationships.length,
      body:
        `<p class="intro">${h(t.relationship.intro)}</p>` +
        relationships
          .map(
            (r) =>
              `<div class="card"><h3>${h(r.sourceLabel)} → ${h(r.relation)} → ${h(r.targetLabel)}</h3><p>${h(r.reason)} (${h(r.confidence)})</p><div class="narr">${md(r.notes)}</div>${Object.keys(r.aliases ?? {}).length ? `<p>${h(t.relationship.aliases(JSON.stringify(r.aliases)))}</p>` : ''}${table(
                t.relationship.head,
                referenceRows(r, t).map((row) => row.map(h)),
              )}</div>`,
          )
          .join(''),
    })
  if (settings.includeIocs) {
    const ind = indicatorAppendix(d, t)
    sections.push({
      id: 'iocs',
      title: t.section.iocs,
      count: ind.rows.length + ind.left,
      body: ind.rows.length
        ? `<p class="intro">${h(t.indicator.intro)}</p>${table(
            t.indicator.head,
            ind.rows.map((r) => {
              const [kind, value, from, rep] = indicatorRow(r, t)
              return [h(kind), `<code>${h(value)}</code>`, h(from), r.verdict ? h(rep) : `<span class="dim">${h(rep)}</span>`]
            }),
          )}${ind.left ? `<div class="cap warn">${h(t.indicator.left(ind.left, MAX_INDICATORS))}</div>` : ''}`
        : `<div class="empty">${h(t.indicator.none)}</div>`,
    })
  }
  if (client.techniques) sections.push(client.techniques)
  if (settings.includeTimeline && d.timeline.length)
    sections.push({
      id: 'timeline',
      title: t.section.timeline,
      count: d.timeline.length,
      body: `<ul class="tl">${d.timeline.map((x) => `<li class="${h(x.severity ?? 'info')}"><div class="t">${x.untimed ? h(t.noEventTime) : t.ts(x.ts)}${x.link ? ` · ${h(`${x.link.source} ${x.link.label ?? x.link.id}`)}` : ''}</div><div>${h(x.text)}</div></li>`).join('')}</ul>`,
    })
  if (settings.includeTasks && d.tasks.length)
    sections.push({
      id: 'tasks',
      title: t.section.tasks,
      count: d.tasks.length,
      body: `<ul class="tasks">${d.tasks.map((x) => `<li class="${x.done ? 'done' : ''}"><span class="box">${x.done ? '✓' : ''}</span>${h(x.text)} <span class="dim">· ${t.ts(x.updatedAt)}</span></li>`).join('')}</ul>`,
    })
  if (settings.includeNotes && d.notes.length)
    sections.push({
      id: 'notes',
      title: t.section.notes,
      count: d.notes.length,
      body: `<div class="notes">${d.notes.map((x) => `<div class="n"><div class="cap">${t.ts(x.createdAt)}</div>${md(x.text)}</div>`).join('')}</div>`,
    })
  const groups = groupByRule(d.findings)
  sections.push({
    id: 'findings',
    title: t.section.findings,
    count: groups.length,
    body: groups.length
      ? `<p class="intro">${h(t.finding.intro)}</p>${table(
          t.finding.ruleHead,
          groups.map((g) => [
            pill(t, g.severity),
            `${h(g.title)}<span class="sub"><code>${h(g.ruleId)}</code>${authorMark(t, d.ruleAuthors?.[g.ruleId])}${measureMark(t, d.measures?.[g.ruleId])}${g.attack.length ? ' · ' + h(g.attack.slice(0, 4).join(' ')) : ''}</span>${claimNote(t, g.ids, d.claims)}`,
            `<span class="nowrap">${t.num(g.findings)} · ${t.num(g.rows)}</span>`,
            `<span class="nowrap">${span(t, g.first, g.last)}</span>`,
            Object.entries(g.statuses)
              .map(([s, c]) => `${statusPill(t, s)}${c > 1 ? ` <span class="dim">×${c}</span>` : ''}`)
              .join(' '),
            g.values.length
              ? `<span class="vals">${g.values
                  .slice(0, MAX_VALUES)
                  .map((v) => `<code>${h(v.length > 90 ? v.slice(0, 89) + '…' : v)}</code>`)
                  .join('')}${g.values.length > MAX_VALUES ? `<span class="dim"> ${h(t.plusMore(g.values.length - MAX_VALUES))}</span>` : ''}</span>`
              : '<span class="dim">–</span>',
          ]),
        )}${groups.some((g) => d.ruleAuthors?.[g.ruleId]) ? `<div class="cap">${h(t.finding.authors)}</div>` : ''}`
      : `<div class="empty">${h(t.finding.none)}</div>`,
  })
  if (d.ai && d.ai.runs) sections.push({ id: 'ai', title: t.section.ai, body: aiSection(t, d.ai) })
  sections.push({ id: 'method', title: t.section.method, body: method(t, d, verdict, confidence) })
  sections.push({
    id: 'settings',
    title: t.section.settings,
    body: `<div class="settings">${h(
      t.settingsLine({
        domains: kase.settings.internalDomains.join(', '),
        vips: kase.settings.vipNames.join(', '),
        start: kase.settings.businessHours.start,
        end: kase.settings.businessHours.end,
        tz: kase.settings.businessHours.tz,
        lookups: d.iocsChecked ?? 0,
        floor: settings.minSeverity,
        onlyReviewed: settings.onlyReviewed,
        fp: settings.includeFp,
        detail: settings.chainDetail,
      }),
    )}</div>`,
  })

  const num = (i: number) => String(i + 1).padStart(2, '0')
  const font =
    d.fontData && /^[A-Za-z0-9+/=]+$/.test(d.fontData) ? `@font-face{font-family:'Gulax';src:url(data:font/woff2;base64,${d.fontData}) format('woff2');font-weight:400;font-style:normal}` : ''
  const generated = t.ts(d.generatedAt ?? Date.now())
  const conclusion = conclusionParts(settings.client, t)
  const preparedFor = [
    settings.client.client.trim() ? t.cover.preparedFor(settings.client.client.trim()) : '',
    settings.client.engagementRef.trim() ? t.cover.engagement(settings.client.engagementRef.trim()) : '',
  ]
    .filter(Boolean)
    .join(' · ')
  const seen = profile.filter((b) => b.state !== 'none')
  const confirmedBadges = profile.filter((b) => b.state === 'confirmed')
  // the firm's name and logo stand where REMN's wordmark stands when the analyst set them
  const brand = firm || 'REMN'
  const mark = `${logo ? `<img class="logo" src="${logo.dataUrl}" alt="${h(firm)}">` : ''}${firm ? `<span class="firm">${h(firm)}</span>` : logo ? '' : '<span class="wordmark">REMN</span>'}`
  const tag = branding.coverLine.trim() || t.cover.tag
  const bold = (k: number) => `<b>${t.num(k)}</b>`
  return `<!doctype html><html lang="${t.lang}"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; base-uri 'none'; form-action 'none'"><meta name="viewport" content="width=device-width"><title>${h(firm ? `${firm} · ${kase.name}` : t.cover.title(kase.name))}</title><style>${font}${CSS}${printCss(t, brand, kase.name, markingLine(settings.client))}</style></head><body>
<div class="cover-page">
<div class="cover${d.issue?.status === 'draft' ? ' draft' : ''}">
${marking(settings.client)}
<div class="brand"><div class="l">${mark}<span class="tag">${h(tag)}</span></div><div class="r">${generated}<br>${h(kase.analyst ? t.cover.analyst(kase.analyst) : t.cover.noAnalyst)}${d.issue ? `<br><span class="issue ${d.issue.status}">${h(d.issue.status === 'final' && d.issue.finalAt ? t.cover.final(t.ts(d.issue.finalAt)) : t.cover.draft)}</span>` : ''}</div></div>
<h1>${h(kase.name)}</h1>
${preparedFor ? `<div class="meta for">${h(preparedFor)}</div>` : ''}
<div class="meta">${h(t.cover.meta(settings.minSeverity, settings.onlyReviewed, settings.includeFp))}</div>
<div class="hero">${seal(t, verdict)}<div class="bottom"><div class="k">${h(t.cover.bottomLine)}</div><div class="line">${line ? md(line) : `<p>${h(verdict.detail)}</p>`}</div>${line ? `<div class="det">${h(verdict.detail)}</div>` : ''}<div class="conf ${confidence.level}"><b>${h(t.cover.completeness(t.level[confidence.level] ?? confidence.level))}</b>${h(confidence.reasons.slice(0, 3).join(' · '))}<span class="sub">${h(t.cover.completenessSub)}</span></div>${
    conclusion.confidence
      ? `<div class="conf analyst"><b>${h(t.cover.analystConfidence(conclusion.confidence))}</b>${h(conclusion.basis)}<span class="sub">${h(t.cover.analystConfidenceSub)}</span></div>`
      : ''
  }</div></div>
<div class="scorecard">${[d.evidence.length, rowsTotal, d.findings.length, d.incidents.length + d.chains.length, verdict.confirmed, d.iocs.length]
    .map((v, i) => `<div class="kpi${i === 4 && verdict.confirmed ? ' critical' : i === 5 ? ' accent' : ''}"><div class="v">${t.num(v)}</div><div class="l">${h(t.cover.kpi[i])}</div></div>`)
    .join('')}</div>
<div class="sevbar">${ORDER.map((s) => (bySev[s] ? `<span title="${h(t.sev[s])} ${bySev[s]}" style="width:${((bySev[s] / total) * 100).toFixed(1)}%;background:var(--${s})"></span>` : '')).join('')}</div>
<div class="legend">${ORDER.map((s) => `<span><i style="background:var(--${s})"></i>${h(t.sev[s])} ${bySev[s] ?? 0}</span>`).join('')}<span class="dim">${t.cover.legend(verdict.confirmed, verdict.reviewed, verdict.falsePositives, d.undecided, bold)}</span></div>
<div class="profile"><div class="k"><span>${h(t.cover.profile)}</span><span>${h(t.cover.profileCount(confirmedBadges.length, seen.length, profile.length))}</span></div><div class="hexes">${profile.map((b) => badge(t, b)).join('')}</div></div>
<div class="ribbons"><span class="ribbon ${verified === d.evidence.length && d.evidence.length ? 'ok' : 'warn'}"><i></i><b>${t.num(verified)}/${t.num(d.evidence.length)}</b> ${h(t.cover.verified)}</span><span class="ribbon ${d.undecided ? 'warn' : 'ok'}"><i></i><b>${h(d.undecided ? t.cover.undecided(t.num(d.undecided)) : t.cover.reviewComplete)}</b></span>${d.findings.some((f) => f.ruleId.startsWith('engine:')) ? `<span class="ribbon ok"><i></i>${h(t.cover.engine)}</span>` : ''}${aiUsed ? `<span class="ribbon ai"><i></i>${h(t.cover.aiText)}</span>` : `<span class="ribbon"><i></i>${h(t.cover.noAiText)}</span>`}${d.iocsChecked ? '' : `<span class="ribbon"><i></i>${h(t.cover.notEnriched)}</span>`}</div>
</div>
<ul class="toc">${sections.map((s, i) => `<li><span class="n">${num(i)}</span>${h(s.title)}${s.count != null ? ` <span class="dim">(${t.num(s.count)})</span>` : ''}</li>`).join('')}</ul>
</div>
${sections.map((s, i) => `<section class="s" id="${h(s.id)}"><div class="s-head"><span class="num">${num(i)}</span><h2>${h(s.title)}</h2><span class="rule"></span>${s.count != null ? `<span class="count">${t.num(s.count)}</span>` : ''}</div>${s.body}</section>`).join('\n')}
<div class="foot"><span class="${firm ? 'wm firm' : 'wm'}">${h(brand)}</span><span>${h(kase.name)} · ${h(verdict.label)} · ${h(t.cover.generated(generated))}</span></div>
${marking(settings.client)}
</body></html>`
}

let fontPromise: Promise<string | undefined> | null = null
/** The wordmark face as base64, fetched once from the app's own files; undefined when unavailable. */
export function loadReportFont(): Promise<string | undefined> {
  if (!fontPromise) {
    fontPromise = (async () => {
      try {
        const resp = await fetch('/fonts/gulax-regular.woff2')
        if (!resp.ok) return undefined
        const buf = new Uint8Array(await resp.arrayBuffer())
        let bin = ''
        for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode(...buf.subarray(i, i + 0x8000))
        return btoa(bin)
      } catch {
        return undefined
      }
    })()
  }
  return fontPromise
}
