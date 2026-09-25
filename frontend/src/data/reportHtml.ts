import type { Case, CaseNote, Evidence, Finding, Ioc, Severity } from '../db/schema'
import type { Chain, ChainStep } from './chains'
import type { ReportStory } from './stories'
import type { ChainReview, ReportSettings } from './review'
import { chainSeverity, effectiveSeverity, stepVisible } from './review'
import type { Incident } from '../rules/incidents'
import type { RelationshipReview } from './relationshipReviews'
import { packageCoverageIssues } from './packageCoverage'
// every time in the report is UTC, whatever the analyst's display setting
import { defang, escapeHtml, fmtBytes, fmtNum, fmtUtc as fmtTs, renderMarkdown } from '../util/format'
import type { GapStatement } from './evidenceGaps'
import { isLead, type MeasureReading } from './ruleMeasures'
import { CHECKED_ROWS, type ClaimCheck, type ReportClaims } from './claims'

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

const TRANSPORT_WORDS: Record<string, string> = {
  browser: 'Ollama on the analyst’s machine',
  openai: 'a local OpenAI-compatible model server',
  server: 'the REMN server’s Ollama',
  claude: 'Claude Code (Anthropic)',
}

function aiSection(a: AiUsage): string {
  const kinds = Object.entries(a.byProposalKind)
  const where = a.transports.map((t) => TRANSPORT_WORDS[t] ?? t)
  return (
    `<p class="intro">A language model assisted this investigation: it read the case through read-only tools and proposed; every change it proposed took effect only when the analyst accepted it. ` +
    `Each run, tool call, proposal and decision is recorded in the case's AI ledger, chained by hash.</p>` +
    `<div class="settings">${n(a.runs)} run${a.runs === 1 ? '' : 's'} · ${n(a.toolCalls)} tool call${a.toolCalls === 1 ? '' : 's'} · ${a.first && a.last ? `${fmtTs(a.first)} to ${fmtTs(a.last)}` : ''}` +
    `${a.models.length ? ` · model${a.models.length === 1 ? '' : 's'}: ${h(a.models.join(', '))}` : ''}${where.length ? ` · through ${h(where.join(', '))}` : ''}</div>` +
    (kinds.length
      ? table(
          ['proposed', 'count', 'accepted', 'rejected'],
          kinds.map(([k, v]) => [h(k.replace('_', ' ')), n(v.proposed), n(v.accepted), n(v.rejected)]),
        )
      : '<div class="empty">The model proposed no change to the case.</div>') +
    `<div class="settings">${n(a.accepted)} accepted, ${n(a.rejected)} rejected${a.undone ? `, ${n(a.undone)} undone after acceptance` : ''}` +
    `${a.notices ? ` · ${n(a.notices)} time${a.notices === 1 ? '' : 's'} the evidence held text addressed to a model (flagged to the analyst)` : ''}</div>` +
    `<div class="settings">ledger: ${n(a.check.entries)} entries, ${a.check.intact ? `chain intact, head <code>${h((a.check.head ?? '').slice(0, 16))}</code>` : `<b>chain broken at entry ${n(a.check.brokenAt ?? 0)}</b>: an entry was changed or removed after it was written`}</div>`
  )
}

const ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const
const rank = (s: string) => Math.max(0, ORDER.length - 1 - ORDER.indexOf(s as never))
const worstOf = (xs: string[]): Severity => (xs.length ? (ORDER.find((s) => xs.includes(s)) ?? 'info') : 'info')
const STATUS_WORD: Record<string, string> = { new: 'not reviewed', reviewed: 'reviewed', escalated: 'confirmed', false_positive: 'false positive' }
const h = escapeHtml
const md = (text: string) => renderMarkdown(text)
const n = (x: number) => fmtNum(x)
const pill = (sev: string) => `<span class="pill ${ORDER.includes(sev as never) ? sev : 'info'}">${h(sev)}</span>`
const statusPill = (s: string) => `<span class="pill st-${h(s)}">${h(STATUS_WORD[s] ?? s)}</span>`
const verdictPill = (v?: string) => (v ? `<span class="pill verdict-${h(v)}">${h(v)}</span>` : '')
const chip = (text: string) => `<span class="chip">${h(text)}</span>`
const rows = (xs: string[][]) => xs.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('')
/** a table whose header row repeats on every printed page */
const table = (head: string[], body: string[][]) => `<table><thead><tr>${head.map((x) => `<th>${x}</th>`).join('')}</tr></thead><tbody>${rows(body)}</tbody></table>`
/** only a PNG data URL this app produced itself is embedded */
/** a graph legend entry: the shape (a CSS class of the report) and the colour the graph draws it in */
type KeyItem = [shape: 'diamond' | 'box' | 'dot' | 'ring' | 'line', color: string, label: string]
const CHAIN_KEY: KeyItem[] = [
  ['diamond', 'var(--critical)', 'seed mail'],
  ['box', 'var(--high)', 'step, coloured by its worst finding'],
  ['ring', 'var(--ink-3)', 'folded routine steps'],
  ['line', 'var(--accent)', 'tie to the mail'],
]
const CAMPAIGN_KEY: KeyItem[] = [
  ['box', 'var(--high)', 'person, coloured by the chain'],
  ['dot', 'var(--high)', 'shared sender or domain'],
  ['dot', 'var(--low)', 'shared machine or IP'],
  ['dot', 'var(--ink-3)', 'in one chain only'],
]
const img = (src: string | undefined, alt: string, caption?: string, key?: KeyItem[]) =>
  src && /^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(src)
    ? `<figure><img src="${src}" alt="${h(alt)}">${
        caption || key
          ? `<figcaption>${key ? key.map(([shape, color, label]) => `<span class="gk"><i class="gk-${shape}" style="--k:${color}"></i>${h(label)}</span>`).join('') : ''}${caption ? h(caption) : ''}</figcaption>`
          : ''
      }</figure>`
    : ''
const span = (from: number | null | undefined, to: number | null | undefined) => (from && to && to !== from ? `${fmtTs(from)} <span class="dim">to</span> ${fmtTs(to)}` : fmtTs(from))
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

/** What the review concluded, from the decisions on chains and incidents. Findings decide nothing on their own. */
export function computeVerdict(d: ReportData): Verdict {
  const confirmedChains = d.chains.filter((c) => d.reviews[c.id]?.verdict === 'confirmed')
  const escalated = d.incidents.filter((i) => i.status === 'escalated')
  const reviewed = d.chains.filter((c) => d.reviews[c.id]?.verdict === 'unsure').length + d.incidents.filter((i) => i.status === 'reviewed').length
  const falsePositives = d.falsePositives ?? d.incidents.filter((i) => i.status === 'false_positive').length
  // a confirmed item the print settings leave out is still confirmed: a presentation filter must not
  // turn "Compromise confirmed" into "Nothing confirmed"
  const unprinted = d.unprintedConfirmed ?? []
  const confirmed = confirmedChains.length + escalated.length + unprinted.length
  const base = { confirmed, reviewed, falsePositives }
  const notPrinted = unprinted.length ? ` ${unprinted.length} of them ${unprinted.length === 1 ? 'is' : 'are'} not printed (below the severity floor or left out).` : ''
  if (confirmed) {
    const sevs = [...confirmedChains.map((c) => chainSeverity(c, d.reviews[c.id])), ...escalated.map((i) => i.severity), ...unprinted.map((u) => u.severity)]
    const severity = worstOf(sevs)
    const confirmedFindings = [...escalated.flatMap((i) => i.findings), ...confirmedChains.flatMap((c) => d.membersOf.get(c.id) ?? []), ...unprinted.flatMap((u) => u.findings)]
    // unwanted software is the verdict when a confirmed item names it and nothing confirmed rises above medium:
    // the runs of the same browser from a user profile are the same thing, not a second threat
    const unwantedPresent = confirmedFindings.some(isUnwanted)
    const onlyUnwanted = unwantedPresent && confirmedFindings.every((f) => isUnwanted(f) || userExecution(f))
    if (onlyUnwanted)
      return {
        ...base,
        kind: 'unwanted',
        severity,
        label: 'Unwanted software',
        detail: `${confirmed} confirmed item${confirmed === 1 ? '' : 's'} describe unwanted or adware-class software at ${severity} severity, no intrusion.${notPrinted}`,
      }
    if (rank(severity) >= rank('high'))
      return {
        ...base,
        kind: 'compromise',
        severity,
        label: 'Compromise confirmed',
        detail: `${confirmed} confirmed item${confirmed === 1 ? '' : 's'}, the worst at ${severity} severity.${notPrinted}`,
      }
    return {
      ...base,
      kind: 'suspicious',
      severity,
      label: 'Suspicious activity confirmed',
      detail: `${confirmed} confirmed item${confirmed === 1 ? '' : 's'} at ${severity} severity; nothing reached high.${notPrinted}`,
    }
  }
  if (reviewed)
    return {
      ...base,
      kind: 'unconfirmed',
      severity: null,
      label: 'Nothing confirmed',
      detail: `${reviewed} item${reviewed === 1 ? '' : 's'} reviewed without confirmation${d.undecided ? `, ${d.undecided} still undecided` : ''}.`,
    }
  if (d.undecided)
    return { ...base, kind: 'pending', severity: null, label: 'Review incomplete', detail: `${d.undecided} item${d.undecided === 1 ? '' : 's'} without a decision; the verdict waits for them.` }
  if (!d.findings.length && !d.chains.length && !d.incidents.length)
    return { ...base, kind: 'clean', severity: null, label: 'No confirmed threat', detail: 'No finding passed the severity floor; there was nothing to decide.' }
  return {
    ...base,
    kind: 'clean',
    severity: null,
    label: 'No confirmed threat',
    detail: falsePositives ? `Every item was reviewed; ${falsePositives} false positive${falsePositives === 1 ? '' : 's'}.` : 'Every item was reviewed and none was confirmed.',
  }
}

/** Why a non-package evidence file was not read completely, or '' when it was. */
export function evidenceIssue(e: Evidence): string {
  const stats = (e.stats ?? {}) as Record<string, unknown>
  if (e.status === 'error') return e.error ? `parse stopped: ${e.error}` : 'parse stopped'
  const errors = Number(stats.errors ?? 0)
  // a member skipped as out of scope ("not a mail file") was not evidence of this kind; one skipped
  // for a size limit, encryption or a compression method was, and was not read
  const members = (Array.isArray(stats.members) ? stats.members : Array.isArray(stats.files) ? stats.files : []) as { status?: string; reason?: string }[]
  const unread = members.filter((m) => m.status === 'skipped' && !/^not (a|an) /i.test(String(m.reason ?? ''))).length
  const bits: string[] = []
  if (errors > 0) bits.push(`${errors} parse error${errors === 1 ? '' : 's'}`)
  if (unread) bits.push(`${unread} archive member${unread === 1 ? '' : 's'} not read`)
  if (e.error) bits.push(e.error)
  return bits.join('; ')
}

export interface Confidence {
  level: 'high' | 'medium' | 'low'
  reasons: string[]
}

/** How far the report can be trusted: decisions made, evidence intact, analysis complete. */
export function computeConfidence(d: ReportData): Confidence {
  const reasons: string[] = []
  const decided = d.chains.filter((c) => d.reviews[c.id]?.verdict).length + d.incidents.filter((i) => i.status !== 'new').length
  const ratio = decided + d.undecided ? decided / (decided + d.undecided) : 1
  if (d.undecided) reasons.push(`${d.undecided} item${d.undecided === 1 ? '' : 's'} not decided`)
  const unverified = d.evidence.filter((e) => e.integrity !== 'verified').length
  if (unverified) reasons.push(`${unverified} evidence file${unverified === 1 ? '' : 's'} without a verified digest`)
  const issues = d.evidence.filter((e) => e.kind === 'package').flatMap((e) => packageCoverageIssues(e))
  if (issues.length) reasons.push(`package coverage: ${issues.length} reported issue${issues.length === 1 ? '' : 's'}`)
  // a parse that failed, stopped at a limit, or skipped members read less than the file holds
  const incomplete = d.evidence.filter((e) => e.kind !== 'package' && evidenceIssue(e)).length
  if (incomplete) reasons.push(`${incomplete} evidence file${incomplete === 1 ? ' was' : 's were'} not read completely`)
  if (d.coverageWarnings?.length) reasons.push(`chain analysis incomplete (${d.coverageWarnings.length} limit${d.coverageWarnings.length === 1 ? '' : 's'} reached)`)
  const rules = d.rules
  const rulesIssue = !!rules && (rules.lastRun == null || rules.evidenceAfter > 0 || rules.errors > 0)
  if (rules?.lastRun == null && rules) reasons.push('the rules have not run on this case')
  else if (rules?.evidenceAfter) reasons.push(`${rules.evidenceAfter} evidence file${rules.evidenceAfter === 1 ? '' : 's'} added after the last rule run`)
  if (rules?.errors) reasons.push(`${rules.errors} rule${rules.errors === 1 ? '' : 's'} failed in the last run`)
  if (!(d.iocsChecked ?? 0)) reasons.push('indicators not enriched (no reputation lookup was run)')
  const complete = !issues.length && !incomplete && !d.coverageWarnings?.length && !rulesIssue
  const level: Confidence['level'] = ratio >= 0.95 && !unverified && complete ? 'high' : ratio >= 0.7 && !unverified ? 'medium' : 'low'
  if (level === 'high') reasons.unshift('every item decided, evidence verified, analysis complete')
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
  const printed = d.findings.filter((f) => f.status !== 'false_positive')
  return BADGES.map((def) => {
    const mine = printed.filter((f) => badgesOf(f).includes(def))
    const confirmed = mine.some((f) => f.id != null && confirmedIds.has(f.id)) || (def.id === 'initial-access' && d.chains.some((c) => d.reviews[c.id]?.verdict === 'confirmed'))
    const techniques = [...new Set(mine.flatMap((f) => f.attack.filter((t) => def.tech.some((p) => t.toUpperCase().startsWith(p)))))].sort().slice(0, 6)
    return { def, state: confirmed ? 'confirmed' : mine.length ? 'observed' : 'none', findings: mine.length, techniques }
  })
}

const HEX = '<svg viewBox="0 0 100 100" aria-hidden="true"><polygon points="50,3 92,26.5 92,73.5 50,97 8,73.5 8,26.5"/></svg>'
const badge = (b: BadgeState) =>
  `<div class="hex ${b.state}" title="${h(b.def.label)}: ${b.findings} finding${b.findings === 1 ? '' : 's'}${b.techniques.length ? ' · ' + h(b.techniques.join(', ')) : ''}">${HEX}<span class="code">${h(b.def.code)}</span><span class="lbl">${h(b.def.label)}</span><span class="n">${b.state === 'none' ? '' : n(b.findings)}</span></div>`

/** The seal on the cover: a hexagon with the verdict, coloured by what it says. */
const seal = (v: Verdict) =>
  `<div class="seal ${v.kind}">${HEX}<div class="seal-in"><span class="k">verdict</span><span class="w">${h(v.label)}</span>${v.severity ? `<span class="s">${h(v.severity)}</span>` : ''}</div></div>`

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

function meter(c: Chain): string {
  const b = c.scoreBreakdown
  const parts: [string, number][] = b
    ? [
        ['seed', b.seed],
        ['links', b.links],
        ['steps', b.steps],
        ['findings', b.findings],
        ['sources', b.sources],
      ]
    : [['score', c.score]]
  const total = Math.max(
    1,
    parts.reduce((s, [, v]) => s + v, 0),
  )
  const colours = ['#1b7f66', '#2fbf8f', '#2f6fdb', '#d9822b', '#8a95a3']
  const segs = parts.map(([k, v], i) => `<span title="${h(k)} ${v}" style="width:${((v / total) * 100).toFixed(1)}%;background:${colours[i % colours.length]}"></span>`).join('')
  return `<span class="meter" title="${h(parts.map(([k, v]) => `${k} ${v}`).join(' · '))}"><span class="bar">${segs}</span><span>score ${c.score}${b?.cap ? ` (capped ${b.cap})` : ''}</span></span>`
}

function chainCard(c: Chain, d: ReportData): string {
  const r = d.reviews[c.id]
  const visible = c.steps.filter((s) => stepVisible(s, d.settings.chainDetail))
  const hidden = c.steps.length - visible.length
  const folded = foldSteps(visible)
  const printed = folded.slice(0, MAX_STEP_ROWS)
  const left = folded.length - printed.length
  const members = d.membersOf.get(c.id) ?? []
  const offset = (f: FoldedStep) =>
    f.n > 1 && f.offsetEnd !== f.offsetMin
      ? `${f.offsetMin >= 0 ? '+' : ''}${Math.round(f.offsetMin)} → ${f.offsetEnd >= 0 ? '+' : ''}${Math.round(f.offsetEnd)} min`
      : `${f.offsetMin >= 0 ? '+' : ''}${Math.round(f.offsetMin)} min`
  const when = (f: FoldedStep) => (f.n > 1 && f.tsEnd !== f.ts ? `${fmtTs(f.ts)}<span class="sub">to ${fmtTs(f.tsEnd)}</span>` : fmtTs(f.ts))
  const narrative = r?.narrative
    ? `<div class="narr">${md(r.narrative)}</div>${r.narrativeBy === 'ai' ? '<div class="cap ai">narrative drafted by the model during triage</div>' : ''}${textNote(`chain:${c.id}`, d.claims)}`
    : `<div class="narr"><p>${h(c.summary)}</p></div>`
  const sev = chainSeverity(c, r)
  return `<div class="card chain ${h(sev)}">
<div class="card-head">${pill(sev)}<h3>${h(c.identityLabel)}</h3>${verdictPill(r?.verdict)}${meter(c)}</div>
<div class="card-meta">Seed ${c.seed.source === 'events' ? 'event' : 'mail'} “${h(c.seed.subject)}” from <code>${h(c.seed.fromAddr ?? '')}</code> at ${fmtTs(c.seed.ts)} (risk ${c.seed.risk}) · ${c.steps.length} steps from ${fmtTs(c.start)} to ${fmtTs(c.end)} · ${c.artifactLinks} artifact tie(s)${c.entities.attackerAddresses.length ? ` · attacker <code>${h(c.entities.attackerAddresses.join(', '))}</code>` : ''}${c.entities.ips.length ? ` · IPs <code>${h(c.entities.ips.join(', '))}</code>` : ''}${c.entities.hosts.length ? ` · hosts <code>${h(c.entities.hosts.join(', '))}</code>` : ''}</div>
${narrative}
${d.settings.includeGraphs ? img(d.graphs[c.id], `graph of the chain for ${c.identityLabel}`, 'Steps by lane, time left to right.', CHAIN_KEY) : ''}
${table(
  ['time (UTC)', 'offset', 'source', 'step', 'ties to the mail / findings'],
  printed.map((f) => {
    const s = f.step
    return [
      `<span class="nowrap">${when(f)}</span>`,
      `<span class="nowrap">${offset(f)}</span>`,
      `<span class="lane ${s.kind === 'mail' ? 'mail' : s.origin === 'm365' ? 'm365' : 'host'}"></span>${h(s.kind === 'mail' ? 'mailbox' : s.origin === 'm365' ? 'Microsoft 365' : 'host')}`,
      h(s.title) +
        (f.n > 1 ? ` <span class="chip">×${f.n}</span>` : s.count > 1 ? ` <span class="chip">×${s.count}</span>` : '') +
        (s.computer || s.ipAddress ? `<span class="sub">${h([s.computer, s.ipAddress].filter(Boolean).join(' · '))}</span>` : ''),
      h([...s.artifacts, ...s.findings.map((x) => x.title)].join('; ')),
    ]
  }),
)}
${left || hidden ? `<div class="cap">${left ? `${left} more step row(s) not printed (open the chain in REMN for the full list)` : ''}${left && hidden ? ' · ' : ''}${hidden ? `${hidden} routine step(s) not printed at the “${h(d.settings.chainDetail)}” detail level` : ''}.</div>` : ''}
${members.length ? `<div class="cap" style="margin-top:8px">${members.length} finding(s) linked to this chain, decided with it</div>${groupedFindings(members, {}, d.measures, d.claims)}` : ''}
${r?.by === 'ai' && r.aiReason ? `<div class="cap ai">Triage note (model): ${h(r.aiReason)}</div>` : ''}
</div>`
}

// ---------------------------------------------------------------------------
// stories
// ---------------------------------------------------------------------------

const PHASE_WORDS: Record<string, string> = {
  reconnaissance: 'Reconnaissance',
  'resource-development': 'Resource development',
  'initial-access': 'Initial access',
  execution: 'Execution',
  persistence: 'Persistence',
  'privilege-escalation': 'Privilege escalation',
  stealth: 'Stealth',
  'defense-impairment': 'Defense impairment',
  'credential-access': 'Credential access',
  discovery: 'Discovery',
  'lateral-movement': 'Lateral movement',
  collection: 'Collection',
  'command-and-control': 'Command and control',
  exfiltration: 'Exfiltration',
  impact: 'Impact',
}

/** A story: its phases in the order they happened, what marks each (its worst findings, else its first step), and where its evidence stops. */
function storyCard({ story: s, key, note }: ReportStory, d: ReportData): string {
  const marks = (phase: string) => {
    const steps = s.steps.filter((st) => st.phase === phase)
    const found = steps.flatMap((st) => st.findings).sort((a, b) => rank(b.severity) - rank(a.severity))
    const titles = [...new Set(found.map((f) => f.title))].slice(0, 2)
    return titles.length ? h(titles.join('; ')) + (new Set(found.map((f) => f.title)).size > 2 ? ' …' : '') : `<span class="dim">${h(steps[0]?.title ?? '')}</span>`
  }
  const who = s.kind === 'host' ? 'Host' : 'Person'
  const where = [
    s.hosts.length ? `hosts <code>${h(s.hosts.slice(0, 6).join(', '))}</code>${s.hosts.length > 6 ? ` +${s.hosts.length - 6}` : ''}` : '',
    s.attackerAddresses.length ? `from <code>${h(s.attackerAddresses.slice(0, 6).join(', '))}</code>` : '',
  ].filter(Boolean)
  return `<div class="card chain ${h(s.severity)}">
<div class="card-head">${pill(s.severity)}<h3>${h(s.title)}</h3>${chip(`${s.confidence} ties`)}</div>
<div class="card-meta">${who} ${h(s.subject.label)} · ${span(s.start, s.end)} · ${n(s.records)} record(s) in ${n(s.steps.length)} step(s)${where.length ? ' · ' + where.join(' · ') : ''}</div>
${note ? `<div class="narr">${md(note)}</div><div class="cap">the analyst's reading of the story</div>${textNote(`story:${key}`, d.claims)}` : `<div class="narr"><p>${h(s.summary || s.headline)}</p></div>`}
${table(
  ['phase', 'when (UTC)', 'steps', 'what marks it'],
  s.phases.map((p) => [`${p.severity ? pill(p.severity) + ' ' : ''}${h(PHASE_WORDS[p.phase] ?? p.label)}`, `<span class="nowrap">${span(p.first, p.last)}</span>`, n(p.steps), marks(p.phase)]),
)}
${s.gaps.length ? `<div class="cap">Where it stops: ${s.gaps.map((g) => h(g)).join(' ')}</div>` : ''}
</div>`
}

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
function measureMark(m: MeasureReading | undefined): string {
  if (!m) return ''
  if (isLead(m)) return ' · <b class="lead">lead</b>'
  if (m.noisy) return ' · <span class="dim">also fires on clean machines</span>'
  return ''
}

const CLAIM_WORD: Record<ClaimCheck['status'], string> = { verified: 'rows checked', unsupported: 'rows missing', contradicted: 'rows disagree' }

/** Whether a rule's findings hold against the rows they cite, and where the first of those rows is in its file. */
function claimNote(ids: number[], claims?: ReportClaims): string {
  if (!claims) return ''
  const cs = ids.map((id) => claims.findings[id]).filter((c): c is ClaimCheck => !!c)
  if (!cs.length) return ''
  const worst = cs.find((c) => c.status === 'contradicted') ?? cs.find((c) => c.status === 'unsupported') ?? cs[0]
  const rec = cs.find((c) => c.records.length)?.records[0]
  const cited = cs.reduce((t, c) => t + c.cited, 0)
  const where = rec ? ` · ${h(rec.file)} ${h(rec.record)}${cited > 1 ? ` <span class="dim">and ${n(cited - 1)} more</span>` : ''}` : ''
  return `<span class="sub claim ${worst.status}" title="${h(worst.reasons.join(' '))}">${CLAIM_WORD[worst.status]}${where}</span>`
}

/** A text's check, under the text, when it names something its rows do not hold. */
function textNote(key: string, claims?: ReportClaims): string {
  const t = claims?.texts.find((x) => x.key === key)
  if (!t || t.check.status === 'verified') return ''
  return `<div class="cap claim ${t.check.status}">Checked against its rows: ${h(t.check.reasons.join(' '))}.</div>`
}

function groupedFindings(findings: Finding[], said: Record<string, string>, measures: Record<string, MeasureReading> = {}, claims?: ReportClaims): string {
  const groups = groupByRule(findings, said)
  return table(
    ['severity', 'finding', 'findings · rows', 'when (UTC)', 'ATT&amp;CK', 'what matched'],
    groups.map((g) => [
      pill(g.severity) + (g.severity !== g.ruleSeverity ? `<span class="sub">rule: ${h(g.ruleSeverity)}</span>` : ''),
      `${h(g.title)}<span class="sub"><code>${h(g.ruleId)}</code>${measureMark(measures[g.ruleId])}${g.escalations.length ? ' · ' + h(g.escalations.slice(0, 2).join(' · ')) : ''}</span>${claimNote(g.ids, claims)}`,
      `<span class="nowrap">${n(g.findings)} · ${n(g.rows)}</span>`,
      `<span class="nowrap">${span(g.first, g.last)}</span>`,
      g.attack
        .slice(0, 4)
        .map((t) => chip(t))
        .join(''),
      g.values.length
        ? `<span class="vals">${g.values
            .slice(0, MAX_VALUES)
            .map((v) => `<code>${h(v.length > 90 ? v.slice(0, 89) + '…' : v)}</code>`)
            .join('')}${g.values.length > MAX_VALUES ? `<span class="dim"> +${g.values.length - MAX_VALUES} more</span>` : ''}</span>`
        : '<span class="dim">–</span>',
    ]),
  )
}

function incidentCard(i: Incident, measures: Record<string, MeasureReading> = {}, claims?: ReportClaims): string {
  const decidedByAi = i.lead.decidedBy === 'ai'
  return `<div class="card inc ${h(i.severity)}">
<div class="card-head">${pill(i.severity)}<h3>${h(i.title)}</h3><span class="stamp st-${h(i.status)}">${h(STATUS_WORD[i.status] ?? i.status)}</span></div>
<div class="card-meta">${h(i.subtitle)} · ${span(i.ts, i.tsEnd)} · ${n(i.refs.length)} row(s)${
    Object.keys(i.entities).length
      ? ' · ' +
        Object.entries(i.entities)
          .slice(0, 6)
          .map(([k, v]) => chip(`${k}=${String(v)}`))
          .join('')
      : ''
  }</div>
${i.lead.notes ? `<div class="note">${md(i.lead.notes)}</div>${i.lead.notesBy === 'ai' ? '<div class="cap ai">note drafted by the model during triage</div>' : ''}` : ''}${textNote(`incident:${i.lead.id ?? i.title}`, claims)}
${decidedByAi && i.lead.aiReason ? `<div class="cap ai">Triage note (model): ${h(i.lead.aiReason)}</div>` : ''}
${groupedFindings(i.findings, i.entities, measures, claims)}
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
  decision: string
  entities: string[]
  note: string
  kind: 'chain' | 'incident'
}

/** The decided items in time order: what a reader should know happened, in the order it happened. */
export const MAX_MOMENTS = 14

export function moments(d: ReportData): { items: Moment[]; decided: boolean; total: number } {
  const out: Moment[] = []
  for (const c of d.chains) {
    const r = d.reviews[c.id]
    if (!r?.verdict || r.verdict === 'benign') continue
    out.push({
      ts: c.start,
      end: c.end,
      severity: chainSeverity(c, r),
      title: `${c.identityLabel}: ${c.seed.subject || 'chain'}`,
      decision: r.verdict,
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
      decision: STATUS_WORD[i.status] ?? i.status,
      entities: Object.values(i.entities).slice(0, 3).map(String),
      note: firstSentence(i.lead.notes || i.lead.aiReason),
      kind: 'incident',
    })
  }
  const decided = out.length > 0
  const confirmed = out.filter((m) => m.decision === 'confirmed')
  const chosen = (confirmed.length ? confirmed : out).sort((a, b) => a.ts - b.ts)
  return { items: chosen.slice(0, MAX_MOMENTS), decided, total: chosen.length }
}

const momentsList = (ms: Moment[]) =>
  `<ol class="moments">${ms
    .map(
      (m) =>
        `<li class="${h(m.severity)}"><div class="t">${m.ts === UNTIMED ? 'no event time<span class="sub">collected artefact</span>' : `${fmtTs(m.ts)}${m.end && m.end !== m.ts ? `<span class="sub">to ${fmtTs(m.end)}</span>` : ''}`}</div><div class="b"><div class="hd">${pill(m.severity)}<b>${h(m.title)}</b><span class="stamp ${m.decision === 'confirmed' ? 'st-escalated' : 'st-reviewed'}">${h(m.decision)}</span></div>${m.entities.length ? `<div class="ents">${m.entities.map((e) => chip(e)).join('')}</div>` : ''}${m.note ? `<div class="nt">${h(m.note)}</div>` : ''}</div></li>`,
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
.meter{display:inline-flex;align-items:center;gap:8px;font-family:var(--mono);font-size:10.5px;color:var(--ink-2)}
.meter .bar{display:flex;width:120px;height:8px;border-radius:4px;overflow:hidden;background:var(--surface-3)}
.meter .bar span{display:block;height:100%}
.narr{border-left:3px solid var(--accent);background:var(--surface-2);padding:8px 12px;margin:8px 0 10px;border-radius:0 6px 6px 0;font-size:12px}
.narr p{margin:0 0 6px}.narr p:last-child{margin:0}
.narr strong{color:var(--ink)}
.cap{font-size:10px;color:var(--ink-3);margin-top:4px}
.cap.ai{color:var(--violet)}.claim.unsupported{color:var(--medium)}.claim.contradicted{color:var(--critical);font-weight:600}
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
.foot{margin-top:40px;border-top:1px solid var(--line);padding-top:6px;font-size:10px;color:var(--ink-3);display:flex;justify-content:space-between}
.foot .wm{font-family:var(--display);letter-spacing:.2em;color:var(--ink-2)}
.empty{color:var(--ink-3);font-size:11.5px}
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

function method(d: ReportData, v: Verdict, conf: Confidence): string {
  const rowsTotal = d.evidence.reduce((t, e) => t + (e.count ?? 0), 0)
  const kinds = [...new Set(d.evidence.map((e) => e.format || e.kind))]
  const rulesFired = new Set(d.findings.map((f) => f.ruleId)).size
  const engine = d.findings.filter((f) => f.ruleId.startsWith('engine:')).length
  const aiTexts =
    d.chains.filter((c) => d.reviews[c.id]?.narrativeBy === 'ai' || d.reviews[c.id]?.by === 'ai').length +
    d.incidents.filter((i) => i.lead.notesBy === 'ai' || i.lead.decidedBy === 'ai').length +
    (d.summaryBy === 'ai' ? 1 : 0)
  const issues = d.evidence.filter((e) => e.kind === 'package').flatMap((e) => packageCoverageIssues(e))
  const printedRules = [...new Set(d.findings.map((f) => f.ruleId))]
  const readings = printedRules.map((r) => d.measures?.[r]).filter((m): m is MeasureReading => !!m?.label)
  const detects = readings.filter((m) => m.verdict === 'detects').length
  const leads = readings.filter(isLead).length
  const leadFindings = d.findings.filter((f) => {
    const m = d.measures?.[f.ruleId]
    return !!m && isLead(m)
  }).length
  // the printed findings and texts, read back against the rows they cite
  const checked = d.findings.map((f) => (f.id != null ? d.claims?.findings[f.id] : undefined)).filter((c): c is ClaimCheck => !!c)
  const claimCount = (s: ClaimCheck['status']) => checked.filter((c) => c.status === s).length
  const texts = d.claims?.texts ?? []
  const byId = new Map(d.findings.filter((f) => f.id != null).map((f) => [f.id!, f]))
  const claimLimits = [
    ...Object.entries(d.claims?.findings ?? {})
      .filter(([id, c]) => c.status !== 'verified' && byId.has(Number(id)))
      .sort((a, b) => (a[1].status === 'contradicted' ? 0 : 1) - (b[1].status === 'contradicted' ? 0 : 1))
      .map(([id, c]) => {
        const f = byId.get(Number(id))!
        return `The finding "${f.title}" (${f.ruleId}) is ${c.status === 'contradicted' ? 'contradicted by its rows' : 'unsupported'}: ${c.reasons.join('; ')}.`
      }),
    ...texts.filter((t) => t.check.status !== 'verified').map((t) => `${t.what[0].toUpperCase()}${t.what.slice(1)} is unsupported: ${t.check.reasons.join('; ')}.`),
  ]
  const sources = [
    `${n(d.evidence.length)} evidence file${d.evidence.length === 1 ? '' : 's'} (${h(kinds.join(', ') || 'none')}), ${n(rowsTotal)} rows parsed`,
    `${n(rulesFired)} rule${rulesFired === 1 ? '' : 's'} produced the printed findings${engine ? `; ${n(engine)} finding${engine === 1 ? '' : 's'} came from an external detection engine` : ''}`,
    ...(checked.length
      ? [
          `each printed finding was read back against the rows it cites (the first ${n(CHECKED_ROWS)} of each): ${n(claimCount('verified'))} verified, ${n(claimCount('unsupported'))} unsupported, ${n(claimCount('contradicted'))} contradicted${texts.length ? `; ${n(texts.length)} text${texts.length === 1 ? '' : 's'} (chain narratives, incident and story notes, the summary) checked for the addresses, accounts and hashes ${texts.length === 1 ? 'it names' : 'they name'}, ${n(texts.filter((t) => t.check.status === 'verified').length)} holding` : ''}`,
        ]
      : []),
    ...(readings.length
      ? [
          `of those rules, ${n(detects)} fire${detects === 1 ? 's' : ''} on recorded attacks of what ${detects === 1 ? 'it looks' : 'they look'} for and ${n(leads)} ${leads === 1 ? 'was' : 'were'} never seen to (their findings are marked lead)${d.measuredOn ? `. ${h(d.measuredOn)}` : ''}`,
        ]
      : []),
    `findings below ${h(d.settings.minSeverity)} severity are not printed${d.settings.onlyReviewed ? '; only reviewed items are printed' : ''}${d.settings.includeFp ? '; false positives are printed' : '; false positives are not printed'}`,
    `${v.confirmed} confirmed, ${v.reviewed} reviewed or unsure, ${v.falsePositives} false positive${v.falsePositives === 1 ? '' : 's'}, ${d.undecided} undecided`,
    aiTexts
      ? `${aiTexts} text${aiTexts === 1 ? '' : 's'} in this report ${aiTexts === 1 ? 'was' : 'were'} drafted by the analyst model and are labelled as such; decisions are the analyst's`
      : 'no text in this report was drafted by a model',
  ]
  const issue = d.issue
  const limits = [
    ...(issue?.status === 'draft'
      ? [`This is a draft. Open before it can be final: ${issue.open.map((c) => `${c.label.toLowerCase()} (${c.detail})`).join('; ') || 'the analyst has not issued it'}.`]
      : []),
    ...(issue?.waived ?? []).map((w) => `Issued with an open check: ${w.label.toLowerCase()}. The analyst's reason: ${w.reason}`),
    ...(d.gaps ?? []).map((g) => g.text),
    ...claimLimits.slice(0, 12),
    ...(claimLimits.length > 12 ? [`${n(claimLimits.length - 12)} more claims are not verified; the Report page lists them.`] : []),
    ...(leadFindings
      ? [
          `${n(leadFindings)} printed finding${leadFindings === 1 ? ' comes from a rule' : 's come from rules'} never seen to detect what ${leadFindings === 1 ? 'it looks' : 'they look'} for on recorded attacks (marked lead): each says where to look, and stands on the rows it cites and the analyst's decision.`,
        ]
      : []),
    'Times are UTC. Rules and timelines describe what the evidence records; the absence of a finding is not evidence of absence.',
    'Collection snapshots record when an artefact was collected, not when it was created or run.',
    ...(d.coverageWarnings ?? []).map((w) => `Chain analysis incomplete: ${w}`),
    ...issues.slice(0, 6).map((x) => `Package coverage: ${x}`),
    d.iocsChecked
      ? `${d.iocsChecked} of ${d.iocsTotal ?? d.iocsChecked} indicators were checked against reputation services.`
      : 'No indicator was checked against a reputation service; indicators are not enriched.',
    ...(d.rules && d.rules.lastRun == null ? ['The detection rules had not run on this case when the report was made.'] : []),
    ...(d.rules?.evidenceAfter ? [`${d.rules.evidenceAfter} evidence file(s) were added after the last rule run; their findings may be missing.`] : []),
    ...d.evidence.filter((e) => e.kind !== 'package' && evidenceIssue(e)).map((e) => `${e.name}: ${evidenceIssue(e)}.`),
    ...conf.reasons.filter((r) => !/^every item decided/.test(r)).map((r) => `Confidence: ${r}.`),
  ]
  return `<div class="method"><div><h4>How this was produced</h4><ul>${sources.map((s) => `<li>${s}</li>`).join('')}</ul></div><div><h4>Where it stops</h4><ul>${limits.map((s) => `<li>${h(s)}</li>`).join('')}</ul></div></div>`
}

export function buildReportHtml(d: ReportData): string {
  const { kase, settings } = d
  const bySev: Record<string, number> = {}
  for (const f of d.findings) bySev[effectiveSeverity(f)] = (bySev[effectiveSeverity(f)] ?? 0) + 1
  const total = Math.max(1, d.findings.length)
  const verdict = computeVerdict(d)
  const confidence = computeConfidence(d)
  const profile = threatProfile(d)
  const happened = moments(d)
  const rowsTotal = d.evidence.reduce((t, e) => t + (e.count ?? 0), 0)
  const verified = d.evidence.filter((e) => e.integrity === 'verified').length
  const aiUsed =
    d.summaryBy === 'ai' || d.chains.some((c) => d.reviews[c.id]?.narrativeBy === 'ai' || d.reviews[c.id]?.by === 'ai') || d.incidents.some((i) => i.lead.notesBy === 'ai' || i.lead.decidedBy === 'ai')
  const line = bottomLine(d.summary)

  const sections: { id: string; title: string; count?: number; body: string }[] = []
  if (d.summary)
    sections.push({
      id: 'summary',
      title: 'Executive summary',
      body: `<div class="narr">${md(d.summary)}</div>${d.summaryBy === 'ai' ? '<div class="cap ai">drafted by the analyst model from the reviewed items; the decisions it rests on are the analyst\'s</div>' : ''}${textNote('summary', d.claims)}${
        d.summaryAt && d.findings.some((f) => f.createdAt > d.summaryAt!)
          ? '<div class="cap">written before the findings last changed: the numbers and ids in it may describe an earlier state of the case</div>'
          : ''
      }`,
    })
  sections.push({
    id: 'happened',
    title: 'What happened',
    count: happened.total,
    body: happened.items.length
      ? `<p class="intro">${happened.items.some((m) => m.decision === 'confirmed') ? 'The confirmed items in the order they happened.' : 'Nothing was confirmed; the reviewed items in the order they happened.'} Dates are event times, UTC.${happened.total > happened.items.length ? ` The first ${happened.items.length} of ${happened.total} are listed; the other ${happened.total - happened.items.length}, the latest, are printed in full in the incident and chain sections.` : ''}</p>${momentsList(happened.items)}`
      : `<div class="empty">${happened.decided ? 'No dated item to place.' : 'No item has been decided yet: run the review before printing.'}</div>`,
  })
  if (d.stories?.length) {
    const left = d.storiesLeft ?? 0
    sections.push({
      id: 'stories',
      title: 'Stories',
      count: d.stories.length,
      body: `<p class="intro">A story is what happened to one person, or on one host, in one incident: the records around what raised a flag, read along the tactics of ATT&amp;CK in the order they happened, each record tied to the story by its account, its logon session, the way into the host or the process that started it. A story is how the case reads, not a decision: the decisions are the chains' and the incidents'. Each says where its evidence stops.</p>${d.stories.map((st) => storyCard(st, d)).join('\n')}${left ? `<div class="cap">${n(left)} more ${left === 1 ? 'story is' : 'stories are'} not printed: below the severity floor${settings.onlyReviewed ? ', without a note (reviewed items only)' : ''} or past the first twenty.</div>` : ''}`,
    })
  }
  if (d.chains.length) {
    const campaign =
      settings.includeGraphs && d.chains.length > 1 && d.graphs.campaign
        ? `<div class="card"><div class="card-head"><h3>Shared between chains</h3></div>${img(d.graphs.campaign, 'campaign graph', 'People in the middle, the senders and domains that reached them on the left, the machines and IPs they touched on the right.', CAMPAIGN_KEY)}<div class="cap">${d.campaignInsights.length ? d.campaignInsights.map((x) => h(x)).join(' · ') : 'no sender, domain, IP or host is shared between the chains'}</div></div>`
        : ''
    sections.push({
      id: 'chains',
      title: 'Attack chains',
      count: d.chains.length,
      body: `<p class="intro">A chain is a suspicious mail and what the recipient's accounts and machines did after it, scored on the seed, the ties to the mail, the steps, the findings and the sources involved. What happened, in order. Findings whose rows are steps of a chain are decided with it.</p>${campaign}${d.chains.map((c) => chainCard(c, d)).join('\n')}`,
    })
  }
  sections.push({
    id: 'incidents',
    title: 'Incidents',
    count: d.incidents.length,
    body: `<p class="intro">Findings on the same mail, or about the same user, host or IP within six hours, are one incident. Each table groups the incident's findings by rule: one line per rule with the count, the span and the values it matched.</p>${d.incidents.length ? d.incidents.map((i) => incidentCard(i, d.measures, d.claims)).join('\n') : '<div class="empty">No incident outside the attack chains passes the severity floor.</div>'}`,
  })
  if (settings.includeEvidence) {
    const packages = d.evidence.filter((e) => e.kind === 'package')
    sections.push({
      id: 'evidence',
      title: 'Evidence and chain of custody',
      count: d.evidence.length,
      body:
        (d.evidence.length
          ? table(
              ['file', 'kind', 'size', 'rows', 'SHA-256', 'integrity', 'read', 'added (UTC)'],
              d.evidence.map((e) => {
                // the digest says the file is the one received; this says whether all of it was read
                const issue = e.kind === 'package' ? packageCoverageIssues(e).join('; ') : evidenceIssue(e)
                return [
                  h(e.name),
                  h(e.format || e.kind),
                  fmtBytes(e.size),
                  n(e.count),
                  `<code>${h(e.sha256Client ?? '')}</code>`,
                  h(e.integrity),
                  issue ? `<span class="warn">incomplete: ${h(issue)}</span>` : 'complete',
                  `<span class="nowrap">${fmtTs(e.addedAt)}</span>`,
                ]
              }),
            )
          : '<div class="empty">No evidence file.</div>') +
        (packages.length
          ? `<h4 class="mono dim" style="margin:10px 0 4px;letter-spacing:.14em;text-transform:uppercase;font-size:9.5px">Investigation package coverage</h4>${table(
              ['package', 'coverage'],
              packages.map((e) => [h(e.name), h(packageCoverageIssues(e).join('; ') || 'No reported import issues')]),
            )}`
          : ''),
    })
  }
  const relationships = (d.relationships ?? []).filter((r) => r.status === 'accepted' && r.includeInReport)
  if (relationships.length)
    sections.push({
      id: 'relationships',
      title: 'Reviewed evidence relationships',
      count: relationships.length,
      body:
        '<p class="intro">Analyst-selected connections. Observation and collection times remain distinct; shared entities do not establish causation.</p>' +
        relationships
          .map(
            (r) =>
              `<div class="card"><h3>${h(r.sourceLabel)} → ${h(r.relation)} → ${h(r.targetLabel)}</h3><p>${h(r.reason)} (${h(r.confidence)})</p><div class="narr">${md(r.notes)}</div>${Object.keys(r.aliases ?? {}).length ? `<p>Explicit aliases: ${h(JSON.stringify(r.aliases))}</p>` : ''}${table(
                ['Source', 'Record', 'Time (UTC)', 'SHA-256'],
                r.references.map((ref) => [
                  h(ref.sourceFile ?? ''),
                  h(`${ref.source} #${ref.id} · evidence #${ref.evidenceId} · source row ${(ref.sourceIndex ?? -1) + 1}`),
                  h(`${ref.recordKind === 'observation' ? 'Collected' : 'Event'}: ${fmtTs(ref.recordKind === 'observation' ? ref.observedAt : ref.ts)}`),
                  h(ref.sourceSha256 ?? ''),
                ]),
              )}</div>`,
          )
          .join(''),
    })
  if (settings.includeIocs)
    sections.push({
      id: 'iocs',
      title: 'Indicators of compromise',
      count: d.iocs.length,
      body: d.iocs.length
        ? `<p class="intro">Indicators flagged by the reputation providers; values are defanged.</p>${table(
            ['kind', 'indicator', 'verdict', 'tags', 'seen'],
            d.iocs.map((i) => [h(i.kind), `<code>${h(defang(i.value))}</code>`, h(i.verdict ?? ''), (i.tags ?? []).map((t) => chip(t)).join(''), h(`${i.count} (${i.sources.join(', ')})`)]),
          )}`
        : '<div class="empty">No indicator flagged: reputation checks were not run, or nothing was found malicious.</div>',
    })
  if (settings.includeTimeline && d.timeline.length)
    sections.push({
      id: 'timeline',
      title: 'Case timeline',
      count: d.timeline.length,
      body: `<ul class="tl">${d.timeline.map((t) => `<li class="${h(t.severity ?? 'info')}"><div class="t">${t.untimed ? 'no event time' : fmtTs(t.ts)}${t.link ? ` · ${h(`${t.link.source} ${t.link.label ?? t.link.id}`)}` : ''}</div><div>${h(t.text)}</div></li>`).join('')}</ul>`,
    })
  if (settings.includeTasks && d.tasks.length)
    sections.push({
      id: 'tasks',
      title: 'Tasks',
      count: d.tasks.length,
      body: `<ul class="tasks">${d.tasks.map((t) => `<li class="${t.done ? 'done' : ''}"><span class="box">${t.done ? '✓' : ''}</span>${h(t.text)} <span class="dim">· ${fmtTs(t.updatedAt)}</span></li>`).join('')}</ul>`,
    })
  if (settings.includeNotes && d.notes.length)
    sections.push({
      id: 'notes',
      title: 'Analyst notes',
      count: d.notes.length,
      body: `<div class="notes">${d.notes.map((x) => `<div class="n"><div class="cap">${fmtTs(x.createdAt)}</div>${md(x.text)}</div>`).join('')}</div>`,
    })
  const groups = groupByRule(d.findings)
  sections.push({
    id: 'findings',
    title: 'Findings by rule',
    count: groups.length,
    body: groups.length
      ? `<p class="intro">Every printed finding, one line per rule: how many findings and rows, when, and the values matched. The incidents above carry the same findings in context.</p>${table(
          ['severity', 'rule', 'findings · rows', 'when (UTC)', 'status', 'what matched'],
          groups.map((g) => [
            pill(g.severity),
            `${h(g.title)}<span class="sub"><code>${h(g.ruleId)}</code>${measureMark(d.measures?.[g.ruleId])}${g.attack.length ? ' · ' + h(g.attack.slice(0, 4).join(' ')) : ''}</span>${claimNote(g.ids, d.claims)}`,
            `<span class="nowrap">${n(g.findings)} · ${n(g.rows)}</span>`,
            `<span class="nowrap">${span(g.first, g.last)}</span>`,
            Object.entries(g.statuses)
              .map(([s, c]) => `${statusPill(s)}${c > 1 ? ` <span class="dim">×${c}</span>` : ''}`)
              .join(' '),
            g.values.length
              ? `<span class="vals">${g.values
                  .slice(0, MAX_VALUES)
                  .map((v) => `<code>${h(v.length > 90 ? v.slice(0, 89) + '…' : v)}</code>`)
                  .join('')}${g.values.length > MAX_VALUES ? `<span class="dim"> +${g.values.length - MAX_VALUES} more</span>` : ''}</span>`
              : '<span class="dim">–</span>',
          ]),
        )}`
      : '<div class="empty">No finding passes the severity floor.</div>',
  })
  if (d.ai && d.ai.runs) sections.push({ id: 'ai', title: 'How AI was used', body: aiSection(d.ai) })
  sections.push({ id: 'method', title: 'Method and limits', body: method(d, verdict, confidence) })
  sections.push({
    id: 'settings',
    title: 'Case settings',
    body: `<div class="settings">internal domains: ${h(kase.settings.internalDomains.join(', ') || '—')} · VIPs: ${h(kase.settings.vipNames.join(', ') || '—')} · business hours ${kase.settings.businessHours.start}h–${kase.settings.businessHours.end}h (${h(kase.settings.businessHours.tz)}) · reputation lookups ${d.iocsChecked ? `run on ${n(d.iocsChecked)} indicator${d.iocsChecked === 1 ? '' : 's'}` : 'not run'} · report floor ${h(settings.minSeverity)}${settings.onlyReviewed ? ' · reviewed items only' : ''}${settings.includeFp ? ' · false positives included' : ''} · chain steps: ${h(settings.chainDetail)}</div>`,
  })

  const num = (i: number) => String(i + 1).padStart(2, '0')
  const font =
    d.fontData && /^[A-Za-z0-9+/=]+$/.test(d.fontData) ? `@font-face{font-family:'Gulax';src:url(data:font/woff2;base64,${d.fontData}) format('woff2');font-weight:400;font-style:normal}` : ''
  const generated = new Date(d.generatedAt ?? Date.now()).toISOString().replace('T', ' ').slice(0, 19) + 'Z'
  const seen = profile.filter((b) => b.state !== 'none')
  const confirmedBadges = profile.filter((b) => b.state === 'confirmed')
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>REMN report · ${h(kase.name)}</title><style>${font}${CSS}</style></head><body>
<div class="cover-page">
<div class="cover${d.issue?.status === 'draft' ? ' draft' : ''}">
<div class="brand"><div class="l"><span class="wordmark">REMN</span><span class="tag">forensic analysis report</span></div><div class="r">${generated}<br>${kase.analyst ? `analyst ${h(kase.analyst)}` : 'analyst not set'}${d.issue ? `<br><span class="issue ${d.issue.status}">${d.issue.status === 'final' && d.issue.finalAt ? `final · issued ${h(new Date(d.issue.finalAt).toISOString().replace('T', ' ').slice(0, 19))}Z` : 'draft · not issued'}</span>` : ''}</div></div>
<h1>${h(kase.name)}</h1>
<div class="meta">All times UTC · findings from ${h(settings.minSeverity)} severity up${settings.onlyReviewed ? ', reviewed items only' : ''}${settings.includeFp ? ', false positives included' : ''}</div>
<div class="hero">${seal(verdict)}<div class="bottom"><div class="k">bottom line</div><div class="line">${line ? md(line) : `<p>${h(verdict.detail)}</p>`}</div>${line ? `<div class="det">${h(verdict.detail)}</div>` : ''}<div class="conf ${confidence.level}"><b>confidence ${confidence.level}</b>${h(confidence.reasons.slice(0, 3).join(' · '))}</div></div></div>
<div class="scorecard"><div class="kpi"><div class="v">${n(d.evidence.length)}</div><div class="l">evidence files</div></div><div class="kpi"><div class="v">${n(rowsTotal)}</div><div class="l">rows analysed</div></div><div class="kpi"><div class="v">${n(d.findings.length)}</div><div class="l">findings</div></div><div class="kpi"><div class="v">${n(d.incidents.length + d.chains.length)}</div><div class="l">incidents · chains</div></div><div class="kpi${verdict.confirmed ? ' critical' : ''}"><div class="v">${n(verdict.confirmed)}</div><div class="l">confirmed</div></div><div class="kpi accent"><div class="v">${n(d.iocs.length)}</div><div class="l">flagged indicators</div></div></div>
<div class="sevbar">${ORDER.map((s) => (bySev[s] ? `<span title="${s} ${bySev[s]}" style="width:${((bySev[s] / total) * 100).toFixed(1)}%;background:var(--${s})"></span>` : '')).join('')}</div>
<div class="legend">${ORDER.map((s) => `<span><i style="background:var(--${s})"></i>${s} ${bySev[s] ?? 0}</span>`).join('')}<span class="dim">· Decisions: <b>${verdict.confirmed}</b> confirmed · <b>${verdict.reviewed}</b> reviewed or unsure · <b>${verdict.falsePositives}</b> false positive${verdict.falsePositives === 1 ? '' : 's'}${d.undecided ? ` · <b>${d.undecided}</b> item${d.undecided === 1 ? '' : 's'} without a decision` : ' · every item decided'}</span></div>
<div class="profile"><div class="k"><span>threat profile</span><span>${confirmedBadges.length ? `${confirmedBadges.length} confirmed · ` : ''}${seen.length} of ${profile.length} tactics observed</span></div><div class="hexes">${profile.map(badge).join('')}</div></div>
<div class="ribbons"><span class="ribbon ${verified === d.evidence.length && d.evidence.length ? 'ok' : 'warn'}"><i></i><b>${n(verified)}/${n(d.evidence.length)}</b> evidence files verified by digest</span><span class="ribbon ${d.undecided ? 'warn' : 'ok'}"><i></i><b>${d.undecided ? n(d.undecided) + ' undecided' : 'review complete'}</b></span>${d.findings.some((f) => f.ruleId.startsWith('engine:')) ? '<span class="ribbon ok"><i></i>external detection engine ran</span>' : ''}${aiUsed ? '<span class="ribbon ai"><i></i>model-drafted text, labelled where it appears</span>' : '<span class="ribbon"><i></i>no model-drafted text</span>'}${d.iocsChecked ? '' : '<span class="ribbon"><i></i>indicators not enriched</span>'}</div>
</div>
<ul class="toc">${sections.map((s, i) => `<li><span class="n">${num(i)}</span>${h(s.title)}${s.count != null ? ` <span class="dim">(${n(s.count)})</span>` : ''}</li>`).join('')}</ul>
</div>
${sections.map((s, i) => `<section class="s" id="${h(s.id)}"><div class="s-head"><span class="num">${num(i)}</span><h2>${h(s.title)}</h2><span class="rule"></span>${s.count != null ? `<span class="count">${n(s.count)}</span>` : ''}</div>${s.body}</section>`).join('\n')}
<div class="foot"><span class="wm">REMN</span><span>${h(kase.name)} · ${h(verdict.label)} · generated ${generated}</span></div>
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
