import type { Chain } from '../../data/chains'
import type { ReportClaims } from '../../data/claims'
import { aiDecided, issueStatus, preflightChecks, type PreflightInput, type ReportIssue } from '../../data/reportPreflight'
import { reportText } from '../../data/reportText'
import { chainSeverity, effectiveSeverity, unprintedConfirmed, type ChainReview, type ReportSettings } from '../../data/review'
import type { CaseNote, Evidence, Finding } from '../../db/schema'
import { buildIncidents } from '../../rules/incidents'

/** The severities from the worst, the order the report lists findings in. */
export const ORDER = ['critical', 'high', 'medium', 'low', 'info']

/**
 * The figures of the report as it stands: the findings it prints and the incidents they make (a
 * finding linked to a printed chain is printed with it), the counts by severity, the case notes by
 * kind, what is undecided or confirmed and not printed, the claims not borne out by their rows,
 * and the preflight checks with the status they give the report, in English and in its language.
 */
export function reportFigures({
  settings,
  findings,
  chains,
  reviews,
  selection,
  printedStories,
  claims,
  notes,
  evidence,
  rulesState,
  issue,
}: {
  settings: ReportSettings
  findings: Finding[]
  chains: Chain[]
  reviews: Record<string, ChainReview>
  selection: { findings: Finding[]; chains: Chain[] }
  printedStories: { decided: { verdict: string; printed: boolean }[] }
  claims: ReportClaims | undefined
  notes: CaseNote[]
  evidence: Evidence[]
  rulesState: PreflightInput['rules']
  issue: ReportIssue
}) {
  const shown = selection.findings
  // findings linked to a printed chain are printed with it, not as incidents
  const grouped = buildIncidents(shown, { chains: selection.chains, severityOf: (c) => chainSeverity(c, reviews[c.id]) })
  const incidents = grouped.filter((i) => i.kind !== 'chain')
  const membersOf = new Map(grouped.filter((i) => i.kind === 'chain' && i.chain).map((i) => [i.chain!.id, i.findings.filter((f) => f.ruleId !== 'chain')]))
  const bySev = shown.reduce((acc, f) => ((acc[effectiveSeverity(f)] = (acc[effectiveSeverity(f)] ?? 0) + 1), acc), {} as Record<string, number>)
  const curated = notes.filter((n) => n.kind === 'timeline').sort((a, b) => a.ts - b.ts)
  const tasks = notes.filter((n) => n.kind === 'task').sort((a, b) => Number(a.done ?? false) - Number(b.done ?? false) || a.createdAt - b.createdAt)
  const analystNotes = notes.filter((n) => n.kind === 'note').sort((a, b) => a.createdAt - b.createdAt)
  // same unit as the Review page: incidents without a decision plus chains without a verdict
  const undecided = buildIncidents(findings, { chains }).filter((i) => (i.kind === 'chain' && i.chain ? !reviews[i.chain.id]?.verdict : i.status === 'new')).length
  const hiddenConfirmed = unprintedConfirmed(findings, chains, reviews, selection)
  // a confirmed story the report leaves out (below the floor, past the first twenty) is a confirmed item not printed too
  const hiddenStories = printedStories.decided.filter((s) => s.verdict === 'confirmed' && !s.printed).length
  const printedChecks = shown.map((f) => (f.id != null ? claims?.findings[f.id] : undefined)).filter((c) => !!c)
  const claimSummary = claims && {
    checked: printedChecks.length,
    unsupported: printedChecks.filter((c) => c.status === 'unsupported').length,
    contradicted: printedChecks.filter((c) => c.status === 'contradicted').length,
    texts: claims.texts.length,
    textsUnsupported: claims.texts.filter((t) => t.check.status === 'unsupported').length,
  }
  const unverified = [
    ...shown.flatMap((f) => {
      const c = f.id != null ? claims?.findings[f.id] : undefined
      return c && c.status !== 'verified' ? [{ what: `${f.title} (${f.ruleId})`, status: c.status, reasons: c.reasons }] : []
    }),
    ...(claims?.texts ?? []).filter((t) => t.check.status === 'unsupported').map((t) => ({ what: t.what, status: t.check.status, reasons: t.check.reasons })),
  ]
  const preflight = { evidence, rules: rulesState, undecided, aiDecided: aiDecided(findings), unprintedConfirmed: hiddenConfirmed.length + hiddenStories, claims: claimSummary }
  const checks = preflightChecks(preflight)
  const status = issueStatus(checks, issue)
  // the page lists the checks in English; the report prints what is open in its own language
  const words = reportText(settings.language)
  const printedStatus = settings.language === 'en' ? status : issueStatus(preflightChecks(preflight, words), issue)
  return { shown, incidents, membersOf, bySev, curated, tasks, analystNotes, undecided, hiddenConfirmed, unverified, checks, status, words, printedStatus }
}
