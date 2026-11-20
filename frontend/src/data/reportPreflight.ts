import { getDb, type Evidence, type Finding } from '../db/schema'
import { evidenceIssue } from './reportHtml'
import { packageCoverageIssues } from './packageCoverage'
import { EN, type ReportText } from './reportText'

/**
 * What must be true before a report is issued as final. A report is a DRAFT, and says so on its
 * cover, until each check passes or the analyst waives it with a reason, which the report prints.
 * A report issued as final goes back to draft by itself when a new check opens (evidence added
 * after, a rule run that failed): the stored state is the analyst's waivers, the status is
 * recomputed every time the report is made.
 */
export interface PreflightCheck {
  id: string
  label: string
  ok: boolean
  detail: string
}

export interface PreflightInput {
  evidence: Evidence[]
  rules?: { lastRun: number | null; evidenceAfter: number; errors: number }
  undecided: number
  /** decided findings whose decision the analyst took from the model's proposal */
  aiDecided: number
  unprintedConfirmed: number
  /** the printed claims read back against their rows (data/claims.ts); left out while the check runs */
  claims?: { checked: number; unsupported: number; contradicted: number; texts: number; textsUnsupported: number }
}

/** The checks, labelled in the words of a report's language (the interface reads them in English). */
export function preflightChecks(p: PreflightInput, t: ReportText = EN): PreflightCheck[] {
  const w = t.preflight
  const incomplete = p.evidence.filter((e) => (e.kind === 'package' ? packageCoverageIssues(e).length > 0 : !!evidenceIssue(e)))
  const unverified = p.evidence.filter((e) => e.integrity !== 'verified')
  const rules = p.rules
  const rulesProblem = !rules ? w.unknown : rules.lastRun == null ? w.notRun : rules.errors ? w.failed(rules.errors) : rules.evidenceAfter ? w.after(rules.evidenceAfter) : ''
  return [
    { id: 'rules', label: w.rules, ok: !rulesProblem, detail: rulesProblem || w.rulesOk },
    {
      id: 'read',
      label: w.read,
      ok: !incomplete.length,
      detail: incomplete.length ? w.readList(incomplete.map((e) => e.name).slice(0, 4), incomplete.length - 4) : w.readOk,
    },
    { id: 'integrity', label: w.integrity, ok: !unverified.length, detail: unverified.length ? w.integrityBad(unverified.length) : w.integrityOk },
    { id: 'decided', label: w.decided, ok: !p.undecided, detail: p.undecided ? w.decidedBad(p.undecided) : w.decidedOk },
    { id: 'ai', label: w.ai, ok: !p.aiDecided, detail: p.aiDecided ? w.aiBad(p.aiDecided) : w.aiOk },
    { id: 'printed', label: w.printed, ok: !p.unprintedConfirmed, detail: p.unprintedConfirmed ? w.printedBad(p.unprintedConfirmed) : w.printedOk },
    claimsCheck(p.claims, t),
  ]
}

function claimsCheck(c: PreflightInput['claims'], t: ReportText): PreflightCheck {
  const w = t.preflight
  if (!c) return { id: 'claims', label: w.claims, ok: false, detail: w.claimsPending }
  const problems = [c.contradicted ? w.contradicted(c.contradicted) : '', c.unsupported ? w.unsupported(c.unsupported) : '', c.textsUnsupported ? w.textsUnsupported(c.textsUnsupported) : ''].filter(
    Boolean,
  )
  return { id: 'claims', label: w.claims, ok: !problems.length, detail: problems.length ? problems.join('; ') : w.claimsOk(c.checked, c.texts) }
}

export interface ReportIssue {
  /** analyst's reasons for going ahead despite an open check, by check id */
  waivers: Record<string, string>
  /** when the analyst issued the report as final (the status still needs every check closed) */
  finalAt?: number
}

export interface IssueStatus {
  status: 'draft' | 'final'
  open: PreflightCheck[]
  waived: { label: string; reason: string }[]
  finalAt?: number
}

export function issueStatus(checks: PreflightCheck[], issue: ReportIssue): IssueStatus {
  const failing = checks.filter((c) => !c.ok)
  const waived = failing.filter((c) => issue.waivers[c.id]?.trim()).map((c) => ({ label: c.label, reason: issue.waivers[c.id].trim() }))
  const open = failing.filter((c) => !issue.waivers[c.id]?.trim())
  const status = issue.finalAt && !open.length ? 'final' : 'draft'
  return { status, open, waived, finalAt: status === 'final' ? issue.finalAt : undefined }
}

export async function loadReportIssue(caseId: number): Promise<ReportIssue> {
  return ((await getDb().kv.get(`report-final-${caseId}`))?.value as ReportIssue | undefined) ?? { waivers: {} }
}

export async function saveReportIssue(caseId: number, issue: ReportIssue): Promise<void> {
  await getDb().kv.put({ key: `report-final-${caseId}`, value: issue })
}

export const aiDecided = (findings: Finding[]) => findings.filter((f) => f.decidedBy === 'ai' && f.status !== 'new').length
