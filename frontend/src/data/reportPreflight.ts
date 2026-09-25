import { getDb, type Evidence, type Finding } from '../db/schema'
import { evidenceIssue } from './reportHtml'
import { packageCoverageIssues } from './packageCoverage'

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

export function preflightChecks(p: PreflightInput): PreflightCheck[] {
  const incomplete = p.evidence.filter((e) => (e.kind === 'package' ? packageCoverageIssues(e).length > 0 : !!evidenceIssue(e)))
  const unverified = p.evidence.filter((e) => e.integrity !== 'verified')
  const rules = p.rules
  const rulesProblem = !rules
    ? 'the state of the last rule run is not known'
    : rules.lastRun == null
      ? 'the detection rules have not run on this case'
      : rules.errors
        ? `${rules.errors} rule(s) failed in the last run`
        : rules.evidenceAfter
          ? `${rules.evidenceAfter} evidence file(s) were added after the last rule run`
          : ''
  return [
    { id: 'rules', label: 'Detection rules ran on all the evidence', ok: !rulesProblem, detail: rulesProblem || 'the last run covered every file' },
    {
      id: 'read',
      label: 'Every evidence file was read completely',
      ok: !incomplete.length,
      detail: incomplete.length
        ? `${incomplete
            .map((e) => e.name)
            .slice(0, 4)
            .join(', ')}${incomplete.length > 4 ? ` and ${incomplete.length - 4} more` : ''}`
        : 'no parse error, limit or unread member',
    },
    {
      id: 'integrity',
      label: 'Every evidence file has a verified digest',
      ok: !unverified.length,
      detail: unverified.length ? `${unverified.length} file(s) without a verified SHA-256` : 'browser and server digests match',
    },
    { id: 'decided', label: 'Every item has a decision', ok: !p.undecided, detail: p.undecided ? `${p.undecided} item(s) without a decision` : 'the review is complete' },
    {
      id: 'ai',
      label: 'Decisions taken from the model were checked',
      ok: !p.aiDecided,
      detail: p.aiDecided ? `${p.aiDecided} decision(s) came from the model's proposals` : 'every decision is the analyst’s',
    },
    {
      id: 'printed',
      label: 'Every confirmed item is printed',
      ok: !p.unprintedConfirmed,
      detail: p.unprintedConfirmed ? `${p.unprintedConfirmed} confirmed item(s) below the severity floor or left out` : 'the report carries every confirmed item',
    },
    claimsCheck(p.claims),
  ]
}

function claimsCheck(c: PreflightInput['claims']): PreflightCheck {
  const label = 'What the report says holds against the rows it cites'
  if (!c) return { id: 'claims', label, ok: false, detail: 'the printed findings and texts are still being checked against their rows' }
  const problems = [
    c.contradicted ? `${c.contradicted} finding(s) contradicted by their rows` : '',
    c.unsupported ? `${c.unsupported} finding(s) whose rows are not all in the case` : '',
    c.textsUnsupported ? `${c.textsUnsupported} text(s) naming values their rows do not hold` : '',
  ].filter(Boolean)
  return {
    id: 'claims',
    label,
    ok: !problems.length,
    detail: problems.length ? problems.join('; ') : `${c.checked} finding(s) and ${c.texts} text(s) read back against their rows`,
  }
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
