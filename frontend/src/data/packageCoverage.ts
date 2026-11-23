import type { Evidence } from '../db/schema'
import { EN, type ReportText } from './reportText'

/** What an investigation package did not read or account for, in the words of a report's language (the interface reads them in English). */
export function packageCoverageIssues(evidence: Evidence, t: ReportText = EN): string[] {
  if (evidence.kind !== 'package' || !evidence.stats) return []
  const stats = evidence.stats
  const w = t.packageIssue
  const messages: string[] = []
  for (const key of ['errors', 'unsupported', 'skipped'] as const) {
    const n = Number(stats[key] ?? 0)
    if (n) messages.push(w[key](n))
  }
  if (stats.inventoryComplete === false) messages.push(w.inventory)
  const checks = Array.isArray(stats.reconciliation) ? stats.reconciliation : []
  const discrepancies = checks.filter((c) => c && typeof c === 'object' && c.status !== 'matched').length
  if (discrepancies) messages.push(w.discrepancies(discrepancies))
  return messages
}

/** The member list of an evidence file: a package's inventory, or what an event-log or mail archive read and left out. */
export function coverageMembers(stats: Record<string, unknown> | undefined): Record<string, unknown>[] {
  const list = Array.isArray(stats?.files) ? stats.files : Array.isArray(stats?.members) ? stats.members : []
  return list.filter((f): f is Record<string, unknown> => !!f && typeof f === 'object' && 'status' in f)
}

/**
 * The clauses of a member's note that say part of the file was not read or not kept: lines past a
 * limit, records past a function's cap, records not of the file's kind, the lines of a Defender log
 * that name nothing it acts on. The other clauses (a date read one way or without a time, a value
 * cut at its length limit, rows repaired or kept with a mismatch marked, an encoding, an engine
 * that did not scan the file) say how a file read whole was read.
 */
const LEFT_OUT = [/\bkept the first [\d,]+ lines\b/, /\bstopped at [\d,]+ records\b/, /\bwere not read\b/, /\blines read, [\d,]+ kept\b/]

/** Whether a member's note says part of the file was not read (the server writes the note, as clauses joined by "; "). */
export function noteLeavesOut(note: unknown): boolean {
  return typeof note === 'string' && LEFT_OUT.some((re) => re.test(note))
}
