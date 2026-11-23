import type { Evidence } from '../db/schema'

export function packageCoverageIssues(evidence: Evidence): string[] {
  if (evidence.kind !== 'package' || !evidence.stats) return []
  const stats = evidence.stats
  const messages: string[] = []
  for (const [key, label] of [
    ['errors', 'failed members'],
    ['unsupported', 'unsupported members'],
    ['skipped', 'skipped members'],
  ] as const) {
    if (Number(stats[key] ?? 0)) messages.push(`${stats[key]} ${label}`)
  }
  if (stats.inventoryComplete === false) messages.push('incomplete member inventory')
  const checks = Array.isArray(stats.reconciliation) ? stats.reconciliation : []
  const discrepancies = checks.filter((c) => c && typeof c === 'object' && c.status !== 'matched').length
  if (discrepancies) messages.push(`${discrepancies} collection summary discrepancies or unresolved entries`)
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
