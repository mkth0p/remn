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
