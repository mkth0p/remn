import { getDb } from '../db/schema'
import { rememberReviews } from './findingReviews'

/**
 * Derived state of a case that is only valid for the evidence it was computed from: findings,
 * the attack-chain snapshot and the last rule-run diagnostics. Removing evidence invalidates
 * all of it (findings reference row ids that no longer exist), so it is cleared and rebuilt by
 * the next rule run. Analyst decisions are archived first (finding-reviews) and come back when
 * the same finding keys reappear.
 */

/** kv keys that belong to one case, by prefix (the case id follows the dash). */
export const CASE_KV_PREFIXES = ['chains-', 'ruleDiags-', 'baseline-', 'mail-calibration-', 'report-summary-', 'finding-reviews-'] as const

export function caseKvKeys(caseId: number): string[] {
  return CASE_KV_PREFIXES.map((p) => `${p}${caseId}`)
}

export async function clearDerivedState(caseId: number): Promise<{ findings: number; chains: number }> {
  const db = getDb()
  return db.transaction('rw', [db.findings, db.kv, db.facets], async () => {
    const findings = await db.findings.where('caseId').equals(caseId).toArray()
    await rememberReviews(caseId, findings)
    await db.findings.where('caseId').equals(caseId).delete()
    const chains = ((await db.kv.get(`chains-${caseId}`))?.value as { chains?: unknown[] } | undefined)?.chains?.length ?? 0
    await db.kv.bulkDelete([`chains-${caseId}`, `ruleDiags-${caseId}`])
    await db.facets.where('caseId').equals(caseId).delete()
    return { findings: findings.length, chains }
  })
}
