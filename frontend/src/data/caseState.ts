import { API_HEADERS } from '../api/client'
import { defaultSettings, deleteCase, deleteCaseData, getDb, type Case } from '../db/schema'
import { DEFAULT_DETECTION_LEVEL } from './detectionLevel'
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

export async function clearDerivedState(caseId: number, removedEvidenceId?: number): Promise<{ findings: number; chains: number }> {
  const db = getDb()
  return db.transaction('rw', [db.findings, db.kv, db.facets], async () => {
    const all = await db.findings.where('caseId').equals(caseId).toArray()
    // An engine's findings (Hayabusa) are made once, at ingest, per evidence file, and point at that
    // file's own rows. Those of the files that stay are still valid, and no rule run could bring them
    // back: removing one file used to erase them all, decisions included. Only the removed file's go.
    const removedTag = removedEvidenceId != null ? `evidence:${removedEvidenceId}` : null
    const keep = (f: (typeof all)[number]) => f.ruleId.startsWith('engine:') && removedTag != null && !(f.tags ?? []).includes(removedTag)
    const findings = all.filter((f) => !keep(f))
    await rememberReviews(caseId, findings)
    await db.findings.bulkDelete(findings.map((f) => f.id!))
    const chains = ((await db.kv.get(`chains-${caseId}`))?.value as { chains?: unknown[] } | undefined)?.chains?.length ?? 0
    await db.kv.bulkDelete([`chains-${caseId}`, `stories-${caseId}`, `ruleDiags-${caseId}`, `relationship-cache-${caseId}`, `relationship-stories-${caseId}`])
    await db.facets.where('caseId').equals(caseId).delete()
    return { findings: findings.length, chains }
  })
}

/**
 * Empty a case and keep it: its server store when it has one, then every browser record. The
 * server's answer is read first. When the store was not removed (the request was refused or the
 * server could not be reached), nothing is deleted in the browser either and the error says so:
 * the analyst must not be told the evidence is gone while the server still holds it.
 */
export async function wipeCase(kase: Case): Promise<void> {
  if (kase.storage === 'server' && kase.serverKey) {
    let r: Response
    try {
      r = await fetch(`/api/store/${kase.serverKey}`, { method: 'DELETE', headers: API_HEADERS })
    } catch (e) {
      throw new Error(`the server store could not be reached (${(e as Error).message}); nothing was deleted`, { cause: e })
    }
    if (!r.ok && r.status !== 404) throw new Error(`the server did not delete the store (HTTP ${r.status}); nothing was deleted`)
  }
  await deleteCaseData(getDb(), kase.id!)
}

/**
 * Delete a case entirely: its server store when it has one, every browser record, custom rules,
 * and the case row. Returns the case to show next: the most recently updated of the remaining
 * ones, or a fresh browser case when none is left. serverCleared is false when the server store
 * could not be removed (server down); the browser side is deleted regardless, and the caller
 * tells the analyst where the store is left.
 */
export async function removeCase(kase: Case): Promise<{ next: Case; serverCleared: boolean }> {
  const db = getDb()
  let serverCleared = true
  if (kase.storage === 'server' && kase.serverKey) {
    serverCleared = await fetch(`/api/store/${kase.serverKey}`, { method: 'DELETE', headers: API_HEADERS })
      .then((r) => r.ok || r.status === 404)
      .catch(() => false)
  }
  await deleteCase(db, kase.id!)
  const rest = (await db.cases.toArray()).sort((a, b) => b.updatedAt - a.updatedAt)
  let next = rest[0]
  if (!next) {
    const id = await db.cases.add({ name: 'Case 1', createdAt: Date.now(), updatedAt: Date.now(), settings: { ...defaultSettings(), detectionLevel: DEFAULT_DETECTION_LEVEL }, storage: 'browser' })
    next = (await db.cases.get(id))!
  }
  await db.kv.put({ key: 'lastCase', value: next.id })
  return { next: { ...next, settings: { ...defaultSettings(), ...next.settings } }, serverCleared }
}
