import { getDb } from '../db/schema'

/** A repeated source is skipped only after a complete, hash-verified earlier import. */
export async function duplicateEvidence(caseId: number, evidenceId: number, name: string, kind: string, sha256: string) {
  return getDb()
    .evidence.where('caseId')
    .equals(caseId)
    .filter(
      (e) =>
        e.id !== evidenceId &&
        e.name === name &&
        e.kind === kind &&
        e.sha256Client === sha256 &&
        e.integrity === 'verified' &&
        e.status === 'done' &&
        !Number(e.stats?.errors ?? 0) &&
        e.stats?.inventoryComplete !== false,
    )
    .first()
}
