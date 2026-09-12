import { getDb, type Finding } from '../db/schema'

type Review = Pick<Finding, 'status' | 'notes' | 'createdAt' | 'severityOverride' | 'reportExclude' | 'chainUnlinked' | 'decidedBy' | 'aiReason' | 'notesBy'> &
  Partial<Pick<Finding, 'source' | 'refs' | 'ruleId'>>

const decided = (f: Finding) => f.status !== 'new' || !!f.notes || !!f.severityOverride || !!f.reportExclude || !!f.chainUnlinked || !!f.aiReason

/** Explicitly reset severity only, including the copy retained across rule refreshes. */
export async function resetFindingSeverityOverrides(caseId: number, ids: number[]): Promise<void> {
  const db = getDb()
  const uniqueIds = [...new Set(ids)]
  if (!uniqueIds.length) return
  await db.transaction('rw', [db.findings, db.kv], async () => {
    const rows = await db.findings.bulkGet(uniqueIds)
    if (rows.some((f) => !f || f.caseId !== caseId)) throw new Error('Findings changed. Refresh the view and retry.')
    await db.findings
      .where('id')
      .anyOf(uniqueIds)
      .modify((f) => {
        delete f.severityOverride
      })
    const key = `finding-reviews-${caseId}`
    const saved = ((await db.kv.get(key))?.value as Record<string, Review>) ?? {}
    for (const f of rows) if (saved[f!.key]) delete saved[f!.key].severityOverride
    await db.kv.put({ key, value: saved })
  })
}

/** Keep decisions when a calibrated rule stops matching and later matches again. */
export async function rememberReviews(caseId: number, findings: Finding[]): Promise<Map<string, Review>> {
  const db = getDb()
  const key = `finding-reviews-${caseId}`
  const saved = ((await db.kv.get(key))?.value as Record<string, Review>) ?? {}
  for (const f of findings) {
    if (decided(f))
      saved[f.key] = {
        source: f.source,
        refs: f.refs,
        ruleId: f.ruleId,
        status: f.status,
        notes: f.notes,
        createdAt: f.createdAt,
        severityOverride: f.severityOverride,
        reportExclude: f.reportExclude,
        chainUnlinked: f.chainUnlinked,
        decidedBy: f.decidedBy,
        aiReason: f.aiReason,
        notesBy: f.notesBy,
      }
  }
  await db.kv.put({ key, value: saved })
  return new Map([...Object.entries(saved), ...findings.map((f) => [f.key, f] as [string, Review])])
}

/** Commit a completed rule evaluation atomically, including archived reviews. */
export async function replaceFindings(caseId: number, ruleIds: string[], findings: Record<string, unknown>[]): Promise<number> {
  const db = getDb()
  const keys = ruleIds.map((id) => [caseId, id] as [number, string])
  return db.transaction('rw', [db.findings, db.kv], async () => {
    // the compound index: a per-rule call (the worker replaces after every rule) must not rescan every finding of the case
    const current = db.findings.where('[caseId+ruleId]').anyOf(keys)
    const reviews = await rememberReviews(caseId, await current.toArray())
    await current.delete()
    const now = Date.now()
    const rows = findings.map((f) => {
      const prev = reviews.get(String(f.key))
      return {
        ...f,
        id: undefined,
        caseId,
        createdAt: prev?.createdAt ?? now,
        status: prev?.status ?? 'new',
        notes: prev?.notes,
        severityOverride: prev?.severityOverride,
        reportExclude: prev?.reportExclude,
        chainUnlinked: prev?.chainUnlinked,
        decidedBy: prev?.decidedBy,
        aiReason: prev?.aiReason,
        notesBy: prev?.notesBy,
      } as Finding
    })
    for (let i = 0; i < rows.length; i += 2000) await db.findings.bulkAdd(rows.slice(i, i + 2000))
    return rows.length
  })
}

/** Drop findings of rules that no longer exist (a pack refreshed, a custom rule deleted); chains are kept. */
export async function pruneOrphanFindings(caseId: number, knownRuleIds: Iterable<string>): Promise<number> {
  const db = getDb()
  const known = new Set(knownRuleIds)
  known.add('chain')
  return db.transaction('rw', [db.findings, db.kv], async () => {
    // an engine's findings belong to no rule in the catalogue and are replaced per evidence instead
    const orphans = await db.findings
      .where('caseId')
      .equals(caseId)
      .filter((f) => !known.has(f.ruleId) && !f.ruleId.startsWith('engine:'))
      .toArray()
    if (!orphans.length) return 0
    await rememberReviews(caseId, orphans)
    await db.findings.bulkDelete(orphans.map((f) => f.id!))
    return orphans.length
  })
}
