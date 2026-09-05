import { getDb, type Finding } from '../db/schema'

type Review = Pick<Finding, 'status' | 'notes' | 'createdAt'>

/** Keep decisions when a calibrated rule stops matching and later matches again. */
export async function rememberReviews(caseId: number, findings: Finding[]): Promise<Map<string, Review>> {
  const db = getDb()
  const key = `finding-reviews-${caseId}`
  const saved = ((await db.kv.get(key))?.value as Record<string, Review>) ?? {}
  for (const f of findings) {
    if (f.status !== 'new' || f.notes) saved[f.key] = { status: f.status, notes: f.notes, createdAt: f.createdAt }
  }
  await db.kv.put({ key, value: saved })
  return new Map([...Object.entries(saved), ...findings.map((f) => [f.key, f] as [string, Review])])
}

/** Commit a completed rule evaluation atomically, including archived reviews. */
export async function replaceFindings(caseId: number, ruleIds: string[], findings: Record<string, unknown>[]): Promise<number> {
  const db = getDb()
  const ids = new Set(ruleIds)
  return db.transaction('rw', [db.findings, db.kv], async () => {
    const current = db.findings.where('caseId').equals(caseId).filter((f) => ids.has(f.ruleId))
    const reviews = await rememberReviews(caseId, await current.toArray())
    await current.delete()
    const now = Date.now()
    const rows = findings.map((f) => {
      const prev = reviews.get(String(f.key))
      return { ...f, id: undefined, caseId, createdAt: prev?.createdAt ?? now, status: prev?.status ?? 'new', notes: prev?.notes } as Finding
    })
    for (let i = 0; i < rows.length; i += 2000) await db.findings.bulkAdd(rows.slice(i, i + 2000))
    return rows.length
  })
}
