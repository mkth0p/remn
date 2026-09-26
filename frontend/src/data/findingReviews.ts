import { getDb, type Finding } from '../db/schema'
import { reviewKey, tableRows, withRecordKeys, type RowLoader } from './findingAnchors'

type Review = Pick<Finding, 'status' | 'notes' | 'createdAt' | 'severityOverride' | 'reportExclude' | 'chainUnlinked' | 'decidedBy' | 'decidedAt' | 'aiReason' | 'notesBy'> &
  Partial<Pick<Finding, 'source' | 'refs' | 'recordKeys' | 'ruleId' | 'key'>>

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
    for (const f of rows) for (const k of [reviewKey(f!), f!.key]) if (saved[k]) delete saved[k].severityOverride
    await db.kv.put({ key, value: saved })
  })
}

/**
 * An analyst's decision on the case's findings of these keys, taken from another page (a story's
 * step disputed on the Stories page): the status, who decided, and why after the note it has. It
 * is archived at once with the other reviews, so a rule rerun that rebuilds the findings keeps it.
 * Returns how many findings it decided.
 */
export async function decideFindings(caseId: number, keys: string[], status: Finding['status'], why?: string): Promise<number> {
  const db = getDb()
  const wanted = [...new Set(keys.filter(Boolean))]
  if (!wanted.length) return 0
  return db.transaction('rw', [db.findings, db.kv], async () => {
    const rows = (await db.findings.where('key').anyOf(wanted).toArray()).filter((f) => f.caseId === caseId)
    const decidedRows = rows.map((f) => ({
      ...f,
      status,
      decidedBy: 'analyst' as const,
      decidedAt: Date.now(),
      ...(why?.trim() ? { notes: [f.notes?.trim(), why.trim()].filter(Boolean).join('\n\n'), notesBy: 'analyst' as const } : {}),
    }))
    for (const f of decidedRows) await db.findings.update(f.id!, { status: f.status, decidedBy: f.decidedBy, decidedAt: f.decidedAt, notes: f.notes, notesBy: f.notesBy })
    await rememberReviews(caseId, decidedRows)
    return decidedRows.length
  })
}

/**
 * Keep decisions when a calibrated rule stops matching and later matches again, and when the
 * evidence is removed and added again: a one-row finding's decision is archived under the key of
 * its record (findingAnchors.ts), which the renumbered row gives back.
 */
export async function rememberReviews(caseId: number, findings: Finding[]): Promise<Map<string, Review>> {
  const db = getDb()
  const key = `finding-reviews-${caseId}`
  const saved = ((await db.kv.get(key))?.value as Record<string, Review>) ?? {}
  for (const f of findings) {
    const at = reviewKey(f)
    // the row-id key an older version archived it under
    if (at !== f.key) delete saved[f.key]
    // a finding the analyst set back to undecided takes its old decision out of the archive, or the
    // false positive they reverted would come back the next time the finding is rebuilt
    if (!decided(f)) {
      delete saved[at]
      continue
    }
    saved[at] = {
      key: f.key,
      source: f.source,
      refs: f.refs,
      recordKeys: f.recordKeys,
      ruleId: f.ruleId,
      status: f.status,
      notes: f.notes,
      createdAt: f.createdAt,
      severityOverride: f.severityOverride,
      reportExclude: f.reportExclude,
      chainUnlinked: f.chainUnlinked,
      decidedBy: f.decidedBy,
      decidedAt: f.decidedAt,
      aiReason: f.aiReason,
      notesBy: f.notesBy,
    }
  }
  await db.kv.put({ key, value: saved })
  // a decision archived under its record is still found by the finding's own key when the record
  // cannot be read this time (a server case the browser cannot reach)
  const aliases = Object.values(saved).flatMap((r) => (r.key ? [[r.key, r] as [string, Review]] : []))
  return new Map([...aliases, ...Object.entries(saved), ...findings.flatMap((f) => [[f.key, f] as [string, Review], [reviewKey(f), f] as [string, Review]])])
}

/**
 * Commit a completed rule evaluation atomically, including archived reviews. The rows the findings
 * cite are read first for their record keys, from this browser unless `load` reads them elsewhere
 * (a server case's store).
 */
export async function replaceFindings(caseId: number, ruleIds: string[], found: Record<string, unknown>[], load?: RowLoader): Promise<number> {
  const db = getDb()
  const keys = ruleIds.map((id) => [caseId, id] as [number, string])
  const evidence = await db.evidence.where('caseId').equals(caseId).toArray()
  const findings = await withRecordKeys(found as unknown as Finding[], evidence, load ?? tableRows(db))
  return db.transaction('rw', [db.findings, db.kv], async () => {
    // the compound index: a per-rule call (the worker replaces after every rule) must not rescan every finding of the case
    const current = db.findings.where('[caseId+ruleId]').anyOf(keys)
    const reviews = await rememberReviews(caseId, await current.toArray())
    await current.delete()
    const now = Date.now()
    const rows = findings.map((f) => {
      // the record's key first: after a re-ingest the row-id key names no decision
      const prev = reviews.get(reviewKey(f)) ?? reviews.get(String(f.key))
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
        decidedAt: prev?.decidedAt,
        aiReason: prev?.aiReason,
        notesBy: prev?.notesBy,
      } as Finding
    })
    for (let i = 0; i < rows.length; i += 2000) await db.findings.bulkAdd(rows.slice(i, i + 2000))
    return rows.length
  })
}

/**
 * Drop findings of rules that no longer exist (a pack refreshed, a custom rule deleted); chains are
 * kept, and so is every finding the analyst decided on: a confirmed finding whose rule this browser
 * does not have (a case imported from another analyst) is a conclusion, not an orphan.
 */
export async function pruneOrphanFindings(caseId: number, knownRuleIds: Iterable<string>): Promise<number> {
  const db = getDb()
  const known = new Set(knownRuleIds)
  known.add('chain')
  return db.transaction('rw', [db.findings, db.kv], async () => {
    // an engine's findings belong to no rule in the catalogue and are replaced per evidence instead
    const orphans = await db.findings
      .where('caseId')
      .equals(caseId)
      .filter((f) => !known.has(f.ruleId) && !f.ruleId.startsWith('engine:') && !decided(f))
      .toArray()
    if (!orphans.length) return 0
    await rememberReviews(caseId, orphans)
    await db.findings.bulkDelete(orphans.map((f) => f.id!))
    return orphans.length
  })
}
