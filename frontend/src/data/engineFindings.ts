/**
 * Findings produced by an external engine (Hayabusa over EVTX) during ingest.
 *
 * The server sends them with refKeys naming the event records they belong to, as
 * computer|channel|recordId, because it does not know the ids the browser will give those rows.
 * The worker builds that index while it inserts the rows and resolves the refs here.
 */
import { getDb, type Finding } from '../db/schema'

export const ENGINE_RULE_PREFIX = 'engine:'

export type EngineFinding = Omit<Finding, 'id' | 'caseId' | 'status' | 'createdAt'> & { refKeys?: string[]; engine?: string }

export function refKey(row: { computer?: unknown; channel?: unknown; recordId?: unknown }): string {
  return `${row.computer ?? ''}|${row.channel ?? ''}|${row.recordId ?? ''}`
}

/** Resolve refKeys into row ids; a key the index does not hold is dropped, not guessed. */
export function resolveEngineRefs<T extends { refKeys?: string[]; refs?: number[] }>(findings: T[], index: Map<string, number>): T[] {
  return findings.map((f) => {
    const refs = (f.refKeys ?? []).map((k) => index.get(k)).filter((id): id is number => typeof id === 'number')
    const { refKeys: _drop, ...rest } = f
    return { ...rest, refs } as T
  })
}

export function isEngineFinding(ruleId: string): boolean {
  return ruleId.startsWith(ENGINE_RULE_PREFIX)
}

/**
 * Store an engine's findings for one piece of evidence, replacing what the same engine produced
 * for that evidence before, and leaving what it produced for other evidence alone. Analyst
 * decisions on a finding whose key survives are kept.
 */
export async function persistEngineFindings(caseId: number, evidenceId: number, engine: string, findings: EngineFinding[]): Promise<number> {
  const db = getDb()
  const evidenceTag = `evidence:${evidenceId}`
  const prefix = `${ENGINE_RULE_PREFIX}${engine}:`
  return db.transaction('rw', [db.findings], async () => {
    const previous = await db.findings
      .where('caseId')
      .equals(caseId)
      .filter((f) => f.ruleId.startsWith(prefix) && (f.tags ?? []).includes(evidenceTag))
      .toArray()
    const reviews = new Map(previous.map((f) => [f.key, f]))
    if (previous.length) await db.findings.bulkDelete(previous.map((f) => f.id!))
    const now = Date.now()
    const rows = findings.map((f) => {
      const prev = reviews.get(f.key)
      const { refKeys: _drop, ...rest } = f
      return {
        ...rest,
        id: undefined,
        caseId,
        tags: Array.from(new Set([...(f.tags ?? []), evidenceTag])),
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
