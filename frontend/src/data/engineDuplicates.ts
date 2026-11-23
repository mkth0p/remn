/**
 * One finding where Hayabusa and REMN's own conversion of the same SigmaHQ rule both fired on the
 * same record. REMN names a converted rule sigma-<id of the Sigma rule>, and an engine's finding
 * names the id of the rule it ran in `sigmaId`: when the two ids are the same and the two findings
 * cite the same row, REMN's
 * finding is kept, it names the engine's (`alsoBy`), and the engine's leaves the findings table for
 * the case's key-value store. It comes back on its own whenever REMN's goes (the rule is turned off
 * or its pack removed, the rules run on other evidence), and it is dropped with its evidence.
 *
 * The ids must be the same, character for character. Hayabusa's own conversion splits some Sigma
 * rules into several and gives the parts new ids; whether one of those still means the rule REMN
 * converted is not known here, so those findings stay apart. An engine's finding the analyst has
 * already decided on stays where the analyst decided it.
 *
 * Both kinds of finding meet only in the browser's findings table, so this runs there, after each
 * write that can make or break a pair: the engine's findings stored at ingest, a rule run, findings
 * of rules that no longer exist removed, evidence removed.
 */
import { getDb, type Finding } from '../db/schema'
import { decided } from './findingReviews'

const SIGMA_RULE_PREFIX = 'sigma-'

export const heldKey = (caseId: number) => `engine-duplicates-${caseId}`

type Held = Omit<Finding, 'id'>

/** How the page names an engine. */
export const ENGINE_NAME: Record<string, string> = { hayabusa: 'Hayabusa' }

/** The engine's name in its finding's rule id (engine:hayabusa:...). */
export const engineOf = (ruleId: string) => ruleId.split(':')[1] ?? ruleId

/**
 * Pair the case's engine findings with REMN's findings of the same Sigma rule on the same record,
 * and part the pairs that no longer hold. Returns how many engine findings are kept inside REMN's.
 */
export async function reconcileEngineDuplicates(caseId: number): Promise<number> {
  const db = getDb()
  return db.transaction('rw', [db.findings, db.kv, db.evidence], async () => {
    const all = await db.findings.where('caseId').equals(caseId).toArray()
    const held = ((await db.kv.get(heldKey(caseId)))?.value as Record<string, Held> | undefined) ?? {}
    const evidence = new Set((await db.evidence.where('caseId').equals(caseId).primaryKeys()).map((id) => `evidence:${id}`))
    // REMN's findings of converted Sigma rules, by rule and cited row
    const ours = new Map<string, Finding>()
    for (const f of all) if (f.ruleId.startsWith(SIGMA_RULE_PREFIX)) for (const ref of f.refs) ours.set(`${f.ruleId}|${f.source}|${ref}`, f)
    const pairOf = (h: Held) => (h.sigmaId && h.refs.length === 1 ? ours.get(`${SIGMA_RULE_PREFIX}${h.sigmaId}|${h.source}|${h.refs[0]}`) : undefined)
    const next: Record<string, Held> = {}
    const also = new Map<Finding, NonNullable<Finding['alsoBy']>>()
    const pair = (h: Held, mine: Finding) => {
      next[h.key] = h
      const list = also.get(mine) ?? []
      list.push({ engine: engineOf(h.ruleId), ruleId: h.ruleId, title: h.title, severity: h.severity })
      also.set(mine, list)
    }
    const leave: number[] = []
    for (const f of all) {
      if (!f.ruleId.startsWith('engine:') || !f.sigmaId || decided(f)) continue
      const mine = pairOf(f)
      if (!mine) continue
      const { id, ...rest } = f
      leave.push(id!)
      pair(rest, mine)
    }
    const inTable = new Set(all.map((f) => f.key))
    const back: Held[] = []
    for (const h of Object.values(held)) {
      // gone with its evidence, or stored again since by a new ingest of the same file
      if (next[h.key] || inTable.has(h.key) || !(h.tags ?? []).some((t) => evidence.has(t))) continue
      const mine = pairOf(h)
      if (mine) pair(h, mine)
      else back.push(h)
    }
    if (leave.length) await db.findings.bulkDelete(leave)
    if (back.length) await db.findings.bulkAdd(back.map((h) => ({ ...h, caseId })))
    for (const f of all) {
      const now = also.get(f)
      if (!now && !f.alsoBy) continue
      if (JSON.stringify(now ?? null) === JSON.stringify(f.alsoBy ?? null)) continue
      await db.findings.update(f.id!, { alsoBy: now })
    }
    await db.kv.put({ key: heldKey(caseId), value: next })
    return Object.keys(next).length
  })
}

/**
 * Forget the engine findings of one evidence file kept inside REMN's: the file is removed, or the
 * engine (when named) stored a new set for it.
 */
export async function forgetHeld(caseId: number, evidenceId: number, engine?: string): Promise<void> {
  const db = getDb()
  const held = ((await db.kv.get(heldKey(caseId)))?.value as Record<string, Held> | undefined) ?? {}
  const tag = `evidence:${evidenceId}`
  const kept = Object.fromEntries(Object.entries(held).filter(([, h]) => !((engine == null || engineOf(h.ruleId) === engine) && (h.tags ?? []).includes(tag))))
  if (Object.keys(kept).length !== Object.keys(held).length) await db.kv.put({ key: heldKey(caseId), value: kept })
}
