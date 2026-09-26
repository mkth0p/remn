/**
 * Cases as the home page sees them: which hold evidence (the app opens on the home page until one
 * does), and starting one from there.
 */
import { defaultSettings, getDb, newServerKey, type Case } from '../db/schema'

/** The case the first visit creates, so the app always has one open. */
export const FIRST_CASE_NAME = 'Case 1'

/** Ids of the cases that hold at least one piece of evidence. */
export async function casesWithEvidence(): Promise<Set<number>> {
  const keys = await getDb().evidence.orderBy('caseId').uniqueKeys()
  return new Set(keys.map(Number))
}

/**
 * Start a case. The first visit's case, still untouched (its default name, no evidence, the only
 * case there is), is taken over rather than left empty beside the new one.
 */
export async function startCase(name: string, storage: 'browser' | 'server'): Promise<Case> {
  const db = getDb()
  const all = await db.cases.toArray()
  const first = all.length === 1 && all[0].name === FIRST_CASE_NAME ? all[0] : undefined
  const untouched = first?.id != null && (await db.evidence.where('caseId').equals(first.id).count()) === 0 && !first.notes
  const title = name.trim() || (untouched ? FIRST_CASE_NAME : `Case ${all.length + 1}`)
  let id: number
  if (untouched && first?.id != null) {
    id = first.id
    const serverKey = storage === 'server' ? (first.serverKey ?? newServerKey()) : undefined
    await db.cases.update(id, { name: title, storage, serverKey, updatedAt: Date.now() })
  } else {
    id = await db.cases.add({ name: title, createdAt: Date.now(), updatedAt: Date.now(), settings: defaultSettings(), storage, serverKey: storage === 'server' ? newServerKey() : undefined })
  }
  await db.kv.put({ key: 'lastCase', value: id })
  const c = (await db.cases.get(id))!
  return { ...c, settings: { ...defaultSettings(), ...c.settings } }
}
