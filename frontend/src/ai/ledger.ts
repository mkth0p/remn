/**
 * The AI ledger of a case: an append-only record of what the model was asked, which tools it ran,
 * what it proposed and what the analyst decided. A tool result is kept as a SHA-256 of its text,
 * not the text. Each entry's hash covers the previous entry's hash, so an entry edited or removed
 * afterwards breaks the chain at that point, which verifyLedger() reports and the report prints.
 * It travels in the case bundle with the rest of the case.
 */
import { getDb, type AiLedgerEntry } from '../db/schema'
import { sha256Hex } from '../util/export'

export type LedgerKind = AiLedgerEntry['kind']

const GENESIS = '0'.repeat(64)

function material(e: Pick<AiLedgerEntry, 'seq' | 'at' | 'kind' | 'text' | 'data' | 'prev'>): string {
  return JSON.stringify([e.seq, e.at, e.kind, e.text, e.data, e.prev])
}

// appends are serialised per case: two tools finishing together must not take the same seq
const queues = new Map<number, Promise<unknown>>()

/** Append one entry; resolves with it once stored. */
export function appendLedger(caseId: number, kind: LedgerKind, text: string, data: unknown = null): Promise<AiLedgerEntry> {
  const prevRun = queues.get(caseId) ?? Promise.resolve()
  const next = prevRun
    .catch(() => undefined)
    .then(async () => {
      const db = getDb()
      const last = await db.aiLedger.where('[caseId+seq]').between([caseId, -Infinity], [caseId, Infinity]).last()
      const entry: AiLedgerEntry = {
        caseId,
        seq: (last?.seq ?? 0) + 1,
        at: Date.now(),
        kind,
        text: text.slice(0, 500),
        data: data == null ? '' : JSON.stringify(data).slice(0, 4000),
        prev: last?.hash ?? GENESIS,
        hash: '',
      }
      entry.hash = await sha256Hex(material(entry))
      entry.id = await db.aiLedger.add(entry)
      return entry
    })
  queues.set(caseId, next)
  return next
}

export async function loadLedger(caseId: number, limit?: number): Promise<AiLedgerEntry[]> {
  const coll = getDb().aiLedger.where('[caseId+seq]').between([caseId, -Infinity], [caseId, Infinity])
  if (!limit) return coll.toArray()
  const rows = await coll.reverse().limit(limit).toArray()
  return rows.reverse()
}

export interface LedgerCheck {
  entries: number
  intact: boolean
  /** the first entry whose hash or link does not hold */
  brokenAt?: number
  head: string | null
}

export async function verifyLedger(caseId: number): Promise<LedgerCheck> {
  const all = await loadLedger(caseId)
  let prev = GENESIS
  for (let i = 0; i < all.length; i++) {
    const e = all[i]
    if (e.seq !== i + 1 || e.prev !== prev || (await sha256Hex(material(e))) !== e.hash) return { entries: all.length, intact: false, brokenAt: e.seq, head: all[all.length - 1].hash }
    prev = e.hash
  }
  return { entries: all.length, intact: true, head: all.length ? prev : null }
}

export interface LedgerSummary {
  runs: number
  toolCalls: number
  proposals: number
  accepted: number
  rejected: number
  undone: number
  notices: number
  models: string[]
  transports: string[]
  first: number | null
  last: number | null
  byProposalKind: Record<string, { proposed: number; accepted: number; rejected: number }>
}

function parseData(text: string): Record<string, unknown> {
  try {
    return text ? (JSON.parse(text) as Record<string, unknown>) : {}
  } catch {
    return {}
  }
}

/** What the report prints about the model's part: counts, models, and the state of the chain. */
export async function summariseLedger(caseId: number): Promise<LedgerSummary & { check: LedgerCheck }> {
  const all = await loadLedger(caseId)
  const s: LedgerSummary = { runs: 0, toolCalls: 0, proposals: 0, accepted: 0, rejected: 0, undone: 0, notices: 0, models: [], transports: [], first: null, last: null, byProposalKind: {} }
  const models = new Set<string>()
  const transports = new Set<string>()
  const kindOf = new Map<string, string>()
  const bucket = (k: string) => (s.byProposalKind[k] ??= { proposed: 0, accepted: 0, rejected: 0 })
  for (const e of all) {
    s.first ??= e.at
    s.last = e.at
    const d = parseData(e.data)
    if (e.kind === 'run' || e.kind === 'triage') {
      s.runs++
      if (d.model) models.add(String(d.model))
      if (d.transport) transports.add(String(d.transport))
    } else if (e.kind === 'tool') s.toolCalls++
    else if (e.kind === 'notice') s.notices++
    else if (e.kind === 'proposal') {
      s.proposals++
      const k = String(d.kind ?? 'other')
      kindOf.set(String(d.id), k)
      bucket(k).proposed++
    } else if (e.kind === 'accepted') {
      s.accepted++
      bucket(kindOf.get(String(d.id)) ?? String(d.kind ?? 'other')).accepted++
    } else if (e.kind === 'rejected') {
      s.rejected++
      bucket(kindOf.get(String(d.id)) ?? String(d.kind ?? 'other')).rejected++
    } else if (e.kind === 'undone') s.undone++
    if (e.kind === 'answer' && d.model) models.add(String(d.model))
  }
  s.models = [...models].sort()
  s.transports = [...transports].sort()
  return { ...s, check: await verifyLedger(caseId) }
}
