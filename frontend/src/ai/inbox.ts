/**
 * The approval inbox: everything the agent wants to change in a case waits here for the analyst.
 *
 * The model has no tool that writes to the case. A review decision, a note or timeline entry, row
 * marks, a detection rule or the executive summary is queued as a proposal with its reason and
 * the rows it cites; the analyst accepts it (one by one or all at once) or rejects it, and only
 * the acceptance writes. An accepted proposal keeps what it replaced, so it can be undone. Nothing
 * in the evidence can accept a proposal: acceptance is a click in this page, and a proposal made
 * after the agent read text addressed to a model, or evidence too long for that check to read
 * whole, is marked and never accepted in bulk: "accept all" leaves it for a one-by-one look.
 *
 * Stored in kv `ai-inbox-<case>` in the shape the case bundle remaps on import (refs as
 * {source, id}, row ids under `refs`, review targets under `target`).
 */
import { create } from 'zustand'
import { getDb, type CaseNote, type RowMark, type RowMarkVerdict, type Severity } from '../db/schema'
import { addNote, deleteNote } from '../data/caseNotes'
import { loadRowMarks, markRows, clearRowMarks } from '../data/rowMarks'
import { getSource } from '../data/source'
import { useStore } from '../state/store'
import { appendLedger } from './ledger'
import type { RowRef } from './evidence'
import { refKey } from './evidence'
import type { Case } from '../db/schema'
import type { Decision, TriageEntry } from '../data/aiReview'

export type ProposalKind = 'decision' | 'note' | 'row_mark' | 'rule' | 'summary'
export type ProposalStatus = 'pending' | 'accepted' | 'rejected' | 'superseded'

export interface Proposal {
  id: string
  kind: ProposalKind
  status: ProposalStatus
  /** one line for the list */
  title: string
  reason: string
  citations: RowRef[]
  /** decision: 'finding:<id>' | 'chain:<id>' | 'incident:<id>' */
  target?: string
  /** `from`: the item's severity when the decision was proposed, so a proposal that lowers it is known */
  decision?: { decision?: Decision; severity?: Severity; from?: Severity; include?: boolean; unlink?: number[]; narrative?: string; note?: string }
  note?: { kind: CaseNote['kind']; text: string; ts?: number | null; link?: CaseNote['link'] }
  mark?: { source: 'events' | 'mails'; refs: number[]; verdict: RowMarkVerdict; tags: string[] }
  rule?: { yaml: string; ruleId: string; test: { findings: number; errors: string[]; sample: string[] } }
  summary?: { text: string }
  createdAt: number
  decidedAt?: number
  by: 'agent' | 'triage' | 'chat'
  model?: string
  /** the conversation that proposed it */
  session?: number
  /** the run had read evidence text addressed to a model before it proposed this */
  exposed?: boolean
  /** the run had read evidence too long or too deeply nested for that check to read whole */
  unchecked?: boolean
  /** what accepting it replaced, for undo */
  applied?: {
    entry?: TriageEntry
    /** the note or custom rule it added ({source, id}: the case bundle renumbers both on import) */
    created?: { source: 'caseNotes' | 'customRules'; id: number }
    previousSummary?: { text: string | null; by: unknown; at: unknown }
    marksBefore?: RowMark[]
    undone?: boolean
  }
  error?: string
}

/** bumped on every change, so the views that list proposals reload */
export const useInbox = create<{ version: number }>(() => ({ version: 0 }))
const bump = () => useInbox.setState((s) => ({ version: s.version + 1 }))

const key = (caseId: number) => `ai-inbox-${caseId}`
const KEEP_DECIDED = 400

export async function loadInbox(caseId: number): Promise<Proposal[]> {
  const row = await getDb().kv.get(key(caseId))
  return ((row?.value as { items?: Proposal[] } | undefined)?.items ?? []).slice()
}

const queues = new Map<number, Promise<unknown>>()
/** Read, change and write the inbox of one case, one change at a time. */
export function updateInbox<T>(caseId: number, change: (items: Proposal[]) => T | Promise<T>): Promise<T> {
  const prev = queues.get(caseId) ?? Promise.resolve()
  const next = prev
    .catch(() => undefined)
    .then(async () => {
      const items = await loadInbox(caseId)
      const out = await change(items)
      const pending = items.filter((p) => p.status === 'pending')
      const decided = items.filter((p) => p.status !== 'pending').slice(-KEEP_DECIDED)
      await getDb().kv.put({ key: key(caseId), value: { items: [...decided, ...pending].sort((a, b) => a.createdAt - b.createdAt) } })
      bump()
      return out
    })
  queues.set(caseId, next)
  return next
}

export const newProposalId = () => `p-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`

/** Queue a proposal. A pending proposal on the same target (decisions) or the same summary is superseded by the new one. */
export async function propose(caseId: number, p: Omit<Proposal, 'id' | 'status' | 'createdAt'> & { id?: string }): Promise<Proposal> {
  const proposal: Proposal = { ...p, id: p.id ?? newProposalId(), status: 'pending', createdAt: Date.now() }
  await updateInbox(caseId, (items) => {
    for (const it of items) {
      if (it.status !== 'pending') continue
      const same = (p.kind === 'decision' && it.kind === 'decision' && it.target === p.target) || (p.kind === 'summary' && it.kind === 'summary')
      if (same) {
        it.status = 'superseded'
        it.decidedAt = Date.now()
      }
    }
    items.push(proposal)
  })
  await appendLedger(caseId, 'proposal', `${p.kind}: ${p.title}`, {
    id: proposal.id,
    kind: p.kind,
    target: p.target,
    by: p.by,
    model: p.model,
    exposed: p.exposed || undefined,
    unchecked: p.unchecked || undefined,
    cites: p.citations.map(refKey).slice(0, 40),
  })
  return proposal
}

export const pendingCount = (items: Proposal[]) => items.filter((p) => p.status === 'pending').length

// ---------------------------------------------------------------------------
// accepting, rejecting, undoing
// ---------------------------------------------------------------------------
async function applyOne(kase: Case, p: Proposal): Promise<Proposal['applied']> {
  const caseId = kase.id!
  const db = getDb()
  switch (p.kind) {
    case 'decision': {
      const { applyProposedDecision } = await import('../data/aiReview')
      const entry = await applyProposedDecision(caseId, p)
      return { entry }
    }
    case 'note': {
      const n = p.note!
      const id = await addNote(caseId, n.kind, n.text, { ts: n.ts ?? Date.now(), link: n.link, ...(n.kind === 'timeline' && n.ts == null ? { untimed: true } : {}) })
      return { created: { source: 'caseNotes', id } }
    }
    case 'row_mark': {
      const m = p.mark!
      const before = await loadRowMarks(caseId, m.source, m.refs)
      const ds = getSource(kase)
      const rows: Record<string, unknown>[] = []
      for (const id of m.refs) {
        const row = m.source === 'events' ? await ds.getEvent(id) : (await ds.getMail(id))?.row
        rows.push((row as Record<string, unknown> | null) ?? { id })
      }
      await markRows(caseId, m.source, rows, { verdict: m.verdict, addTags: m.tags, reason: p.reason, by: 'ai' })
      // without the table id: a bundle import renumbers marks, and undo finds the current mark by row
      return { marksBefore: [...before.values()].map(({ id: _id, ...rest }) => rest as RowMark) }
    }
    case 'rule': {
      const r = p.rule!
      const id = await db.customRules.add({ caseId, ruleId: r.ruleId, yaml: r.yaml, enabled: true, updatedAt: Date.now() })
      useStore.getState().bumpRules()
      return { created: { source: 'customRules', id } }
    }
    case 'summary': {
      const [text, by, at] = await Promise.all([db.kv.get(`report-summary-${caseId}`), db.kv.get(`report-summary-by-${caseId}`), db.kv.get(`report-summary-at-${caseId}`)])
      await db.kv.bulkPut([
        { key: `report-summary-${caseId}`, value: p.summary!.text },
        { key: `report-summary-by-${caseId}`, value: 'ai' },
        { key: `report-summary-at-${caseId}`, value: Date.now() },
      ])
      return { previousSummary: { text: (text?.value as string | undefined) ?? null, by: by?.value ?? null, at: at?.value ?? null } }
    }
  }
}

/** Accept proposals (the analyst's click): each is written, logged, and kept with what it replaced. */
export async function acceptProposals(kase: Case, ids: string[], edits: Record<string, Partial<Proposal>> = {}): Promise<{ accepted: number; failed: { id: string; error: string }[] }> {
  const caseId = kase.id!
  const failed: { id: string; error: string }[] = []
  let accepted = 0
  for (const id of ids) {
    const items = await loadInbox(caseId)
    const found = items.find((x) => x.id === id)
    if (!found || found.status !== 'pending') continue
    const p: Proposal = { ...found, ...(edits[id] ?? {}) }
    try {
      const applied = await applyOne(kase, p)
      await updateInbox(caseId, (all) => {
        const it = all.find((x) => x.id === id)
        if (it) Object.assign(it, edits[id] ?? {}, { status: 'accepted', decidedAt: Date.now(), applied, error: undefined })
      })
      await appendLedger(caseId, 'accepted', `${p.kind}: ${p.title}`, { id, kind: p.kind, edited: edits[id] ? Object.keys(edits[id]) : undefined })
      accepted++
    } catch (e) {
      const error = (e as Error).message || String(e)
      failed.push({ id, error })
      await updateInbox(caseId, (all) => {
        const it = all.find((x) => x.id === id)
        if (it) it.error = error
      })
    }
  }
  return { accepted, failed }
}

const RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

/**
 * Why a decision waits for the analyst whatever was read before it, or null. What a lure in the
 * evidence would ask for is a decision that hides: one that lowers a severity, leaves an item out
 * of the report or dismisses it as a false positive (a benign chain).
 */
export function heldByAction(p: Proposal): string | null {
  const d = p.kind === 'decision' ? p.decision : undefined
  if (d?.decision === 'false_positive') return 'it would mark the item a false positive'
  if (d?.decision === 'benign') return 'it would mark the chain benign'
  if (d?.include === false) return 'it would leave the item out of the report'
  if (d?.severity && !d.from) return `it would set the severity to ${d.severity}, and the severity it replaces was not recorded`
  if (d?.severity && d.from && RANK[d.severity] < RANK[d.from]) return `it would lower the severity from ${d.from} to ${d.severity}`
  return null
}

/**
 * Why a proposal waits for the analyst to look at it alone, or null when "accept all" may take it.
 * A decision that hides waits whatever the check for text addressed to a model found, since that
 * check finds only the phrasings it has patterns for (a lure in another language, encoded or split
 * passes). What it did find, and what it could not read whole, keep any proposal out too.
 */
export function heldForReview(p: Proposal): string | null {
  const byAction = heldByAction(p)
  if (byAction) return byAction
  if (p.exposed) return 'the agent proposed it after reading evidence text addressed to a model'
  if (p.unchecked) return 'the agent proposed it after reading evidence too long or too deeply nested to check whole for such text'
  return null
}

/** "Accept all": every pending proposal but those held for review, which stay pending. */
export async function acceptAll(kase: Case): Promise<{ accepted: number; failed: { id: string; error: string }[]; held: number }> {
  const pending = (await loadInbox(kase.id!)).filter((p) => p.status === 'pending').reverse()
  const bulk = pending.filter((p) => !heldForReview(p))
  const r = await acceptProposals(
    kase,
    bulk.map((p) => p.id),
  )
  return { ...r, held: pending.length - bulk.length }
}

export async function rejectProposals(caseId: number, ids: string[], why = ''): Promise<void> {
  const done: Proposal[] = []
  await updateInbox(caseId, (all) => {
    for (const it of all)
      if (ids.includes(it.id) && it.status === 'pending') {
        it.status = 'rejected'
        it.decidedAt = Date.now()
        done.push(it)
      }
  })
  for (const p of done) await appendLedger(caseId, 'rejected', `${p.kind}: ${p.title}`, { id: p.id, kind: p.kind, why: why || undefined })
}

/** Put back what an accepted proposal changed. */
export async function undoProposal(kase: Case, id: string): Promise<void> {
  const caseId = kase.id!
  const db = getDb()
  const p = (await loadInbox(caseId)).find((x) => x.id === id)
  if (!p || p.status !== 'accepted' || !p.applied || p.applied.undone) return
  const a = p.applied
  if (a.entry) {
    const { undoEntry } = await import('../data/aiReview')
    await undoEntry(caseId, a.entry)
  }
  if (a.created?.source === 'caseNotes') await deleteNote(a.created.id)
  if (a.created?.source === 'customRules') {
    await db.customRules.delete(a.created.id)
    useStore.getState().bumpRules()
  }
  if (a.previousSummary) {
    const s = a.previousSummary
    if (s.text == null) await db.kv.bulkDelete([`report-summary-${caseId}`, `report-summary-by-${caseId}`, `report-summary-at-${caseId}`])
    else
      await db.kv.bulkPut([
        { key: `report-summary-${caseId}`, value: s.text },
        { key: `report-summary-by-${caseId}`, value: s.by },
        { key: `report-summary-at-${caseId}`, value: s.at },
      ])
  }
  if (a.marksBefore && p.mark) {
    const had = new Set(a.marksBefore.map((m) => m.rowId))
    await clearRowMarks(
      caseId,
      p.mark.source,
      p.mark.refs.filter((r) => !had.has(r)),
    )
    const current = await loadRowMarks(caseId, p.mark.source, [...had])
    if (a.marksBefore.length) await db.rowMarks.bulkPut(a.marksBefore.map((m) => ({ ...m, id: current.get(m.rowId)?.id })))
  }
  await updateInbox(caseId, (all) => {
    const it = all.find((x) => x.id === id)
    if (it?.applied) it.applied.undone = true
  })
  await appendLedger(caseId, 'undone', `${p.kind}: ${p.title}`, { id, kind: p.kind })
}
