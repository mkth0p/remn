/**
 * The hypothesis board: the agent's working theories about a case, each with the rows for and
 * against it. The board is the agent's scratch state, not a conclusion of the case: the agent
 * writes it directly, the analyst edits, settles or deletes entries, and turns one into a case
 * note with a click. Nothing on the board reaches the report unless the analyst makes it a note.
 * Stored in kv `ai-hypotheses-<case>`; refs as {source, id} so the case bundle remaps them.
 */
import { create } from 'zustand'
import { getDb } from '../db/schema'
import { refKey, type RowRef } from './evidence'

export type HypothesisStatus = 'open' | 'supported' | 'refuted' | 'inconclusive'

export interface Hypothesis {
  /** h1, h2… stable within a case, so the model can update one by id */
  id: string
  statement: string
  status: HypothesisStatus
  confidence?: 'low' | 'medium' | 'high'
  support: RowRef[]
  against: RowRef[]
  next?: string
  by: 'ai' | 'analyst'
  createdAt: number
  updatedAt: number
  history: { at: number; status: HypothesisStatus; by: 'ai' | 'analyst' }[]
}

export const useBoard = create<{ version: number }>(() => ({ version: 0 }))
const key = (caseId: number) => `ai-hypotheses-${caseId}`
const MAX = 60

export async function loadBoard(caseId: number): Promise<Hypothesis[]> {
  const row = await getDb().kv.get(key(caseId))
  return ((row?.value as { items?: Hypothesis[] } | undefined)?.items ?? []).slice()
}

const queues = new Map<number, Promise<unknown>>()
export function updateBoard<T>(caseId: number, change: (items: Hypothesis[]) => T): Promise<T> {
  const next = (queues.get(caseId) ?? Promise.resolve())
    .catch(() => undefined)
    .then(async () => {
      const items = await loadBoard(caseId)
      const out = change(items)
      await getDb().kv.put({ key: key(caseId), value: { items: items.slice(-MAX) } })
      useBoard.setState((s) => ({ version: s.version + 1 }))
      return out
    })
  queues.set(caseId, next)
  return next
}

const mergeRefs = (a: RowRef[], b: RowRef[]) => {
  const seen = new Set(a.map(refKey))
  return [...a, ...b.filter((r) => !seen.has(refKey(r)))].slice(0, 40)
}

export interface HypothesisInput {
  id?: string
  statement?: string
  status?: HypothesisStatus
  confidence?: Hypothesis['confidence']
  support?: RowRef[]
  against?: RowRef[]
  next?: string
}

/** Add a hypothesis, or update the one with this id; refs add to those it had. */
export function recordHypothesis(caseId: number, input: HypothesisInput, by: 'ai' | 'analyst'): Promise<Hypothesis> {
  return updateBoard(caseId, (items) => {
    const now = Date.now()
    const existing = input.id ? items.find((h) => h.id === input.id) : undefined
    if (existing) {
      if (input.statement) existing.statement = input.statement.slice(0, 600)
      if (input.status && input.status !== existing.status) {
        existing.status = input.status
        existing.history.push({ at: now, status: input.status, by })
      }
      if (input.confidence) existing.confidence = input.confidence
      if (input.support) existing.support = mergeRefs(existing.support, input.support)
      if (input.against) existing.against = mergeRefs(existing.against, input.against)
      if (input.next !== undefined) existing.next = input.next.slice(0, 300) || undefined
      existing.updatedAt = now
      return existing
    }
    const n = items.reduce((m, h) => Math.max(m, Number(h.id.replace(/^h/, '')) || 0), 0) + 1
    const status = input.status ?? 'open'
    const h: Hypothesis = {
      id: `h${n}`,
      statement: (input.statement ?? '').slice(0, 600),
      status,
      confidence: input.confidence,
      support: input.support ?? [],
      against: input.against ?? [],
      next: input.next?.slice(0, 300) || undefined,
      by,
      createdAt: now,
      updatedAt: now,
      history: [{ at: now, status, by }],
    }
    items.push(h)
    return h
  })
}

export function removeHypothesis(caseId: number, id: string): Promise<void> {
  return updateBoard(caseId, (items) => {
    const i = items.findIndex((h) => h.id === id)
    if (i >= 0) items.splice(i, 1)
  })
}

/** The board as a few lines of working memory for the model. */
export function boardMemory(items: Hypothesis[]): string {
  if (!items.length) return ''
  return (
    'Hypotheses:\n' +
    items
      .slice(-15)
      .map(
        (h) =>
          `- ${h.id} (${h.status}${h.confidence ? `, ${h.confidence}` : ''}): ${h.statement.slice(0, 220)}` +
          (h.support.length ? ` for: ${h.support.slice(0, 8).map(refKey).join(' ')}` : '') +
          (h.against.length ? ` against: ${h.against.slice(0, 6).map(refKey).join(' ')}` : '') +
          (h.next ? ` next: ${h.next.slice(0, 120)}` : ''),
      )
      .join('\n')
  )
}
