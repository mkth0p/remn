/**
 * The scenarios chosen for a case and the analyst's answers to their questions (DFIQ calls an
 * answer a Conclusion): a status (open, answered, cannot be answered from this evidence), the
 * analyst's text and what it cites.
 *
 * The chosen scenarios are a kv entry of the case, the answers rows of their own table; both are
 * in the case bundle (data/caseBundle.ts). A cited row is kept by its record key
 * (data/recordKeys.ts) as well as its id, and a cited finding by the key its decision is archived
 * under (data/findingAnchors.ts), so a citation survives the evidence being removed and added
 * again, and the case being imported elsewhere: resolveCitation finds the row again from its key.
 */
import { getDb, type Evidence, type Finding, type QuestionAnswer, type QuestionCitation } from '../../db/schema'
import type { Filter } from '../../rules/filter'
import { reviewKey } from '../findingAnchors'
import { recordLabel, recordRef } from '../recordKeys'
import type { DataSource } from '../source'
import { scenarioViews } from './catalog'
import { coverage, type EvidenceProfile } from './coverage'

export type AnswerStatus = QuestionAnswer['status']
export const ANSWER_STATUSES: { id: AnswerStatus; label: string }[] = [
  { id: 'open', label: 'open' },
  { id: 'answered', label: 'answered' },
  { id: 'cannot', label: 'cannot answer from this evidence' },
]
export const ANSWER_LABEL = Object.fromEntries(ANSWER_STATUSES.map((s) => [s.id, s.label])) as Record<AnswerStatus, string>

export const QUESTION_SCENARIOS_KEY = (caseId: number) => `question-scenarios-${caseId}`

export async function loadScenarioChoice(caseId: number): Promise<string[]> {
  const v = (await getDb().kv.get(QUESTION_SCENARIOS_KEY(caseId)))?.value as { scenarios?: string[] } | undefined
  return Array.isArray(v?.scenarios) ? v.scenarios.filter((s) => typeof s === 'string') : []
}

export async function saveScenarioChoice(caseId: number, scenarios: string[]): Promise<void> {
  await getDb().kv.put({ key: QUESTION_SCENARIOS_KEY(caseId), value: { scenarios: [...new Set(scenarios)], updatedAt: Date.now() } })
}

/** The case's answers by question id. */
export async function loadAnswers(caseId: number): Promise<Map<string, QuestionAnswer>> {
  const rows = await getDb().questionAnswers.where('caseId').equals(caseId).toArray()
  return new Map(rows.map((r) => [r.questionId, r]))
}

/** Change one answer, creating it on first use; returns the answer as stored. */
export async function updateAnswer(caseId: number, questionId: string, change: (a: QuestionAnswer) => void): Promise<QuestionAnswer> {
  const db = getDb()
  return db.transaction('rw', db.questionAnswers, async () => {
    const now = Date.now()
    const current = await db.questionAnswers.where('[caseId+questionId]').equals([caseId, questionId]).first()
    const next: QuestionAnswer = current ? { ...current, citations: [...(current.citations ?? [])] } : { caseId, questionId, status: 'open', text: '', citations: [], createdAt: now, updatedAt: now }
    change(next)
    next.updatedAt = now
    next.id = await db.questionAnswers.put(next)
    return next
  })
}

export function setAnswer(caseId: number, questionId: string, patch: Partial<Pick<QuestionAnswer, 'status' | 'text'>>): Promise<QuestionAnswer> {
  return updateAnswer(caseId, questionId, (a) => Object.assign(a, patch))
}

/** What identifies a citation whatever its row id: its record key, the finding's key, or the row id when neither is known. */
export const citationId = (c: Pick<QuestionCitation, 'source' | 'recordKey' | 'key' | 'rowId'>) => `${c.source}:${c.recordKey || c.key || `#${c.rowId}`}`

export function addCitation(caseId: number, questionId: string, c: QuestionCitation): Promise<QuestionAnswer> {
  return updateAnswer(caseId, questionId, (a) => {
    if (!a.citations.some((x) => citationId(x) === citationId(c))) a.citations.push(c)
  })
}

export function removeCitation(caseId: number, questionId: string, id: string): Promise<QuestionAnswer> {
  return updateAnswer(caseId, questionId, (a) => {
    a.citations = a.citations.filter((x) => citationId(x) !== id)
  })
}

/** A citation of an event or mail row, by its record key. */
export function rowCitation(row: Record<string, unknown>, source: 'events' | 'mails', evidence?: Evidence): QuestionCitation {
  const ref = recordRef(row, source, evidence)
  const ts = source === 'mails' ? (row.date as number | null | undefined) : (row.ts as number | null | undefined)
  return { source, rowId: typeof row.id === 'number' ? row.id : undefined, recordKey: ref.key, label: recordLabel(ref), ts: ts ?? null, addedAt: Date.now() }
}

/** A citation of a finding, by the key its decision is archived under. */
export function findingCitation(f: Finding): QuestionCitation {
  return { source: 'findings', key: reviewKey(f), label: `${f.title} (${f.ruleId})`, ts: f.ts, addedAt: Date.now() }
}

/** A filter that finds the rows that may hold this record key (a record number, a message index, a cloud record id). */
export function recordKeyFilter(source: 'events' | 'mails', recordKey: string): Filter | null {
  const cut = recordKey.lastIndexOf('#')
  if (cut < 0) return null
  const fragment = recordKey.slice(cut + 1)
  const eq = (field: string, value: unknown): Filter => ({ conditions: [{ field, op: 'eq', value }] })
  if (source === 'mails') {
    if (/^m\d+$/.test(fragment)) return eq('sourceIndex', Number(fragment.slice(1)))
    if (fragment.startsWith('mid:')) return eq('messageId', fragment.slice(4))
    return null
  }
  const parts = fragment.split('|')
  if (parts.length === 3 && /^\d+$/.test(parts[2])) return eq('recordId', Number(parts[2]))
  if (/^\d+$/.test(fragment)) return eq('recordId', Number(fragment))
  if (/^i\d+$/.test(fragment)) return eq('sourceIndex', Number(fragment.slice(1)))
  if (/^id\d+$/.test(fragment)) return null
  return eq('recordKey', fragment)
}

export interface ResolvedCitation {
  /** the row id or finding id the citation names now; null when it is no longer in the case */
  id: number | null
  /** the row was found again under another id than the one stored */
  moved: boolean
}

/** Where a citation is now: its stored row id when that row is still its record, the row that holds its record key otherwise. */
export async function resolveCitation(c: QuestionCitation, source: DataSource, evidence: Evidence[], findings: Finding[]): Promise<ResolvedCitation> {
  if (c.source === 'findings') {
    const f = findings.find((x) => reviewKey(x) === c.key || x.key === c.key)
    return { id: f?.id ?? null, moved: false }
  }
  const byId = new Map(evidence.map((e) => [e.id!, e]))
  const keyOf = (row: Record<string, unknown>) => recordRef(row, c.source as 'events' | 'mails', byId.get(Number(row.evidenceId))).key
  if (c.rowId != null) {
    const row = c.source === 'mails' ? (await source.getMail(c.rowId).catch(() => null))?.row : await source.getEvent(c.rowId).catch(() => null)
    if (row && (!c.recordKey || keyOf(row) === c.recordKey)) return { id: c.rowId, moved: false }
  }
  if (!c.recordKey) return { id: null, moved: false }
  const filter = recordKeyFilter(c.source, c.recordKey)
  if (!filter) return { id: null, moved: false }
  try {
    const res = c.source === 'mails' ? await source.searchMails(filter, 500) : await source.searchEvents(filter, 500)
    const hit = (res.rows as Record<string, unknown>[]).find((r) => keyOf(r) === c.recordKey)
    return hit && typeof hit.id === 'number' ? { id: hit.id, moved: hit.id !== c.rowId } : { id: null, moved: false }
  } catch {
    return { id: null, moved: false }
  }
}

// ---------------------------------------------------------------------------
// the report

export interface ReportQuestion {
  id: string
  name: string
  status: AnswerStatus
  text: string
  citations: { label: string; source: QuestionCitation['source']; ts?: number | null }[]
  /** "covered by …" or "not covered: …", when the case's evidence was read */
  coverage?: string
  covered?: boolean
  answeredAt?: number
}

export interface ReportQuestions {
  scenarios: { id: string; name: string; origin: 'dfiq' | 'remn'; facets: { id: string; name: string; questions: ReportQuestion[] }[] }[]
  /** each question once, whichever scenarios share it */
  counts: Record<AnswerStatus, number>
  /** open questions the case's evidence does not cover */
  uncovered: number
}

/** The chosen scenarios with every question's answer, for the report; undefined when no scenario is chosen. */
export function questionsForReport(scenarioIds: string[], answers: Map<string, QuestionAnswer>, profile?: EvidenceProfile | null): ReportQuestions | undefined {
  const views = scenarioViews(scenarioIds)
  if (!views.length) return undefined
  const counts: Record<AnswerStatus, number> = { open: 0, answered: 0, cannot: 0 }
  const seen = new Set<string>()
  let uncovered = 0
  const scenarios = views.map((v) => ({
    id: v.scenario.id,
    name: v.scenario.name,
    origin: v.scenario.origin,
    facets: v.facets.map((f) => ({
      id: f.facet.id,
      name: f.facet.name,
      questions: f.questions.map((q): ReportQuestion => {
        const a = answers.get(q.id)
        const status: AnswerStatus = a?.status ?? 'open'
        const cov = profile ? coverage(q, profile) : null
        if (!seen.has(q.id)) {
          seen.add(q.id)
          counts[status]++
          if (status === 'open' && cov && !cov.covered) uncovered++
        }
        return {
          id: q.id,
          name: q.name,
          status,
          text: a?.text ?? '',
          citations: (a?.citations ?? []).map((c) => ({ label: c.label, source: c.source, ts: c.ts })),
          coverage: cov?.text,
          covered: cov?.covered,
          answeredAt: a && a.status !== 'open' ? a.updatedAt : undefined,
        }
      }),
    })),
  }))
  return { scenarios, counts, uncovered }
}
