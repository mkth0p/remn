import { runAgent } from '../ai/chat'
import { getDb, type Case, type Finding, type Severity } from '../db/schema'
import { useStore } from '../state/store'
import { fmtTs } from '../util/format'
import type { Chain } from './chains'
import {
  applyChainVerdict,
  chainSeverity,
  loadChainReviews,
  overridesForIncident,
  saveChainReview,
  SEVERITIES,
  setChainUnlinked,
  stepVisible,
  type ChainReview,
  type ReviewItem,
  type Verdict,
} from './review'
import { effectiveSeverity, type Incident } from '../rules/incidents'

/**
 * The model's part in the review: proposals it records from the chat (suggest_review tool), and the
 * triage pass that decides a whole queue. Both produce the same decision shape; a suggestion waits
 * for the analyst, a triage decision is written and can be undone from the log.
 */

export type Decision = 'reviewed' | 'escalated' | 'false_positive' | 'confirmed' | 'benign' | 'unsure'
const INCIDENT_DECISIONS: Decision[] = ['reviewed', 'escalated', 'false_positive']
const CHAIN_DECISIONS: Decision[] = ['confirmed', 'benign', 'unsure']

/** What models write instead of the exact words, and what each means. */
const DECISION_ALIASES: Record<string, Decision> = {
  confirm: 'confirmed',
  confirmed: 'confirmed',
  malicious: 'confirmed',
  true_positive: 'confirmed',
  tp: 'confirmed',
  compromised: 'confirmed',
  escalate: 'escalated',
  escalated: 'escalated',
  escalation: 'escalated',
  action: 'escalated',
  needs_action: 'escalated',
  benign: 'benign',
  dismiss: 'benign',
  dismissed: 'benign',
  not_malicious: 'benign',
  harmless: 'benign',
  noise: 'benign',
  legitimate: 'benign',
  unsure: 'unsure',
  uncertain: 'unsure',
  inconclusive: 'unsure',
  unknown: 'unsure',
  needs_review: 'unsure',
  investigate: 'unsure',
  suspicious: 'unsure',
  undetermined: 'unsure',
  reviewed: 'reviewed',
  review: 'reviewed',
  no_action: 'reviewed',
  close: 'reviewed',
  closed: 'reviewed',
  informational: 'reviewed',
  expected: 'reviewed',
  acknowledged: 'reviewed',
  false_positive: 'false_positive',
  falsepositive: 'false_positive',
  fp: 'false_positive',
  misfire: 'false_positive',
  misfired: 'false_positive',
}
/** the same meaning said in the other kind's words */
const TO_CHAIN: Partial<Record<Decision, Decision>> = { escalated: 'confirmed', reviewed: 'unsure', false_positive: 'benign' }
const TO_INCIDENT: Partial<Record<Decision, Decision>> = { confirmed: 'escalated', benign: 'reviewed', unsure: 'reviewed' }

/** A model's decision word as one of the item kind's decisions, or null when it means nothing known. */
export function normaliseDecision(raw: unknown, kind: 'chain' | 'incident'): Decision | null {
  const key = String(raw ?? '')
    .toLowerCase()
    .trim()
    .replace(/[\s-]+/g, '_')
  const d = DECISION_ALIASES[key]
  if (!d) return null
  const allowed = kind === 'chain' ? CHAIN_DECISIONS : INCIDENT_DECISIONS
  if (allowed.includes(d)) return d
  return (kind === 'chain' ? TO_CHAIN[d] : TO_INCIDENT[d]) ?? null
}

export interface Suggestion {
  /** 'chain:<chain id>' | 'finding:<finding id>' | 'incident:<incident id>' */
  target: string
  severity?: Severity
  decision?: Decision
  include?: boolean
  /** chains: linked finding ids to take out of the chain */
  unlink?: number[]
  /** chains: the report narrative the model drafted */
  narrative?: string
  /** incidents: the note printed with the incident */
  note?: string
  reason: string
  at: number
  by: 'chat' | 'triage'
  model?: string
}

export async function loadSuggestions(caseId: number): Promise<Record<string, Suggestion>> {
  return ((await getDb().kv.get(`ai-suggestions-${caseId}`))?.value as Record<string, Suggestion> | undefined) ?? {}
}
export async function saveSuggestion(caseId: number, s: Suggestion): Promise<Record<string, Suggestion>> {
  const all = await loadSuggestions(caseId)
  all[s.target] = s
  await getDb().kv.put({ key: `ai-suggestions-${caseId}`, value: all })
  return all
}
export async function removeSuggestion(caseId: number, target: string): Promise<Record<string, Suggestion>> {
  const all = await loadSuggestions(caseId)
  delete all[target]
  await getDb().kv.put({ key: `ai-suggestions-${caseId}`, value: all })
  return all
}

/** The suggestions that concern one review item: its own target, or any of its findings. */
export function suggestionsFor(it: ReviewItem, all: Record<string, Suggestion>): Suggestion[] {
  const out: Suggestion[] = []
  const own = all[it.kind === 'chain' ? `chain:${it.chain!.id}` : `incident:${it.incident!.id}`]
  if (own) out.push(own)
  for (const f of it.incident?.findings ?? []) {
    const s = all[`finding:${f.id}`]
    if (s) out.push(s)
  }
  return out
}

// ---------------------------------------------------------------------------
// what the model sees
// ---------------------------------------------------------------------------
const short = (s: string | undefined | null, n: number) => (s && s.length > n ? s.slice(0, n - 1) + '…' : s || '')

export function describeIncident(inc: Incident): Record<string, unknown> {
  return {
    id: `incident:${inc.id}`,
    kind: inc.kind,
    decisions: INCIDENT_DECISIONS,
    title: short(inc.title, 140),
    severity: inc.severity,
    status: inc.status,
    source: inc.source,
    from: inc.ts ? new Date(inc.ts).toISOString() : null,
    to: inc.tsEnd ? new Date(inc.tsEnd).toISOString() : null,
    rows: inc.refs.length,
    entities: Object.fromEntries(
      Object.entries(inc.entities)
        .slice(0, 8)
        .map(([k, v]) => [k, short(v, 80)]),
    ),
    findings: inc.findings.slice(0, 12).map((f) => ({
      id: f.id,
      rule: f.ruleId,
      severity: effectiveSeverity(f),
      title: short(f.title, 140),
      rows: f.count,
      ...(f.escalation ? { note: short(f.escalation, 120) } : {}),
      ...(f.notes ? { analystNote: short(f.notes, 200) } : {}),
    })),
  }
}

export function describeChain(c: Chain, review: ChainReview | undefined, members: Finding[]): Record<string, unknown> {
  const steps = c.steps.filter((s) => stepVisible(s, 'weighted')).slice(0, 14)
  return {
    id: `chain:${c.id}`,
    kind: 'chain',
    decisions: CHAIN_DECISIONS,
    recipient: c.identityLabel,
    score: c.score,
    severity: chainSeverity(c, review),
    scoreBreakdown: c.scoreBreakdown ?? null,
    artifactLinks: c.artifactLinks,
    seed: {
      subject: short(c.seed.subject, 120),
      from: c.seed.fromAddr,
      at: new Date(c.seed.ts).toISOString(),
      risk: c.seed.risk,
      flags: c.seed.flags.slice(0, 10),
      findings: c.seed.findings.slice(0, 6).map((f) => short(f.title, 100)),
    },
    steps: steps.map(
      (s) =>
        `+${Math.round(s.offsetMin)} min [${s.kind === 'mail' ? 'mail' : (s.origin ?? 'host')}] ${short(s.title, 110)}${s.artifacts.length ? ' | ties: ' + short(s.artifacts.join('; '), 160) : ''}${s.findings.length ? ' | findings: ' + short(s.findings.map((f) => f.title).join('; '), 160) : ''}`,
    ),
    stepsNotShown: Math.max(0, c.steps.length - steps.length),
    linkedFindings: members
      .filter((f) => f.ruleId !== 'chain')
      .slice(0, 20)
      .map((f) => ({ id: f.id, rule: f.ruleId, severity: effectiveSeverity(f), title: short(f.title, 120), source: f.source, rows: f.count })),
  }
}

export function describeItem(it: ReviewItem, reviews: Record<string, ChainReview>): Record<string, unknown> {
  if (it.kind === 'chain' && it.chain) return describeChain(it.chain, reviews[it.chain.id], it.incident?.findings ?? [])
  return describeIncident(it.incident!)
}

// ---------------------------------------------------------------------------
// decisions
// ---------------------------------------------------------------------------
export interface ParsedDecision {
  id: string
  decision: Decision
  severity?: Severity
  include?: boolean
  unlink: number[]
  reason: string
  narrative?: string
  note?: string
}

/** The model's reply (a JSON array, possibly fenced or wrapped in prose) as validated decisions for the ids asked about. */
export function parseDecisions(text: string, items: ReviewItem[]): { decisions: ParsedDecision[]; rejected: string[] } {
  const byId = new Map(items.map((it) => [it.id, it]))
  const rejected: string[] = []
  let raw: unknown = null
  const t = text.trim()
  const start = t.indexOf('[')
  const end = t.lastIndexOf(']')
  if (start !== -1 && end > start) {
    try {
      raw = JSON.parse(t.slice(start, end + 1))
    } catch {
      raw = null
    }
  }
  if (raw == null) {
    // one object per line, or a single object
    const objs: unknown[] = []
    for (const m of t.matchAll(/\{[^{}]*\}/g)) {
      try {
        objs.push(JSON.parse(m[0]))
      } catch {
        /* skip */
      }
    }
    raw = objs
  }
  const decisions: ParsedDecision[] = []
  const seen = new Set<string>()
  for (const x of Array.isArray(raw) ? raw : []) {
    if (!x || typeof x !== 'object') continue
    const o = x as Record<string, unknown>
    const id = String(o.id ?? '')
    const it = byId.get(id)
    if (!it || seen.has(id)) {
      rejected.push(`unknown or repeated id "${short(id, 60)}"`)
      continue
    }
    const allowed = it.kind === 'chain' ? CHAIN_DECISIONS : INCIDENT_DECISIONS
    const decision = normaliseDecision(o.decision ?? o.verdict ?? o.status, it.kind)
    if (!decision) {
      rejected.push(`${id}: decision "${short(String(o.decision ?? ''), 40)}" is not one of ${allowed.join(', ')}`)
      continue
    }
    const sevRaw = typeof o.severity === 'string' ? o.severity.toLowerCase().trim() : ''
    const severity = SEVERITIES.includes(sevRaw as Severity) ? (sevRaw as Severity) : undefined
    const include = typeof o.include === 'boolean' ? o.include : undefined
    const memberIds = new Set((it.incident?.findings ?? []).filter((f) => f.ruleId !== 'chain').map((f) => f.id))
    const unlink = it.kind === 'chain' && Array.isArray(o.unlink) ? (o.unlink as unknown[]).map(Number).filter((n) => memberIds.has(n)) : []
    const reason = short(String(o.reason ?? o.why ?? '').trim(), 700) || '(no reason given)'
    const narrative = it.kind === 'chain' ? short(String(o.narrative ?? o.note ?? '').trim(), 2500) || undefined : undefined
    const note = it.kind !== 'chain' ? short(String(o.note ?? o.narrative ?? '').trim(), 900) || undefined : undefined
    seen.add(id)
    decisions.push({ id, decision, severity, include, unlink, reason, narrative, note })
  }
  return { decisions, rejected }
}

interface FindingSnapshot {
  id: number
  status: Finding['status']
  severityOverride?: Severity
  reportExclude?: boolean
  chainUnlinked?: boolean
  decidedBy?: Finding['decidedBy']
  aiReason?: string
  notes?: string
  notesBy?: Finding['notesBy']
}

export interface TriageEntry {
  id: string
  kind: 'chain' | 'incident'
  title: string
  decision: Decision
  severityBefore: Severity
  severityAfter: Severity
  includeBefore: boolean
  includeAfter: boolean
  unlinked: { id: number; title: string }[]
  reason: string
  /** the model also wrote the chain narrative / the incident note */
  wrote?: 'narrative' | 'note'
  before: { findings: FindingSnapshot[]; chainReview?: ChainReview | null }
  undone?: boolean
}

export interface TriageRun {
  at: number
  model: string
  transport: string
  asked: number
  entries: TriageEntry[]
  errors: string[]
  rejected: string[]
  /** the executive summary was drafted at the end of the pass */
  summaryDrafted?: boolean
}

export async function loadTriageRun(caseId: number): Promise<TriageRun | null> {
  return ((await getDb().kv.get(`ai-triage-${caseId}`))?.value as TriageRun | undefined) ?? null
}
export async function saveTriageRun(caseId: number, run: TriageRun): Promise<void> {
  await getDb().kv.put({ key: `ai-triage-${caseId}`, value: run })
}

const snapshot = (f: Finding): FindingSnapshot => ({
  id: f.id!,
  status: f.status,
  severityOverride: f.severityOverride,
  reportExclude: f.reportExclude,
  chainUnlinked: f.chainUnlinked,
  decidedBy: f.decidedBy,
  aiReason: f.aiReason,
  notes: f.notes,
  notesBy: f.notesBy,
})

/** Write one decision (incident status/severity/inclusion, or chain verdict/severity/inclusion/unlinks) and return the log entry with what it replaced. */
export async function applyDecision(caseId: number, it: ReviewItem, d: ParsedDecision, reviews: Record<string, ChainReview>): Promise<TriageEntry> {
  const db = getDb()
  const inc = it.incident
  const findings = inc?.findings ?? []
  const before = { findings: findings.map(snapshot), chainReview: it.chain ? (reviews[it.chain.id] ?? null) : undefined }
  const entry: TriageEntry = {
    id: it.id,
    kind: it.kind,
    title: it.title,
    decision: d.decision,
    severityBefore: it.severity,
    severityAfter: it.severity,
    includeBefore: true,
    includeAfter: true,
    unlinked: [],
    reason: d.reason,
    before,
  }
  if (it.kind === 'chain' && it.chain) {
    const c = it.chain
    const rev = reviews[c.id]
    entry.includeBefore = rev?.include ?? rev?.verdict !== 'benign'
    const members = findings.filter((f) => !d.unlink.includes(f.id!))
    await applyChainVerdict(caseId, c, members, d.decision as Verdict, 'ai', d.reason)
    const patch: Partial<ChainReview> = {}
    if (d.severity && d.severity !== chainSeverity(c, rev)) patch.severityOverride = d.severity === c.severity ? undefined : d.severity
    if (d.include !== undefined) patch.include = d.include
    // the analyst's narrative is kept; one the model drafted earlier is replaced
    if (d.narrative && (!rev?.narrative || rev.narrativeBy === 'ai')) {
      patch.narrative = d.narrative
      patch.narrativeBy = 'ai'
      entry.wrote = 'narrative'
    }
    if (Object.keys(patch).length) await saveChainReview(caseId, c.id, patch)
    entry.severityAfter = d.severity ?? chainSeverity(c, rev)
    entry.includeAfter = d.include ?? d.decision !== 'benign'
    if (d.unlink.length) {
      await setChainUnlinked(d.unlink, true)
      entry.unlinked = d.unlink.map((id) => ({ id, title: findings.find((f) => f.id === id)?.title ?? String(id) }))
    }
    return entry
  }
  if (!inc) return entry
  entry.includeBefore = !(findings.length > 0 && findings.every((f) => f.reportExclude))
  const status = d.decision as Finding['status']
  await Promise.all(findings.map((f) => db.findings.update(f.id!, { status, decidedBy: 'ai', aiReason: f.id === inc.lead.id ? d.reason : f.aiReason })))
  if (d.note && (!inc.lead.notes || inc.lead.notesBy === 'ai')) {
    await db.findings.update(inc.lead.id!, { notes: d.note, notesBy: 'ai' })
    entry.wrote = 'note'
  }
  if (d.severity && d.severity !== inc.severity) {
    await Promise.all(overridesForIncident(inc, d.severity).map((o) => db.findings.update(o.id, { severityOverride: o.severityOverride })))
    entry.severityAfter = d.severity
  }
  if (d.include !== undefined) {
    await Promise.all(findings.map((f) => db.findings.update(f.id!, { reportExclude: d.include ? undefined : true })))
    entry.includeAfter = d.include
  } else entry.includeAfter = entry.includeBefore
  return entry
}

/** Put back what a decision replaced. */
export async function undoEntry(caseId: number, entry: TriageEntry): Promise<void> {
  const db = getDb()
  await Promise.all(
    entry.before.findings.map((s) =>
      db.findings.update(s.id, {
        status: s.status,
        severityOverride: s.severityOverride,
        reportExclude: s.reportExclude,
        chainUnlinked: s.chainUnlinked,
        decidedBy: s.decidedBy,
        aiReason: s.aiReason,
        ...(entry.wrote === 'note' ? { notes: s.notes, notesBy: s.notesBy } : {}),
      }),
    ),
  )
  if (entry.kind === 'chain' && entry.before.chainReview !== undefined) {
    const all = await loadChainReviews(caseId)
    const chainId = entry.id.replace(/^chain:/, '')
    if (entry.before.chainReview) all[chainId] = entry.before.chainReview
    else delete all[chainId]
    await db.kv.put({ key: `chain-reviews-${caseId}`, value: all })
  }
  entry.undone = true
}

// ---------------------------------------------------------------------------
// the triage pass
// ---------------------------------------------------------------------------
export interface TriageProgress {
  done: number
  total: number
  batch: number
  batches: number
}

const INSTRUCTION =
  'Decide on every item below and reply with ONLY a JSON array, one object per item, in the same order: {"id": "<id as given>", "decision": "<exactly one of the item\'s "decisions" values: chains confirmed|benign|unsure, incidents escalated|reviewed|false_positive>", "severity": "<critical|high|medium|low|info>", "include": <true|false>, "reason": "<one or two factual sentences>", "unlink": [<finding ids that do not belong to the chain, chains only, usually empty>], "narrative": "<chains only: 4 to 7 sentences for the report>", "note": "<incidents only: 1 to 3 sentences printed with the incident>"}.'

export function batchSize(): number {
  return useStore.getState().aiConfig.transport === 'claude' ? 8 : 4
}

/**
 * Ask the model for a decision on each item, in batches, and either record them as suggestions
 * (apply: false) or write them (apply: true). Returns the log; the caller shows it.
 */
export async function runTriage(
  kase: Case,
  items: ReviewItem[],
  reviews: Record<string, ChainReview>,
  opts: {
    apply: boolean
    batch?: number
    model?: string
    signal?: AbortSignal
    onProgress?: (p: TriageProgress) => void
    /** run after the decisions (apply mode): drafts the executive summary */ draftSummary?: () => Promise<unknown>
  },
): Promise<TriageRun> {
  const caseId = kase.id!
  const size = Math.max(1, opts.batch ?? batchSize())
  const batches: ReviewItem[][] = []
  for (let i = 0; i < items.length; i += size) batches.push(items.slice(i, i + size))
  const run: TriageRun = { at: Date.now(), model: opts.model ?? '', transport: useStore.getState().aiConfig.transport, asked: items.length, entries: [], errors: [], rejected: [] }
  let currentReviews = reviews
  for (let b = 0; b < batches.length; b++) {
    if (opts.signal?.aborted) {
      run.errors.push(`stopped after ${b} of ${batches.length} batches`)
      break
    }
    const batch = batches[b]
    opts.onProgress?.({ done: b * size, total: items.length, batch: b + 1, batches: batches.length })
    const payload = batch.map((it) => describeItem(it, currentReviews))
    const prompt = `${INSTRUCTION}\n\nItems:\n${JSON.stringify(payload, null, 1).slice(0, 90_000)}`
    let text: string
    try {
      const msgs = await runAgent([{ role: 'user', content: prompt }], kase, { mode: 'triage', tools: false, think: false, maxIterations: 1, model: opts.model, signal: opts.signal })
      const last = [...msgs].reverse().find((m) => m.role === 'assistant')
      text = last?.content ?? ''
      if (!last || text.startsWith('⚠')) throw new Error(text.replace(/^⚠\s*/, '') || 'the model returned nothing')
      if (!last.stats || !run.model) run.model = String((last.stats as Record<string, unknown> | undefined)?.model ?? run.model)
    } catch (e) {
      if ((e as Error).name === 'AbortError') {
        run.errors.push(`stopped during batch ${b + 1} of ${batches.length}`)
        break
      }
      run.errors.push(`batch ${b + 1}: ${(e as Error).message}`)
      continue
    }
    const { decisions, rejected } = parseDecisions(text, batch)
    run.rejected.push(...rejected)
    const answered = new Set(decisions.map((d) => d.id))
    for (const it of batch) if (!answered.has(it.id)) run.rejected.push(`${it.id}: no decision in the reply`)
    for (const d of decisions) {
      const it = batch.find((x) => x.id === d.id)!
      if (opts.apply) {
        const entry = await applyDecision(caseId, it, d, currentReviews)
        run.entries.push(entry)
        if (it.kind === 'chain') currentReviews = await loadChainReviews(caseId)
      } else {
        const target = it.kind === 'chain' ? `chain:${it.chain!.id}` : `incident:${it.incident!.id}`
        await saveSuggestion(caseId, {
          target,
          severity: d.severity,
          decision: d.decision,
          include: d.include,
          unlink: d.unlink.length ? d.unlink : undefined,
          narrative: d.narrative,
          note: d.note,
          reason: d.reason,
          at: Date.now(),
          by: 'triage',
          model: run.model || undefined,
        })
        run.entries.push({
          id: it.id,
          kind: it.kind,
          title: it.title,
          decision: d.decision,
          severityBefore: it.severity,
          severityAfter: d.severity ?? it.severity,
          includeBefore: true,
          includeAfter: d.include ?? true,
          unlinked: d.unlink.map((id) => ({ id, title: String(id) })),
          reason: d.reason,
          before: { findings: [] },
        })
      }
    }
  }
  opts.onProgress?.({ done: items.length, total: items.length, batch: batches.length, batches: batches.length })
  if (opts.apply && opts.draftSummary && !opts.signal?.aborted && run.entries.length) {
    try {
      await opts.draftSummary()
      run.summaryDrafted = true
    } catch (e) {
      run.errors.push(`executive summary: ${(e as Error).message}`)
    }
  }
  if (opts.apply) await saveTriageRun(caseId, run)
  return run
}

/** Apply a recorded suggestion as a decision (the analyst accepted it). */
export async function applySuggestion(caseId: number, it: ReviewItem, s: Suggestion, reviews: Record<string, ChainReview>): Promise<TriageEntry | null> {
  const allowed = it.kind === 'chain' ? CHAIN_DECISIONS : INCIDENT_DECISIONS
  const decision: Decision = s.decision && allowed.includes(s.decision) ? s.decision : it.kind === 'chain' ? 'unsure' : 'reviewed'
  const memberIds = new Set((it.incident?.findings ?? []).map((f) => f.id))
  const entry = await applyDecision(
    caseId,
    it,
    { id: it.id, decision, severity: s.severity, include: s.include, unlink: (s.unlink ?? []).filter((id) => memberIds.has(id)), reason: s.reason, narrative: s.narrative, note: s.note },
    reviews,
  )
  await removeSuggestion(caseId, s.target)
  return entry
}

export const fmtWhen = (t: number) => fmtTs(t)
