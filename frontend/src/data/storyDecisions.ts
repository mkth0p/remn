/**
 * The analyst's decisions on stories (docs/stories.md "Decisions"): a decision on each story (open,
 * reviewed, confirmed incident, benign, false positive), a step confirmed or disputed, records taken
 * out of a story, a story merged into another and a story split in two at a step, each with the
 * analyst's reason.
 *
 * They are overrides of what the engine builds, applied to every build as it comes
 * (applyStoryDecisions): the engine is never asked to build anything else. Each is kept with the
 * anchor a story's note keeps (what the story is about and the findings on its steps,
 * data/stories.ts), so a rebuild that renames a story or changes its id finds it again; a step and a
 * record are kept by the records themselves ({source, id}, which the case bundle renumbers on
 * import), since a rebuild regroups steps but does not renumber records.
 */
import { getDb, type Finding, type Severity } from '../db/schema'
import {
  anchorFit,
  PHASE_LABEL,
  PHASES,
  refRow,
  resolveStoryNotes,
  storyAnchor,
  type Confidence,
  type Identity,
  type ReportStory,
  type Story,
  type StoryAnchor,
  type StoryNotes,
  type StoryPhase,
  type StoryResult,
  type StoryStep,
} from './stories'

export type StoryVerdict = 'open' | 'reviewed' | 'confirmed' | 'benign' | 'false_positive'
export const STORY_VERDICTS: { id: StoryVerdict; label: string }[] = [
  { id: 'open', label: 'open' },
  { id: 'reviewed', label: 'reviewed' },
  { id: 'confirmed', label: 'confirmed incident' },
  { id: 'benign', label: 'benign' },
  { id: 'false_positive', label: 'false positive' },
]
export const STORY_VERDICT_LABEL = Object.fromEntries(STORY_VERDICTS.map((v) => [v.id, v.label])) as Record<StoryVerdict, string>
/** A decision that says the story is not an incident: the report leaves the story out and nothing is merged into it. */
export const dismissed = (v?: StoryVerdict) => v === 'benign' || v === 'false_positive'
/** The decisions that need the analyst's reason: the ones the report acts on. */
export const needsReason = (v: StoryVerdict) => v === 'confirmed' || dismissed(v)

/** A record of the evidence, written as the case bundle renumbers it on import (a chain's seed is written so too). */
export interface RowRef {
  source: 'events' | 'mails'
  id: number
}
interface Reasoned {
  reason: string
  decidedAt: number
}
export interface StoryCall extends Reasoned {
  verdict: StoryVerdict
}
/** A step confirmed (it happened as the story says, and belongs to it as its tie says) or disputed. */
export interface StepCall extends Reasoned {
  verdict: 'confirmed' | 'disputed'
  /** the step's records when it was decided, its first one first */
  rows: RowRef[]
  /** what the step read and when, to name it should a rebuild no longer hold it */
  title: string
  ts: number
}
/** Records the analyst took out of a story: not part of it, whatever a rebuild says. */
export interface RecordsOut extends Reasoned {
  rows: RowRef[]
  title: string
  ts: number
}
/** The story split in two: the steps from the one holding `from` on are a story of their own, with their own decision. */
export interface StorySplit extends Reasoned {
  from: RowRef
  title: string
  ts: number
  call?: StoryCall
}
/** The story merged into another: its steps read as the other story's. */
export interface StoryMerge extends Reasoned {
  /** what the story it went into is about, found again after a rebuild as a note's story is */
  into: StoryAnchor
  /** the two organisations when they differ, as the analyst confirmed them */
  orgs?: string[]
}
export interface StoryDecision {
  /** the story's anchor as it read at the last decision */
  anchor: StoryAnchor
  updatedAt: number
  call?: StoryCall
  steps?: StepCall[]
  out?: RecordsOut[]
  split?: StorySplit
  merge?: StoryMerge
}
export type StoryDecisions = Record<string, StoryDecision>
export const STORY_DECISIONS_KEY = (caseId: number) => `story-decisions-${caseId}`

/** the records a step decision keeps to find its step again, and those a record decision takes out */
const STEP_ROWS = 50
const OUT_ROWS = 5_000

export const refText = (r: RowRef) => `${r.source === 'mails' ? 'mail' : 'event'}:${r.id}`
export function rowsOf(step: Pick<StoryStep, 'refs'>, max: number): RowRef[] {
  return step.refs
    .slice(0, max)
    .map(refRow)
    .filter((r): r is RowRef => !!r)
}

export async function loadStoryDecisions(caseId: number): Promise<StoryDecisions> {
  return ((await getDb().kv.get(STORY_DECISIONS_KEY(caseId)))?.value as StoryDecisions | undefined) ?? {}
}

/** Change the case's story decisions in one transaction, as notes are saved: two tabs deciding at once keep both. */
export async function updateStoryDecisions(caseId: number, change: (all: StoryDecisions) => void): Promise<StoryDecisions> {
  const db = getDb()
  return db.transaction('rw', db.kv, async () => {
    const all: StoryDecisions = { ...(((await db.kv.get(STORY_DECISIONS_KEY(caseId)))?.value as StoryDecisions | undefined) ?? {}) }
    change(all)
    await db.kv.put({ key: STORY_DECISIONS_KEY(caseId), value: all })
    return all
  })
}

const isEmpty = (d: StoryDecision) => !d.call && !d.steps?.length && !d.out?.length && !d.split && !d.merge

/** An engine story and the key of the decision it is decided under (null before its first). */
export interface DecisionSource {
  story: Story
  key: string | null
}

/**
 * Change the decision of an engine story: its entry, or a new one under the story's id, with the
 * story's anchor as it reads now. An entry left with nothing in it is removed.
 */
export function decideStory(caseId: number, target: DecisionSource, identities: Identity[], change: (d: StoryDecision) => void): Promise<StoryDecisions> {
  return updateStoryDecisions(caseId, (all) => {
    // an entry under the story's own id is this story's: a story that kept its id is found by it first
    const key = target.key && all[target.key] ? target.key : target.story.id
    const next: StoryDecision = { ...(all[key] ?? {}), anchor: storyAnchor(target.story, identities), updatedAt: Date.now() }
    change(next)
    if (isEmpty(next)) delete all[key]
    else all[key] = next
  })
}

/** Set a story's decision, or its second part's when it is split; open with no reason clears it. */
export function setCall(d: StoryDecision, part: StoryView['part'], verdict: StoryVerdict, reason: string): void {
  const call = verdict === 'open' && !reason.trim() ? undefined : { verdict, reason: reason.trim(), decidedAt: Date.now() }
  if (part === 'split') {
    if (d.split) d.split = { ...d.split, call }
  } else d.call = call
}

/** Confirm or dispute a step, or take the analyst's call on it back (null): one call per step, the latest. */
export function setStepCall(d: StoryDecision, step: StoryStep, verdict: StepCall['verdict'] | null, reason = ''): void {
  const mine = new Set(step.refs)
  d.steps = (d.steps ?? []).filter((c) => !c.rows.some((r) => mine.has(refText(r))))
  if (verdict) d.steps.push({ verdict, reason: reason.trim(), decidedAt: Date.now(), rows: rowsOf(step, STEP_ROWS), title: step.title, ts: step.ts })
}

/** Take a step call back, found by what it holds (for one whose step a rebuild no longer holds). */
export function dropStepCall(d: StoryDecision, call: StepCall): void {
  const same = (c: StepCall) => c.decidedAt === call.decidedAt && c.title === call.title && c.ts === call.ts
  d.steps = (d.steps ?? []).filter((c) => !same(c))
}

/** Take a step's records out of the story. */
export function takeOut(d: StoryDecision, step: StoryStep, reason: string): void {
  d.out = [...(d.out ?? []), { rows: rowsOf(step, OUT_ROWS), reason: reason.trim(), decidedAt: Date.now(), title: step.title, ts: step.ts }]
}

/** Put records taken out back in their story. */
export function putBack(d: StoryDecision, out: RecordsOut): void {
  d.out = (d.out ?? []).filter((o) => !(o.decidedAt === out.decidedAt && o.title === out.title))
}

/** Split the story at a step: that step and the ones after it are a story of their own. */
export function splitAt(d: StoryDecision, step: StoryStep, reason: string): void {
  const [from] = rowsOf(step, 1)
  if (from) d.split = { from, title: step.title, ts: step.ts, reason: reason.trim(), decidedAt: Date.now() }
}

export function mergeInto(d: StoryDecision, into: StoryAnchor, reason: string, orgs?: string[]): void {
  d.merge = { into, reason: reason.trim(), decidedAt: Date.now(), ...(orgs ? { orgs } : {}) }
}

/**
 * Which story each decision is on: the one that kept its id, else the one that fits its anchor
 * best, as a note finds its story (data/stories.ts anchorFit); each story takes one decision and
 * each decision one story, the best fits first. The others are the decisions whose story is gone.
 */
export function resolveStoryDecisions(stories: Story[], identities: Identity[], decisions: StoryDecisions): { byStory: Map<string, string>; orphans: string[] } {
  const keys = Object.keys(decisions).filter((k) => decisions[k]?.anchor)
  const byStory = new Map<string, string>()
  if (!keys.length) return { byStory, orphans: [] }
  const anchors = stories.map((s) => storyAnchor(s, identities))
  const pairs: { key: string; story: Story; score: number; distance: number }[] = []
  for (const key of keys) {
    const d = decisions[key]
    stories.forEach((story, i) => {
      const score = story.id === key ? 100 : anchorFit(d.anchor, story, anchors[i])
      if (score) pairs.push({ key, story, score, distance: Math.abs(story.start - d.anchor.start) })
    })
  }
  pairs.sort((a, b) => b.score - a.score || a.distance - b.distance || decisions[b.key].updatedAt - decisions[a.key].updatedAt)
  const placed = new Set<string>()
  for (const p of pairs) {
    if (placed.has(p.key) || byStory.has(p.story.id)) continue
    byStory.set(p.story.id, p.key)
    placed.add(p.key)
  }
  return { byStory, orphans: keys.filter((k) => !placed.has(k)) }
}

/** The story an anchor fits best among these, the nearest in time on a tie. */
function bestFit(anchor: StoryAnchor, stories: Story[], identities: Identity[]): Story | null {
  let best: { story: Story; score: number } | null = null
  for (const story of stories) {
    const score = anchorFit(anchor, story, storyAnchor(story, identities))
    if (score && (!best || score > best.score || (score === best.score && Math.abs(story.start - anchor.start) < Math.abs(best.story.start - anchor.start)))) best = { story, score }
  }
  return best?.story ?? null
}

/** Each step call on the step that holds its first record, else on the one that holds most of its records; the latest call on a step wins. */
function matchStepCalls(steps: StoryStep[], calls: StepCall[]): { calls: Map<string, StepCall>; lost: StepCall[] } {
  const where = new Map<string, string>()
  for (const st of steps) for (const r of st.refs) if (!where.has(r)) where.set(r, st.id)
  const out = new Map<string, StepCall>()
  const lost: StepCall[] = []
  for (const c of [...calls].sort((a, b) => a.decidedAt - b.decidedAt)) {
    let id = c.rows.length ? where.get(refText(c.rows[0])) : undefined
    if (!id) {
      const votes = new Map<string, number>()
      for (const r of c.rows) {
        const s = where.get(refText(r))
        if (s) votes.set(s, (votes.get(s) ?? 0) + 1)
      }
      id = [...votes.entries()].sort((a, b) => b[1] - a[1])[0]?.[0]
    }
    if (id) out.set(id, c)
    else lost.push(c)
  }
  return { calls: out, lost }
}

// the engine's weights and names of severities (mirror of stories.SEV_WEIGHT and _SEV_NAME)
const SEV_WEIGHT: Record<string, number> = { critical: 5, high: 4, medium: 2, low: 1, info: 0 }
const SEV_NAME: Record<number, Severity> = { 5: 'critical', 4: 'high', 2: 'medium', 1: 'low', 0: 'info' }
const weight = (s: string | null | undefined) => SEV_WEIGHT[String(s ?? '').toLowerCase()] ?? 0
const PHASE_ORDER = new Map(PHASES.map((p, i) => [p.id, i]))
const topOf = (steps: StoryStep[]) => Math.max(0, ...steps.flatMap((s) => s.findings.map((f) => weight(f.severity))))
const uniq = <T>(xs: T[]) => [...new Set(xs)]

/** The phases of these steps, as the engine states them (mirror of stories._story). */
function phasesOf(steps: StoryStep[]): StoryPhase[] {
  const by = new Map<string, StoryStep[]>()
  for (const s of steps) if (s.phase) by.set(s.phase, [...(by.get(s.phase) ?? []), s])
  return [...by.entries()]
    .map(([phase, ss]) => {
      const top = topOf(ss)
      return {
        phase,
        label: PHASE_LABEL[phase] ?? phase,
        first: Math.min(...ss.map((s) => s.ts)),
        last: Math.max(...ss.map((s) => s.tsEnd)),
        steps: ss.length,
        records: ss.reduce((n, s) => n + s.count, 0),
        findings: new Set(ss.flatMap((s) => s.findings.map((f) => f.key ?? f.ruleId))).size,
        severity: top ? SEV_NAME[top] : null,
      }
    })
    .sort((a, b) => a.first - b.first || (PHASE_ORDER.get(a.phase) ?? 99) - (PHASE_ORDER.get(b.phase) ?? 99))
}

/** A headline and a few sentences from these steps, as the engine writes them (mirror of stories._describe). */
function describe(steps: StoryStep[], phases: StoryPhase[], attacker: string[], hosts: string[], shared: string[]): { headline: string; summary: string } {
  const parts: string[] = []
  for (const p of phases) {
    const cands = steps.filter((s) => s.phase === p.phase && s.findings.length)
    if (!cands.length) continue
    const worst = (s: StoryStep) => Math.max(...s.findings.map((f) => weight(f.severity)))
    const best = cands.reduce((a, b) => (worst(b) > worst(a) || (worst(b) === worst(a) && b.ts < a.ts) ? b : a))
    const f = best.findings.reduce((a, b) => (weight(b.severity) > weight(a.severity) ? b : a))
    const t = f.title || f.ruleId
    if (t && !parts.includes(t)) parts.push(t)
  }
  const headline = parts.length ? parts.slice(0, 4).join(' → ') + (parts.length > 4 ? ` → ${parts.length - 4} more` : '') : 'No phase is flagged'
  const lines: string[] = []
  const first = steps.find((s) => s.tie.kind === 'flag' || s.tie.kind === 'chain') ?? steps[0]
  if (first) lines.push(`It starts with: ${first.title.slice(0, 180)}.`)
  const flagged = steps.filter((s) => s.findings.length)
  if (phases.length) lines.push(`${phases.length} phase${phases.length !== 1 ? 's' : ''}: ${phases.map((p) => p.label.toLowerCase()).join(', ')}.`)
  if (flagged.length) lines.push(`${flagged.length} of its ${steps.length} steps carry findings.`)
  if (attacker.length) lines.push(`The findings name ${[...attacker].sort().slice(0, 3).join(', ')} as a source.`)
  if (shared.length) lines.push(`Most of the organisation's users sign in from ${[...shared].sort().slice(0, 3).join(', ')}, which the findings name: it ties nothing to the story.`)
  if (hosts.length) lines.push(`Hosts: ${hosts.slice(0, 5).join(', ')}${hosts.length > 5 ? ' and more' : ''}.`)
  return { headline: headline.slice(0, 300), summary: lines.join(' ').slice(0, 900) }
}

/** Three techniques or more matched one to one to three phases or more (mirror of stories._three_in_three). */
function threeInThree(firm: { key: string; phase: string }[]): boolean {
  const phasesOf = new Map<string, Set<string>>()
  for (const f of firm) phasesOf.set(f.key, (phasesOf.get(f.key) ?? new Set()).add(f.phase))
  const owner = new Map<string, string>()
  const assign = (key: string, tried: Set<string>): boolean => {
    for (const p of [...(phasesOf.get(key) ?? [])].sort()) {
      if (tried.has(p)) continue
      tried.add(p)
      const had = owner.get(p)
      if (had === undefined || assign(had, tried)) {
        owner.set(p, key)
        return true
      }
    }
    return false
  }
  return [...phasesOf.keys()].sort().filter((key) => assign(key, new Set())).length >= 3
}

const byIdOnce = <T extends { id: string }>(xs: T[]) => [...new Map(xs.map((x) => [x.id, x])).values()]

/**
 * A story as the page shows it once the analyst's decisions apply to these steps: its phases, its
 * severity, its headline and its findings read from the steps that are not disputed, as the engine
 * reads them from all of them (mirror of stories._story); a step the analyst confirmed counts as a
 * strong tie. The score stays the engine's (the highest of merged stories).
 */
function restate(base: Story, steps: StoryStep[], calls: Map<string, StepCall>, merged: Story[], id = base.id): Story {
  const all = [base, ...merged]
  const kept = steps.filter((s) => calls.get(s.id)?.verdict !== 'disputed')
  const phases = phasesOf(kept)
  let severity = SEV_NAME[topOf(kept)] ?? 'low'
  // three techniques in three phases, each with a finding of medium or more from a rule that can be
  // believed, is an intrusion however each rule reads alone (a story built before the engine said
  // which findings those are falls back on three phases with a finding of medium or more)
  const keptIds = new Set(kept.map((s) => s.id))
  const raises = all.every((s) => s.firm) ? threeInThree(all.flatMap((s) => s.firm ?? []).filter((f) => keptIds.has(f.step))) : phases.filter((p) => weight(p.severity) >= 2).length >= 3
  if (raises && weight(severity) < 4) severity = 'high'
  const flags = kept.filter((s) => s.tie.kind === 'flag' || s.tie.kind === 'chain')
  const confidence: Confidence = flags.every((s) => s.tie.confidence === 'strong' || calls.get(s.id)?.verdict === 'confirmed') ? 'strong' : 'medium'
  const hosts = uniq(steps.map((s) => s.host).filter((h): h is string => !!h)).sort()
  const attacker = uniq(all.flatMap((s) => s.attackerAddresses)).sort()
  const shared = uniq(all.flatMap((s) => s.sharedAddresses ?? [])).sort()
  const { headline, summary } = describe(kept, phases, attacker, hosts, shared)
  return {
    ...base,
    id,
    headline,
    summary,
    start: steps.length ? Math.min(...steps.map((s) => s.ts)) : base.start,
    end: steps.length ? Math.max(...steps.map((s) => s.tsEnd)) : base.end,
    severity,
    score: Math.max(...all.map((s) => s.score)),
    confidence,
    phases,
    steps,
    records: steps.reduce((n, s) => n + s.refs.length, 0),
    hosts,
    accounts: uniq(steps.flatMap((s) => s.accounts)).sort(),
    ips: uniq(steps.map((s) => s.ip).filter((ip): ip is string => !!ip)).sort(),
    attackerAddresses: attacker,
    sharedAddresses: shared,
    chains: uniq(all.flatMap((s) => s.chains)),
    findings: uniq(kept.flatMap((s) => s.findings.map((f) => f.key ?? f.ruleId))).sort(),
    campaigns: uniq(all.flatMap((s) => s.campaigns)),
    gaps: uniq(all.flatMap((s) => s.gaps)),
    lineage: merged.length
      ? {
          sessions: byIdOnce(all.flatMap((s) => s.lineage.sessions)),
          hops: byIdOnce(all.flatMap((s) => s.lineage.hops)),
          processes: byIdOnce(all.flatMap((s) => s.lineage.processes)),
          devices: [...new Map(all.flatMap((s) => s.lineage.devices ?? []).map((d) => [d.key, d])).values()],
        }
      : base.lineage,
  }
}

/** A story as the page shows it, with the decisions that shaped it. */
export interface StoryView {
  /** the story as shown: the engine's, or restated from the steps the decisions leave */
  story: Story
  /** the engine's story it is built on (the one others were merged into, the one that was split) */
  base: Story
  /** the key of the decision it is decided under, null before its first */
  key: string | null
  /** a whole story (or the first part of a split one), or the second part of a split */
  part: 'story' | 'split'
  entry?: StoryDecision
  /** the decision on this story (or on this part) */
  call?: StoryCall
  /** the analyst's call on each step shown, by step id */
  steps: Map<string, StepCall>
  /** step calls whose step this build no longer holds, with the story whose decision holds them */
  lostSteps: { call: StepCall; source: DecisionSource }[]
  /** the records taken out of it, with how many of them the engine's story held this build */
  out: { out: RecordsOut; found: number; source: DecisionSource }[]
  /** the stories merged into it */
  merged: { story: Story; key: string; merge: StoryMerge }[]
  /** its split, and whether this build could apply it (its step is still in the story, and not first) */
  split?: StorySplit & { applied: boolean }
  /** its merge into a story this build no longer holds */
  mergeLost?: StoryMerge
  /** the engine's stories whose steps it shows, each with the key of its decision: a step's decision goes to the story that holds it */
  sources: DecisionSource[]
}

export interface DecidedStories {
  views: StoryView[]
  /** each view by its story's id, and by the id of each engine story merged into it */
  byId: Map<string, StoryView>
  /** the decisions whose story this build no longer holds */
  orphans: { key: string; entry: StoryDecision }[]
}

/** The id of the second part of a split story. */
export const splitId = (id: string) => `${id}~2`

/**
 * The stories of a build with the analyst's decisions applied, in the build's order: records taken
 * out, steps confirmed and disputed, merged stories read as one (the story merged into keeps its
 * place), split stories as two parts in a row.
 */
export function applyStoryDecisions(res: StoryResult | null, decisions: StoryDecisions): DecidedStories {
  const stories = res?.stories ?? []
  const identities = res?.identities ?? []
  const { byStory, orphans } = resolveStoryDecisions(stories, identities, decisions)
  interface Prep {
    story: Story
    key: string | null
    entry?: StoryDecision
    steps: StoryStep[]
    calls: Map<string, StepCall>
    lost: StoryView['lostSteps']
    out: StoryView['out']
  }
  const prep = new Map<string, Prep>()
  for (const s of stories) {
    const key = byStory.get(s.id) ?? null
    const entry = key ? decisions[key] : undefined
    let steps = s.steps
    const out: StoryView['out'] = []
    if (entry?.out?.length) {
      const held = new Set(s.steps.flatMap((st) => st.refs))
      const gone = new Set<string>()
      for (const o of entry.out) {
        const refs = o.rows.map(refText)
        refs.forEach((r) => gone.add(r))
        out.push({ out: o, found: refs.filter((r) => held.has(r)).length, source: { story: s, key } })
      }
      steps = s.steps.flatMap((st) => {
        const refs = st.refs.filter((r) => !gone.has(r))
        if (refs.length === st.refs.length) return [st]
        return refs.length ? [{ ...st, refs, count: Math.max(refs.length, st.count - (st.refs.length - refs.length)) }] : []
      })
    }
    const { calls, lost } = matchStepCalls(steps, entry?.steps ?? [])
    prep.set(s.id, { story: s, key, entry, steps, calls, lost: lost.map((call) => ({ call, source: { story: s, key } })), out })
  }
  // where each merged story goes: the story its target's anchor fits, followed through merges of merges
  const into = new Map<string, string>()
  const lostMerge = new Set<string>()
  for (const p of prep.values()) {
    if (!p.entry?.merge) continue
    const target = bestFit(
      p.entry.merge.into,
      stories.filter((s) => s.id !== p.story.id),
      identities,
    )
    if (target) into.set(p.story.id, target.id)
    else lostMerge.add(p.story.id)
  }
  const root = (id: string) => {
    const seen = new Set([id])
    let cur = id
    while (into.has(cur)) {
      cur = into.get(cur)!
      if (seen.has(cur)) return id // a loop merges nothing
      seen.add(cur)
    }
    return cur
  }
  const members = new Map<string, Prep[]>()
  for (const p of prep.values()) {
    const r = root(p.story.id)
    if (r !== p.story.id) members.set(r, [...(members.get(r) ?? []), p])
  }
  const views: StoryView[] = []
  const byId = new Map<string, StoryView>()
  for (const s of stories) {
    if (root(s.id) !== s.id) continue
    const p = prep.get(s.id)!
    const merged = members.get(s.id) ?? []
    let steps = [...p.steps]
    if (merged.length) {
      const seen = new Set(steps.map((x) => x.id))
      for (const m of merged)
        for (const st of m.steps) {
          if (seen.has(st.id)) continue
          seen.add(st.id)
          steps.push(st)
        }
      steps = steps.sort((a, b) => a.ts - b.ts || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    }
    const calls = new Map([...p.calls, ...merged.flatMap((m) => [...m.calls])])
    const split = p.entry?.split
    const at = split ? steps.findIndex((st) => st.refs.includes(refText(split.from))) : -1
    const parts = at > 0 ? [steps.slice(0, at), steps.slice(at)] : [steps]
    const sources: DecisionSource[] = [{ story: s, key: p.key }, ...merged.map((m) => ({ story: m.story, key: m.key }))]
    const common = {
      base: s,
      key: p.key,
      entry: p.entry,
      sources,
      split: split ? { ...split, applied: at > 0 } : undefined,
    }
    parts.forEach((partSteps, i) => {
      const mine = new Map([...calls].filter(([id]) => partSteps.some((st) => st.id === id)))
      const changed = merged.length > 0 || parts.length > 1 || p.out.length > 0 || [...mine.values()].some((c) => c.verdict === 'disputed')
      const story = changed
        ? restate(
            s,
            partSteps,
            mine,
            merged.map((m) => m.story),
            i ? splitId(s.id) : s.id,
          )
        : mine.size
          ? { ...s, confidence: restate(s, partSteps, mine, []).confidence }
          : s
      const view: StoryView = i
        ? { ...common, story, part: 'split', call: split?.call, steps: mine, lostSteps: [], out: [], merged: [] }
        : {
            ...common,
            story,
            part: 'story',
            call: p.entry?.call,
            steps: mine,
            lostSteps: [...p.lost, ...merged.flatMap((m) => m.lost)],
            out: [...p.out, ...merged.flatMap((m) => m.out)],
            merged: merged.map((m) => ({ story: m.story, key: m.key!, merge: m.entry!.merge! })),
            mergeLost: lostMerge.has(s.id) ? p.entry?.merge : undefined,
          }
      views.push(view)
      byId.set(story.id, view)
      if (!i) for (const m of merged) byId.set(m.story.id, view)
    })
  }
  return { views, byId, orphans: orphans.map((key) => ({ key, entry: decisions[key] })) }
}

/** Whether a story may be merged into another, and whether the two are of different organisations (the page asks first). */
export function mergeCheck(source: StoryView, target: StoryView): { ok: boolean; why?: string; orgs?: string[] } {
  if (source.base.id === target.base.id) return { ok: false, why: 'A story is not merged into itself.' }
  if (source.part === 'split' || target.part === 'split') return { ok: false, why: 'The second part of a split story is not merged: undo the split first.' }
  if (source.split) return { ok: false, why: 'A story split in two is not merged: undo the split first.' }
  if (dismissed(target.call?.verdict))
    return {
      ok: false,
      why: `The story of ${target.story.title} is decided ${STORY_VERDICT_LABEL[target.call!.verdict]}: nothing is merged into a dismissed story. Change its decision first.`,
    }
  const a = source.story.subject.org
  const b = target.story.subject.org
  if (a && b && a.toLowerCase() !== b.toLowerCase()) return { ok: true, orgs: [a, b] }
  return { ok: true }
}

/** Put a decision whose story is gone on another story: its anchor becomes that story's, and what the story's own decision holds stays first. */
export function attachStoryDecision(caseId: number, orphan: string, target: DecisionSource, identities: Identity[]): Promise<StoryDecisions> {
  return updateStoryDecisions(caseId, (all) => {
    const moved = all[orphan]
    if (!moved) return
    const into = target.key && target.key !== orphan ? all[target.key] : undefined
    const key = into ? target.key! : orphan
    all[key] = {
      anchor: storyAnchor(target.story, identities),
      updatedAt: Date.now(),
      call: into?.call ?? moved.call,
      steps: [...(moved.steps ?? []), ...(into?.steps ?? [])],
      out: [...(into?.out ?? []), ...(moved.out ?? [])],
      split: into?.split ?? moved.split,
      merge: into?.merge ?? moved.merge,
    }
    if (key !== orphan) delete all[orphan]
  })
}

export function deleteStoryDecision(caseId: number, key: string): Promise<StoryDecisions> {
  return updateStoryDecisions(caseId, (all) => {
    delete all[key]
  })
}

/** How many decisions shape a view (the count on its Decisions tab). */
export function decisionCount(view: StoryView): number {
  return (view.call && view.call.verdict !== 'open' ? 1 : 0) + view.steps.size + view.lostSteps.length + view.out.length + view.merged.length + (view.split ? 1 : 0) + (view.mergeLost ? 1 : 0)
}

/** What a decision whose story is gone holds, in words. */
export function decisionSummary(d: StoryDecision): string {
  return [
    d.call ? STORY_VERDICT_LABEL[d.call.verdict] : '',
    d.steps?.length ? `${d.steps.length} step decision${d.steps.length === 1 ? '' : 's'}` : '',
    d.out?.length ? `${d.out.length} group${d.out.length === 1 ? '' : 's'} of records taken out` : '',
    d.split ? 'split in two' : '',
    d.merge ? `merged into ${d.merge.into.title}` : '',
  ]
    .filter(Boolean)
    .join(' · ')
}

// ---------------------------------------------------------------------------
// the report
// ---------------------------------------------------------------------------

/** What the report prints of the decisions on a story. */
export interface ReportStoryDecisions {
  call?: StoryCall
  /** which part of a split story it is */
  part?: 'first' | 'second'
  split?: { title: string; ts: number; reason: string }
  merged: { title: string; reason: string; orgs?: string[] }[]
  out: { title: string; count: number; reason: string }[]
  /** the disputed steps, left out of its phases and severity */
  disputed: { id: string; title: string; ts: number; reason: string }[]
  confirmedSteps: number
}

/** A decided story as the report's verdict reads it (data/reportHtml.ts computeVerdict). */
export interface DecidedStory {
  title: string
  verdict: Exclude<StoryVerdict, 'open'>
  reason: string
  /** its severity as the page shows it (disputed steps left out) */
  severity: Severity
  start: number
  end: number
  hosts: string[]
  /** the case's findings on its steps that are not disputed, false positives left out */
  findings: Finding[]
  /** whether the report prints it */
  printed: boolean
}

function reportDecisions(v: StoryView): ReportStoryDecisions | undefined {
  const disputed = v.story.steps.filter((s) => v.steps.get(s.id)?.verdict === 'disputed').map((s) => ({ id: s.id, title: s.title, ts: s.ts, reason: v.steps.get(s.id)!.reason }))
  const confirmedSteps = [...v.steps.values()].filter((c) => c.verdict === 'confirmed').length
  const out: ReportStoryDecisions = {
    call: v.call && v.call.verdict !== 'open' ? v.call : undefined,
    part: v.split?.applied ? (v.part === 'split' ? 'second' : 'first') : undefined,
    split: v.split?.applied ? { title: v.split.title, ts: v.split.ts, reason: v.split.reason } : undefined,
    merged: v.merged.map((m) => ({ title: m.story.title, reason: m.merge.reason, orgs: m.merge.orgs })),
    out: v.out.filter((o) => o.found).map((o) => ({ title: o.out.title, count: o.found, reason: o.out.reason })),
    disputed,
    confirmedSteps,
  }
  return out.call || out.split || out.merged.length || out.out.length || disputed.length || confirmedSteps ? out : undefined
}

const SEV_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

export interface StoriesForReport {
  stories: ReportStory[]
  /** the stories not printed and not dismissed: below the floor, undecided without a note when only reviewed items print, past `max` */
  left: number
  /** notes whose story is gone */
  orphans: number
  /** the stories decided benign or false positive: the report leaves them out */
  dismissed: number
  /** every decided story of the case, printed or not, for the verdict */
  decided: DecidedStory[]
  /** decisions whose story is gone */
  decisionsOrphaned: number
}

/**
 * The stories a report prints, with the analyst's decisions applied: those not decided benign or
 * false positive, at or above its severity floor (with a note or a decision, when it prints reviewed
 * items only), the highest-scoring first, at most `max`. A story's note is found on the engine's
 * story, so a split keeps it on the first part and a merge prints the merged story's note too.
 */
export function storiesForReport(res: StoryResult | null, notes: StoryNotes, decisions: StoryDecisions, findings: Finding[], floor: Severity, onlyReviewed = false, max = 20): StoriesForReport {
  const decided = applyStoryDecisions(res, decisions)
  const { byStory: noteOf, orphans } = resolveStoryNotes(res?.stories ?? [], res?.identities ?? [], notes)
  const rows = decided.views.map((view) => {
    const own = view.part === 'story' ? noteOf.get(view.base.id) : undefined
    const others = view.part === 'story' ? view.merged.flatMap((m) => (noteOf.has(m.story.id) ? [{ title: m.story.title, on: noteOf.get(m.story.id)! }] : [])) : []
    const texts = [own?.note.text.trim(), ...others.map((o) => `On the story of ${o.title}, merged into this one: ${o.on.note.text.trim()}`)].filter(Boolean)
    return { view, key: own?.key ?? others[0]?.on.key ?? view.story.id, note: texts.join('\n\n') || undefined }
  })
  const out = rows.filter((r) => dismissed(r.view.call?.verdict)).length
  const picked = rows
    .filter((r) => !dismissed(r.view.call?.verdict))
    .filter((r) => (SEV_RANK[r.view.story.severity] ?? 0) >= (SEV_RANK[floor] ?? 0) && (!onlyReviewed || r.note || (r.view.call && r.view.call.verdict !== 'open')))
    .sort((a, b) => b.view.story.score - a.view.story.score || a.view.story.start - b.view.story.start)
    .slice(0, max)
  const printed = new Set(picked.map((r) => r.view))
  const byKey = new Map(findings.map((f) => [f.key, f]))
  return {
    stories: picked.map((r) => ({ story: r.view.story, key: r.key, note: r.note, decisions: reportDecisions(r.view) })),
    left: rows.length - picked.length - out,
    orphans: orphans.length,
    dismissed: out,
    decided: decided.views
      .filter((v) => v.call && v.call.verdict !== 'open')
      .map((v) => ({
        title: v.part === 'split' ? `${v.story.title} (second part)` : v.story.title,
        verdict: v.call!.verdict as DecidedStory['verdict'],
        reason: v.call!.reason,
        severity: v.story.severity,
        start: v.story.start,
        end: v.story.end,
        hosts: v.story.hosts,
        findings: v.story.findings.map((k) => byKey.get(k)).filter((f): f is Finding => !!f && f.status !== 'false_positive'),
        printed: printed.has(v),
      })),
    decisionsOrphaned: decided.orphans.length,
  }
}
