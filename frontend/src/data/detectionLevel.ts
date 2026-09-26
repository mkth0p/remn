/**
 * The case's detection level: which findings stand on their own in the queue, from the fewest lines
 * (1) to every finding on its own (5). No level drops a finding: a finding below its rule's floor
 * is folded with the other findings of its rule on the same host into one, so every level detects
 * what the rules detect and the level only decides how many lines the analyst reads.
 *
 * A level is a budget of findings per clean machine. Each rule's noise is what its measure says it
 * raised on the clean Windows machines of evtx-baseline, per machine that logs what it reads
 * (rules/measures.json), and a finding stands on its own when that noise fits the budget of its
 * severity: the budget doubles with each severity step, so a critical finding may come from a rule
 * four times noisier than a medium one. Level 4 also keeps every medium and higher finding on its
 * own, as REMN raised them before levels. A rule no clean machine could measure (mail, Microsoft
 * 365, other products' logs, a rule changed since it was measured) keeps its findings from medium
 * up on their own below the last level; the analyst's own rules are never folded.
 *
 * The levels were chosen and measured on 2026-09-26 with every rule's findings on every recording
 * and clean machine the rule measure uses. The lines of each clean machine were counted with the
 * rules' noise taken from the six other machines, so the figures below are held out for noise; the
 * levels never read the attack libraries, so they are held out for detection too
 * (docs/detection.md#detection-level).
 */
import type { Finding, Severity } from '../db/schema'
import type { RuleMeasure } from './ruleMeasures'
import { fmtNum } from '../util/format'

export type DetectionLevel = 1 | 2 | 3 | 4 | 5

/** A new case's level. */
export const DEFAULT_DETECTION_LEVEL: DetectionLevel = 2
/** A case created before there were levels keeps every finding on its own until its level is set. */
export const LEGACY_DETECTION_LEVEL: DetectionLevel = 5
/** The severity floor of a rule no clean machine could measure, below the last level: medium. */
export const UNMEASURED_FLOOR = 2

export interface LevelInfo {
  level: DetectionLevel
  label: string
  /** findings per clean machine a medium rule may raise; doubled per severity step above, halved below */
  budget: number
  /** a severity rank kept on its own whatever its rule's noise (level 4 keeps every medium and higher finding) */
  always?: number
  /** in a sentence, what the level keeps on its own */
  text: string
  /** measured, per clean machine: findings on their own, and lines (those plus one per rule and host folded) */
  measured: { alone: number; perCleanMachine: number }
}

export const MEASURED_ON = { attackData: 535, evtxToMitre: 279, attackSamples: 278, cleanMachines: 7, date: '2026-09-26' }

/** What every level detects, since none drops a finding: recordings with a finding of their technique. */
export const DETECTED = { attackData: 249, evtxToMitre: 123, attackSamples: 266 }

export const DETECTION_LEVELS: LevelInfo[] = [
  {
    level: 1,
    label: 'compact',
    budget: 0.1,
    text: 'Only rules that stayed silent on the clean machines raise findings on their own; the findings of every other rule are folded into one per host.',
    measured: { alone: 11, perCleanMachine: 73 },
  },
  {
    level: 2,
    label: 'balanced',
    budget: 0.5,
    text: 'Also rules that fired a few times across all the clean machines.',
    measured: { alone: 40, perCleanMachine: 92 },
  },
  {
    level: 3,
    label: 'detailed',
    budget: 5,
    text: 'Also rules that fire up to a few times per clean machine at medium, more at high and critical.',
    measured: { alone: 164, perCleanMachine: 186 },
  },
  {
    level: 4,
    label: 'broad',
    budget: 5,
    always: 2,
    text: 'Every medium and higher finding on its own, as before levels, and the low findings of rules quiet on the clean machines.',
    measured: { alone: 314, perCleanMachine: 330 },
  },
  {
    level: 5,
    label: 'every finding',
    budget: Infinity,
    text: 'Every finding of every enabled rule on its own, low and informational included; nothing is folded.',
    measured: { alone: 587, perCleanMachine: 587 },
  },
]

/** Raising every medium and higher finding and nothing else, the measure's reference before levels (measured the same way, with the rule levels of 2026-09-26). */
export const BEFORE_LEVELS = { attackData: 245, evtxToMitre: 112, attackSamples: 264, perCleanMachine: 241 }

const RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }
/** No severity of the rule stands on its own. */
export const NEVER = 5

export function levelInfo(level: number | undefined): LevelInfo {
  return DETECTION_LEVELS.find((l) => l.level === level) ?? DETECTION_LEVELS[LEGACY_DETECTION_LEVEL - 1]
}

/** A case's level: the one it was given, or every finding for a case from before levels. */
export function caseLevel(settings: { detectionLevel?: number } | undefined): DetectionLevel {
  const l = settings?.detectionLevel
  return l === 1 || l === 2 || l === 3 || l === 4 || l === 5 ? l : LEGACY_DETECTION_LEVEL
}

/** Findings per clean machine that logs what the rule reads, half a finding added so a rule silent on one machine is not taken as silent on all; null when no clean machine measured it. */
export function ruleNoise(m: RuleMeasure | undefined): number | null {
  if (!m || m.changed || m.settings?.length || !m.clean?.of) return null
  return (m.clean.findings + 0.5) / m.clean.of
}

/** The lowest severity rank (0 info to 4 critical) whose findings the level raises, NEVER when none. */
export function severityFloor(level: DetectionLevel, noise: number | null, origin?: 'bundled' | 'pack' | 'custom'): number {
  const { budget, always = NEVER } = levelInfo(level)
  if (origin === 'custom' || budget === Infinity) return 0
  if (noise == null) return Math.min(UNMEASURED_FLOOR, always)
  const s = Math.max(0, Math.ceil(2 + Math.log2(noise / budget) - 1e-9))
  return Math.min(s > 4 ? NEVER : s, always)
}

export const severityRank = (s: unknown): number => RANK[String(s ?? '').toLowerCase() as Severity] ?? RANK.medium

/** The lowest level that raises a finding of this severity from a rule of this noise. */
export function lowestLevel(severity: Severity, noise: number | null, origin?: 'bundled' | 'pack' | 'custom'): DetectionLevel {
  for (const l of DETECTION_LEVELS) if (severityFloor(l.level, noise, origin) <= RANK[severity]) return l.level
  return 5
}

/** The highest severity a rule's findings can carry: its own, or its follow-up's. */
export function ruleTopSeverity(rule: { severity: Severity; then?: { severity?: Severity } }): Severity {
  const t = rule.then?.severity
  return t && RANK[t] > RANK[rule.severity] ? t : rule.severity
}

export interface LevelRule {
  rule: { id: string; severity: Severity; then?: { severity?: Severity } }
  origin: 'bundled' | 'pack' | 'custom'
  measured?: RuleMeasure
}

/**
 * Each rule's severity floor at the level, by rule id: a run keeps the findings of a rule at or
 * above its floor; a rule whose floor is above its highest severity need not run at all.
 */
export function severityFloors(rules: LevelRule[], level: DetectionLevel): Record<string, number> {
  const out: Record<string, number> = {}
  for (const r of rules) out[r.rule.id] = severityFloor(level, ruleNoise(r.measured), r.origin)
  return out
}

/** Whether any finding of the rule can stand on its own at the level. */
export function ruleRaises(r: LevelRule, floors: Record<string, number>): boolean {
  return (floors[r.rule.id] ?? 0) <= RANK[ruleTopSeverity(r.rule)]
}

/** Whether a finding stands on its own under these floors (a rule without a floor keeps all). */
export function raised(f: { ruleId?: unknown; severity?: unknown }, floors: Record<string, number> | undefined): boolean {
  if (!floors) return true
  const floor = floors[String(f.ruleId ?? '')]
  return floor == null || severityRank(f.severity) >= floor
}

const pct = (n: number, of: number) => `${Math.round((n / of) * 100)}%`

/** What a level detected and cost when it was measured, in a sentence. */
export function levelMeasured(level: DetectionLevel): string {
  const m = levelInfo(level).measured
  return `Every level detected ${pct(DETECTED.attackData, MEASURED_ON.attackData)}, ${pct(DETECTED.evtxToMitre, MEASURED_ON.evtxToMitre)} and ${pct(DETECTED.attackSamples, MEASURED_ON.attackSamples)} of the attack_data, EVTX-to-MITRE-Attack and EVTX-ATTACK-SAMPLES recordings (every medium and higher finding: ${pct(BEFORE_LEVELS.attackData, MEASURED_ON.attackData)}, ${pct(BEFORE_LEVELS.evtxToMitre, MEASURED_ON.evtxToMitre)} and ${pct(BEFORE_LEVELS.attackSamples, MEASURED_ON.attackSamples)}). This one gave about ${fmtNum(m.perCleanMachine)} lines per clean machine, ${fmtNum(m.alone)} of them findings on their own (every medium and higher finding: ${fmtNum(BEFORE_LEVELS.perCleanMachine)}).`
}

const MAX_FOLDED_REFS = 5000

/** The host a finding is about, for folding: its computer, host or workstation, lowercased. */
const foldHost = (f: Pick<Finding, 'entities'>) => String(f.entities?.computer || f.entities?.host || f.entities?.workstation || '').toLowerCase()

/**
 * Fold the findings below their rule's floor: the findings of one rule on one host become one,
 * led by the most severe (then the earliest), with their count, time span and the rows they cite
 * (up to 5,000), and `folded` set to how many it stands for. A finding `keep` says so stays on its
 * own (one an analyst decided on). Findings at or above the floor are returned as they are.
 */
export function foldBelowLevel<F extends Finding>(findings: F[], floors: Record<string, number> | undefined, keep: (f: F) => boolean = () => false): F[] {
  if (!floors) return findings
  const out: F[] = []
  const groups = new Map<string, F[]>()
  for (const f of findings) {
    if (raised(f, floors) || keep(f)) out.push(f)
    else {
      const k = `${f.ruleId}\u0000${foldHost(f)}`
      const g = groups.get(k)
      if (g) g.push(f)
      else groups.set(k, [f])
    }
  }
  for (const g of groups.values()) {
    const lead = g.reduce((a, b) => (severityRank(b.severity) > severityRank(a.severity) || (severityRank(b.severity) === severityRank(a.severity) && (b.ts ?? Infinity) < (a.ts ?? Infinity)) ? b : a))
    if (g.length === 1) {
      out.push({ ...lead, folded: 1 })
      continue
    }
    const host = foldHost(lead)
    let first: number | null = null
    let last: number | null = null
    for (const f of g) {
      if (f.ts != null && (first == null || f.ts < first)) first = f.ts
      const end = f.tsEnd ?? f.ts
      if (end != null && (last == null || end > last)) last = end
    }
    const refs: number[] = []
    const recordKeys: string[] = []
    const withKeys = g.every((f) => Array.isArray(f.recordKeys))
    for (const f of g) {
      for (let i = 0; i < (f.refs?.length ?? 0) && refs.length < MAX_FOLDED_REFS; i++) {
        refs.push(f.refs[i])
        if (withKeys) recordKeys.push(f.recordKeys![i] ?? '')
      }
    }
    out.push({
      ...lead,
      key: `${lead.ruleId}|folded|${host}`,
      title: `${lead.title} (${fmtNum(g.length)} findings${host ? ` on ${host}` : ''}, folded at this detection level)`,
      count: g.reduce((n, f) => n + (f.count || 1), 0),
      ts: first ?? lead.ts,
      tsEnd: last ?? lead.tsEnd ?? null,
      refs,
      ...(withKeys ? { recordKeys } : {}),
      folded: g.length,
    })
  }
  return out
}
