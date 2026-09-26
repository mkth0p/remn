/**
 * The case's detection level: which findings the rules raise, from fewest false positives (1) to
 * every finding (5). A level is a budget of findings per clean machine. Each rule's noise is what
 * its measure says it raised on the clean Windows machines of evtx-baseline, per machine that logs
 * what it reads (rules/measures.json), and a finding is raised when that noise fits the budget of
 * its severity: the budget doubles with each severity step, so a critical finding may come from a
 * rule four times noisier than a medium one. Level 4 also raises every medium and higher finding
 * whatever its rule's noise, as REMN did before levels, so it detects at least what that did. A rule no clean machine could measure (mail, Microsoft
 * 365, other products' logs, a rule changed since it was measured) raises its findings from medium
 * up below the last level, as every rule did before levels; the analyst's own rules are always
 * raised.
 *
 * The levels were chosen and measured on 2026-09-26 with every rule's findings on every recording
 * and clean machine the rule measure uses. The noise of each clean machine was counted with the
 * rules' noise taken from the six other machines, so the figures below are held out for noise; the
 * levels never read the attack libraries, so they are held out for detection too
 * (docs/detection.md#detection-level).
 */
import type { Severity } from '../db/schema'
import type { RuleMeasure } from './ruleMeasures'
import { fmtNum } from '../util/format'

export type DetectionLevel = 1 | 2 | 3 | 4 | 5

/** A new case's level. */
export const DEFAULT_DETECTION_LEVEL: DetectionLevel = 3
/** A case created before there were levels raised every finding, and keeps doing so until it is set. */
export const LEGACY_DETECTION_LEVEL: DetectionLevel = 5
/** The severity floor of a rule no clean machine could measure, below the last level: medium. */
export const UNMEASURED_FLOOR = 2

export interface LevelInfo {
  level: DetectionLevel
  label: string
  /** findings per clean machine a medium rule may raise; doubled per severity step above, halved below */
  budget: number
  /** a severity rank raised whatever its rule's noise (level 4 raises every medium and higher finding) */
  always?: number
  /** in a sentence, what the level raises */
  text: string
  /** measured: recordings detected (a finding of the recording's technique) and findings per clean machine */
  measured: { attackData: number; evtxToMitre: number; attackSamples: number; perCleanMachine: number }
}

export const MEASURED_ON = { attackData: 535, evtxToMitre: 279, attackSamples: 278, cleanMachines: 7, date: '2026-09-26' }

export const DETECTION_LEVELS: LevelInfo[] = [
  {
    level: 1,
    label: 'fewest false positives',
    budget: 0.1,
    text: 'Only rules that stayed silent on the clean machines that log what they read.',
    measured: { attackData: 222, evtxToMitre: 91, attackSamples: 227, perCleanMachine: 11 },
  },
  {
    level: 2,
    label: 'quiet',
    budget: 0.5,
    text: 'Adds rules that fired a few times across all the clean machines.',
    measured: { attackData: 231, evtxToMitre: 100, attackSamples: 253, perCleanMachine: 40 },
  },
  {
    level: 3,
    label: 'balanced',
    budget: 5,
    text: 'Rules that fire up to a few times per clean machine at medium, more at high and critical, and low findings of rules quiet there.',
    measured: { attackData: 239, evtxToMitre: 114, attackSamples: 265, perCleanMachine: 164 },
  },
  {
    level: 4,
    label: 'broad',
    budget: 5,
    always: 2,
    text: 'Every medium and higher finding, as before levels, and the low findings of rules quiet on the clean machines.',
    measured: { attackData: 248, evtxToMitre: 118, attackSamples: 266, perCleanMachine: 314 },
  },
  {
    level: 5,
    label: 'every finding',
    budget: Infinity,
    text: 'Every finding of every enabled rule, low and informational included.',
    measured: { attackData: 249, evtxToMitre: 123, attackSamples: 266, perCleanMachine: 587 },
  },
]

/** Raising every medium and higher finding, as REMN did before levels (measured the same way, with the rule levels of 2026-09-26). */
export const BEFORE_LEVELS = { attackData: 245, evtxToMitre: 112, attackSamples: 264, perCleanMachine: 241 }

const RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }
/** No severity of the rule is raised. */
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

/** Whether a rule can raise anything at the level. */
export function ruleRaises(r: LevelRule, floors: Record<string, number>): boolean {
  return (floors[r.rule.id] ?? 0) <= RANK[ruleTopSeverity(r.rule)]
}

/** Whether a finding is raised under these floors (a rule without a floor keeps all). */
export function raised(f: { ruleId?: unknown; severity?: unknown }, floors: Record<string, number> | undefined): boolean {
  if (!floors) return true
  const floor = floors[String(f.ruleId ?? '')]
  return floor == null || severityRank(f.severity) >= floor
}

const pct = (n: number, of: number) => `${Math.round((n / of) * 100)}%`

/** What a level detected and cost when it was measured, in a sentence. */
export function levelMeasured(level: DetectionLevel): string {
  const m = levelInfo(level).measured
  return `Detected ${pct(m.attackData, MEASURED_ON.attackData)}, ${pct(m.evtxToMitre, MEASURED_ON.evtxToMitre)} and ${pct(m.attackSamples, MEASURED_ON.attackSamples)} of the attack_data, EVTX-to-MITRE-Attack and EVTX-ATTACK-SAMPLES recordings, with about ${fmtNum(m.perCleanMachine)} findings per clean machine (every medium and higher finding: ${fmtNum(BEFORE_LEVELS.perCleanMachine)}).`
}
