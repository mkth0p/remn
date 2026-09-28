/**
 * What the home page quotes. The rule measures come from the server (rules/measures.json, through
 * /api/meta) so they follow every measurement; the comparisons below are the dated results of the
 * reviews in docs/reviews and docs/validation.md, copied as they were published.
 */
import type { Meta } from '../api/client'
import type { MeasureSources } from './ruleMeasures'
import measuredLibraries from './libraryMeasures.json'

/** docs/reviews/2026-09-25-head-to-head.md: the three tools on a library none of their rules were written against. */
export const HEAD_TO_HEAD = {
  date: '2026-09-25',
  library: { name: 'EVTX-to-MITRE-Attack', sha: '4748560', files: 279, events: 12_812 },
  tools: ['REMN', 'Hayabusa', 'Chainsaw'] as const,
  /** files detected, by lowest level counted: REMN default rules, Hayabusa every rule, Chainsaw SigmaHQ with hunting and its own rules */
  detected: { info: [123, 106, 70], medium: [109, 86, 52], high: [80, 55, 32] } as Record<'info' | 'medium' | 'high', [number, number, number]>,
  /** medium and above, scored on the techniques the rules' authors tagged, without the title map */
  authorTags: [101, 74, 45] as [number, number, number],
  /** medium and above, detected by at least one of the three */
  union: 113,
  onlyRemn: 26,
  onlyRemnOwnRules: 23,
  versions: 'REMN e90a455, SQL engine, default rules. Hayabusa v4.1.0, hayabusa-rules 610b16b (4,658 rules). Chainsaw v2.16.5, SigmaHQ 272daf82 (2,857 rules) + 74 native.',
  /** medium and above, each tool with its threat-hunting rules: [tactic, files, REMN, Hayabusa, Chainsaw] */
  tactics: [
    ['Persistence', 82, 33, 29, 17],
    ['Defense Evasion', 55, 26, 20, 8],
    ['Credential Access', 47, 19, 14, 11],
    ['Discovery', 29, 2, 2, 1],
    ['Execution', 19, 10, 6, 5],
    ['Privilege Escalation', 19, 5, 6, 5],
    ['Lateral Movement', 17, 11, 6, 4],
    ['Impact', 5, 3, 3, 1],
    ['Initial Access', 3, 0, 0, 0],
    ['Command and Control', 2, 0, 0, 0],
    ['Collection', 1, 0, 0, 0],
  ] as [string, number, number, number, number][],
}

/** docs/reviews/2026-09-25-noise-and-held-out.md: the clean machines of evtx-baseline. */
export const HELD_OUT = {
  date: '2026-09-25',
  clean: {
    /** REMN's own rules on the seven clean machines */
    own: { rules: 19, highCritical: 200, events: 2_698, mediumUp: 1_332 },
    /** with SigmaHQ's Windows and emerging-threats packs, as REMN runs by default */
    withPacks: { highCritical: 427, events: 3_915 },
    critical: { logCleared: 80, of: 85 },
    /** events of the two grouped findings left: an AV installer reading LSASS, a program reading TeamViewer's memory */
    twoFindingsEvents: 2_380,
  },
}

/** docs/validation.md: the mail score on public corpora, default settings (2026-09-06). */
export const MAIL_CORPORA = {
  date: '2026-09-06',
  /** [corpus, class, mails, share high or above, share medium or above] */
  rows: [
    ['Phishing Pot, 2022–2026 (sample)', 'phishing', 800, 63, 91],
    ['Nazario corpus, 2004–2007', 'phishing', 2_293, 61, 76],
    ['SpamAssassin easy_ham', 'legitimate', 800, 0, 2],
    ['SpamAssassin hard_ham', 'legitimate', 251, 14, 62],
  ] as [string, 'phishing' | 'legitimate', number, number, number][],
}

/** A level cut: a finding of any level, of medium and above, of high and above. */
export type Cut = 'any' | 'medium' | 'high'

export interface LibraryRow {
  key: string
  name: string
  /** REMN's rules were reviewed or written against the library as a whole: practice, not a test */
  practice: boolean
  recordings: number
  /** recordings with at least one event REMN read */
  read: number
  events: number
  /** recordings with a finding of their technique, at or above each cut */
  detected: Record<Cut, number>
  /** recordings with any finding of medium level and above, of whatever technique */
  alertMedium: number
}

/**
 * tools/library_measures.py figures, from one harvest of every rule on every library at one commit
 * (docs/reviews/2026-09-28-measures-across-libraries.md): what the default rule set detects in each
 * library, by tactic, on the clean machines and on MITRE's APT29 evaluation.
 */
export interface LibraryMeasures {
  commit: string
  measured: string
  rules: { all: number; default: number }
  libraries: LibraryRow[]
  /** by tactic, in the order an intrusion reads; each held-out library (and 'all' of them): [recordings, detected at any level, medium and above, high and above] */
  tactics: { id: string; label: string; cells: Record<string, [number, number, number, number]> }[]
  /** ATT&CK techniques (parent ids) the held-out libraries record, and those a finding of medium and above detects */
  techniques: { recorded: number; detected: number; byLibrary: Record<string, [number, number]> }
  /** the clean machines of evtx-baseline: findings of the default rule set by level */
  clean: { machine: string; events: number; medium: number; high: number; critical: number }[]
  apt29: Partial<Record<'day1' | 'day2', { events: number; hosts: Record<string, { medium: number; high: number; attacked: boolean | null }> }>>
  throughput: { events: number; loadSeconds: number; rulesSeconds: number }
  attackDataMaxMb: number
}

export const LIBRARY_MEASURES = measuredLibraries as unknown as LibraryMeasures

/** The held-out libraries together: recordings read and detected at each cut. */
export function heldOut(m: LibraryMeasures = LIBRARY_MEASURES): { libraries: number; read: number; events: number; detected: Record<Cut, number> } {
  const rows = m.libraries.filter((l) => !l.practice && l.read > 0)
  const sum = (f: (l: LibraryRow) => number) => rows.reduce((n, l) => n + f(l), 0)
  return {
    libraries: rows.length,
    read: sum((l) => l.read),
    events: sum((l) => l.events),
    detected: { any: sum((l) => l.detected.any), medium: sum((l) => l.detected.medium), high: sum((l) => l.detected.high) },
  }
}

/** The rule the home page's example finding comes from. */
export const EXAMPLE_RULE = 'win-lsass-memory-access'

export interface LiveFigures {
  measured: string
  rules: number
  detect: number
  /** recorded attacks the rules were run on, all libraries together */
  recordings: number
  libraries: { name: string; recordings: number; ref: string }[]
  baseline?: { machines: number; events: number; tag: string }
  /** the example rule's own measure */
  example?: { hits: number; of: number; cleanFindings: number }
}

const short = (sha: string) => sha.slice(0, 7)

/** The figures the server's measures give, or null before they have loaded (or when the rules were never measured). */
export function liveFigures(meta: Meta | null | undefined): LiveFigures | null {
  const m: MeasureSources | null | undefined = meta?.measures
  if (!m?.sources || !m.totals) return null
  const s = m.sources
  const libraries = [
    s.evtxToMitre && { name: 'EVTX-to-MITRE-Attack', recordings: s.evtxToMitre.recordings, ref: short(s.evtxToMitre.sha) },
    s.attackDataWindows && { name: 'attack_data, Windows', recordings: s.attackDataWindows.recordings, ref: short(s.attackDataWindows.sha) },
    s.attackData && { name: 'attack_data, M365 and Entra', recordings: s.attackData.recordings, ref: short(s.attackData.sha) },
    s.attackSamples && { name: 'EVTX-ATTACK-SAMPLES', recordings: s.attackSamples.recordings, ref: short(s.attackSamples.sha) },
    s.sigma && { name: 'SigmaHQ regression samples', recordings: s.sigma.recordings, ref: short(s.sigma.sha) },
  ].filter((l): l is { name: string; recordings: number; ref: string } => !!l && l.recordings > 0)
  const rule = meta?.rules.find((r) => r.rule?.id === EXAMPLE_RULE)?.measured
  return {
    measured: m.measured,
    rules: m.totals.rules,
    detect: m.totals.detect,
    recordings: libraries.reduce((n, l) => n + l.recordings, 0),
    libraries,
    baseline: s.baseline ? { machines: s.baseline.machines, events: s.baseline.events, tag: s.baseline.tag } : undefined,
    example: rule && !rule.changed && rule.hits && rule.of ? { hits: rule.hits, of: rule.of, cleanFindings: rule.clean?.findings ?? 0 } : undefined,
  }
}
