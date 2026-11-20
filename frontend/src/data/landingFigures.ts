/**
 * What the home page quotes besides the committed rule measure (measureFigures.ts, read from
 * rules/measures.json and rules/measures-detail.json when the page is built): the example rule's
 * measure as the server serves it, the run of every rule on every library by
 * tools/library_measures.py, and the mail corpora of docs/validation.md.
 */
import type { Meta } from '../api/client'
import measuredLibraries from './libraryMeasures.json'

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
  /** medium and above, scored on the techniques the rules' authors tagged, without the title map */
  authorTagsMedium: number
  /** medium and above, by REMN's own rules alone */
  ownRulesMedium: number
}

/**
 * tools/library_measures.py figures, from one harvest of every rule on every library at one commit
 * (docs/reviews/2026-09-28-measures-across-libraries.md): what the default rule set detects in each
 * library, by tactic, on the clean machines and on the APT29 emulation OTRF recorded.
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

/** The example rule's own measure, as the server serves it with the rule. */
export interface ExampleMeasure {
  hits: number
  of: number
  cleanFindings: number
}

/** The example rule's measure, or null before the server's rules have loaded, or when the rule changed since it was measured or never fired on what it looks for. */
export function exampleMeasure(meta: Meta | null | undefined): ExampleMeasure | null {
  const rule = meta?.rules.find((r) => r.rule?.id === EXAMPLE_RULE)?.measured
  return rule && !rule.changed && rule.hits && rule.of ? { hits: rule.hits, of: rule.of, cleanFindings: rule.clean?.findings ?? 0 } : null
}
