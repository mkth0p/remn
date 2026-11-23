import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'
import type { Finding } from '../db/schema'
import { foldBelowLevel, foldWidespread, NEVER } from '../data/detectionLevel'
import { RE_VALUE_MAX, type Row, type SettingsLike } from './filter'
import { COLLAPSE_AFTER, MAX_FINDINGS, MAX_REFS, runRule, validateRule, type Rule, type RuleDiag } from './engine'

/**
 * Engine parity: the browser engine must find exactly what the SQL engine found on the same rows,
 * and rate each finding the same: same severity, same count of rows or values, same escalation. The fixture (rows +
 * the SQL engine's findings) is written by tools/parity_fixture.py; when a rule or an engine
 * changes on purpose, regenerate it and review the diff.
 */
const FIX = resolve(__dirname, '../../../tests/fixtures/parity')
type Rated = { key: string; severity: string; count: number; escalation: string | null }
const RULES = resolve(__dirname, '../../../rules')

function loadBundledRules(): Rule[] {
  const out: Rule[] = []
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name)
      if (statSync(p).isDirectory()) {
        if (name !== 'community') walk(p)
        continue
      }
      if (!/\.ya?ml$/.test(name)) continue
      for (const doc of yaml.loadAll(readFileSync(p, 'utf-8'))) {
        if (!doc || typeof doc !== 'object') continue
        const v = validateRule(doc)
        if (v.ok) out.push(v.rule)
      }
    }
  }
  walk(RULES)
  return out
}

describe('engine parity with the SQL engine', () => {
  const events = JSON.parse(readFileSync(join(FIX, 'events.json'), 'utf-8')) as Row[]
  const mails = JSON.parse(readFileSync(join(FIX, 'mails.json'), 'utf-8')) as Row[]
  const expected = JSON.parse(readFileSync(join(FIX, 'expected.json'), 'utf-8')) as { settings: SettingsLike; rules: string[]; findings: Record<string, Rated[]>; errors: unknown[] }
  const rules = loadBundledRules()

  it('covers the same bundled rule set', () => {
    expect(rules.map((r) => r.id).sort()).toEqual(expected.rules)
    expect(expected.errors).toEqual([])
  })

  it('produces the same findings, with the same severity, count and escalation, for every bundled rule', () => {
    const diffs: string[] = []
    for (const rule of rules) {
      const rows = rule.source === 'mails' ? mails : events
      const got: Rated[] = runRule(rule, { rows, settings: expected.settings, thenRows: () => rows })
        .map((f) => ({ key: f.key, severity: f.severity, count: f.count, escalation: f.escalation ?? null }))
        .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
      // the fixture is written with sorted keys: rebuild each finding in the order the browser side uses
      const want: Rated[] = (expected.findings[rule.id] ?? []).map(({ key, severity, count, escalation }) => ({ key, severity, count, escalation }))
      if (JSON.stringify(got) !== JSON.stringify(want)) diffs.push(`${rule.id}: browser ${JSON.stringify(got)} vs sql ${JSON.stringify(want)}`)
    }
    expect(diffs, diffs.join('\n')).toEqual([])
  })
})

describe('engine parity past the finding cap', () => {
  // rules on rows of their own (tools/parity_fixture.py cap_case), each choosing what to keep in another way
  const cap = JSON.parse(readFileSync(join(FIX, 'cap.json'), 'utf-8')) as {
    default: number
    rows: Row[]
    rules: unknown[]
    findings: Record<string, string[]>
    cuts: Record<string, { detail: string; dropped: number }>
  }

  it('caps a rule that sets no max_findings at the same number', () => {
    expect(MAX_FINDINGS).toBe(cap.default)
  })

  it('keeps the same findings and reports the same cut for every rule past its cap', () => {
    expect(cap.rules).toHaveLength(Object.keys(cap.cuts).length)
    for (const r of cap.rules) {
      const v = validateRule(r)
      if (!v.ok) throw new Error(v.error)
      const diags: RuleDiag[] = []
      const keys = runRule(v.rule, { rows: cap.rows, onDiag: (d) => diags.push(d) })
        .map((f) => f.key)
        .sort()
      const cut = diags.find((d) => d.reason === 'truncated')
      expect({ rule: v.rule.id, keys, cut: cut && { detail: cut.detail, dropped: cut.dropped } }).toEqual({ rule: v.rule.id, keys: cap.findings[v.rule.id], cut: cap.cuts[v.rule.id] })
    }
  })
})

describe('engine parity on values longer than a regular expression reads', () => {
  // rules on rows of their own (tools/parity_fixture.py long_case); a long text is stored as pieces repeated
  const long = JSON.parse(readFileSync(join(FIX, 'long.json'), 'utf-8')) as {
    max: number
    rows: Row[]
    rules: unknown[]
    findings: Record<string, string[]>
    cuts: Record<string, { detail: string; longValues: number }>
  }
  const expand = (v: unknown): unknown => {
    if (!v || typeof v !== 'object' || !('repeat' in v) || !Array.isArray(v.repeat)) return v
    return (v.repeat as [string, number][]).map(([piece, times]) => piece.repeat(times)).join('')
  }
  const rows: Row[] = long.rows.map((r) => Object.fromEntries(Object.entries(r).map(([k, v]) => [k, expand(v)])))

  it('reads as many characters of a value', () => {
    expect(RE_VALUE_MAX).toBe(long.max)
  })

  it('finds the same and counts the same rows read in part for every rule', () => {
    expect(long.rules).toHaveLength(Object.keys(long.cuts).length)
    for (const r of long.rules) {
      const v = validateRule(r)
      if (!v.ok) throw new Error(v.error)
      const diags: RuleDiag[] = []
      const keys = runRule(v.rule, { rows, onDiag: (d) => diags.push(d) })
        .map((f) => f.key)
        .sort()
      const cuts = diags.filter((d) => d.reason === 'values_cut').map((d) => ({ detail: d.detail, longValues: d.longValues }))
      expect({ rule: v.rule.id, keys, cuts }).toEqual({ rule: v.rule.id, keys: long.findings[v.rule.id], cuts: [long.cuts[v.rule.id]] })
    }
  })
})

describe('engine parity on the paths of a large case', () => {
  // rules on rows of their own (tools/parity_fixture.py scale_case): a per-row rule collapsed past
  // COLLAPSE_AFTER rows, a group whose other entities differ from row to row, bursts; with ties in
  // time and rows without one
  const scale = JSON.parse(readFileSync(join(FIX, 'scale.json'), 'utf-8')) as { collapseAfter: number; maxRefs: number; rows: Row[]; rules: unknown[]; findings: Record<string, Finding[]> }
  // what a finding carries that the detection level's folding reads, an absent value as the SQL engine writes it
  const FIELDS = ['key', 'ruleId', 'title', 'severity', 'count', 'escalation', 'ts', 'tsEnd', 'entities', 'refs'] as const
  const pick = (f: Partial<Finding>) => Object.fromEntries(FIELDS.map((k) => [k, f[k] ?? null]))
  const byKey = (a: Record<string, unknown>, b: Record<string, unknown>) => (String(a.key) < String(b.key) ? -1 : String(a.key) > String(b.key) ? 1 : 0)
  const rules = scale.rules.map((r) => {
    const v = validateRule(r)
    if (!v.ok) throw new Error(v.error)
    return v.rule
  })
  const browser = (rule: Rule) => runRule(rule, { rows: scale.rows }).map((f) => ({ ...f, caseId: 1, createdAt: 0, status: 'new' }) as Finding)
  const sql = (rule: Rule) => (scale.findings[rule.id] ?? []).map((f) => ({ ...f, source: rule.source, attack: [], caseId: 1, createdAt: 0, status: 'new' }) as Finding)

  it('collapses past as many rows and cites as many rows of a finding', () => {
    expect(COLLAPSE_AFTER).toBe(scale.collapseAfter)
    expect(scale.rows.length).toBeGreaterThan(COLLAPSE_AFTER)
    expect(MAX_REFS).toBe(scale.maxRefs)
  })

  it.each(scale.rules.map((r) => [(r as { id: string }).id]))('%s gives every finding the same host, times and rows', (id) => {
    const rule = rules.find((r) => r.id === id) as Rule
    expect(browser(rule).map(pick).sort(byKey)).toEqual(sql(rule).map(pick).sort(byKey))
  })

  it("folds a server case's findings as it folds a browser case's", () => {
    // every rule below its floor, as at a level that raises none of them; and the case's own hosts as the measure of noise
    const floors = Object.fromEntries(rules.map((r) => [r.id, NEVER]))
    const fold = (fs: Finding[]) =>
      foldBelowLevel(fs, floors)
        .map((f) => ({ ...pick(f), folded: f.folded ?? null }))
        .sort(byKey)
    const widespread = (fs: Finding[]) =>
      foldWidespread(fs, floors)
        .map((f) => ({ ...pick(f), folded: f.folded ?? null }))
        .sort(byKey)
    const [ours, theirs] = [rules.flatMap(browser), rules.flatMap(sql)]
    expect(fold(ours)).toEqual(fold(theirs))
    expect(fold(ours).some((f) => (f.folded ?? 0) > 1)).toBe(true)
    expect(widespread(ours)).toEqual(widespread(theirs))
  })
})

describe('engine parity on the Sublime pack', () => {
  // the pack's rules on the parity mails and on mails of their own (tools/parity_fixture.py sublime_case)
  const sub = JSON.parse(readFileSync(join(FIX, 'sublime.json'), 'utf-8')) as { rules: string[]; rows: Row[]; errors: unknown[]; findings: Record<string, Rated[]> }
  const expected = JSON.parse(readFileSync(join(FIX, 'expected.json'), 'utf-8')) as { settings: SettingsLike }
  const rows = [...(JSON.parse(readFileSync(join(FIX, 'mails.json'), 'utf-8')) as Row[]), ...sub.rows]
  const dir = join(RULES, 'community', 'sublime')
  const rules = readdirSync(dir)
    .filter((n) => n.endsWith('.yaml'))
    .flatMap((n) => yaml.loadAll(readFileSync(join(dir, n), 'utf-8')))
    .map((doc) => validateRule(doc))
    .map((v) => {
      if (!v.ok) throw new Error(v.error)
      return v.rule
    })

  it('covers every rule of the pack', () => {
    expect(rules.map((r) => r.id).sort()).toEqual(sub.rules)
    expect(sub.errors).toEqual([])
    // the mails of their own make the rules that keep case, and the sender name written in a linear form, fire
    expect(Object.keys(sub.findings).length).toBeGreaterThanOrEqual(4)
  })

  it('produces the same findings, with the same severity, count and escalation, for every rule of the pack', () => {
    const diffs: string[] = []
    for (const rule of rules) {
      const got: Rated[] = runRule(rule, { rows, settings: expected.settings, thenRows: () => rows })
        .map((f) => ({ key: f.key, severity: f.severity, count: f.count, escalation: f.escalation ?? null }))
        .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
      const want: Rated[] = (sub.findings[rule.id] ?? []).map(({ key, severity, count, escalation }) => ({ key, severity, count, escalation }))
      if (JSON.stringify(got) !== JSON.stringify(want)) diffs.push(`${rule.id}: browser ${JSON.stringify(got)} vs sql ${JSON.stringify(want)}`)
    }
    expect(diffs, diffs.join('\n')).toEqual([])
  })
})
