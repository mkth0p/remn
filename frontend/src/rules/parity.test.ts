import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'
import type { Row, SettingsLike } from './filter'
import { MAX_FINDINGS, runRule, validateRule, type Rule, type RuleDiag } from './engine'

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
