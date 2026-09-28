import { describe, expect, it } from 'vitest'
import { caseLevel, DETECTION_LEVELS, lowestLevel, NEVER, raised, ruleNoise, ruleRaises, ruleTopSeverity, severityFloor, severityFloors, UNMEASURED_FLOOR } from './detectionLevel'
import type { RuleMeasure } from './ruleMeasures'

const clean = (findings: number, of = 7): RuleMeasure => ({ hits: 1, of: 2, clean: { findings, events: findings, machines: Math.min(findings, of), scope: 1000, of } })

describe('the detection level', () => {
  it('takes a rule noise as its clean findings per machine that logs what it reads, half a finding added', () => {
    expect(ruleNoise(clean(0))).toBeCloseTo(0.5 / 7)
    expect(ruleNoise(clean(398))).toBeCloseTo(398.5 / 7)
    expect(ruleNoise(undefined)).toBeNull()
    expect(ruleNoise({ hits: 1, of: 1 })).toBeNull()
    expect(ruleNoise({ ...clean(0), changed: true })).toBeNull()
    expect(ruleNoise({ ...clean(0), settings: ['internal_domains'] })).toBeNull()
  })

  it('raises a rule silent on clean machines from medium up at level 1, and every severity at level 5', () => {
    const silent = ruleNoise(clean(0))
    expect(severityFloor(1, silent)).toBe(2)
    expect(severityFloor(3, silent)).toBe(0)
    expect(severityFloor(5, ruleNoise(clean(5000)))).toBe(0)
  })

  it('lets a critical finding come from a rule four times noisier than a medium one', () => {
    // 5 findings per machine: medium fits level 3 (budget 5), 20 per machine needs critical
    expect(severityFloor(3, 5)).toBe(2)
    expect(severityFloor(3, 20)).toBe(4)
    expect(severityFloor(3, 21)).toBe(NEVER)
    expect(severityFloor(4, 21)).toBe(2)
  })

  it('raises every medium and higher finding at level 4, as before levels, and low ones of quiet rules', () => {
    expect(severityFloor(4, 5000)).toBe(2)
    expect(severityFloor(4, null)).toBe(2)
    expect(severityFloor(4, ruleNoise(clean(0)))).toBe(0)
  })

  it('raises what no clean machine could measure from medium up, and the analyst own rules always', () => {
    for (const l of [1, 2, 3, 4] as const) expect(severityFloor(l, null)).toBe(UNMEASURED_FLOOR)
    expect(severityFloor(5, null)).toBe(0)
    expect(severityFloor(1, 1000, 'custom')).toBe(0)
  })

  it('never takes a noisier rule in at a lower level: the levels nest', () => {
    for (const noise of [0.01, 0.1, 0.5, 2, 5, 20, 57, 300])
      for (let l = 1; l < 5; l++) expect(severityFloor((l + 1) as 2 | 3 | 4 | 5, noise)).toBeLessThanOrEqual(severityFloor(l as 1 | 2 | 3 | 4, noise))
    const figures = DETECTION_LEVELS.map((l) => l.measured)
    for (let i = 1; i < figures.length; i++) {
      expect(figures[i].alone).toBeGreaterThan(figures[i - 1].alone)
      expect(figures[i].perCleanMachine).toBeGreaterThan(figures[i - 1].perCleanMachine)
    }
    for (const f of figures) expect(f.perCleanMachine).toBeGreaterThanOrEqual(f.alone)
  })

  it('gives the lowest level a rule raises its top severity at, its follow-up included', () => {
    const rule = { id: 'r', severity: 'medium' as const, then: { severity: 'critical' as const } }
    expect(ruleTopSeverity(rule)).toBe('critical')
    expect(lowestLevel('medium', 57)).toBe(4)
    expect(lowestLevel('low', 57)).toBe(5)
    expect(lowestLevel('critical', 57)).toBe(4)
    expect(lowestLevel('high', ruleNoise(clean(0)))).toBe(1)
  })

  it('keeps only the findings at or above their rule floor, and skips a rule that can raise nothing', () => {
    const loud = { rule: { id: 'loud', severity: 'medium' as const }, origin: 'bundled' as const, measured: clean(398) }
    const quiet = { rule: { id: 'quiet', severity: 'low' as const }, origin: 'pack' as const, measured: clean(0) }
    const floors = severityFloors([loud, quiet], 3)
    expect(ruleRaises(loud, floors)).toBe(false)
    expect(ruleRaises(quiet, floors)).toBe(true)
    expect(raised({ ruleId: 'quiet', severity: 'low' }, floors)).toBe(true)
    expect(raised({ ruleId: 'loud', severity: 'medium' }, floors)).toBe(false)
    expect(raised({ ruleId: 'other', severity: 'info' }, floors)).toBe(true)
    expect(raised({ ruleId: 'loud', severity: 'medium' }, undefined)).toBe(true)
  })

  it('leaves a case from before levels at every finding', () => {
    expect(caseLevel({})).toBe(5)
    expect(caseLevel({ detectionLevel: 2 })).toBe(2)
    expect(caseLevel({ detectionLevel: 9 })).toBe(5)
  })
})
