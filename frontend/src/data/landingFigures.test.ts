import { expect, it } from 'vitest'
import type { Meta } from '../api/client'
import { EXAMPLE_RULE, exampleMeasure, heldOut, LIBRARY_MEASURES } from './landingFigures'

const rule = (id: string, measured?: object) => ({ file: `${id}.yml`, yaml: '', rule: { id }, measured })
const meta = (extra: Partial<Meta>) => ({ rules: [], ...extra }) as unknown as Meta

// the figures of the whole measure are no longer read from the server: measureFigures.test.ts
it("reads the example rule's measure from the server", () => {
  const ex = exampleMeasure(meta({ rules: [rule('other', { hits: 1, of: 1 }), rule(EXAMPLE_RULE, { hits: 15, of: 19, clean: { findings: 2, events: 2380, machines: 2, scope: 7, of: 7 } })] }))
  expect(ex).toEqual({ hits: 15, of: 19, cleanFindings: 2 })
})

it('shows no example when the rule changed since it was measured or never fired', () => {
  expect(exampleMeasure(meta({ rules: [rule(EXAMPLE_RULE, { hits: 15, of: 19, changed: true })] }))).toBeNull()
  expect(exampleMeasure(meta({ rules: [rule(EXAMPLE_RULE, { hits: 0, of: 19 })] }))).toBeNull()
  expect(exampleMeasure(meta({}))).toBeNull()
})

it('has no example before the rules load', () => {
  expect(exampleMeasure(null)).toBeNull()
})

it('quotes the library measures as measured: every count within its library, each level cut within the one below', () => {
  const m = LIBRARY_MEASURES
  expect(m.libraries.length).toBeGreaterThan(0)
  for (const l of m.libraries) {
    expect(l.read).toBeLessThanOrEqual(l.recordings)
    expect(l.detected.any).toBeLessThanOrEqual(l.read)
    expect(l.detected.medium).toBeLessThanOrEqual(l.detected.any)
    expect(l.detected.high).toBeLessThanOrEqual(l.detected.medium)
    expect(l.detected.medium).toBeLessThanOrEqual(l.alertMedium)
  }
  const h = heldOut(m)
  const all = m.tactics.reduce((n, t) => n + (t.cells.all?.[0] ?? 0), 0)
  expect(all).toBeLessThanOrEqual(h.read)
  for (const t of m.tactics)
    for (const [n, any, medium, high] of Object.values(t.cells)) {
      expect(any).toBeLessThanOrEqual(n)
      expect(medium).toBeLessThanOrEqual(any)
      expect(high).toBeLessThanOrEqual(medium)
    }
  expect(m.techniques.detected).toBeLessThanOrEqual(m.techniques.recorded)
  for (const day of Object.values(m.apt29)) for (const host of Object.values(day!.hosts)) expect(host.high).toBeLessThanOrEqual(host.medium)
})
