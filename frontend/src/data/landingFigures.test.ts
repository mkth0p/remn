import { expect, it } from 'vitest'
import type { Meta } from '../api/client'
import { EXAMPLE_RULE, HEAD_TO_HEAD, liveFigures } from './landingFigures'

const measures = {
  version: 1,
  measured: '2026-09-25',
  sources: {
    evtxToMitre: { repo: 'r', sha: '4748560aaaaaaaa', recordings: 279 },
    attackData: { repo: 'r', sha: '7a5e9d5bbbbbbbb', recordings: 0 },
    sigma: { repo: 'r', sha: 'cccccccccccc', recordings: 459 },
    baseline: { repo: 'r', tag: 'v0.8.4', machines: 7, events: 6_611_184 },
  },
  totals: { rules: 3008, detect: 1023 },
}
const rule = (id: string, measured?: object) => ({ file: `${id}.yml`, yaml: '', rule: { id }, measured })
const meta = (extra: Partial<Meta>) => ({ rules: [], ...extra }) as unknown as Meta

it("reads the server's measures: totals, the libraries with recordings, the baseline and the example rule", () => {
  const live = liveFigures(meta({ measures, rules: [rule('other', { hits: 1, of: 1 }), rule(EXAMPLE_RULE, { hits: 15, of: 19, clean: { findings: 2, events: 2380, machines: 2, scope: 7, of: 7 } })] }))
  expect(live).toEqual({
    measured: '2026-09-25',
    rules: 3008,
    detect: 1023,
    recordings: 738,
    libraries: [
      { name: 'EVTX-to-MITRE-Attack', recordings: 279, ref: '4748560' },
      { name: 'SigmaHQ regression samples', recordings: 459, ref: 'ccccccc' },
    ],
    baseline: { machines: 7, events: 6_611_184, tag: 'v0.8.4' },
    example: { hits: 15, of: 19, cleanFindings: 2 },
  })
})

it('shows no example when the rule changed since it was measured or never fired', () => {
  expect(liveFigures(meta({ measures, rules: [rule(EXAMPLE_RULE, { hits: 15, of: 19, changed: true })] }))?.example).toBeUndefined()
  expect(liveFigures(meta({ measures, rules: [rule(EXAMPLE_RULE, { hits: 0, of: 19 })] }))?.example).toBeUndefined()
  expect(liveFigures(meta({ measures }))?.example).toBeUndefined()
})

it('has nothing to show before the measures load, or from a server without totals', () => {
  expect(liveFigures(null)).toBeNull()
  expect(liveFigures(meta({}))).toBeNull()
  expect(liveFigures(meta({ measures: { ...measures, totals: undefined } }))).toBeNull()
})

it('quotes the head-to-head as published: every count within the library', () => {
  for (const counts of Object.values(HEAD_TO_HEAD.detected)) for (const n of counts) expect(n).toBeLessThanOrEqual(HEAD_TO_HEAD.library.files)
  expect(HEAD_TO_HEAD.tactics.reduce((n, [, files]) => n + files, 0)).toBeLessThanOrEqual(HEAD_TO_HEAD.library.files)
})
