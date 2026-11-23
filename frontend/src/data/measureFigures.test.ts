import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import committed from 'virtual:rule-measure'
import { measureFigures, type MeasureDetail, type MeasureFile } from './measureFigures'

// an invented measure: four rules, two libraries and two clean machines
const MEASURES: MeasureFile = {
  measured: '2030-01-02',
  sources: {
    evtxToMitre: { repo: 'example/mitre', sha: 'abcdef0123456789', recordings: 10 },
    attackSamples: { repo: 'example/samples', sha: '0123456789abcdef', recordings: 4 },
    baseline: { repo: 'example/baseline', tag: 'v1', machines: 2, events: 5_000 },
  },
  rules: {
    'win-one': { hits: 2 },
    'sigma-two': { hits: 1 },
    'sigma-hunt': { hits: 1 },
    'win-quiet': {},
    'm365-needs-domains': { settings: ['internalDomains'] },
  },
}
const DETAIL: MeasureDetail = {
  rules: {
    'win-one': { hits: ['evtxToMitre:a.evtx', 'attackSamples:x.evtx'], clean: { pc1: 3, pc2: 1 }, severity: 'high' },
    'sigma-two': { hits: ['evtxToMitre:a.evtx', 'evtxToMitre:b.evtx'], clean: { pc1: 5 }, severity: 'medium' },
    'sigma-hunt': { hits: ['evtxToMitre:c.evtx'], clean: { pc2: 40 }, severity: 'critical' },
    'win-quiet': { clean: { pc1: 2 }, severity: 'low' },
  },
}

describe('the figures of a rule measure', () => {
  it('count the rules measured and those that detect, and each library as the rules a new case enables detect it', () => {
    const f = measureFigures(MEASURES, DETAIL, new Set(['sigma-hunt']))
    expect(f).toMatchObject({ measured: '2030-01-02', rules: 5, detect: 3, baseline: { tag: 'v1', machines: 2, events: 5_000 } })
    expect(f.libraries).toEqual([
      { key: 'evtxToMitre', name: 'EVTX-to-MITRE-Attack', ref: 'abcdef0', recordings: 10, detected: 2, own: 1, heldOut: true, note: 'no rule written against it before it was first measured' },
      { key: 'attackSamples', name: 'EVTX-ATTACK-SAMPLES', ref: '0123456', recordings: 4, detected: 1, own: 1, heldOut: false, note: 'the rules were reviewed against it' },
    ])
  })

  it('count the findings on the clean machines at the severity each rule had, for REMN’s own rules and for those enabled by default', () => {
    const f = measureFigures(MEASURES, DETAIL, new Set(['sigma-hunt']))
    expect(f.clean.own).toEqual({ rules: 2, highCritical: 4, mediumUp: 4 })
    expect(f.clean.defaults).toEqual({ rules: 3, highCritical: 4, mediumUp: 9 })
    // a pack switched on by the analyst is not counted among the defaults
    expect(measureFigures(MEASURES, DETAIL, new Set()).clean.defaults).toEqual({ rules: 4, highCritical: 44, mediumUp: 49 })
  })
})

describe('the committed measure the build reads', () => {
  // README.md quotes the measure, and tests/backend/test_quoted_measures.py holds its figures to the
  // two files; what the pages are built with must say the same
  const readme = readFileSync(new URL('../../../README.md', import.meta.url), 'utf-8').replace(/\s+/g, ' ')
  const quoted = (pattern: RegExp) => (pattern.exec(readme) ?? []).slice(1).map((n) => (/^\d{4}-/.test(n) ? n : Number(n.replace(/,/g, ''))))
  const library = (key: string) => committed.libraries.find((l) => l.key === key)!

  it('gives the date, the rule counts and the clean machines the README quotes', () => {
    expect(quoted(/The committed measure, `rules\/measures.json`, was taken on (\d{4}-\d\d-\d\d)/)).toEqual([committed.measured])
    expect(quoted(/of the ([\d,]+) event rules measured then, ([\d,]+) fire on a recording/)).toEqual([committed.rules, committed.detect])
    expect(quoted(/REMN's own rules raised ([\d,]+) findings at high or critical/)).toEqual([committed.clean.own.highCritical])
  })

  it('gives the detections of the rules enabled by default the README quotes', () => {
    expect(quoted(/detect ([\d,]+) of the ([\d,]+) Windows datasets of Splunk attack_data/)).toEqual([library('attackDataWindows').detected, library('attackDataWindows').recordings])
    expect(quoted(/and ([\d,]+) of the ([\d,]+) files of EVTX-to-MITRE-Attack/)).toEqual([library('evtxToMitre').detected, library('evtxToMitre').recordings])
    expect(quoted(/and ([\d,]+) of the ([\d,]+) files of EVTX-ATTACK-SAMPLES/)).toEqual([library('attackSamples').detected, library('attackSamples').recordings])
  })
})
