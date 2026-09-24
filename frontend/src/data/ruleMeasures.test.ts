import { describe, expect, it } from 'vitest'
import { fmtRate, isLead, measuredOn, readMeasure } from './ruleMeasures'

const clean = { findings: 0, events: 0, machines: 0, scope: 1_250_000, of: 7 }

describe('what a rule’s measure says', () => {
  it('says a rule detects what fires on recordings of what it looks for, its own sample among them', () => {
    const r = readMeasure({ own: true, of: 12, hits: 3, fires: 5, clean }, 'pack')
    expect(r).toMatchObject({ verdict: 'detects', label: 'detects', noisy: false })
    expect(r.attacks).toBe('Fires on 3 of 12 recorded attacks of what it looks for, its own SigmaHQ test sample among them.')
    expect(r.clean).toBe('It never fired on the 1,250,000 events of what it reads on 7 clean Windows machines.')
    expect(isLead(r)).toBe(false)
  })

  it('calls a rule never seen to detect what it looks for a lead, whether or not a recording was there', () => {
    const tried = readMeasure({ of: 4, fires: 2, clean }, 'bundled')
    expect(tried.verdict).toBe('lead')
    expect(tried.attacks).toBe('Fires on none of the 4 recorded attacks of what it looks for: its findings are leads to check, not detections.')
    const untried = readMeasure({}, 'bundled')
    expect(untried.attacks).toMatch(/^No recording of what it looks for was available/)
    expect(untried.clean).toMatch(/^No clean machine it was measured on logs what it reads/)
    expect(isLead(tried) && isLead(untried)).toBe(true)
  })

  it('says when a converted rule misses the sample SigmaHQ recorded for it', () => {
    const r = readMeasure({ own: false, of: 3 }, 'pack')
    expect(r).toMatchObject({ verdict: 'misses', label: 'misses its sample' })
    expect(r.attacks).toContain('Does not fire on the SigmaHQ sample recorded for it nor on the 2 other recordings of what it looks for')
    expect(isLead(r)).toBe(true)
    // a miss of its own sample said beside the recordings it does detect
    expect(readMeasure({ own: false, of: 3, hits: 1, fires: 1 }).attacks).toBe('Fires on 1 of 3 recorded attacks of what it looks for, though not on the SigmaHQ sample recorded for it.')
  })

  it('says how often a rule fires on clean machines, per 10,000 events of what it reads', () => {
    const r = readMeasure({ of: 1, hits: 1, fires: 1, clean: { findings: 41, events: 43, machines: 3, scope: 1_250_000, of: 7 } })
    expect(r.noisy).toBe(true)
    expect(r.rate).toBeCloseTo(0.344, 3)
    expect(r.clean).toBe('On clean Windows machines it fired 41 times, on 3 of 7, matching 43 of the 1,250,000 events of what it reads (0.34 per 10,000): benign activity matches it too.')
    // a rule that matches every event it reads
    expect(readMeasure({ of: 1, clean: { findings: 218, events: 218, machines: 7, scope: 218, of: 7 } }).clean).toContain('matching 218 of the 218 events of what it reads (100%)')
  })

  it('does not stand a measure against a rule that changed, a custom rule or one that needs the case’s settings', () => {
    expect(readMeasure({ changed: true })).toMatchObject({ verdict: 'changed', clean: '' })
    expect(readMeasure({ hits: 5, of: 5 }, 'custom')).toMatchObject({ verdict: 'custom', label: 'your rule' })
    expect(readMeasure({ settings: ['expected_countries'] }).attacks).toBe("Not measured: it runs only once the case's expected countries is set, which recorded attacks do not have.")
    expect(readMeasure(undefined)).toMatchObject({ verdict: 'unmeasured', label: '' })
  })

  it('writes rates to two figures and names what was measured on', () => {
    expect([0, 0.004, 0.344, 2.46, 13.6, 2500].map(fmtRate)).toEqual(['0', 'under 0.01', '0.34', '2.5', '14', '2,500'])
    expect(
      measuredOn({
        version: 1,
        measured: '2026-09-24',
        sources: {
          sigma: { repo: 'SigmaHQ/sigma', sha: 'x', recordings: 457 },
          attackSamples: { repo: 'r', sha: 'y', recordings: 278 },
          attackData: { repo: 'splunk/attack_data', sha: 'z', recordings: 81, unreadable: 16 },
          baseline: { repo: 'NextronSystems/evtx-baseline', tag: 'v0.8.4', machines: 7, events: 6_611_184 },
        },
      }),
    ).toBe(
      'Measured on 2026-09-24 on 457 SigmaHQ regression samples, 278 EVTX-ATTACK-SAMPLES recordings and 81 Microsoft 365 and Entra ID datasets of Splunk attack_data, and on the logs of 7 clean Windows machines of evtx-baseline v0.8.4 (6,611,184 events).',
    )
    expect(measuredOn(null)).toBe('')
  })
})
