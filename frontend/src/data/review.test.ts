import { describe, expect, it } from 'vitest'
import type { Chain, ChainStep } from './chains'
import type { Finding } from '../db/schema'
import { buildIncidents } from '../rules/incidents'
import { DEFAULT_REPORT, overridesForIncident, reviewQueue, selectForReport, stepVisible, verdictStatus } from './review'

let seq = 1
const f = (p: Partial<Finding> & { ruleId: string; severity: Finding['severity'] }): Finding => ({
  id: seq++,
  caseId: 1,
  key: `${p.ruleId}|${seq}`,
  title: p.ruleId,
  source: 'mails',
  ts: 10,
  entities: {},
  count: 1,
  refs: [seq],
  attack: [],
  status: 'new',
  createdAt: 0,
  ...p,
})
const step = (p: Partial<ChainStep>): ChainStep => ({
  kind: 'event',
  source: 'events',
  id: null,
  count: 1,
  weight: 1,
  artifacts: [],
  findings: [],
  offsetMin: 1,
  ts: 1,
  tsEnd: 1,
  title: 't',
  origin: 'm365',
  ...p,
})
const chain = (id: string, score: number, severity: Chain['severity']): Chain => ({
  id,
  identity: id,
  identityLabel: `${id}@corp.test`,
  start: 0,
  end: 1,
  score,
  severity,
  artifactLinks: 1,
  summary: '',
  seed: { id: 1, ts: 0, subject: 's', fromAddr: 'x@evil.test', risk: 90, flags: [], findings: [], urlDomains: [], attachments: [] },
  steps: [],
  entities: { user: id, ips: [], hosts: [], attackerAddresses: [], domains: [] },
})

describe('report selection', () => {
  it('applies the severity floor to the effective severity, drops excluded and false-positive findings, and honours chain verdicts', () => {
    const rows = [
      f({ ruleId: 'a', severity: 'critical' }),
      f({ ruleId: 'b', severity: 'low', severityOverride: 'high' }),
      f({ ruleId: 'c', severity: 'high', severityOverride: 'low' }),
      f({ ruleId: 'd', severity: 'critical', reportExclude: true }),
      f({ ruleId: 'e', severity: 'critical', status: 'false_positive' }),
      f({ ruleId: 'g', severity: 'medium', status: 'new' }),
    ]
    const chains = [chain('x', 90, 'critical'), chain('y', 60, 'high'), chain('z', 40, 'medium')]
    const sel = selectForReport(rows, chains, { y: { verdict: 'benign' }, z: { severityOverride: 'low' } }, { ...DEFAULT_REPORT, minSeverity: 'medium' })
    expect(sel.findings.map((x) => x.ruleId)).toEqual(['a', 'b', 'g'])
    expect(sel.chains.map((c) => c.id)).toEqual(['x'])
    const strict = selectForReport(rows, chains, {}, { ...DEFAULT_REPORT, minSeverity: 'high', onlyReviewed: true, includeFp: true })
    expect(strict.findings.map((x) => x.ruleId)).toEqual(['e'])
    expect(selectForReport(rows, chains, {}, { ...DEFAULT_REPORT, includeChains: false }).chains).toEqual([])
  })

  it('prints chain steps by detail level', () => {
    const linked = step({ artifacts: ['mail URL domain x'] })
    const weighted = step({ weight: 3 })
    const routine = step({ weight: 1 })
    expect([linked, weighted, routine].map((s) => stepVisible(s, 'linked'))).toEqual([true, false, false])
    expect([linked, weighted, routine].map((s) => stepVisible(s, 'weighted'))).toEqual([true, true, false])
    expect([linked, weighted, routine].map((s) => stepVisible(s, 'all'))).toEqual([true, true, true])
  })

  it('orders the queue chains first by score, then incidents, and marks what is done', () => {
    const inc = buildIncidents([f({ ruleId: 'a', severity: 'high', status: 'reviewed' }), f({ ruleId: 'b', severity: 'low' })])
    const q = reviewQueue(inc, [chain('lo', 40, 'medium'), chain('hi', 95, 'critical')], { lo: { verdict: 'unsure' } })
    expect(q.map((i) => i.id)).toEqual(['chain:hi', 'chain:lo', ...inc.map((i) => `incident:${i.id}`)])
    expect(q.map((i) => i.done)).toEqual([false, true, true, false])
  })

  it('rescoring an incident overrides the members above the target, or raises the lead', () => {
    const [inc] = buildIncidents([f({ ruleId: 'a', severity: 'critical', refs: [7] }), f({ ruleId: 'b', severity: 'medium', refs: [7] }), f({ ruleId: 'c', severity: 'low', refs: [7] })])
    const down = overridesForIncident(inc, 'medium')
    expect(down).toEqual([{ id: inc.findings[0].id, severityOverride: 'medium' }])
    const up = overridesForIncident(buildIncidents([f({ ruleId: 'd', severity: 'low', refs: [8] })])[0], 'high')
    expect(up[0].severityOverride).toBe('high')
    expect(overridesForIncident(inc, null).every((o) => o.severityOverride === undefined)).toBe(true)
  })
})

describe('chains in the queue and the report', () => {
  const c = chain('alice', 90, 'critical')
  c.seed.id = 7
  c.steps = [step({ id: 11 })]
  const rows = () => [
    f({ ruleId: 'chain', key: 'chain|alice|7', severity: 'critical', refs: [7] }),
    f({ ruleId: 'mail-credential-phishing', severity: 'low', refs: [7] }),
    f({ ruleId: 'win-logon-external', severity: 'low', source: 'events', refs: [11], entities: { targetUser: 'alice' } }),
    f({ ruleId: 'other', severity: 'high', refs: [8] }),
  ]

  it('lists the chain once, with its incident, and never its members as separate items', () => {
    const inc = buildIncidents(rows(), { chains: [c] })
    const q = reviewQueue(inc, [c], {})
    expect(q.map((i) => i.id)).toEqual(['chain:alice', 'incident:mail:8'])
    expect(q[0].incident?.findings).toHaveLength(3)
    expect(q[0].sub).toContain('3 findings')
  })

  it('members follow their chain into or out of the report, whatever their severity', () => {
    const inReport = selectForReport(rows(), [c], { alice: { verdict: 'confirmed' } }, { ...DEFAULT_REPORT, minSeverity: 'high' })
    expect(inReport.findings.map((x) => x.ruleId).sort()).toEqual(['chain', 'mail-credential-phishing', 'other', 'win-logon-external'])
    const out = selectForReport(rows(), [c], { alice: { verdict: 'benign' } }, { ...DEFAULT_REPORT, minSeverity: 'high' })
    expect(out.findings.map((x) => x.ruleId)).toEqual(['other'])
    expect(out.chains).toEqual([])
  })

  it('a verdict maps to the status its linked findings get', () => {
    expect(verdictStatus('confirmed')).toBe('escalated')
    expect(verdictStatus('benign')).toBe('false_positive')
    expect(verdictStatus('unsure')).toBe('reviewed')
  })
})
