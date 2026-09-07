import { describe, expect, it } from 'vitest'
import type { Finding } from '../db/schema'
import type { Chain } from '../data/chains'
import { buildIncidents, chainMembership, deriveStatus, primaryEntity } from './incidents'

let seq = 1
function f(p: Partial<Finding> & { ruleId: string; severity: Finding['severity']; source: Finding['source'] }): Finding {
  return { id: seq++, caseId: 1, key: `${p.ruleId}|${seq}`, title: p.ruleId, ts: null, entities: {}, count: 1, refs: [], attack: [], status: 'new', createdAt: 0, ...p }
}
const H = 3_600_000

describe('incidents', () => {
  it('folds every finding on one mail, including the chain it seeded, into one incident', () => {
    const rows = [
      f({ ruleId: 'mail-html-attachment', severity: 'low', source: 'mails', refs: [7], ts: 10, entities: { fromAddr: 'x@evil.test', subject: 'Urgent invoice' } }),
      f({ ruleId: 'mail-credential-phishing', severity: 'critical', source: 'mails', refs: [7], ts: 10, entities: { fromAddr: 'x@evil.test', subject: 'Urgent invoice' } }),
      f({ ruleId: 'mail-high-risk-score', severity: 'medium', source: 'mails', refs: [7], ts: 10, entities: { fromAddr: 'x@evil.test', subject: 'Urgent invoice' } }),
      f({ ruleId: 'chain', severity: 'critical', source: 'mails', refs: [7], ts: 10, tsEnd: 10 + 3 * H, title: 'Attack chain: alice', entities: { user: 'alice@corp.test' } }),
      f({ ruleId: 'mail-credential-phishing', severity: 'critical', source: 'mails', refs: [8], ts: 20, entities: { fromAddr: 'y@evil.test', subject: 'Other' } }),
    ]
    const inc = buildIncidents(rows)
    expect(inc).toHaveLength(2)
    const a = inc.find((i) => i.id === 'mail:7')!
    expect(a.kind).toBe('mail')
    expect(a.title).toBe('Urgent invoice')
    expect(a.severity).toBe('critical')
    expect(a.findings).toHaveLength(4)
    expect(a.rules.sort()).toEqual(['chain', 'mail-credential-phishing', 'mail-high-risk-score', 'mail-html-attachment'])
    expect(a.entities.user).toBe('alice@corp.test')
    expect(a.tsEnd).toBe(10 + 3 * H)
    expect(a.subtitle).toContain('from x@evil.test')
  })

  it('clusters event findings about one user by time gap and separates hosts', () => {
    const rows = [
      f({ ruleId: 'win-bruteforce', severity: 'high', source: 'events', ts: 0, tsEnd: H, entities: { targetUser: 'bob', computer: 'WS-1' }, refs: [1, 2, 3], count: 3 }),
      f({ ruleId: 'win-new-service', severity: 'medium', source: 'events', ts: 2 * H, entities: { subjectUser: 'BOB', computer: 'WS-1' }, refs: [4] }),
      f({ ruleId: 'win-log-cleared', severity: 'critical', source: 'events', ts: 30 * H, entities: { targetUser: 'bob' }, refs: [5] }),
      f({ ruleId: 'win-defender-off', severity: 'high', source: 'events', ts: 3 * H, entities: { computer: 'WS-9' }, refs: [6] }),
    ]
    const inc = buildIncidents(rows, { gapMs: 6 * H })
    expect(inc.map((i) => i.kind)).toEqual(['entity', 'entity', 'entity'])
    const bobEarly = inc.find((i) => i.findings.some((x) => x.ruleId === 'win-bruteforce'))!
    expect(bobEarly.findings.map((x) => x.ruleId).sort()).toEqual(['win-bruteforce', 'win-new-service'])
    expect(bobEarly.title).toBe('bob')
    expect(bobEarly.tsEnd).toBe(2 * H)
    const bobLate = inc.find((i) => i.findings.some((x) => x.ruleId === 'win-log-cleared'))!
    expect(bobLate.findings).toHaveLength(1)
    expect(inc.find((i) => i.title === 'WS-9')!.findings[0].ruleId).toBe('win-defender-off')
    expect(inc[0].severity).toBe('critical')
  })

  it('keeps grouped mail findings and entity-less findings as their own incidents', () => {
    const rows = [
      f({ ruleId: 'mail-sender-burst', severity: 'medium', source: 'mails', refs: [1, 2, 3], count: 3, entities: { fromAddr: 'bulk@x.test' } }),
      f({ ruleId: 'sigma-something', severity: 'low', source: 'events', refs: [9], entities: { image: 'C:\\x.exe' } }),
    ]
    const inc = buildIncidents(rows)
    expect(inc.map((i) => i.kind)).toEqual(['group', 'group'])
    expect(inc[0].subtitle).toContain('fromAddr=bulk@x.test')
  })

  it('derives the status from the members', () => {
    const mk = (...s: Finding['status'][]) => s.map((status) => f({ ruleId: 'r', severity: 'low', source: 'events', status }))
    expect(deriveStatus(mk('new', 'reviewed'))).toBe('new')
    expect(deriveStatus(mk('reviewed', 'false_positive'))).toBe('reviewed')
    expect(deriveStatus(mk('false_positive', 'false_positive'))).toBe('false_positive')
    expect(deriveStatus(mk('new', 'escalated'))).toBe('escalated')
  })

  it('ignores comma lists and placeholders when picking the primary entity', () => {
    expect(primaryEntity(f({ ruleId: 'r', severity: 'low', source: 'events', entities: { targetUser: 'a, b', computer: 'WS-1' } }))).toEqual({ field: 'computer', value: 'WS-1' })
    expect(primaryEntity(f({ ruleId: 'r', severity: 'low', source: 'events', entities: { targetUser: '-', ipAddress: '10.0.0.1' } }))).toEqual({ field: 'ipAddress', value: '10.0.0.1' })
    expect(primaryEntity(f({ ruleId: 'r', severity: 'low', source: 'events', entities: { image: 'x' } }))).toBeNull()
  })
})

describe('false positives', () => {
  it('do not decide the severity or headline of an incident but stay listed', () => {
    const rows = [
      f({ ruleId: 'mail-credential-phishing', severity: 'critical', source: 'mails', refs: [7], status: 'false_positive', title: 'Credential phishing' }),
      f({ ruleId: 'mail-high-risk-score', severity: 'medium', source: 'mails', refs: [7], title: 'High overall risk score' }),
    ]
    const [inc] = buildIncidents(rows)
    expect(inc.severity).toBe('medium')
    expect(inc.lead.ruleId).toBe('mail-high-risk-score')
    expect(inc.findings).toHaveLength(2)
    expect(inc.status).toBe('new')
  })
})

const chainOf = (id: string, seedId: number, stepIds: number[], score = 80): Chain => ({
  id, identity: id, identityLabel: `${id}@corp.test`, start: 0, end: 10 * H, score, severity: 'high', artifactLinks: 1, summary: '',
  seed: { id: seedId, ts: 0, subject: 'Urgent invoice', fromAddr: 'x@evil.test', risk: 90, flags: [], findings: [], urlDomains: [], attachments: [] },
  steps: stepIds.map((sid, i) => ({ kind: 'event' as const, source: 'events' as const, id: sid, refs: i === 0 ? [sid, sid + 100] : undefined, ts: (i + 1) * H, tsEnd: (i + 1) * H, count: 1, title: `step ${sid}`, weight: 2, artifacts: [], findings: [], offsetMin: 60 })),
  entities: { user: id, ips: [], hosts: [], attackerAddresses: [], domains: [] },
})

describe('chain membership', () => {
  it('folds the chain row, the seed mail findings and the step findings into one chain incident', () => {
    const c = chainOf('alice', 7, [11, 12])
    const rows = [
      f({ ruleId: 'chain', key: 'chain|alice|7', severity: 'high', source: 'mails', refs: [7], ts: 0, title: 'Attack chain: alice' }),
      f({ ruleId: 'mail-credential-phishing', severity: 'critical', source: 'mails', refs: [7], ts: 0, entities: { subject: 'Urgent invoice' } }),
      f({ ruleId: 'win-logon-external', severity: 'medium', source: 'events', refs: [11], ts: H, entities: { targetUser: 'alice' } }),
      f({ ruleId: 'win-folded', severity: 'low', source: 'events', refs: [111], ts: H, entities: { targetUser: 'alice' } }),
      f({ ruleId: 'win-elsewhere', severity: 'high', source: 'events', refs: [99], ts: 2 * H, entities: { targetUser: 'alice' } }),
      f({ ruleId: 'win-burst', severity: 'high', source: 'events', refs: [11, 12, 500], ts: 2 * H, entities: { targetUser: 'alice' } }),
    ]
    const m = chainMembership(rows, [c])
    expect([...m.keys()].map((id) => rows.find((r) => r.id === id)!.ruleId).sort()).toEqual(['chain', 'mail-credential-phishing', 'win-folded', 'win-logon-external'])
    const inc = buildIncidents(rows, { chains: [c] })
    const ci = inc.find((i) => i.kind === 'chain')!
    expect(ci.id).toBe('chain:alice')
    expect(ci.chain).toBe(c)
    expect(ci.lead.ruleId).toBe('chain')
    expect(ci.severity).toBe('high')
    expect(ci.findings).toHaveLength(4)
    expect(ci.subtitle).toContain('3 linked findings')
    // the event outside the chain and the burst that reaches past it stay their own incident
    const others = inc.filter((i) => i.kind !== 'chain')
    expect(others).toHaveLength(1)
    expect(others[0].findings.map((x) => x.ruleId).sort()).toEqual(['win-burst', 'win-elsewhere'])
  })

  it('an unlinked finding leaves the chain and is decided on its own; the higher-scoring chain wins an overlap', () => {
    const a = chainOf('alice', 7, [11], 60)
    const b = chainOf('bob', 7, [11], 90)
    const rows = [
      f({ ruleId: 'mail-credential-phishing', severity: 'critical', source: 'mails', refs: [7], ts: 0, entities: { subject: 'Urgent invoice' } }),
      f({ ruleId: 'win-logon-external', severity: 'medium', source: 'events', refs: [11], ts: H, entities: { targetUser: 'alice' }, chainUnlinked: true }),
    ]
    const m = chainMembership(rows, [a, b])
    expect(m.get(rows[0].id!)).toBe('bob')
    expect(m.has(rows[1].id!)).toBe(false)
    const inc = buildIncidents(rows, { chains: [a, b], severityOf: (c) => (c.id === 'bob' ? 'critical' : c.severity) })
    expect(inc.map((i) => i.kind).sort()).toEqual(['chain', 'entity'])
    expect(inc.find((i) => i.kind === 'chain')!.severity).toBe('critical')
  })

  it('without chains nothing changes', () => {
    const rows = [f({ ruleId: 'chain', key: 'chain|alice|7', severity: 'high', source: 'mails', refs: [7] })]
    expect(buildIncidents(rows)[0].kind).toBe('mail')
    expect(chainMembership(rows, []).size).toBe(0)
  })
})
