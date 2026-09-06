import { describe, expect, it } from 'vitest'
import type { Finding } from '../db/schema'
import { buildIncidents, deriveStatus, primaryEntity } from './incidents'

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
