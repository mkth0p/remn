import { describe, expect, it } from 'vitest'
import { compileCond, parseDuration, parseThreshold, ruleApplicable, ruleChannels, ruleEventIds, ruleFields, runRule, validateRule, type Rule, type RuleDiag } from './engine'

const T0 = Date.UTC(2026, 8, 1, 22, 0, 0)
let id = 1
const ev = (eventId: number, offsetS: number, extra: Record<string, unknown> = {}) => ({ id: id++, eventId, ts: T0 + offsetS * 1000, provider: 'Microsoft-Windows-Security-Auditing', ...extra })

describe('compileCond', () => {
  it('parses field|op keys, arrays and any_of groups', () => {
    const pred = compileCond({ eventId: 4625, 'ipAddress|exists': true, 'targetUser|not_endswith': '$', any_of: [{ 'subStatus|contains': 'c000006a' }, { 'status|contains': 'c000006a' }] })
    expect(pred({ eventId: 4625, ipAddress: '1.2.3.4', targetUser: 'bob', subStatus: '0xC000006A' })).toBe(true)
    expect(pred({ eventId: 4625, ipAddress: '1.2.3.4', targetUser: 'WS01$', subStatus: '0xC000006A' })).toBe(false)
    expect(pred({ eventId: 4624, ipAddress: '1.2.3.4', targetUser: 'bob' })).toBe(false)
  })
  it('rejects unknown operators', () => {
    expect(() => compileCond({ 'x|bogus': 1 })).toThrow()
  })
})

describe('helpers', () => {
  it('parses durations and thresholds', () => {
    expect(parseDuration('5m')).toBe(300000)
    expect(parseDuration('2h')).toBe(7200000)
    expect(parseDuration('bad')).toBeNull()
    expect(parseThreshold('>= 5')!(5)).toBe(true)
    expect(parseThreshold('>= 5')!(4)).toBe(false)
    expect(parseThreshold('== 1')!(2)).toBe(false)
    expect(parseThreshold(3)!(3)).toBe(true)
  })
  it('extracts pinned event ids and referenced fields', () => {
    expect(ruleEventIds({ eventId: 4625 })).toEqual([4625])
    expect(ruleEventIds({ 'eventId|in': [1, 2] })).toEqual([1, 2])
    expect(ruleEventIds({ any_of: [{ eventId: 4624, logonType: 10 }, { eventId: 1149 }] })).toEqual([4624, 1149])
    expect(ruleEventIds({ any_of: [{ eventId: 4624 }, { 'provider|contains': 'x' }] })).toBeNull()
    // all_of: any member that pins ids bounds the rule; several pinned members intersect
    expect(ruleEventIds({ all_of: [{ 'channel|contains': 'sysmon', eventId: 1 }, { 'image|endswith': 'x.exe' }] })).toEqual([1])
    expect(ruleEventIds({ all_of: [{ any_of: [{ eventId: 1 }, { eventId: 4688 }] }, { 'eventId|in': [1, 7] }] })).toEqual([1])
    expect(ruleEventIds({ all_of: [{ any_of: [{ eventId: 1 }, { eventId: 4688 }] }, { eventId: 7045 }] })).toEqual([1, 4688])
    expect(ruleEventIds({ all_of: [{ 'image|endswith': 'x' }] })).toBeNull()
    expect(Array.from(ruleFields({ 'bodyText|re': 'x', any_of: [{ subject: 'y' }] }))).toEqual(['bodyText', 'subject'])
  })
})

describe('runRule', () => {
  const brute: Rule = {
    id: 'bf',
    title: 'brute',
    severity: 'high',
    source: 'events',
    where: { eventId: 4625, 'ipAddress|exists': true },
    group_by: ['ipAddress'],
    window: '5m',
    threshold: '>= 5',
    then: { where: { eventId: 4624 }, join: ['ipAddress'], within: '15m', severity: 'critical', title: 'success after burst' },
  }
  it('detects a burst inside a sliding window and escalates on follow-up', () => {
    const rows = [
      ...Array.from({ length: 6 }, (_, i) => ev(4625, i * 30, { ipAddress: '10.9.9.9', targetUser: 'admin' })),
      ...Array.from({ length: 3 }, (_, i) => ev(4625, i * 30, { ipAddress: '10.8.8.8', targetUser: 'bob' })),
      ev(4625, 3600, { ipAddress: '10.9.9.9', targetUser: 'admin' }), // isolated, outside the burst
    ]
    const success = ev(4624, 400, { ipAddress: '10.9.9.9', targetUser: 'admin', logonType: 3 })
    const findings = runRule(brute, { rows, thenRows: () => [success] })
    expect(findings).toHaveLength(1)
    const f = findings[0]
    expect(f.entities.ipAddress).toBe('10.9.9.9')
    expect(f.count).toBe(6)
    expect(f.severity).toBe('critical')
    expect(f.title).toContain('success after burst')
    expect(f.refs).toContain(success.id)
  })
  it('counts distinct values for spraying', () => {
    const spray: Rule = { id: 'spray', title: 's', severity: 'high', source: 'events', where: { eventId: 4625 }, group_by: ['ipAddress'], window: '30m', distinct: 'targetUser', threshold: '>= 3' }
    const rows = ['a', 'b', 'c', 'a'].map((u, i) => ev(4625, i * 10, { ipAddress: '1.1.1.1', targetUser: u }))
    const f = runRule(spray, { rows })
    expect(f).toHaveLength(1)
    expect(f[0].entities.targetUser).toBe('a, b, c')
    expect(runRule(spray, { rows: rows.slice(0, 2) })).toHaveLength(0)
  })
  it('produces one finding per row for simple rules and applies time conditions', () => {
    const night: Rule = {
      id: 'night',
      title: 'n',
      severity: 'medium',
      source: 'events',
      where: { eventId: 4624, 'logonType|in': [2, 10] },
      time: { outside_business_hours: true },
      exclude: { 'targetUser|in_setting': 'service_accounts' },
    }
    const rows = [ev(4624, 0, { logonType: 10, targetUser: 'alice' }), ev(4624, 0, { logonType: 10, targetUser: 'svc_x' }), ev(4624, 12 * 3600, { logonType: 10, targetUser: 'alice' })]
    const settings = { businessHours: { start: 8, end: 19, tz: 'UTC' }, weekendDays: [0, 6], service_accounts: ['svc_x'] }
    const f = runRule(night, { rows, settings })
    expect(f).toHaveLength(1)
    expect(f[0].entities.targetUser).toBe('alice')
  })
  it('excludes trusted senders via flag and via domain-suffix setting', () => {
    const vip: Rule = {
      id: 'vip',
      title: 'v',
      severity: 'critical',
      source: 'mails',
      where: { 'fromNameNorm|in_setting': 'vip_names', 'fromRegistrable|nin_setting': 'internal_domains' },
      exclude: { any_of: [{ 'flags|contains': 'trusted_sender' }, { 'fromRegistrable|in_setting': 'trusted_senders' }, { 'fromAddr|in_setting': 'trusted_senders' }] },
      entities: ['fromNameNorm', 'fromRegistrable'],
    }
    const rows = [
      { id: 1, date: T0, fromNameNorm: 'lefevre marie', fromRegistrable: 'microsoft.com', fromAddr: 'noreply@email.teams.microsoft.com', flags: ['trusted_sender'] },
      { id: 2, date: T0, fromNameNorm: 'lefevre marie', fromRegistrable: 'example-saas.com', fromAddr: 'mentions@old.example-saas.com', flags: [] },
      { id: 3, date: T0, fromNameNorm: 'lefevre marie', fromRegistrable: 'interne-fr.co', fromAddr: 'marie.lefevre@interne-fr.co', flags: [] },
    ]
    const settings = { vip_names: ['Marie Lefevre'], internal_domains: ['interne.fr'], trusted_senders: ['example-saas.com'] }
    const f = runRule(vip, { rows, settings })
    expect(f).toHaveLength(1)
    expect(f[0].entities.fromRegistrable).toBe('interne-fr.co')
  })
  it('groups without a window (same name, different domains)', () => {
    const same: Rule = { id: 'same', title: 's', severity: 'high', source: 'mails', where: { 'fromNameNorm|exists': true }, group_by: ['fromNameNorm'], distinct: 'fromRegistrable', threshold: '>= 2' }
    const rows = [
      { id: 1, date: T0, fromNameNorm: 'lefevre marie', fromRegistrable: 'interne.fr' },
      { id: 2, date: T0 + 1000, fromNameNorm: 'lefevre marie', fromRegistrable: 'interne-fr.co' },
      { id: 3, date: T0 + 2000, fromNameNorm: 'dupont jean', fromRegistrable: 'interne.fr' },
    ]
    const f = runRule(same, { rows })
    expect(f).toHaveLength(1)
    expect(f[0].entities.fromRegistrable).toContain('interne-fr.co')
    expect(f[0].refs).toEqual([1, 2])
  })
  it('escalates severity with then_flags', () => {
    const r: Rule = { id: 'macro', title: 'm', severity: 'high', source: 'mails', where: { 'flags|contains': 'att_office_macro' }, then_flags: [{ att_macro_autoexec: 'critical' }] }
    const f = runRule(r, {
      rows: [
        { id: 1, date: T0, flags: ['att_office_macro', 'att_macro_autoexec'] },
        { id: 2, date: T0, flags: ['att_office_macro'] },
      ],
    })
    expect(f.map((x) => x.severity)).toEqual(['critical', 'high'])
  })
})

describe('diagnostics', () => {
  it('explains why a rule produced zero findings', () => {
    const rows = [ev(4625, 0, { ipAddress: '1.1.1.1', targetUser: 'a' }), ev(4625, 10, { ipAddress: '1.1.1.1', targetUser: 'svc_x' })]
    const diag = (rule: Rule, settings?: Record<string, unknown>): RuleDiag | undefined => {
      let d: RuleDiag | undefined
      runRule(rule, { rows, settings, onDiag: (x) => (d = x) })
      return d
    }
    expect(diag({ id: 'absent', title: 'a', severity: 'low', source: 'events', where: { eventId: 1102 } })?.reason).toBe('no_selector_match')
    expect(diag({ id: 'vip', title: 'v', severity: 'low', source: 'events', where: { 'targetUser|in_setting': 'vip_names' } }, { vip_names: [] })?.reason).toBe('missing_setting')
    expect(diag({ id: 'req', title: 'r', severity: 'low', source: 'events', where: { eventId: 4625 }, require_setting: 'internal_ips' }, {})?.reason).toBe('missing_setting')
    const excl = diag({ id: 'excl', title: 'e', severity: 'low', source: 'events', where: { eventId: 4625 }, exclude: { 'targetUser|in': ['a', 'svc_x'] } })
    expect(excl?.reason).toBe('all_excluded')
    expect(excl?.matched).toBe(2)
    const thr = diag({ id: 'thr', title: 't', severity: 'low', source: 'events', where: { eventId: 4625 }, group_by: ['ipAddress'], window: '5m', threshold: '>= 5' })
    expect(thr?.reason).toBe('below_threshold')
    let fired: RuleDiag | undefined
    const found = runRule({ id: 'ok', title: 'o', severity: 'low', source: 'events', where: { eventId: 4625 } }, { rows, onDiag: (x) => (fired = x) })
    expect(found).toHaveLength(2)
    expect(fired).toBeUndefined()
  })
})

describe('validateRule', () => {
  it('accepts valid rules and reports problems', () => {
    expect(validateRule({ id: 'a', title: 't', severity: 'low', source: 'events', where: { eventId: 1 } }).ok).toBe(true)
    expect(validateRule({ id: 'a', title: 't', severity: 'nope', source: 'events' }).ok).toBe(false)
    expect(validateRule({ id: 'a', title: 't', severity: 'low', source: 'events', where: { 'x|re': '(' } }).ok).toBe(false)
    expect(validateRule({ id: 'a', title: 't', severity: 'low', source: 'events', threshold: 'lots' }).ok).toBe(false)
  })
})

describe('applicability', () => {
  const present = { eventIds: new Set([4624, 4625]), channels: ['security', 'system'] }
  const rule = (where: Rule['where']): Rule => ({ id: 'r', title: 'r', severity: 'low', source: 'events', where })
  it('pins channels like event ids: exact, contains, any_of (all alternatives), all_of (any member)', () => {
    expect(ruleChannels({ channel: 'Security', eventId: 4688 })).toEqual([{ value: 'security', contains: false }])
    expect(ruleChannels({ 'channel|contains': 'sysmon' })).toEqual([{ value: 'sysmon', contains: true }])
    expect(
      ruleChannels({
        any_of: [
          { 'channel|contains': 'sysmon', eventId: 1 },
          { channel: 'Security', eventId: 4688 },
        ],
      }),
    ).toEqual([
      { value: 'sysmon', contains: true },
      { value: 'security', contains: false },
    ])
    expect(ruleChannels({ any_of: [{ channel: 'Security' }, { 'image|contains': 'x' }] })).toBeNull()
    expect(ruleChannels({ all_of: [{ 'image|contains': 'x' }, { channel: 'System' }] })).toEqual([{ value: 'system', contains: false }])
    expect(ruleChannels({ 'image|contains': 'x' })).toBeNull()
  })
  it('skips rules whose event ids or channels are absent and keeps the rest', () => {
    expect(ruleApplicable(rule({ eventId: 4688 }), present)).toEqual({ ok: false, detail: 'no event id 4688 in this evidence' })
    expect(ruleApplicable(rule({ eventId: 4624, 'channel|contains': 'sysmon' }), present)).toEqual({ ok: false, detail: 'no "sysmon" channel in this evidence' })
    expect(ruleApplicable(rule({ eventId: 4624, channel: 'Security' }), present)).toEqual({ ok: true })
    expect(ruleApplicable(rule({ targetUser: 'alice' }), present)).toEqual({ ok: true })
    expect(ruleApplicable({ ...rule({ 'risk|gte': 80 }), source: 'mails' }, { eventIds: new Set(), channels: [] })).toEqual({ ok: true })
  })
})
