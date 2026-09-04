import { describe, expect, it } from 'vitest'
import { compileFilter, extractEventIds, getPath, ipInCidr, isOutsideHours, localHourAndDay, matchCondition } from './filter'

const row = {
  eventId: 4625,
  ts: Date.UTC(2026, 8, 1, 22, 13, 40),
  targetUser: 'Administrator',
  ipAddress: '10.1.2.3',
  logonType: 3,
  flags: ['spf_fail', 'att_office_macro'],
  attachments: [{ name: 'a.docm', flags: ['office_macro'] }, { name: 'b.pdf', flags: ['pdf_javascript'] }],
  data: { LogonType: '3', Status: '0xc000006d' },
  raw: '{"System":{"EventID":4625}}',
}

describe('getPath', () => {
  it('reads nested and flattened array paths', () => {
    expect(getPath(row, 'data.Status')).toBe('0xc000006d')
    expect(getPath(row, 'attachments.name')).toEqual(['a.docm', 'b.pdf'])
    expect(getPath(row, 'attachments.flags')).toEqual(['office_macro', 'pdf_javascript'])
    expect(getPath(row, 'missing.x')).toBeUndefined()
  })
})

describe('matchCondition', () => {
  it('compares strings case-insensitively and numbers numerically', () => {
    expect(matchCondition(row, { field: 'targetUser', op: 'eq', value: 'administrator' })).toBe(true)
    expect(matchCondition(row, { field: 'eventId', op: 'eq', value: 4625 })).toBe(true)
    expect(matchCondition(row, { field: 'eventId', op: 'in', value: [4624, 4625] })).toBe(true)
    expect(matchCondition(row, { field: 'logonType', op: 'gte', value: 3 })).toBe(true)
    expect(matchCondition(row, { field: 'data.LogonType', op: 'eq', value: 3 })).toBe(true)
    expect(matchCondition(row, { field: 'data.Status', op: 'contains', value: 'C000006D' })).toBe(true)
  })
  it('handles arrays with contains / contains_any / not_contains', () => {
    expect(matchCondition(row, { field: 'flags', op: 'contains', value: 'spf_fail' })).toBe(true)
    expect(matchCondition(row, { field: 'flags', op: 'contains_any', value: ['x', 'att_office_macro'] })).toBe(true)
    expect(matchCondition(row, { field: 'flags', op: 'not_contains', value: 'dkim_fail' })).toBe(true)
    expect(matchCondition(row, { field: 'attachments.flags', op: 'contains', value: 'pdf_javascript' })).toBe(true)
    // object values are matched on their JSON, not "[object Object]" (data|contains: USBSTOR style rules)
    expect(matchCondition({ data: { Path: 'USBSTOR\\Disk&Ven' } }, { field: 'data', op: 'contains', value: 'usbstor' })).toBe(true)
    expect(matchCondition({ data: { Path: 'PCI\\VEN' } }, { field: 'data', op: 'contains', value: 'usbstor' })).toBe(false)
    // comma-joined strings from LLM-built filters are treated as lists
    expect(matchCondition(row, { field: 'flags', op: 'in', value: 'dkim_fail,spf_fail' })).toBe(true)
    expect(matchCondition(row, { field: 'flags', op: 'contains_any', value: 'nope, att_office_macro' })).toBe(true)
  })
  it('supports regex, prefix/suffix and existence', () => {
    expect(matchCondition(row, { field: 'targetUser', op: 're', value: '^admin' })).toBe(true)
    expect(matchCondition(row, { field: 'targetUser', op: 're', value: '(?i)^ADMIN' })).toBe(true)
    expect(matchCondition(row, { field: 'targetUser', op: 'not_endswith', value: '$' })).toBe(true)
    expect(matchCondition(row, { field: 'workstation', op: 'exists' })).toBe(false)
    expect(matchCondition(row, { field: 'workstation', op: 'empty' })).toBe(true)
  })
  it('resolves settings lists (CIDR, names, domains)', () => {
    const settings = { internal_ips: ['10.0.0.0/8'], vip_names: ['Lefevre Marie'], internal_domains: ['interne.fr'] }
    expect(matchCondition(row, { field: 'ipAddress', op: 'in_setting', value: 'internal_ips' }, settings)).toBe(true)
    expect(matchCondition({ ipAddress: '8.8.8.8' }, { field: 'ipAddress', op: 'nin_setting', value: 'internal_ips' }, settings)).toBe(true)
    expect(matchCondition({ fromNameNorm: 'lefevre marie' }, { field: 'fromNameNorm', op: 'in_setting', value: 'vip_names' }, settings)).toBe(true)
    expect(matchCondition({ fromNameNorm: 'marie lefevre' }, { field: 'fromNameNorm', op: 'in_setting', value: 'vip_names' }, settings)).toBe(true)
    expect(matchCondition({ fromRegistrable: 'mail.interne.fr' }, { field: 'fromRegistrable', op: 'in_setting', value: 'internal_domains' }, settings)).toBe(true)
    expect(matchCondition({ fromRegistrable: 'interne-fr.co' }, { field: 'fromRegistrable', op: 'nin_setting', value: 'internal_domains' }, settings)).toBe(true)
  })
})

describe('ipInCidr', () => {
  it('matches v4 ranges and exact ips', () => {
    expect(ipInCidr('192.168.1.10', '192.168.0.0/16')).toBe(true)
    expect(ipInCidr('172.32.0.1', '172.16.0.0/12')).toBe(false)
    expect(ipInCidr('127.0.0.1', '127.0.0.1')).toBe(true)
    expect(ipInCidr('fe80::1', 'fe80::/10')).toBe(true)
  })
})

describe('compileFilter', () => {
  it('applies time range, conditions, regex and text', () => {
    const f = compileFilter({ conditions: [{ field: 'eventId', op: 'eq', value: 4625 }], timeRange: { from: '2026-09-01T00:00:00Z', to: '2026-09-02T00:00:00Z' }, regex: { field: '*', pattern: 'EventID":4625' }, text: 'administrator' })
    expect(f(row)).toBe(true)
    expect(f({ ...row, ts: Date.UTC(2026, 8, 3) })).toBe(false)
    expect(compileFilter({ conditions: [{ field: 'eventId', op: 'eq', value: 4624 }, { field: 'eventId', op: 'eq', value: 4625 }], logic: 'or' })(row)).toBe(true)
  })
  it('handles hour ranges with time zones', () => {
    // 22:13 UTC = 00:13 in Europe/Paris (CEST) -> outside 8-19
    expect(compileFilter({ hourRange: { from: 8, to: 19, outside: true, tz: 'Europe/Paris' } })(row)).toBe(true)
    expect(compileFilter({ hourRange: { from: 8, to: 19, outside: false, tz: 'Europe/Paris' } })(row)).toBe(false)
    expect(localHourAndDay(row.ts, 'Europe/Paris').hour).toBe(0)
    expect(isOutsideHours(23, 22, 6)).toBe(false)
    expect(isOutsideHours(12, 22, 6)).toBe(true)
  })
})

describe('extractEventIds', () => {
  it('finds pinned ids for index pre-selection', () => {
    expect(extractEventIds([{ field: 'eventId', op: 'in', value: [4624, 4625] }, { field: 'x', op: 'eq', value: 1 }])).toEqual([4624, 4625])
    expect(extractEventIds([{ field: 'eventId', op: 'ne', value: 1 }])).toBeNull()
    expect(extractEventIds([{ field: 'eventId', op: 'eq', value: 1 }, { field: 'y', op: 'eq', value: 2 }], 'or')).toBeNull()
  })
})
