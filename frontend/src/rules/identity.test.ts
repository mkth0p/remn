import { describe, expect, it } from 'vitest'
import { resolveUsers } from './identity'
import { buildIncidents } from './incidents'
import type { Finding } from '../db/schema'

describe('one person, one key', () => {
  it('joins DOMAIN\\user, user@domain and a bare name of the same account', () => {
    const r = resolveUsers(['daniel.roy', 'NORTHSTAR\\daniel.roy', 'daniel.roy@northstar.example'])
    expect(new Set([...r.values()].map((x) => x.key))).toEqual(new Set(['daniel.roy@northstar.example']))
    expect(r.get('northstar\\daniel.roy')?.label).toBe('daniel.roy@northstar.example')
  })

  it('never joins accounts of different tenants, and leaves an ambiguous bare name apart', () => {
    const r = resolveUsers(['alice.martin@northstar.example', 'alice.martin@other-tenant.example', 'alice.martin'])
    expect(r.get('alice.martin@northstar.example')?.key).not.toBe(r.get('alice.martin@other-tenant.example')?.key)
    expect(r.get('alice.martin')?.key).toBe('alice.martin')
  })

  it('gives an ambiguous bare name to the internal domain when the case names it', () => {
    const r = resolveUsers(['alice.martin@northstar.example', 'alice.martin@other-tenant.example', 'alice.martin'], ['northstar.example'])
    expect(r.get('alice.martin')?.key).toBe('alice.martin@northstar.example')
  })

  it('leaves machine accounts, SIDs and a NetBIOS domain it cannot place as they are', () => {
    const r = resolveUsers(['WS01$', 'S-1-5-18', 'CONTOSO\\bob', 'bob@fabrikam.example'])
    expect(r.has('ws01$')).toBe(false)
    expect(r.get('contoso\\bob')?.key).toBe('bob@netbios:contoso')
    expect(r.get('bob@fabrikam.example')?.key).not.toBe(r.get('contoso\\bob')?.key)
  })

  it('makes one incident of one person seen under three spellings', () => {
    let id = 1
    const f = (user: string, ruleId: string): Finding =>
      ({
        id: id++,
        caseId: 1,
        ruleId,
        key: `${ruleId}|${id}`,
        title: ruleId,
        severity: 'high',
        source: 'events',
        ts: 1_000 + id,
        entities: { targetUser: user },
        count: 1,
        refs: [id],
        attack: [],
        tags: [],
        status: 'new',
        createdAt: 0,
      }) as Finding
    const incidents = buildIncidents([f('daniel.roy', 'a'), f('NORTHSTAR\\daniel.roy', 'b'), f('daniel.roy@northstar.example', 'c')])
    expect(incidents).toHaveLength(1)
    expect(incidents[0].title).toBe('daniel.roy@northstar.example')
  })
})
