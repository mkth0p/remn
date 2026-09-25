import { describe, expect, it } from 'vitest'
import { iocsToStix } from './export'
import type { Case, Ioc } from '../db/schema'

const kase = { id: 1, name: 'Case' } as Case
const ioc = (kind: string, value: string, verdict?: string): Ioc => ({ caseId: 1, kind, value, verdict, count: 2, sources: ['mails'], tags: [] }) as unknown as Ioc

describe('STIX 2.1 export', () => {
  it('escapes quotes and backslashes in every pattern', async () => {
    const b = (await iocsToStix(kase, [ioc('email', "sean.o'brien@example.ie", 'suspicious'), ioc('url', 'https://evil.example/a\\', 'malicious')])) as { objects: Record<string, string>[] }
    const patterns = b.objects.filter((o) => o.type === 'indicator').map((o) => o.pattern)
    expect(patterns).toEqual(["[email-addr:value = 'sean.o\\'brien@example.ie']", "[url:value = 'https://evil.example/a\\\\']"])
  })

  it('makes indicators only of flagged values, observables of the rest, with ids that do not change', async () => {
    const rows = [ioc('domain', 'contoso.com'), ioc('ip', '198.51.100.7', 'malicious')]
    const a = (await iocsToStix(kase, rows)) as { objects: Record<string, unknown>[] }
    const b = (await iocsToStix(kase, rows)) as { objects: Record<string, unknown>[] }
    expect(a.objects.map((o) => o.type)).toEqual(['identity', 'domain-name', 'ipv4-addr', 'indicator'])
    expect(a.objects.map((o) => o.id)).toEqual(b.objects.map((o) => o.id))
    // the STIX 2.1 deterministic id of domain-name "contoso.com": UUIDv5 in the SCO namespace over
    // {"value":"contoso.com"}, as Python's uuid.uuid5 computes it
    expect(a.objects[1].id).toBe('domain-name--9149e804-cc28-5e74-907e-f50cb89af4b3')
  })
})
