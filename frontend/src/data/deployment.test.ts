import { describe, expect, it } from 'vitest'
import { deployment } from './deployment'
import type { Health } from '../api/client'

const health = (over: Partial<Health>): Health =>
  ({ ok: true, name: 'REMN', version: '0.1.1', stateless: true, limits: { maxUploadMb: 512, inMemoryMb: 256 }, ollama: {}, optional: {}, providers: [], ...over }) as Health

describe('deployment', () => {
  it('names the host that parses the evidence on a public instance', () => {
    const d = deployment(
      health({ mode: 'browser-only', build: '0.1.1+abcdef123456', source: 'https://example.org/tree/abc', profile: 'public', limits: { maxUploadMb: 512, inMemoryMb: 256, uploadMaxAgeS: 1800 } }),
      'remn.tech',
    )
    expect(d.tier).toBe('uploaded-not-kept')
    expect(d.parsing).toContain('uploaded to remn.tech')
    expect(d.parsing).not.toContain('local server')
    expect(d.isolated).toBe(true)
    expect(d.abandonedMinutes).toBe(30)
    expect(d.source).toBe('https://example.org/tree/abc')
  })

  it('claims no isolation the server does not declare', () => {
    const d = deployment(health({ mode: 'browser-only' }), 'remn.example.org')
    expect(d.isolated).toBe(false)
    expect(d.abandonedMinutes).toBeNull()
  })

  it('says this machine when the page is served from loopback', () => {
    for (const host of ['localhost', '127.0.0.1', '[::1]']) expect(deployment(health({ mode: 'browser-only' }), host).tier).toBe('this-machine')
    expect(deployment(health({ mode: 'full' }), 'remn.corp.example').tier).toBe('self-hosted')
  })

  it('reports a page built from another commit than the server', () => {
    expect(deployment(health({ build: '0.1.1+aaaaaaaaaaaa' }), 'x.example').mismatch).toBe(typeof __REMN_BUILD__ === 'string' && !__REMN_BUILD__.endsWith('+unknown'))
    expect(deployment(health({ build: '0.1.1+unknown' }), 'x.example').mismatch).toBe(false)
  })
})
