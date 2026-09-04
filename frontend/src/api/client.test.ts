import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { API_HEADERS, apiGet, onAuthError, setApiToken } from './client'
import { uuid4 } from '../util/uuid'

const fetchMock = vi.fn()
beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})
afterEach(() => {
  vi.unstubAllGlobals()
  setApiToken(null)
  onAuthError(null)
})

describe('setApiToken', () => {
  it('mutates the shared header object in place', () => {
    const ref = API_HEADERS
    setApiToken('tok-123')
    expect(ref['X-Forensic-Client']).toBe('tok-123')
    setApiToken(null)
    expect(ref['X-Forensic-Client']).toBe('remn')
  })

  it('is sent on requests', async () => {
    setApiToken('tok-abc')
    fetchMock.mockResolvedValueOnce(new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }))
    await apiGet('/api/health')
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect((init.headers as Record<string, string>)['X-Forensic-Client']).toBe('tok-abc')
  })
})

describe('onAuthError', () => {
  it('fires on 401 with code auth and the error still throws', async () => {
    const handler = vi.fn()
    onAuthError(handler)
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ error: 'invalid access token', code: 'auth' }), { status: 401, headers: { 'Content-Type': 'application/json' } }))
    await expect(apiGet('/api/health')).rejects.toThrow('invalid access token')
    expect(handler).toHaveBeenCalledTimes(1)
  })

  it('does not fire on plain 401 without the auth code', async () => {
    const handler = vi.fn()
    onAuthError(handler)
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ error: 'nope' }), { status: 401, headers: { 'Content-Type': 'application/json' } }))
    await expect(apiGet('/x')).rejects.toThrow()
    expect(handler).not.toHaveBeenCalled()
  })
})

describe('uuid4', () => {
  it('produces v4-shaped ids', () => {
    expect(uuid4()).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
  })

  it('falls back to getRandomValues when randomUUID is missing (insecure context)', () => {
    const orig = globalThis.crypto
    vi.stubGlobal('crypto', { getRandomValues: (b: Uint8Array) => orig.getRandomValues(b) })
    try {
      expect(uuid4()).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    } finally {
      vi.unstubAllGlobals()
    }
  })
})
