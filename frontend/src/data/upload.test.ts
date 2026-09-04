import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { chunkedUpload } from './upload'
import { getDb } from '../db/schema'

// hashOnly spins a real web worker: stub it out
vi.mock('./ingest', () => ({ hashOnly: vi.fn(async () => 'cafe'.repeat(16)) }))

const fetchMock = vi.fn()

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function makeFile(size: number): File {
  const f = new File([new Uint8Array(size)], 'big.bin', { lastModified: 1725000000000 })
  return f
}

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})
afterEach(async () => {
  vi.unstubAllGlobals()
  await getDb().kv.clear()
})

describe('chunkedUpload resume', () => {
  it('keeps the kv record and server partial on transient failure, resumes on retry', async () => {
    const file = makeFile(64)
    // 1st attempt: init ok, first chunk fails 3 times -> throw, NO delete
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      if (url === '/api/upload/init') return json({ uploadId: 'up1', chunkSize: 32 })
      if (url.startsWith('/api/upload/up1/chunk')) return new Response('boom', { status: 500 })
      throw new Error(`unexpected ${init?.method} ${url}`)
    })
    await expect(chunkedUpload(file)).rejects.toThrow('chunk upload failed')
    expect(fetchMock.mock.calls.some(([u, i]) => String(u) === '/api/upload/up1' && (i as RequestInit)?.method === 'DELETE')).toBe(false)
    const rec = await getDb().kv.get('upload-big.bin-64-1725000000000')
    expect((rec?.value as { uploadId: string }).uploadId).toBe('up1')

    // 2nd attempt (same file re-dropped): status says 32 bytes are there -> resume without init
    fetchMock.mockReset()
    let completed = false
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      const u = String(url)
      if (u === '/api/upload/up1' && (!init?.method || init.method === 'GET')) return json({ received: 32, complete: false, size: 64 })
      if (u.startsWith('/api/upload/up1/chunk?offset=32')) return json({ received: 64 })
      if (u === '/api/upload/up1/complete') {
        completed = true
        return json({ sha256: 'cafe'.repeat(16), size: 64 })
      }
      throw new Error(`unexpected ${init?.method} ${u}`)
    })
    const res = await chunkedUpload(file)
    expect(completed).toBe(true)
    expect(res.resumedFrom).toBe(32)
    expect(fetchMock.mock.calls.some(([u]) => String(u) === '/api/upload/init')).toBe(false)
    expect(await getDb().kv.get('upload-big.bin-64-1725000000000')).toBeUndefined()
  })

  it('discards the partial and the kv record on explicit cancel', async () => {
    const file = makeFile(64)
    const ctrl = new AbortController()
    const deletes: string[] = []
    fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
      const u = String(url)
      if (u === '/api/upload/init') return json({ uploadId: 'up2', chunkSize: 32 })
      if (u.startsWith('/api/upload/up2/chunk')) {
        ctrl.abort()
        throw new DOMException('aborted', 'AbortError')
      }
      if (u === '/api/upload/up2' && init?.method === 'DELETE') {
        deletes.push(u)
        return json({ deleted: true })
      }
      throw new Error(`unexpected ${init?.method} ${u}`)
    })
    await expect(chunkedUpload(file, undefined, ctrl.signal)).rejects.toThrow()
    expect(deletes).toEqual(['/api/upload/up2'])
    expect(await getDb().kv.get('upload-big.bin-64-1725000000000')).toBeUndefined()
  })
})
