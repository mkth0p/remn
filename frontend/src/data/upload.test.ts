import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { chunkedUpload, forgetUpload } from './upload'
import { getDb } from '../db/schema'

// hashOnly spins a real web worker: stub it out. The stub is a plain function and not vi.fn,
// because a spy handles the promise it returns and would hide an unhandled rejection.
type HashOnly = (file: File, onProgress?: (p: number) => void, signal?: AbortSignal) => Promise<string>
const hash = vi.hoisted(() => ({ impl: null as HashOnly | null }))
vi.mock('./ingest', () => ({ hashOnly: ((file, onProgress, signal) => (hash.impl ? hash.impl(file, onProgress, signal) : Promise.resolve('cafe'.repeat(16)))) satisfies HashOnly }))

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
  hash.impl = null
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

describe('the hash beside a failed upload', () => {
  it('is stopped when the upload fails, rather than read the rest of the file for nothing', async () => {
    const file = makeFile(64)
    let hashSignal: AbortSignal | undefined
    hash.impl = (_file, _onProgress, signal) =>
      new Promise((_resolve, reject) => {
        hashSignal = signal
        signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))
      })
    fetchMock.mockImplementation(async (url: string) => {
      if (url === '/api/upload/init') return json({ uploadId: 'up3', chunkSize: 32 })
      return new Response('boom', { status: 500 })
    })
    await expect(chunkedUpload(file)).rejects.toThrow('chunk upload failed')
    expect(hashSignal?.aborted).toBe(true)
  })

  it('does not leave its own failure unhandled when the upload failed first', async () => {
    const file = makeFile(64)
    const unhandled: unknown[] = []
    const onUnhandled = (reason: unknown) => unhandled.push(reason)
    process.on('unhandledRejection', onUnhandled)
    let failHash: (e: Error) => void = () => undefined
    hash.impl = () => new Promise<string>((_resolve, reject) => (failHash = reject))
    fetchMock.mockImplementation(async (url: string) => {
      if (url === '/api/upload/init') return json({ uploadId: 'up4', chunkSize: 32 })
      return new Response('boom', { status: 500 })
    })
    try {
      await expect(chunkedUpload(file)).rejects.toThrow('chunk upload failed')
      failHash(new Error('the file could not be read'))
      await new Promise((r) => setTimeout(r, 20))
      expect(unhandled).toEqual([])
    } finally {
      process.off('unhandledRejection', onUnhandled)
    }
  })
})

describe('forgetUpload', () => {
  it('drops the resume record and asks the server to discard the partial', async () => {
    const db = getDb()
    await db.kv.put({ key: 'upload-big.bin-4096-1725000000000', value: { uploadId: 'u-9', name: 'big.bin', size: 4096, lastModified: 1725000000000, received: 1024 } })
    fetchMock.mockResolvedValueOnce(json({ deleted: true }))
    expect(await forgetUpload({ name: 'big.bin', size: 4096, lastModified: 1725000000000 })).toBe(true)
    expect(fetchMock.mock.calls.some(([url, init]) => String(url) === '/api/upload/u-9' && (init as RequestInit).method === 'DELETE')).toBe(true)
    expect(await db.kv.get('upload-big.bin-4096-1725000000000')).toBeUndefined()
    expect(await forgetUpload({ name: 'other.bin', size: 1, lastModified: 2 })).toBe(false)
  })
})
