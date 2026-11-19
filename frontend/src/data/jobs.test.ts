import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { waitForJob } from './jobs'

const fetchMock = vi.fn()
const answer = (status: string) =>
  new Response(JSON.stringify({ id: 'job1', kind: 'rules', label: '', status, progress: {}, error: null, log: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } })
beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})
afterEach(() => vi.unstubAllGlobals())

describe('waitForJob', () => {
  it('presents the case key on every read of the job', async () => {
    fetchMock.mockResolvedValueOnce(answer('running')).mockResolvedValueOnce(answer('done'))
    expect((await waitForJob('job1', 'case-key-1', undefined, undefined, 0)).status).toBe('done')
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual(['/api/jobs/job1?case=case-key-1', '/api/jobs/job1?case=case-key-1'])
  })

  it('presents the case key when it cancels the job', async () => {
    fetchMock.mockResolvedValue(new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }))
    const stop = new AbortController()
    stop.abort()
    await expect(waitForJob('job1', 'case-key-1', undefined, stop.signal)).rejects.toThrow('cancelled')
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/jobs/job1?case=case-key-1')
    expect(init.method).toBe('DELETE')
  })
})
