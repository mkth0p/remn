import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { RemnDB, setDb, type Case } from '../db/schema'
import { useStore } from '../state/store'
import { chunkedUpload } from './upload'
import { waitForJob, type JobInfo } from './jobs'
import { apiGet, apiPost } from '../api/client'

// invented server answers: one upload, one ingest job, two engine findings
vi.mock('./upload', () => ({ chunkedUpload: vi.fn(async () => ({ uploadId: 'u1', sha256Client: 'ab', sha256Server: 'ab', size: 10 })), forgetUpload: vi.fn(async () => false) }))
const done: JobInfo = {
  id: 'j1',
  kind: 'ingest',
  label: '',
  status: 'done',
  progress: {},
  error: null,
  log: [],
  result: { count: 4, format: 'evtx', findings: [{ engine: 'hayabusa' }, { engine: 'hayabusa' }] },
}
vi.mock('./jobs', () => ({ waitForJob: vi.fn() }))
vi.mock('./engineFindings', () => ({ persistEngineFindings: vi.fn(async () => 2) }))
vi.mock('./duplicateEvidence', () => ({ duplicateEvidence: vi.fn(async () => undefined) }))
vi.mock('./findingsState', () => ({ autoRunAfterIngest: vi.fn() }))
vi.mock('../api/client', () => ({ apiPost: vi.fn(async () => ({ jobId: 'j1' })), apiGet: vi.fn(), API_HEADERS: {} }))

const kase = { id: 1, name: 'c', createdAt: 0, updatedAt: 0, storage: 'server', serverKey: 'k'.repeat(16), settings: {} } as unknown as Case
const evtx = (name: string) => ({ name, size: 10, webkitRelativePath: '', lastModified: 0 }) as unknown as File
const file = evtx('host-a-security.evtx')

/** Wait until the store lists a job in the given phase, and return its id. */
async function jobIn(phase: string): Promise<number> {
  for (let i = 0; i < 200; i++) {
    const job = useStore.getState().jobs.find((j) => j.phase === phase)
    if (job) return job.id
    await new Promise((r) => setTimeout(r, 5))
  }
  throw new Error(`no job reached ${phase}`)
}

describe('an import into the server store', () => {
  let db: RemnDB
  const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) => new Response('{"deleted":true}', { status: 200 }))
  beforeEach(() => {
    db = new RemnDB(`ingest-server-${Math.random()}`)
    setDb(db)
    useStore.setState({ console: [], toasts: [], jobs: [] } as never)
    vi.mocked(waitForJob).mockReset()
    vi.mocked(waitForJob).mockResolvedValue(done)
    vi.mocked(chunkedUpload).mockClear()
    vi.mocked(apiGet).mockReset()
    vi.mocked(apiPost).mockClear()
    fetchMock.mockClear()
    vi.stubGlobal('fetch', fetchMock)
  })
  afterEach(async () => {
    vi.unstubAllGlobals()
    await db.delete()
  })

  it('names the file in the console line about the findings of an engine', async () => {
    const { ingestToServer } = await import('./ingest')
    await ingestToServer(file, kase, 'evtx')
    const lines = useStore.getState().console.map((l) => l.text)
    expect(lines).toContain('[host-a-security.evtx] 2 finding(s) from hayabusa stored')
  })

  it('can be cancelled while the server parses: the job is stopped, then its rows and evidence are removed', async () => {
    const order: string[] = []
    // the job runs until the import is cancelled, then ends as cancelled
    vi.mocked(waitForJob).mockImplementation(async (_id, _caseKey, _onProgress, signal) => {
      if (!signal) {
        order.push('settled')
        throw new Error('cancelled')
      }
      await new Promise<void>((resolve) => signal.addEventListener('abort', () => resolve()))
      order.push('stop asked')
      throw new Error('cancelled')
    })
    fetchMock.mockImplementation(async (url: string) => {
      order.push(`DELETE ${url}`)
      return new Response('{"deleted":true}', { status: 200 })
    })
    const { cancelImport, ingestToServer } = await import('./ingest')
    const running = ingestToServer(file, kase, 'evtx')
    const jobId = await jobIn('parsing')
    const evidenceId = (await db.evidence.toArray())[0].id
    cancelImport(jobId)
    await running
    // the rows go only once the job has stopped, or it would write after their removal
    expect(order).toEqual(['stop asked', 'settled', `DELETE /api/store/${kase.serverKey}/evidence/${evidenceId}`])
    expect(await db.evidence.count()).toBe(0)
    expect(useStore.getState().jobs).toEqual([])
    const lines = useStore.getState().console.map((l) => l.text)
    expect(lines.some((l) => l.startsWith('[host-a-security.evtx] import cancelled'))).toBe(true)
    expect(lines.some((l) => l.includes('rows stored on the server'))).toBe(false)
  })

  it('cancelled during the upload, leaves nothing on the server to remove and only drops its evidence entry', async () => {
    vi.mocked(chunkedUpload).mockImplementationOnce(
      (_file, _onProgress, signal) => new Promise((_resolve, reject) => signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))),
    )
    const { cancelImport, ingestToServer } = await import('./ingest')
    const running = ingestToServer(file, kase, 'evtx')
    cancelImport(await jobIn('hashing'))
    await running
    expect(waitForJob).not.toHaveBeenCalled()
    expect(fetchMock).not.toHaveBeenCalled()
    expect(await db.evidence.count()).toBe(0)
    expect(useStore.getState().jobs).toEqual([])
  })

  it('cancelled in a drop of several files, does not import the files after it, and says how many', async () => {
    vi.mocked(chunkedUpload).mockImplementationOnce(
      (_file, _onProgress, signal) => new Promise((_resolve, reject) => signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')))),
    )
    const { cancelImport, ingestFiles } = await import('./ingest')
    const running = ingestFiles([evtx('a.evtx'), evtx('b.evtx'), evtx('c.evtx')], kase, () => 'evtx')
    cancelImport(await jobIn('hashing'))
    await running
    expect(chunkedUpload).toHaveBeenCalledTimes(1)
    expect(await db.evidence.count()).toBe(0)
    expect(useStore.getState().console.map((l) => l.text)).toContain('import cancelled: 2 more file(s) of this drop were not imported')
  })

  it('numbers the file above the highest evidence number the server holds, so another browser’s file is not refused', async () => {
    const { ingestToServer } = await import('./ingest')
    // invented case summary: another browser added evidence #7 and #12 to the case
    vi.mocked(apiGet).mockResolvedValue({ evidence: [{ id: 7 }, { id: 12 }] })
    await db.evidence.add({ caseId: 2, name: 'other-case.evtx', size: 1, kind: 'evtx', integrity: 'verified', addedAt: 1, status: 'done', count: 0 })
    const id = await ingestToServer(file, kase, 'evtx')
    expect(id).toBe(13)
    expect(vi.mocked(apiGet).mock.calls[0][0]).toBe(`/api/store/${kase.serverKey}`)
    const sent = vi.mocked(apiPost).mock.calls.find(([url]) => url.endsWith('/ingest'))![1] as { evidence: { id: number } }
    expect(sent.evidence.id).toBe(13)
    expect((await db.evidence.get(13))?.name).toBe('host-a-security.evtx')
    // the browser's own numbering goes on above it
    vi.mocked(apiGet).mockResolvedValue({ evidence: [{ id: 7 }, { id: 12 }, { id: 13 }] })
    expect(await ingestToServer(evtx('host-b-security.evtx'), kase, 'evtx')).toBe(14)
  })

  it('keeps the browser’s own number when it is already above the server’s, or the server’s list cannot be read', async () => {
    const { ingestToServer } = await import('./ingest')
    await db.evidence.bulkAdd([20, 21].map((id) => ({ id, caseId: 2, name: `other-${id}.evtx`, size: 1, kind: 'evtx', integrity: 'verified', addedAt: 1, status: 'done', count: 0 }) as never))
    vi.mocked(apiGet).mockResolvedValue({ evidence: [{ id: 3 }] })
    expect(await ingestToServer(file, kase, 'evtx')).toBe(22)
    vi.mocked(apiGet).mockRejectedValue(new Error('no store for this case yet'))
    expect(await ingestToServer(evtx('host-b-security.evtx'), kase, 'evtx')).toBe(23)
    expect(await db.evidence.where('caseId').equals(1).count()).toBe(2)
  })
})
