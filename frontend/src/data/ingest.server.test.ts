import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { RemnDB, setDb, type Case } from '../db/schema'
import { useStore } from '../state/store'

// invented server answers: one upload, one ingest job, two engine findings
vi.mock('./upload', () => ({ chunkedUpload: vi.fn(async () => ({ uploadId: 'u1', sha256Client: 'ab', sha256Server: 'ab', size: 10 })) }))
vi.mock('./jobs', () => ({
  waitForJob: vi.fn(async () => ({ id: 'j1', status: 'done', result: { count: 4, format: 'evtx', findings: [{ engine: 'hayabusa' }, { engine: 'hayabusa' }] } })),
}))
vi.mock('./engineFindings', () => ({ persistEngineFindings: vi.fn(async () => 2) }))
vi.mock('./duplicateEvidence', () => ({ duplicateEvidence: vi.fn(async () => undefined) }))
vi.mock('./findingsState', () => ({ autoRunAfterIngest: vi.fn() }))
vi.mock('../api/client', () => ({ apiPost: vi.fn(async () => ({ jobId: 'j1' })), apiGet: vi.fn(), API_HEADERS: {} }))

const kase = { id: 1, name: 'c', createdAt: 0, updatedAt: 0, storage: 'server', serverKey: 'k'.repeat(16), settings: {} } as unknown as Case
const file = { name: 'host-a-security.evtx', size: 10, webkitRelativePath: '', lastModified: 0 } as unknown as File

describe('an import into the server store', () => {
  let db: RemnDB
  beforeEach(() => {
    db = new RemnDB(`ingest-server-${Math.random()}`)
    setDb(db)
    useStore.setState({ console: [], toasts: [], jobs: [] } as never)
  })
  afterEach(async () => {
    await db.delete()
  })

  it('names the file in the console line about the findings of an engine', async () => {
    const { ingestToServer } = await import('./ingest')
    await ingestToServer(file, kase, 'evtx')
    const lines = useStore.getState().console.map((l) => l.text)
    expect(lines).toContain('[host-a-security.evtx] 2 finding(s) from hayabusa stored')
  })
})
