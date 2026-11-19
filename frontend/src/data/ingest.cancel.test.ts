import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { RemnDB, setDb, type Case, type EventRow } from '../db/schema'
import { useStore } from '../state/store'

vi.mock('./upload', () => ({ chunkedUpload: vi.fn(), forgetUpload: vi.fn(async () => false) }))
vi.mock('./findingsState', () => ({ autoRunAfterIngest: vi.fn() }))
vi.mock('../api/client', () => ({ apiPost: vi.fn(), apiGet: vi.fn(), API_HEADERS: {} }))

/** Stands for the ingest worker: records what it is sent and whether it was stopped. */
class FakeWorker {
  static all: FakeWorker[] = []
  onmessage: ((ev: MessageEvent) => void) | null = null
  onerror: ((ev: ErrorEvent) => void) | null = null
  received: { cmd: string }[] = []
  terminated = false
  constructor() {
    FakeWorker.all.push(this)
  }
  postMessage(msg: { cmd: string }) {
    this.received.push(msg)
    // the rebuild of facets and indicators that follows a removal
    if (msg.cmd === 'rebuild') queueMicrotask(() => this.onmessage?.({ data: { type: 'rebuilt', rows: 0, iocs: 0 } } as MessageEvent))
  }
  send(data: Record<string, unknown>) {
    this.onmessage?.({ data } as MessageEvent)
  }
  terminate() {
    this.terminated = true
  }
}

const kase = { id: 1, name: 'c', createdAt: 0, updatedAt: 0, storage: 'browser', settings: {} } as unknown as Case
const file = { name: 'host-b-system.evtx', size: 10, webkitRelativePath: '', lastModified: 0 } as unknown as File

describe('cancelling an import into the browser store', () => {
  let db: RemnDB
  beforeEach(() => {
    db = new RemnDB(`ingest-cancel-${Math.random()}`)
    setDb(db)
    FakeWorker.all = []
    vi.stubGlobal('Worker', FakeWorker)
    useStore.setState({ console: [], toasts: [], jobs: [] } as never)
  })
  afterEach(async () => {
    vi.unstubAllGlobals()
    await db.delete()
  })

  it('stops the worker and removes the rows it had written with the evidence entry', async () => {
    const { cancelImport, ingestToBrowser } = await import('./ingest')
    const running = ingestToBrowser(file, kase, 'evtx')
    await vi.waitFor(() => expect(FakeWorker.all[0]?.received[0]?.cmd).toBe('ingest'))
    const worker = FakeWorker.all[0]
    const evidenceId = (await db.evidence.toArray())[0].id!
    // the worker has written its first batches
    await db.events.bulkAdd(Array.from({ length: 3 }, (_, i) => ({ caseId: 1, evidenceId, ts: i, eventId: 7045, data: {} }) as unknown as EventRow))
    worker.send({ type: 'progress', rows: 3 })
    const jobId = useStore.getState().jobs[0].id
    cancelImport(jobId)
    expect(worker.terminated).toBe(true)
    // a message already on its way from the stopped worker changes nothing
    worker.send({ type: 'done', count: 3, integrity: 'verified' })
    await running
    expect(await db.events.count()).toBe(0)
    expect(await db.evidence.count()).toBe(0)
    expect(useStore.getState().jobs).toEqual([])
    const lines = useStore.getState().console.map((l) => l.text)
    expect(lines).toContain('[host-b-system.evtx] import cancelled: the 3 row(s) it had written were removed')
    expect(lines.some((l) => l.includes('rows stored'))).toBe(false)
  })

  it('only drops the evidence entry when nothing had been written yet', async () => {
    const { cancelImport, ingestToBrowser } = await import('./ingest')
    const running = ingestToBrowser(file, kase, 'evtx')
    await vi.waitFor(() => expect(FakeWorker.all[0]?.received[0]?.cmd).toBe('ingest'))
    cancelImport(useStore.getState().jobs[0].id)
    await running
    // no rebuild of the case's facets and indicators for an import that wrote nothing
    expect(FakeWorker.all.map((w) => w.received.map((m) => m.cmd))).toEqual([['ingest']])
    expect(await db.evidence.count()).toBe(0)
    expect(useStore.getState().console.map((l) => l.text)).toContain('[host-b-system.evtx] import cancelled: nothing had been written')
  })
})
