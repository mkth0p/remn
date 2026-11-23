import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { RemnDB, setDb, type Case, type Evidence } from '../db/schema'
import { useStore } from '../state/store'
import { apiPost } from '../api/client'
import { waitForJob, type JobInfo } from './jobs'
import type { IngestRequest } from '../workers/ingest.worker'

// invented server answers: an upload, then an ingest job that read a message trace in the zone set for it
vi.mock('./upload', () => ({ chunkedUpload: vi.fn(async () => ({ uploadId: 'u2', sha256Client: 'ab', sha256Server: 'ab', size: 10 })), forgetUpload: vi.fn(async () => false) }))
vi.mock('./jobs', () => ({ waitForJob: vi.fn() }))
vi.mock('./engineFindings', () => ({ persistEngineFindings: vi.fn(async () => 0) }))
vi.mock('./duplicateEvidence', () => ({ duplicateEvidence: vi.fn(async () => undefined) }))
vi.mock('./findingsState', () => ({ autoRunAfterIngest: vi.fn() }))
vi.mock('../api/client', () => ({ apiPost: vi.fn(async () => ({ jobId: 'j2' })), apiGet: vi.fn(), API_HEADERS: {} }))
const removed: number[] = []
vi.mock('./source', () => ({ getSource: () => ({ deleteEvidence: async (id: number) => (removed.push(id), { findings: 0, chains: 0 }) }) }))

const kase = { id: 1, name: 'c', createdAt: 0, updatedAt: 0, storage: 'server', serverKey: 'k'.repeat(16), settings: {} } as unknown as Case
const file = { name: 'enhanced-summary.csv', size: 10, webkitRelativePath: '', lastModified: 0 } as unknown as File
const read: JobInfo = {
  id: 'j2',
  kind: 'ingest',
  label: '',
  status: 'done',
  progress: {},
  error: null,
  log: [],
  result: { count: 3, format: 'package', stats: { count: 3, dates: { zone: 'Europe/Paris' }, zoneSet: 3 } },
}

describe('reading an evidence file again with a date setting', () => {
  let db: RemnDB
  let evidence: Evidence
  beforeEach(async () => {
    db = new RemnDB(`ingest-again-${Math.random()}`)
    setDb(db)
    useStore.setState({ console: [], toasts: [], jobs: [] } as never)
    removed.length = 0
    vi.mocked(apiPost).mockClear()
    vi.mocked(waitForJob).mockResolvedValue(read)
    const stats = { count: 3, zoneAssumed: 3 }
    const id = await db.evidence.add({
      caseId: 1,
      name: 'enhanced-summary.csv',
      kind: 'package',
      size: 10,
      sha256Client: 'ab',
      integrity: 'verified',
      status: 'done',
      count: 3,
      addedAt: 1,
      stats,
      note: 'from the admin',
    })
    evidence = (await db.evidence.get(id))!
  })
  afterEach(async () => {
    await db.delete()
  })

  it('imports the file with the setting, then removes the evidence it replaces, keeps the note and says what the server did', async () => {
    // what had been removed when the server finished reading the new copy
    let removedWhileReading: number[] | undefined
    vi.mocked(waitForJob).mockImplementation(async () => ((removedWhileReading = [...removed]), read))
    const { readAgain } = await import('./ingest')
    const id = await readAgain(evidence, file, kase, { zone: 'Europe/Paris' }, async () => 'ab')
    expect(removedWhileReading).toEqual([])
    expect(removed).toEqual([evidence.id])
    expect(id).not.toBe(evidence.id)
    const body = vi.mocked(apiPost).mock.calls[0][1] as { options: Record<string, unknown> }
    expect(body.options.dates).toEqual({ zone: 'Europe/Paris' })
    // the server is told which evidence the read replaces, so its records are not taken for repeats
    expect(body.options.replaces).toBe(evidence.id)
    expect(await db.evidence.get(id)).toMatchObject({ dates: { zone: 'Europe/Paris' }, note: 'from the admin', stats: { zoneSet: 3 } })
    const lines = useStore.getState().console.map((l) => l.text)
    expect(lines).toContain(
      `[enhanced-summary.csv] evidence #${evidence.id} read again: dates in the order the file shows, times without a zone in Europe/Paris, as set for the evidence; it is replaced once the new read succeeds`,
    )
    expect(lines).toContain(`[enhanced-summary.csv] evidence #${evidence.id} replaced by evidence #${id}`)
    expect(lines).toContain(
      '[enhanced-summary.csv] dates in the order the file shows, times without a zone in Europe/Paris, as set for the evidence: 3 record(s) were read in Europe/Paris: their times say none',
    )
  })

  it('keeps the evidence as it was when the new read fails, and removes what the failed read wrote', async () => {
    vi.mocked(waitForJob).mockRejectedValue(new Error('the parse stopped'))
    const { readAgain } = await import('./ingest')
    const before = await db.evidence.count()
    await expect(readAgain(evidence, file, kase, { zone: 'Europe/Paris' }, async () => 'ab')).rejects.toThrow(`the new read failed: the parse stopped; evidence #${evidence.id} is kept as it was`)
    expect(removed).toHaveLength(1)
    expect(removed[0]).not.toBe(evidence.id)
    expect(await db.evidence.get(evidence.id!)).toMatchObject({ status: 'done', note: 'from the admin', stats: { zoneAssumed: 3 } })
    expect(await db.evidence.count()).toBe(before + 1)
    const lines = useStore.getState().console.map((l) => l.text)
    expect(lines).toContain(`[enhanced-summary.csv] evidence #${evidence.id} kept as it was: the new read failed: the parse stopped`)
  })

  it('reads the file again in a case kept in this browser, and replaces the evidence only when the read succeeds', async () => {
    const local = { ...kase, storage: 'browser', serverKey: undefined } as unknown as Case
    const sent: IngestRequest[] = []
    let outcome: 'done' | 'error' = 'done'
    class FakeWorker {
      onmessage: ((e: MessageEvent<Record<string, unknown>>) => void) | null = null
      onerror: ((e: ErrorEvent) => void) | null = null
      postMessage(req: IngestRequest) {
        sent.push(req)
        void (async () => {
          // what the worker writes on the evidence, then what it says
          if (outcome === 'done') await db.evidence.update(req.evidenceId, { status: 'done', count: 3, integrity: 'verified' })
          else await db.evidence.update(req.evidenceId, { status: 'error', error: 'the stream ended early' })
          this.onmessage?.({ data: outcome === 'done' ? { type: 'done', count: 3, integrity: 'verified', stats: null } : { type: 'error', error: 'the stream ended early' } } as MessageEvent)
        })()
      }
      terminate() {}
    }
    vi.stubGlobal('Worker', FakeWorker)
    try {
      const { readAgain } = await import('./ingest')
      outcome = 'error'
      await expect(readAgain(evidence, file, local, { order: 'day-first' }, async () => 'ab')).rejects.toThrow(`evidence #${evidence.id} is kept as it was`)
      expect(removed).toEqual([sent[0].evidenceId])
      outcome = 'done'
      const id = await readAgain(evidence, file, local, { order: 'day-first' }, async () => 'ab')
      expect(sent.map((r) => r.replaces)).toEqual([evidence.id, evidence.id])
      expect(removed).toEqual([sent[0].evidenceId, evidence.id])
      expect(await db.evidence.get(id)).toMatchObject({ status: 'done', note: 'from the admin', dates: { order: 'day-first' } })
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('refuses a file that is not the one the evidence was read from, and keeps the evidence', async () => {
    const { readAgain } = await import('./ingest')
    await expect(readAgain(evidence, file, kase, { order: 'day-first' }, async () => 'cd')).rejects.toThrow(
      "enhanced-summary.csv is not the file of this evidence: its SHA-256 is cd, the evidence's ab",
    )
    expect(removed).toEqual([])
    expect(apiPost).not.toHaveBeenCalled()
  })

  it('sends no setting when none is set, and says a guess in the console', async () => {
    vi.mocked(waitForJob).mockResolvedValue({ ...read, result: { count: 3, format: 'package', stats: { count: 3, dateOrderGuessed: 3 } } })
    const { ingestToServer } = await import('./ingest')
    await ingestToServer(file, kase, 'package')
    const body = vi.mocked(apiPost).mock.calls[0][1] as { options: Record<string, unknown> }
    expect('dates' in body.options).toBe(false)
    const line = useStore.getState().console.find((l) => l.text.includes('dated month-first'))
    expect(line?.level).toBe('warn')
    expect(line?.text).toContain('The evidence detail sets the date order and zone to read it again.')
  })
})
