import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { RemnDB, setDb, type Case, type Evidence } from '../db/schema'
import { useStore } from '../state/store'
import { apiPost } from '../api/client'
import { waitForJob, type JobInfo } from './jobs'

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

  it('removes the evidence, imports the file with the setting, keeps the note and says what the server did', async () => {
    const { readAgain } = await import('./ingest')
    const id = await readAgain(evidence, file, kase, { zone: 'Europe/Paris' }, async () => 'ab')
    expect(removed).toEqual([evidence.id])
    const body = vi.mocked(apiPost).mock.calls[0][1] as { options: Record<string, unknown> }
    expect(body.options.dates).toEqual({ zone: 'Europe/Paris' })
    expect(await db.evidence.get(id)).toMatchObject({ dates: { zone: 'Europe/Paris' }, note: 'from the admin', stats: { zoneSet: 3 } })
    const lines = useStore.getState().console.map((l) => l.text)
    expect(lines).toContain(
      `[enhanced-summary.csv] evidence #${evidence.id} removed to be read again: dates in the order the file shows, times without a zone in Europe/Paris, as set for the evidence`,
    )
    expect(lines).toContain(
      '[enhanced-summary.csv] dates in the order the file shows, times without a zone in Europe/Paris, as set for the evidence: 3 record(s) were read in Europe/Paris: their times say none',
    )
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
