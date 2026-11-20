import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case } from '../db/schema'
import { wipeCase } from './caseState'

vi.mock('../api/client', () => ({ apiPost: vi.fn(), API_HEADERS: {} }))
vi.mock('./rules', () => ({ settingsForRules: (k: Case) => ({ internal_domains: k.settings.internalDomains }) }))

const kase: Case = { id: 1, name: 'Stale', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
const finding = (key: string, ruleId = 'mail-x'): Record<string, unknown> => ({
  caseId: 1,
  ruleId,
  key,
  title: key,
  severity: 'high',
  source: 'mails',
  ts: 1,
  entities: {},
  count: 1,
  refs: [1],
  attack: [],
  tags: [],
  status: 'new',
  createdAt: 1,
})
let db: RemnDB

beforeEach(() => {
  db = new RemnDB(`wipe-${Math.random()}`)
  setDb(db)
})
afterEach(async () => {
  await db.delete()
})

describe('emptying a case', () => {
  const server: Case = { id: 3, name: 'Server', storage: 'server', serverKey: 'k3', createdAt: 3, updatedAt: 3, settings: defaultSettings() }
  const seed = async () => {
    await db.cases.add(server)
    await db.evidence.add({ caseId: 3, name: 'a.evtx' } as never)
    await db.findings.add({ ...finding('f-3'), caseId: 3 } as never)
  }
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('keeps every browser record when the server refuses to delete its store, and says so', async () => {
    await seed()
    const fetchMock = vi.fn(async () => new Response('{"detail":"unauthorised"}', { status: 401 }))
    vi.stubGlobal('fetch', fetchMock)
    await expect(wipeCase(server)).rejects.toThrow(/HTTP 401.*nothing was deleted/)
    expect(fetchMock).toHaveBeenCalledWith('/api/store/k3', expect.objectContaining({ method: 'DELETE' }))
    expect(await db.evidence.where('caseId').equals(3).count()).toBe(1)
    expect(await db.findings.where('caseId').equals(3).count()).toBe(1)
  })

  it('keeps every browser record when the server cannot be reached', async () => {
    await seed()
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('Failed to fetch')
      }),
    )
    await expect(wipeCase(server)).rejects.toThrow(/could not be reached.*nothing was deleted/)
    expect(await db.evidence.where('caseId').equals(3).count()).toBe(1)
  })

  it('empties the browser side once the server store is gone, and keeps the case', async () => {
    await seed()
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => new Response(null, { status: 404 })),
    )
    await wipeCase(server)
    expect(await db.evidence.where('caseId').equals(3).count()).toBe(0)
    expect(await db.findings.where('caseId').equals(3).count()).toBe(0)
    expect(await db.cases.get(3)).toBeDefined()
  })

  it('never asks a server about a browser case', async () => {
    await db.cases.add(kase)
    await db.events.add({ caseId: 1, evidenceId: 1, ts: 1, eventId: 4624, channel: 'Security', data: {} } as never)
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    await wipeCase(kase)
    expect(fetchMock).not.toHaveBeenCalled()
    expect(await db.events.where('caseId').equals(1).count()).toBe(0)
  })
})
