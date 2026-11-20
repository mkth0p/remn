import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case, type Ioc } from '../db/schema'

// the server job a rule run waits on: the test hands back the job as the server would finish it
const job = vi.hoisted(() => ({ result: {} as unknown, progress: [] as unknown[] }))
vi.mock('./jobs', () => ({
  waitForJob: async (_id: string, _key: string, onJob: (j: { progress: unknown }) => void) => {
    for (const p of job.progress) onJob({ progress: p })
    return { result: job.result }
  },
}))

const { getSource } = await import('./source')

let db: RemnDB
const browser: Case = { id: 1, name: 'browser case', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
const server: Case = { ...browser, id: 2, name: 'server case', storage: 'server', serverKey: 'k-7' }
const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) => new Response('{}', { status: 200 }))
const lastCall = () => {
  const [url, init] = fetchMock.mock.calls[fetchMock.mock.calls.length - 1]
  return { url, method: init?.method ?? 'GET', body: init?.body ? JSON.parse(String(init.body)) : null }
}
const answer = (body: unknown, status = 200) => fetchMock.mockImplementationOnce(async () => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } }))

beforeEach(async () => {
  db = new RemnDB(`source-${Math.random()}`)
  setDb(db)
  fetchMock.mockClear()
  vi.stubGlobal('fetch', fetchMock)
  job.result = {}
  job.progress = []
})
afterEach(async () => {
  vi.unstubAllGlobals()
  db.close()
  await db.delete()
})

// invented indicators of one case
const ioc = (kind: Ioc['kind'], value: string, count: number, patch: Partial<Ioc> = {}): Ioc => ({ caseId: 1, kind, value, sources: ['events'], firstSeen: 1, lastSeen: 2, count, ...patch })

describe('the data source of a case', () => {
  it('is the server store only for a server case that has a store key', () => {
    expect(getSource(browser).kind).toBe('browser')
    expect(getSource(server).kind).toBe('server')
    expect(getSource({ ...server, serverKey: undefined }).kind).toBe('browser')
  })
})

describe('the browser store', () => {
  it('reads an event or a mail of its own case only, a mail with its body', async () => {
    await db.events.bulkAdd([
      { id: 10, caseId: 1, evidenceId: 1, ts: 1, eventId: 4624 },
      { id: 11, caseId: 9, evidenceId: 2, ts: 1, eventId: 4625 },
    ])
    await db.mails.add({ id: 20, caseId: 1, evidenceId: 1, ts: 1, subject: 'Invoice 4471' } as never)
    await db.mailBodies.add({ caseId: 1, mailId: 20, text: 'see the attachment' } as never)
    const src = getSource(browser)
    expect(await src.getEvent(10)).toMatchObject({ id: 10, eventId: 4624 })
    expect(await src.getEvent(11)).toBeNull()
    expect(await src.getMail(20)).toMatchObject({ row: { subject: 'Invoice 4471' }, body: { text: 'see the attachment' } })
    expect(await src.getMail(21)).toBeNull()
  })

  it('lists indicators worst first, then by count, filtered and paged, with the count of every kind', async () => {
    await db.iocs.bulkAdd([
      ioc('ip', '198.51.100.7', 3, { verdict: 'malicious', checkedAt: 5 }),
      ioc('ip', '203.0.113.9', 40),
      ioc('domain', 'files.example.net', 12, { verdict: 'suspicious', checkedAt: 5 }),
      ioc('url', 'https://files.example.net/Invoice.HTA', 2),
      ioc('domain', 'cdn.example.org', 7, { verdict: 'clean', checkedAt: 5 }),
      { ...ioc('ip', '192.0.2.1', 99), caseId: 9 },
    ])
    const src = getSource(browser)
    const all = await src.listIocs({})
    expect(all.rows.map((r) => r.value)).toEqual(['198.51.100.7', 'files.example.net', 'cdn.example.org', '203.0.113.9', 'https://files.example.net/Invoice.HTA'])
    expect(all).toMatchObject({ total: 5, kinds: { ip: 2, domain: 2, url: 1 } })
    // a URL keeps the case of its path: the search ignores case on both sides
    expect((await src.listIocs({ q: 'invoice.hta' })).rows.map((r) => r.value)).toEqual(['https://files.example.net/Invoice.HTA'])
    expect((await src.listIocs({ kind: 'ip' })).rows.map((r) => r.value)).toEqual(['198.51.100.7', '203.0.113.9'])
    expect((await src.listIocs({ onlyBad: true })).rows.map((r) => r.value)).toEqual(['198.51.100.7', 'files.example.net'])
    expect((await src.listIocs({ unchecked: true })).total).toBe(2)
    const page = await src.listIocs({ offset: 1, limit: 2 })
    expect(page.rows.map((r) => r.value)).toEqual(['files.example.net', 'cdn.example.org'])
    expect(page.total).toBe(5)
  })

  it('records a reputation on the indicator it names and leaves the others', async () => {
    await db.cases.add(browser)
    await db.iocs.bulkAdd([ioc('ip', '198.51.100.7', 3), ioc('ip', '203.0.113.9', 4)])
    await getSource(browser).setIocReputation([{ kind: 'ip', value: '198.51.100.7', verdict: 'malicious', tags: ['c2'], summary: { hits: 4 }, verdicts: { a: 'bad' }, checkedAt: 77 }])
    const [hit, other] = await db.iocs.orderBy('value').toArray()
    expect(hit).toMatchObject({ verdict: 'malicious', tags: ['c2'], checkedAt: 77, reputation: { summary: { hits: 4 }, verdicts: { a: 'bad' } } })
    expect(other.verdict).toBeUndefined()
  })
})

describe('the server store', () => {
  it('asks the case store for rows with the case settings the rules use', async () => {
    answer({ rows: [{ id: 1, eventId: 4624 }], truncated: true })
    const res = await getSource(server).searchEvents({ conditions: [], sort: { field: 'ts', dir: 'desc' } } as never, 50)
    expect(res).toEqual({ rows: [{ id: 1, eventId: 4624 }], truncated: true })
    const call = lastCall()
    expect(call).toMatchObject({ url: '/api/store/k-7/search', method: 'POST', body: { source: 'events', limit: 50, sort: { field: 'ts', dir: 'desc' } } })
    expect(call.body.settings).toBeTruthy()
    answer({ count: 12 })
    expect(await getSource(server).countMails({ conditions: [] } as never)).toBe(12)
    expect(lastCall()).toMatchObject({ url: '/api/store/k-7/count', body: { source: 'mails' } })
  })

  it('lists indicators with their filters in the address and numbers the rows from the offset', async () => {
    answer({ rows: [{ kind: 'ip', value: '198.51.100.7', count: '3', verdict: 'malicious', summary: { hits: 4 } }], total: 31, kinds: { ip: 31 } })
    const res = await getSource(server).listIocs({ kind: 'ip', q: '198', onlyBad: true, unchecked: true, offset: 30, limit: 10, sort: 'count' })
    const url = new URL(lastCall().url, 'http://remn.invalid')
    expect(url.pathname).toBe('/api/store/k-7/iocs')
    expect(Object.fromEntries(url.searchParams)).toEqual({ kind: 'ip', q: '198', bad: '1', unchecked: '1', limit: '10', offset: '30', sort: 'count' })
    expect(res.rows).toEqual([
      {
        id: 31,
        caseId: 2,
        kind: 'ip',
        value: '198.51.100.7',
        sources: [],
        firstSeen: null,
        lastSeen: null,
        count: 3,
        verdict: 'malicious',
        tags: [],
        checkedAt: null,
        reputation: { summary: { hits: 4 }, verdicts: undefined },
      },
    ])
    expect(res).toMatchObject({ total: 31, kinds: { ip: 31 } })
  })

  it('reads a mail with its body tied to the case, and nothing when the store refuses', async () => {
    answer({ id: 5, subject: 'Payroll', body: { text: 'hello' } })
    expect(await getSource(server).getMail(5)).toEqual({ row: { id: 5, subject: 'Payroll' }, body: { text: 'hello', caseId: 2, mailId: 5 } })
    expect(lastCall().url).toBe('/api/store/k-7/row?source=mails&id=5')
    answer({ error: 'no such row' }, 404)
    expect(await getSource(server).getEvent(6)).toBeNull()
  })

  it('runs the rules as a server job, reports its progress and names each rule that failed', async () => {
    answer({ jobId: 'j-1' })
    job.progress = [{ index: 1, total: 2, ruleId: 'win-a', findings: 3 }, {}]
    job.result = { findings: [{ ruleId: 'win-a' }], byRule: { 'win-a': 3 }, errors: [{ ruleId: 'win-b', error: 'unknown field' }] }
    const progress = vi.fn()
    const res = await getSource(server).runRules([{ id: 'win-a' }, { id: 'win-b' }] as never, progress)
    expect(lastCall()).toMatchObject({ url: '/api/store/k-7/rules/run', body: { rules: [{ id: 'win-a' }, { id: 'win-b' }] } })
    expect(progress.mock.calls).toEqual([[1, 2, 'win-a', 3]])
    expect(res).toEqual({ findings: [{ ruleId: 'win-a' }], byRule: { 'win-a': 3 }, errors: ['win-b: unknown field'], diagnostics: [] })
  })

  it('says so when the server refuses to delete an evidence, and keeps it listed', async () => {
    await db.evidence.add({ id: 4, caseId: 2, name: 'Security.evtx', size: 1, kind: 'evtx', integrity: 'verified', addedAt: 1, status: 'done', count: 2 })
    fetchMock.mockImplementationOnce(async () => new Response('', { status: 503 }))
    await expect(getSource(server).deleteEvidence(4)).rejects.toThrow('server refused the deletion (HTTP 503)')
    expect(lastCall()).toMatchObject({ url: '/api/store/k-7/evidence/4', method: 'DELETE' })
    expect(await db.evidence.get(4)).toBeTruthy()
  })
})
