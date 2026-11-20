import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterEach, beforeAll, expect, it, vi } from 'vitest'
import { getDb } from '../db/schema'
import type { IngestRequest } from './ingest.worker'

const mocks = vi.hoisted(() => ({ stream: vi.fn(), post: vi.fn() }))
vi.mock('../api/client', () => ({ streamNdjson: mocks.stream, setApiToken: vi.fn() }))
vi.mock('../parsers/evtx/load', async () => {
  const { EvtxDecoder } = await import('../parsers/evtx/decoder')
  return { loadEvtxDecoder: () => EvtxDecoder.load(readFileSync(join(__dirname, '../parsers/evtx/evtx.wasm'))) }
})
vi.mock('hash-wasm', () => ({ createSHA256: async () => ({ init: () => {}, update: () => {}, digest: () => 'a'.repeat(64) }) }))
const context = { postMessage: mocks.post, onmessage: null as unknown as (e: { data: IngestRequest }) => Promise<void> }

let IocCounter: typeof import('./ingest.worker').IocCounter
beforeAll(async () => {
  vi.stubGlobal('self', context)
  IocCounter = (await import('./ingest.worker')).IocCounter
})
afterEach(async () => {
  for (const table of getDb().tables) await table.clear()
  mocks.stream.mockReset()
  mocks.post.mockClear()
})

async function run(rows: Record<string, unknown>[], done = true) {
  const db = getDb()
  const id = await db.evidence.add({ caseId: 1, name: 'package.zip', kind: 'package', size: 1, status: 'hashing', integrity: 'pending', count: 0, addedAt: 1 })
  mocks.stream.mockImplementation(async (_url, _form, onRow) => {
    await onRow({ type: 'meta', format: 'investigation-package', sha256: 'a'.repeat(64) })
    for (const row of rows) await onRow({ ...row })
    if (done) await onRow({ type: 'done', sha256: 'a'.repeat(64), stats: { count: rows.length, files: [], unsupported: 1 } })
  })
  await context.onmessage({
    data: { cmd: 'ingest', jobId: 1, caseId: 1, evidenceId: id, file: new File(['x'], 'package.zip'), kind: 'package', includeRaw: true, settings: { internalDomains: [], brands: [], vipNames: [] } },
  })
  return id
}

it('keeps alternating mail and observation rows in their own stores, facets and child tables', async () => {
  const mail = {
    type: 'mail',
    subject: 'test',
    fromAddr: 'sender@example.test',
    fromDomain: 'example.test',
    risk: 0,
    date: 1,
    attachments: [{ name: 'a.bin', sha256: 'b'.repeat(64), flags: [] }],
    urls: [],
    bodyText: 'message',
  }
  const event = { type: 'event', eventId: null, ts: null, recordKind: 'observation', artifactType: 'process', sourceFile: 'Processes/data.csv', computer: 'WS01' }
  const id = await run([mail, event, mail, event])
  const db = getDb()
  expect(await db.events.count()).toBe(2)
  expect(await db.mails.count()).toBe(2)
  expect(await db.mailBodies.count()).toBe(2)
  expect(await db.attachments.count()).toBe(2)
  expect((await db.events.toArray()).every((r) => r.recordKind === 'observation' && r.ts === null && r.sourceFile === 'Processes/data.csv')).toBe(true)
  const facets = await db.facets.toArray()
  expect(facets.find((f) => f.field === 'computer')).toMatchObject({ source: 'events', count: 2 })
  expect(facets.find((f) => f.field === 'fromDomain')).toMatchObject({ source: 'mails', count: 2 })
  expect(await db.evidence.get(id)).toMatchObject({ status: 'done', count: 4, integrity: 'verified', stats: { unsupported: 1 } })
  expect(mocks.stream.mock.calls[0][0]).toBe('/api/ingest/package')
})
it('marks a truncated stream as incomplete while retaining emitted records', async () => {
  const id = await run([{ type: 'event', eventId: 1, ts: 1 }], false)
  expect(await getDb().evidence.get(id)).toMatchObject({ status: 'error', count: 1 })
  expect(await getDb().events.count()).toBe(1)
})
it('adds a cloud record the case already holds only once, and counts it once', async () => {
  const signIn = (key: string, ip: string) => ({ type: 'event', ts: 1, provider: 'Microsoft Entra ID Sign-in', operation: 'SignIn', ipAddress: ip, recordKey: key })
  const first = await run([signIn('entra:1', '198.51.100.1'), signIn('entra:2', '198.51.100.2')])
  // another export, not the same file: the whole-file duplicate check lets it through
  await getDb().evidence.update(first, { sha256Client: 'b'.repeat(64), sha256Server: 'b'.repeat(64) })
  const again = await run([signIn('entra:2', '198.51.100.2'), signIn('entra:3', '198.51.100.3'), { type: 'event', ts: 2, eventId: 4624, ipAddress: '198.51.100.2' }])
  const db = getDb()
  expect((await db.events.toArray()).map((r) => r.recordKey ?? r.eventId).sort()).toEqual([4624, 'entra:1', 'entra:2', 'entra:3'])
  // the record already held is no row of the new evidence, and says so, and the stream is not called incomplete
  expect(await db.evidence.get(again)).toMatchObject({ status: 'done', count: 2, stats: { duplicates: 1 } })
  expect(mocks.post).toHaveBeenCalledWith(expect.objectContaining({ type: 'done', count: 2, duplicates: 1, error: null }))
  // the skipped record adds nothing to the facets: the address is counted for the rows written
  const ip = (await db.facets.toArray()).find((f) => f.field === 'ipAddress' && f.value === '198.51.100.2')
  expect(ip?.count).toBe(2)
})
it('parses an EVTX file in the worker without sending it anywhere', async () => {
  const db = getDb()
  const id = await db.evidence.add({ caseId: 1, name: 'Defender.evtx', kind: 'evtx', size: 1, status: 'hashing', integrity: 'pending', count: 0, addedAt: 1 })
  const bytes = readFileSync(join(__dirname, '../../../tests/fixtures/evtx/lab-Defender.evtx'))
  await context.onmessage({
    data: {
      cmd: 'ingest',
      jobId: 1,
      caseId: 1,
      evidenceId: id,
      file: new File([bytes], 'Defender.evtx'),
      kind: 'evtx',
      includeRaw: true,
      parseInBrowser: true,
      settings: { internalDomains: [], brands: [], vipNames: [] },
    },
  })
  expect(mocks.stream).not.toHaveBeenCalled()
  const rows = await db.events.toArray()
  expect(rows).toHaveLength(10)
  expect(rows[0]).toMatchObject({ caseId: 1, evidenceId: id, sourceFile: 'Defender.evtx', provider: expect.stringContaining('Defender') })
  expect(typeof rows[0].raw).toBe('string')
  const ev = await db.evidence.get(id)
  expect(ev).toMatchObject({ status: 'done', count: 10, format: 'evtx', parsedIn: 'browser', integrity: 'verified' })
  expect(ev?.sha256Server).toBeUndefined()
  expect(ev?.stats).toMatchObject({ count: 10, errors: 0, sequences: [{ file: 'Defender.evtx', count: 10, missing: 0, checksums: { chunks: 1, fileHeader: true } }] })
  expect((await db.facets.toArray()).find((f) => f.field === 'provider')).toMatchObject({ count: 10 })
})
it('says so when a file sent to be parsed here is not an event log', async () => {
  const db = getDb()
  const id = await db.evidence.add({ caseId: 1, name: 'x.evtx', kind: 'evtx', size: 1, status: 'hashing', integrity: 'pending', count: 0, addedAt: 1 })
  await context.onmessage({
    data: {
      cmd: 'ingest',
      jobId: 1,
      caseId: 1,
      evidenceId: id,
      file: new File(['not an event log'], 'x.evtx'),
      kind: 'evtx',
      includeRaw: true,
      parseInBrowser: true,
      settings: { internalDomains: [], brands: [], vipNames: [] },
    },
  })
  expect(await db.evidence.get(id)).toMatchObject({ status: 'error', error: 'not an EVTX file (no ElfFile header)', count: 0, parsedIn: 'browser' })
})
it('keeps the case of the path of a URL indicator, and folds only its scheme and host', async () => {
  const link = { url: 'Www.Example.TEST/Login/Reset?t=Q1', scheme: '', domain: 'www.example.test' }
  await run([
    { type: 'event', ts: 1, eventId: 1, provider: 'Proxy', url: 'HTTPS://Files.Example.TEST/Share/Q3-Invoice.PDF?id=AbC' },
    { type: 'mail', subject: 's', fromAddr: 'a@example.test', risk: 0, date: 1, attachments: [], urls: [link], bodyText: 'x' },
  ])
  const urls = (await getDb().iocs.toArray()).filter((i) => i.kind === 'url')
  expect(urls.map((i) => i.value).sort()).toEqual(['https://files.example.test/Share/Q3-Invoice.PDF?id=AbC', 'www.example.test/Login/Reset?t=Q1'])
})
it('adds to an indicator an older version stored in lower case, rather than list it twice', async () => {
  const db = getDb()
  await db.iocs.add({
    caseId: 1,
    kind: 'url',
    value: 'https://files.example.test/share/q3-invoice.pdf',
    sources: ['mail-url'],
    firstSeen: 1,
    lastSeen: 1,
    count: 2,
    verdict: 'malicious',
    checkedAt: 5,
  })
  await run([{ type: 'event', ts: 9, eventId: 1, provider: 'Proxy', url: 'https://files.example.test/Share/Q3-Invoice.PDF' }])
  const urls = (await db.iocs.toArray()).filter((i) => i.kind === 'url')
  expect(urls).toEqual([expect.objectContaining({ value: 'https://files.example.test/share/q3-invoice.pdf', count: 3, lastSeen: 9, verdict: 'malicious', sources: ['mail-url', 'Proxy'] })])
})
it('keeps the reputation found for an indicator stored in lower case when the indicators are rebuilt', async () => {
  const db = getDb()
  await db.events.add({ caseId: 1, evidenceId: 1, ts: 1, eventId: 1, provider: 'Proxy', url: 'https://files.example.test/Share/Q3-Invoice.PDF' } as never)
  await db.iocs.add({ caseId: 1, kind: 'url', value: 'https://files.example.test/share/q3-invoice.pdf', sources: ['Proxy'], firstSeen: 1, lastSeen: 1, count: 1, verdict: 'malicious', checkedAt: 5 })
  await context.onmessage({ data: { cmd: 'rebuild', caseId: 1 } as unknown as IngestRequest })
  const urls = (await db.iocs.toArray()).filter((i) => i.kind === 'url')
  expect(urls).toEqual([expect.objectContaining({ value: 'https://files.example.test/Share/Q3-Invoice.PDF', verdict: 'malicious', checkedAt: 5 })])
})
it('says which import stopped collecting indicators at the limit, and a rebuild that did', async () => {
  IocCounter.limit = 3
  try {
    const dns = (ts: number, query: string) => ({ type: 'event', ts, eventId: 22, provider: 'Microsoft-Windows-Sysmon', query })
    await run([dns(1, 'a.example.test'), dns(2, 'b.example.test'), dns(3, 'c.example.test'), dns(4, 'd.example.test'), dns(5, 'a.example.test')])
    const db = getDb()
    expect((await db.iocs.toArray()).map((i) => [i.value, i.count])).toEqual([
      ['a.example.test', 2],
      ['b.example.test', 1],
      ['c.example.test', 1],
    ])
    expect((await db.kv.get('iocs-capped-1'))?.value).toEqual({ limit: 3, files: ['package.zip'] })
    expect(mocks.post).toHaveBeenCalledWith({ type: 'log', level: 'warn', text: 'indicators: collection stopped at 3 distinct values; later ones of this file are not in the Indicators list' })
    // recomputed after a removal, the indicators of the whole case meet the same limit
    await context.onmessage({ data: { cmd: 'rebuild', caseId: 1 } as unknown as IngestRequest })
    expect((await db.kv.get('iocs-capped-1'))?.value).toEqual({ limit: 3, files: [], rebuilt: true })
    IocCounter.limit = 50_000
    await context.onmessage({ data: { cmd: 'rebuild', caseId: 1 } as unknown as IngestRequest })
    expect(await db.kv.get('iocs-capped-1')).toBeUndefined()
    expect(await db.iocs.count()).toBe(4)
  } finally {
    IocCounter.limit = 50_000
  }
})
