import { afterEach, beforeAll, expect, it, vi } from 'vitest'
import { getDb } from '../db/schema'
import type { IngestRequest } from './ingest.worker'

const mocks = vi.hoisted(() => ({ stream: vi.fn(), post: vi.fn() }))
vi.mock('../api/client', () => ({ streamNdjson: mocks.stream, setApiToken: vi.fn() }))
vi.mock('hash-wasm', () => ({ createSHA256: async () => ({ init: () => {}, update: () => {}, digest: () => 'a'.repeat(64) }) }))
const context = { postMessage: mocks.post, onmessage: null as unknown as (e: { data: IngestRequest }) => Promise<void> }

beforeAll(async () => {
  vi.stubGlobal('self', context)
  await import('./ingest.worker')
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
