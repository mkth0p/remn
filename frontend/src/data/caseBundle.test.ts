import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { defaultSettings, getDb, RemnDB, setDb, type Case } from '../db/schema'
import { restoreCaseBundle, writeCaseBundle } from './caseBundle'
import { migrateCaseToServer } from './migrate'

vi.mock('../state/store', () => ({ toast: vi.fn(), useStore: { getState: () => ({ setCurrentCase: vi.fn(), bumpRules: vi.fn() }) } }))
let db: RemnDB
let kase: Case
beforeEach(async () => {
  db = new RemnDB(`bundle-${Math.random()}`)
  setDb(db)
  kase = { id: 1, name: 'Reviewed case', createdAt: 1, updatedAt: 1, storage: 'browser', settings: defaultSettings() }
  await db.cases.add(kase)
  await db.cases.add({ ...kase, id: 2, name: 'Other case' })
  await db.evidence.add({ id: 9, caseId: 1, name: 'mail.eml', kind: 'mail', status: 'done', count: 1 } as never)
  await db.mails.add({ id: 70, caseId: 1, evidenceId: 9, subject: 'Invoice', risk: 10, to: [], cc: [], bcc: [] } as never)
  await db.mailBodies.put({ mailId: 70, caseId: 1, bodyText: 'Original body', bodyHtml: null, headersText: null, visibleText: null })
  await db.events.add({ id: 80, caseId: 1, evidenceId: 9, ts: 1, eventId: 4625 } as never)
  await db.findings.add({
    id: 90,
    caseId: 1,
    key: 'mail-test|70',
    ruleId: 'mail-test',
    source: 'mails',
    refs: [70],
    status: 'reviewed',
    notes: 'Verified with supplier',
    severityOverride: 'low',
  } as never)
  await db.caseNotes.add({ id: 10, caseId: 1, text: 'Linked evidence', link: { source: 'events', id: 80 } } as never)
  await db.kv.bulkPut([
    {
      key: 'chains-1',
      value: { chains: [{ id: 'chain-alice@example.com-70', identity: 'alice@example.com', seed: { id: 70 }, steps: [{ source: 'events', id: 80, refs: [80] }] }], stats: { eventsTruncated: 1 } },
    },
    { key: 'chain-reviews-1', value: { 'chain-alice@example.com-70': { verdict: 'benign', narrative: 'Analyst narrative' } } },
    { key: 'report-settings-1', value: { onlyReviewed: true } },
    { key: 'finding-reviews-1', value: { 'mail-test|70': { status: 'reviewed', notes: 'Archived decision' } } },
    { key: 'ai-triage-1', value: { entries: [{ id: 'incident:mail:70', before: { findings: [{ id: 90, status: 'new' }] } }] } },
    { key: 'chains-2', value: { privateToAnotherCase: true } },
    {
      key: 'relationship-reviews-1',
      value: {
        stable: {
          notes: 'Reviewed link',
          references: [
            { source: 'events', id: 80, evidenceId: 9 },
            { source: 'mails', id: 70, evidenceId: 9 },
          ],
        },
      },
    },
    { key: 'relationship-cache-1', value: { privateCache: true } },
  ])
})
afterEach(async () => {
  vi.unstubAllGlobals()
  await db.delete()
  setDb(null)
})

async function backup() {
  const chunks: string[] = []
  await writeCaseBundle(kase, {
    write: async (text) => {
      chunks.push(text)
    },
  })
  return new File(chunks, 'case.remn.ndjson')
}

it('restores all analyst state with correct evidence, finding and chain references into a populated browser', async () => {
  const id = await restoreCaseBundle(await backup())
  const mail = (await db.mails.where('caseId').equals(id).toArray())[0]
  const event = (await db.events.where('caseId').equals(id).toArray())[0]
  const finding = (await db.findings.where('caseId').equals(id).toArray())[0]
  expect(mail.id).toBe(140)
  expect((await db.mailBodies.get(mail.id!))?.bodyText).toBe('Original body')
  expect(finding).toMatchObject({ key: 'mail-test|140', refs: [mail.id], notes: 'Verified with supplier', severityOverride: 'low' })
  expect((await db.caseNotes.where('caseId').equals(id).first())?.link?.id).toBe(event.id)
  expect((await db.kv.get(`chain-reviews-${id}`))?.value).toEqual({ 'chain-alice@example.com-140': { verdict: 'benign', narrative: 'Analyst narrative' } })
  expect((await db.kv.get(`finding-reviews-${id}`))?.value).toHaveProperty('mail-test|140')
  const chain = (await db.kv.get(`chains-${id}`))?.value as { chains: { seed: { id: number }; steps: { id: number; refs: number[] }[] }[] }
  expect(chain.chains[0].seed.id).toBe(mail.id)
  expect(chain.chains[0].steps[0]).toMatchObject({ id: event.id, refs: [event.id] })
  expect((await db.kv.get(`ai-triage-${id}`))?.value).toMatchObject({ entries: [{ id: 'incident:mail:140', before: { findings: [{ id: finding.id }] } }] })
  expect((await db.findings.get(90))?.refs).toEqual([70])
  expect((await db.kv.get(`relationship-reviews-${id}`))?.value).toMatchObject({
    stable: {
      notes: 'Reviewed link',
      references: [
        { source: 'events', id: event.id, evidenceId: event.evidenceId },
        { source: 'mails', id: mail.id, evidenceId: mail.evidenceId },
      ],
    },
  })
  expect(await db.kv.get(`relationship-cache-${id}`)).toBeUndefined()
})

it('rejects corruption or truncation before creating any case', async () => {
  const data = await (await backup()).text()
  for (const text of [data.replace('Original body', 'Tampered body'), data.slice(0, -90)]) {
    await expect(restoreCaseBundle(new File([text], 'bad'))).rejects.toThrow()
    expect(await db.cases.count()).toBe(2)
  }
})

it('rolls back a failed migration and retains reviewed findings and browser evidence', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response('failed', { status: 500 })),
  )
  await expect(migrateCaseToServer(kase)).rejects.toThrow('Server import failed')
  expect((await db.cases.get(1))?.storage).toBe('browser')
  expect(await db.mails.get(70)).toBeDefined()
  expect((await db.findings.get(90))?.notes).toBe('Verified with supplier')
})

it('migration transmits original IDs and retains reviews after switching storage', async () => {
  const sent: Record<string, unknown>[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (_url: string, init: RequestInit) => {
      const rows = String(init.body)
        .trim()
        .split('\n')
        .map((s) => JSON.parse(s))
      sent.push(...rows)
      return Response.json({ events: rows.filter((r) => r.type === 'event').length, mails: rows.filter((r) => r.type === 'mail').length })
    }),
  )
  await migrateCaseToServer(kase)
  expect(sent.find((r) => r.type === 'mail')).toMatchObject({ id: 70, bodyText: 'Original body' })
  expect((await getDb().cases.get(1))?.storage).toBe('server')
  expect(await db.mails.count()).toBe(0)
  expect((await db.findings.get(90))?.refs).toEqual([70])
  expect(await db.kv.get('chain-reviews-1')).toBeDefined()
})

it('server backup keeps private row IDs while remapping evidence ownership and browser finding IDs', async () => {
  kase = { ...kase, storage: 'server', serverKey: 'old-server' }
  const imported: Record<string, unknown>[] = []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      if (url.endsWith('/export'))
        return new Response(
          [
            { type: 'evidence', id: 9, name: 'mail.eml' },
            { type: 'mail', id: 70, evidenceId: 9, subject: 'Original server mail', bodyText: 'Server body' },
            { type: 'event', id: 80, evidenceId: 9, eventId: 4625 },
          ]
            .map((r) => JSON.stringify(r))
            .join('\n') + '\n',
        )
      const rows = String(init?.body)
        .trim()
        .split('\n')
        .map((s) => JSON.parse(s))
      imported.push(...rows)
      return Response.json({ events: rows.filter((r) => r.type === 'event').length, mails: rows.filter((r) => r.type === 'mail').length })
    }),
  )
  const id = await restoreCaseBundle(await backup())
  const restored = await db.cases.get(id)
  expect(restored?.serverKey).not.toBe('old-server')
  expect(imported.find((r) => r.type === 'mail')).toMatchObject({ id: 70, evidenceId: 18, bodyText: 'Server body' })
  expect(imported.find((r) => r.type === 'evidence')?.id).toBe(18)
  expect((await db.findings.where('caseId').equals(id).first())?.refs).toEqual([70])
  expect(await db.mails.where('caseId').equals(id).count()).toBe(0)
})

it('restores legacy browser bundles with remapped references', async () => {
  const { sha256Hex } = await import('../util/export')
  const payload = JSON.stringify({ format: 'remn-case', version: 1, case: kase, evidence: await db.evidence.toArray(), mails: await db.mails.toArray(), findings: await db.findings.toArray() })
  const file = new File([`{"sha256":"${await sha256Hex(payload)}","bundle":${payload}}`], 'legacy.remn.json')
  const id = await restoreCaseBundle(file)
  expect((await db.findings.where('caseId').equals(id).first())?.refs).toEqual([140])
})
