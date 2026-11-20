import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case, type Ioc, type MailRow } from '../db/schema'
import { mirrorToMails } from './iocs'
import { getSource } from './source'

vi.mock('../api/client', () => ({ apiPost: vi.fn(), apiGet: vi.fn(), lookupReputation: vi.fn(), API_HEADERS: {} }))

const kase: Case = { id: 1, name: 'Indicators', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
const ioc = (kind: Ioc['kind'], value: string, verdict?: string): Ioc => ({
  caseId: 1,
  kind,
  value,
  sources: ['mail-url'],
  firstSeen: 1,
  lastSeen: 1,
  count: 1,
  verdict,
  checkedAt: verdict ? 1 : null,
})
// invented mails, each with one link
const mail = (id: number, url: string) =>
  ({
    id,
    caseId: 1,
    evidenceId: 1,
    date: 1,
    subject: 's',
    fromAddr: 'a@example.test',
    to: [],
    cc: [],
    bcc: [],
    flags: [],
    risk: 1,
    attachments: [],
    urls: [{ url, scheme: 'https', domain: 'files.example.test' }],
  }) as unknown as MailRow

describe('indicators whose URL keeps its case', () => {
  let db: RemnDB
  beforeEach(() => {
    db = new RemnDB(`iocs-${Math.random()}`)
    setDb(db)
  })
  afterEach(async () => {
    await db.delete()
  })

  it('give their verdict to the mail that links to them, and so does one an older version stored in lower case', async () => {
    await db.iocs.bulkAdd([ioc('url', 'https://files.example.test/Share/Payload.EXE', 'malicious'), ioc('url', 'https://files.example.test/old/invoice.pdf', 'suspicious')])
    await db.mails.bulkAdd([mail(1, 'https://Files.Example.TEST/Share/Payload.EXE'), mail(2, 'https://files.example.test/Old/Invoice.PDF'), mail(3, 'https://files.example.test/share/payload.exe')])
    await mirrorToMails(1)
    const worst = async (id: number) => (await db.mails.get(id))?.reputation?.worst
    expect(await worst(1)).toBe('malicious')
    expect(await worst(2)).toBe('suspicious')
    // another path is another resource
    expect(await worst(3)).toBeUndefined()
  })

  it('are found by a search in any case', async () => {
    await db.iocs.bulkAdd([ioc('url', 'https://files.example.test/Share/Payload.EXE'), ioc('domain', 'files.example.test')])
    const found = await getSource(kase).listIocs({ q: 'payload.exe' })
    expect(found.rows.map((r) => r.value)).toEqual(['https://files.example.test/Share/Payload.EXE'])
    expect((await getSource(kase).listIocs({ q: 'Files.Example' })).total).toBe(2)
  })
})
