import { beforeAll, describe, expect, it } from 'vitest'
import { RemnDB, setDb, type EventRow, type MailRow } from '../db/schema'
import { aggregateEvents, countEvents, searchEvents, searchMails, timelineEvents } from './queries'

const T0 = Date.UTC(2026, 8, 1, 22, 0, 0)

describe('queries over IndexedDB', () => {
  beforeAll(async () => {
    const db = new RemnDB('test-queries')
    setDb(db)
    const events: EventRow[] = []
    for (let i = 0; i < 300; i++) {
      events.push({
        caseId: 1,
        evidenceId: 1,
        ts: T0 + i * 60_000,
        eventId: i % 3 === 0 ? 4625 : 4624,
        provider: 'Security',
        channel: 'Security',
        computer: i % 2 ? 'WS01' : 'WS02',
        targetUser: i % 5 === 0 ? 'admin' : 'bob',
        ipAddress: `10.0.0.${i % 7}`,
        summary: `event ${i}`,
        data: { X: i },
      })
    }
    await db.events.bulkAdd(events)
    const mails: MailRow[] = [
      {
        caseId: 1,
        evidenceId: 2,
        folder: 'Inbox',
        subject: 'URGENT invoice',
        date: T0,
        fromName: 'Marie',
        fromNameNorm: 'marie',
        fromAddr: 'm@interne-fr.co',
        fromDomain: 'interne-fr.co',
        fromRegistrable: 'interne-fr.co',
        replyTo: [],
        returnPath: null,
        to: [],
        cc: [],
        bcc: [],
        recipientCount: 0,
        messageId: null,
        originIp: '185.220.101.4',
        hopCount: 2,
        hops: [],
        auth: {},
        keywordHits: {},
        urls: [],
        urlCount: 0,
        attachments: [{ name: 'a.docm', ext: 'docm', realExt: 'docx', size: 10, sha256: 'x', md5: 'y', risk: 90, flags: ['office_macro'] }],
        attachmentCount: 1,
        maxAttachmentRisk: 90,
        lookalike: {},
        flags: ['spf_fail', 'att_office_macro'],
        risk: 95,
      },
      {
        caseId: 1,
        evidenceId: 2,
        folder: 'Inbox',
        subject: 'hello',
        date: null,
        fromName: 'Bob',
        fromNameNorm: 'bob',
        fromAddr: 'b@x.com',
        fromDomain: 'x.com',
        fromRegistrable: 'x.com',
        replyTo: [],
        returnPath: null,
        to: [],
        cc: [],
        bcc: [],
        recipientCount: 0,
        messageId: null,
        originIp: null,
        hopCount: 0,
        hops: [],
        auth: {},
        keywordHits: {},
        urls: [],
        urlCount: 0,
        attachments: [],
        attachmentCount: 0,
        maxAttachmentRisk: 0,
        lookalike: {},
        flags: [],
        risk: 0,
      },
    ]
    await db.mails.bulkAdd(mails)
  })

  it('searches with index pre-selection and sorts by time', async () => {
    const r = await searchEvents(1, { conditions: [{ field: 'eventId', op: 'eq', value: 4625 }] }, { limit: 10 })
    expect(r.rows).toHaveLength(10)
    expect(r.truncated).toBe(true)
    expect(r.rows[0].ts).toBeGreaterThan(r.rows[1].ts!)
    expect(await countEvents(1, { conditions: [{ field: 'eventId', op: 'eq', value: 4625 }] })).toBe(100)
    expect(await countEvents(1, {})).toBe(300)
  })
  it('filters by time range through the [caseId+ts] index', async () => {
    const r = await searchEvents(1, { timeRange: { from: new Date(T0 + 10 * 60_000).toISOString(), to: new Date(T0 + 19 * 60_000).toISOString() }, sort: { field: 'ts', dir: 'asc' } })
    expect(r.rows).toHaveLength(10)
    expect(r.rows[0].summary).toBe('event 10')
  })
  it('aggregates and builds timelines', async () => {
    const agg = await aggregateEvents(1, { conditions: [{ field: 'targetUser', op: 'eq', value: 'admin' }] }, 'computer')
    expect(agg.total).toBe(60)
    expect(agg.groups.map((g) => g.value).sort()).toEqual(['WS01', 'WS02'])
    const tl = await timelineEvents(1, {}, 'hour')
    expect(tl.reduce((s, b) => s + b.count, 0)).toBe(300)
    expect(tl).toHaveLength(5)
  })
  it('searches mails including undated ones and nested attachment paths', async () => {
    const all = await searchMails(1, {})
    expect(all.rows).toHaveLength(2)
    const macro = await searchMails(1, { conditions: [{ field: 'attachments.flags', op: 'contains', value: 'office_macro' }] })
    expect(macro.rows).toHaveLength(1)
    expect(macro.rows[0].subject).toBe('URGENT invoice')
    const risky = await searchMails(1, { conditions: [{ field: 'risk', op: 'gte', value: 50 }], text: 'urgent' })
    expect(risky.rows).toHaveLength(1)
  })
})

describe('collection snapshots without an event time', () => {
  // Autoruns, services and installed programs are snapshots: the collection parser sets ts: null.
  // Dexie omits rows with a null key from the [caseId+ts] index, so a read that walks that index
  // never sees them, while the case totals still count them. They then read as missing evidence.
  beforeAll(async () => {
    const db = new RemnDB('test-queries-undated')
    setDb(db)
    await db.events.bulkAdd([
      { caseId: 1, evidenceId: 9, ts: T0, eventId: 4624, provider: 'Security', channel: 'Security', summary: 'dated logon' },
      { caseId: 1, evidenceId: 9, ts: null, recordKind: 'observation', artifactType: 'autorun', summary: 'Run key: updater.exe' },
      { caseId: 1, evidenceId: 9, ts: null, recordKind: 'observation', artifactType: 'service', summary: 'Service: RemoteRegistry' },
    ] as unknown as EventRow[])
  })

  it('lists undated observations alongside dated events when no time range is set', async () => {
    const { rows } = await searchEvents(1, {}, { limit: 100 })
    const summaries = rows.map((r) => (r as { summary?: string }).summary)
    expect(summaries).toContain('Run key: updater.exe')
    expect(summaries).toContain('Service: RemoteRegistry')
    expect(rows).toHaveLength(3)
  })

  it('counts them, so the total agrees with the list', async () => {
    expect(await countEvents(1, {})).toBe(3)
  })

  it('excludes them when a time range is set, since an undated row is not inside one', async () => {
    const ranged = { timeRange: { from: T0 - 1000, to: T0 + 1000 } }
    const { rows } = await searchEvents(1, ranged, { limit: 100 })
    expect(rows).toHaveLength(1)
    expect(await countEvents(1, ranged)).toBe(1)
  })
})
