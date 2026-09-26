import { beforeAll, describe, expect, it } from 'vitest'
import { RemnDB, setDb, type EventRow } from '../db/schema'
import { stackEvents } from './queries'

const T0 = Date.UTC(2026, 8, 1, 22, 0, 0)

describe('stacking over IndexedDB', () => {
  beforeAll(async () => {
    const db = new RemnDB('test-stack')
    setDb(db)
    const rows: EventRow[] = []
    const add = (computer: string, image: string | null, extra: Partial<EventRow> = {}) =>
      rows.push({ caseId: 1, evidenceId: 1, ts: T0 + rows.length * 1000, eventId: 1, provider: 'Microsoft-Windows-Sysmon', channel: 'Sysmon', computer, image, ...extra })
    for (const host of ['WS01.corp.local', 'WS02.corp.local', 'WS03', 'DC01.corp.local']) {
      for (let i = 0; i < 5; i++) add(host, 'C:\\Windows\\System32\\svchost.exe')
      add(host, null, { eventId: 4624, provider: 'Microsoft-Windows-Security-Auditing' })
    }
    add('WS02.corp.local', 'C:\\Users\\Public\\evil.exe')
    add('WS01.corp.local', 'C:\\ProgramData\\Tool\\agent.exe')
    add('ws03', 'c:\\programdata\\tool\\AGENT.exe')
    // another case's rows are not counted
    rows.push({ caseId: 2, evidenceId: 9, ts: T0, eventId: 1, computer: 'X', image: 'C:\\other.exe' })
    await db.events.bulkAdd(rows)
  })

  it('puts the value seen on the fewest hosts, then in the fewest events, first', async () => {
    const s = await stackEvents(1, {}, 'image')
    expect(s).toMatchObject({ distinct: 3, events: 23, blank: 4, hosts: 4, truncated: false })
    expect(s.rows.map((r) => [r.count, r.hosts])).toEqual([
      [1, 1],
      [2, 2],
      [20, 4],
    ])
    expect(s.rows[0]).toMatchObject({ value: 'C:\\Users\\Public\\evil.exe', hostList: ['ws02'], first: T0 + 24_000, last: T0 + 24_000 })
    // two spellings of one path group together; hosts are named without their domain
    expect(s.rows[1].value.toLowerCase()).toBe('c:\\programdata\\tool\\agent.exe')
    expect(s.rows[1].hostList).toEqual(['ws01', 'ws03'])
    expect(s.rows[2].hostList).toEqual(['dc01', 'ws01', 'ws02', 'ws03'])
  })

  it('orders most frequent first on request and says how many values a limit left out', async () => {
    const s = await stackEvents(1, {}, 'image', 'common', 1)
    expect(s.rows).toHaveLength(1)
    expect(s.rows[0].count).toBe(20)
    expect(s).toMatchObject({ distinct: 3, truncated: true, order: 'common' })
  })

  it('honours the filter and stacks provider / event ID pairs', async () => {
    const one = await stackEvents(1, { conditions: [{ field: 'computer', op: 'eq', value: 'WS02.corp.local' }] }, 'image')
    expect(one.rows.map((r) => r.count)).toEqual([1, 5])
    expect(one.hosts).toBe(1)
    expect((await stackEvents(1, { text: 'evil' }, 'image')).distinct).toBe(1)
    const pairs = await stackEvents(1, {}, 'providerEventId')
    expect(pairs.rows.map((r) => [r.value, r.count, r.hosts])).toEqual([
      ['Microsoft-Windows-Security-Auditing / 4624', 4, 4],
      ['Microsoft-Windows-Sysmon / 1', 23, 4],
    ])
    await expect(stackEvents(1, {}, 'raw')).rejects.toThrow()
  })
})
