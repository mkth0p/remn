import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { apiPost } from '../api/client'
import { defaultSettings, RemnDB, setDb, type Case } from '../db/schema'
import { loadChains } from './chains'
import {
  accountName,
  buildStories,
  isInternalIp,
  loadStories,
  noteKey,
  refRow,
  reportStories,
  selectRows,
  slimFinding,
  storyCoverageWarnings,
  storyRowIds,
  windows,
  type Story,
  type StoryResult,
} from './stories'

vi.mock('../api/client', () => ({ apiPost: vi.fn(), API_HEADERS: {} }))
vi.mock('./rules', () => ({ settingsForRules: (k: Case) => ({ internal_domains: k.settings.internalDomains }) }))

const DAY = 86_400_000
const T0 = 1_788_510_000_000
const kase: Case = { id: 1, name: 'Lab', storage: 'browser', createdAt: 1, updatedAt: 1, settings: { ...defaultSettings(), internalDomains: ['northstar.example'] } }
let db: RemnDB

const event = (id: number, ts: number, extra: Record<string, unknown>) => ({ id, caseId: 1, evidenceId: 1, ts, eventId: 4624, computer: 'WS-001', ...extra })
const finding = (id: number, refs: number[], extra: Record<string, unknown> = {}) => ({
  id,
  caseId: 1,
  ruleId: `rule-${id}`,
  key: `rule-${id}|${refs[0]}`,
  title: 'x',
  severity: 'high',
  source: 'events',
  ts: T0,
  entities: {},
  count: refs.length,
  refs,
  attack: ['T1021.001'],
  tags: ['lateral-movement'],
  status: 'new',
  createdAt: 1,
  ...extra,
})

beforeEach(() => {
  db = new RemnDB(`stories-${Math.random()}`)
  setDb(db)
  vi.mocked(apiPost).mockReset()
})
afterEach(async () => {
  await db.delete()
})

describe('the rows a browser case posts', () => {
  it('reads the flagged records and, around them, the names, addresses and hosts they point at', async () => {
    await db.events.bulkAdd([
      // the flag: an RDP logon from outside
      event(1, T0, { targetUser: 'daniel.roy', targetDomain: 'NORTHSTAR', logonType: 10, ipAddress: '203.0.113.69', raw: '<Event/>' }),
      // daniel's own record an hour later, the same address trying someone else, a logon on the flagged host
      event(2, T0 + 3_600_000, { eventId: 4698, subjectUser: 'daniel.roy', taskName: '\\t', computer: 'WS-004' }),
      event(3, T0 - 60_000, { eventId: 4625, targetUser: 'employee019', ipAddress: '203.0.113.69', computer: 'WS-009' }),
      event(4, T0 + 60_000, { eventId: 4688, subjectUser: 'SYSTEM', computer: 'WS-001', data: { ProcessId: '0x10', Irrelevant: 'x' } }),
      // not selected: another person on another host, and daniel five days later
      event(5, T0, { targetUser: 'carla.morel', computer: 'WS-003', ipAddress: '10.0.0.3' }),
      event(6, T0 + 5 * DAY, { targetUser: 'daniel.roy', computer: 'WS-004' }),
      // a host's routine noise that is not what lineage reads
      event(7, T0, { eventId: 7036, computer: 'WS-001' }),
    ] as never)
    await db.mails.bulkAdd([
      {
        id: 1,
        caseId: 1,
        evidenceId: 2,
        date: T0 - 600_000,
        subject: 'Invoice',
        fromAddr: 'documents@secure-documents.example',
        to: [{ addr: 'daniel.roy@northstar.example' }],
        cc: [],
        bcc: [],
        flags: [],
        risk: 81,
        urls: [],
        attachments: [{ name: 'a.html', sha256: 'ab' }],
      },
      {
        id: 2,
        caseId: 1,
        evidenceId: 2,
        date: T0 - 300_000,
        subject: 'RE: Invoice',
        fromAddr: 'daniel.roy@northstar.example',
        to: [{ addr: 'documents@secure-documents.example' }],
        cc: [],
        bcc: [],
        flags: [],
        risk: 5,
        urls: [],
        attachments: [],
      },
      {
        id: 3,
        caseId: 1,
        evidenceId: 2,
        date: T0,
        subject: 'Newsletter',
        fromAddr: 'news@vendor.example',
        to: [{ addr: 'carla.morel@northstar.example' }],
        cc: [],
        bcc: [],
        flags: [],
        risk: 3,
        urls: [],
        attachments: [],
      },
    ] as never)
    const findings = [finding(1, [1], { entities: { ipAddress: '203.0.113.69' } })].map((f) => slimFinding(f as never))
    const { events, mails, truncated } = await selectRows(1, findings)
    expect(events.map((e) => e.id).sort()).toEqual([1, 2, 3, 4])
    // only the fields the story engine reads travel, and of data only its keys
    expect(events.find((e) => e.id === 1)).not.toHaveProperty('raw')
    expect(events.find((e) => e.id === 4)?.data).toEqual({ ProcessId: '0x10' })
    // the seed (risk 81) and the reply of a flagged person; not the newsletter
    expect(mails.map((m) => m.id)).toEqual([1, 2])
    expect(mails[0].attachments).toEqual([{ name: 'a.html', sha256: 'ab' }])
    expect(truncated).toEqual([])
  })

  it('posts the effective severity, tags, techniques and entities of each finding and leaves false positives out', async () => {
    await db.events.add(event(1, T0, { targetUser: 'daniel.roy' }) as never)
    await db.findings.bulkAdd([
      finding(1, [1], { severityOverride: 'critical', entities: { ipAddress: '203.0.113.69' } }),
      finding(2, [1], { status: 'false_positive' }),
      finding(3, [1], { ruleId: 'chain' }),
    ] as never)
    const result = { version: 1, stories: [], campaigns: [], chains: { chains: [], stats: {} }, identities: [], hosts: [], unstoried: [], stats: {} }
    vi.mocked(apiPost).mockResolvedValue(result)
    await buildStories(kase)
    const [path, body] = vi.mocked(apiPost).mock.calls[0] as [string, { findings: unknown[]; events: unknown[] }]
    expect(path).toBe('/api/stories/build')
    expect(body.findings).toEqual([
      {
        ruleId: 'rule-1',
        title: 'x',
        severity: 'critical',
        source: 'events',
        refs: [1],
        ts: T0,
        key: 'rule-1|1',
        tags: ['lateral-movement'],
        attack: ['T1021.001'],
        entities: { ipAddress: '203.0.113.69' },
      },
    ])
    expect(body.events).toHaveLength(1)
  })
})

describe('the snapshot', () => {
  it('keeps the stories for the page and the chains for the review, and a server case asks the API to read its store', async () => {
    const chain = {
      id: 'chain-daniel-1',
      identity: 'daniel.roy@northstar.example',
      identityLabel: 'daniel.roy@northstar.example',
      seed: { id: 1, source: 'mails', subject: 'Invoice', ts: T0 },
      steps: [],
      start: T0,
      end: T0,
      score: 90,
      severity: 'critical',
      entities: { user: 'daniel', ips: [], hosts: [], attackerAddresses: [], domains: [] },
      summary: '',
    }
    const result = {
      version: 1,
      stories: [{ id: 'story-1' }],
      campaigns: [],
      chains: { chains: [chain], stats: {} },
      identities: [],
      hosts: [],
      unstoried: [],
      stats: { truncated: ['hosts'] },
    } as unknown as StoryResult
    vi.mocked(apiPost).mockResolvedValue(result)
    const server: Case = { ...kase, storage: 'server', serverKey: 'abc' }
    const r = await buildStories(server)
    expect(vi.mocked(apiPost).mock.calls[0][1]).toMatchObject({ storeKey: 'abc' })
    expect((await loadStories(1))?.stories).toEqual([{ id: 'story-1' }])
    expect(r.builtAt).toBeGreaterThan(0)
    expect((await loadChains(1))?.chains.map((c) => c.id)).toEqual(['chain-daniel-1'])
    expect(await db.findings.where('[caseId+ruleId]').equals([1, 'chain']).count()).toBe(1)
    expect(storyCoverageWarnings(r.stats)).toEqual([expect.stringContaining('on the flagged hosts passed 50,000')])
  })
})

describe('values', () => {
  it('reads account names, private addresses, windows and references as the Python does', () => {
    expect(accountName('NORTHSTAR\\Daniel.Roy')).toBe('daniel.roy')
    expect(accountName('daniel.roy@northstar.example')).toBe('daniel.roy')
    expect([accountName('WS-001$'), accountName('NT AUTHORITY\\SYSTEM'), accountName('S-1-5-18'), accountName('-')]).toEqual([null, null, null, null])
    expect([isInternalIp('10.0.0.5'), isInternalIp('203.0.113.69'), isInternalIp('198.51.100.10'), isInternalIp('8.8.8.8')]).toEqual([true, false, false, false])
    expect(windows([T0, T0 + DAY, T0 + 10 * DAY])).toEqual([
      [T0 - DAY, T0 + 4 * DAY],
      [T0 + 9 * DAY, T0 + 13 * DAY],
    ])
    expect(windows([1, 10 * DAY, 20 * DAY], DAY, DAY, 2)).toEqual([[1 - DAY, 21 * DAY]])
    expect(refRow('event:12')).toEqual({ source: 'events', id: 12 })
    expect(refRow('mail:3')).toEqual({ source: 'mails', id: 3 })
    expect(refRow('entra:x')).toBeNull()
  })
})

describe('the stories a report prints', () => {
  const story = (id: string, severity: Story['severity'], score: number, refs: string[] = []) =>
    ({ id, kind: 'person', title: `story ${id}`, start: T0, severity, score, steps: [{ refs }] }) as unknown as Story
  it('keeps those at the floor or above, the highest-scoring first, and with only reviewed items those with a note', () => {
    const stories = [story('a', 'medium', 40), story('b', 'critical', 90), story('c', 'low', 99), story('d', 'high', 70)]
    const notes = { [noteKey(stories[3])]: { text: ' read it ', updatedAt: 1 } }
    const all = reportStories(stories, notes, 'medium')
    expect(all.stories.map((s) => s.story.id)).toEqual(['b', 'd', 'a'])
    expect(all.stories[1]).toMatchObject({ key: noteKey(stories[3]), note: 'read it' })
    expect(all.left).toBe(1)
    expect(reportStories(stories, notes, 'medium', true).stories.map((s) => s.story.id)).toEqual(['d'])
    expect(reportStories(stories, notes, 'low', false, 2)).toMatchObject({ left: 2 })
  })
  it('checks a note against the rows of its steps', () => {
    expect(storyRowIds(story('a', 'high', 1, ['event:1', 'mail:2', 'event:3', 'entra:x']), 1)).toEqual({ events: [1], mails: [2] })
  })
})
