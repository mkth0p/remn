// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { RelationshipResult } from '../data/relationships'
import type { Story, StoryResult, StoryStep } from '../data/stories'
import { defaultSettings, RemnDB, setDb, type Case } from '../db/schema'
import { useStore } from '../state/store'

vi.mock('../api/client', () => ({ apiPost: vi.fn(), apiGet: vi.fn(), API_HEADERS: {} }))
vi.mock('../data/source', () => ({
  getSource: () => ({
    kind: 'browser',
    getEvent: async (id: number) => ({ id, caseId: 1, ts: 1, eventId: 4624, computer: 'WS-004', summary: `event ${id}` }),
    getMail: async () => null,
    searchEvents: async () => ({ rows: [] }),
    searchMails: async () => ({ rows: [] }),
    listIocs: async () => ({ rows: [] }),
  }),
}))
vi.mock('../data/rules', () => ({ loadRules: async () => [{ rule: { id: 'win-rdp-logon-external' }, measured: { of: 13, hits: 12, fires: 12 }, origin: 'bundled' }], settingsForRules: () => ({}) }))
vi.mock('../data/evidenceGaps', () => ({ loadEvidenceGaps: async () => [{ kind: 'record-holes', severity: 'high', text: 'Security.evtx: 12 records are missing between 100 and 112.' }] }))
vi.mock('../data/claims', async (orig) => ({
  ...(await orig<typeof import('../data/claims')>()),
  readRows: async (_s: unknown, kind: string, ids: number[]) => new Map(ids.map((id) => [id, { id, kind, ipAddress: '203.0.113.69', computer: 'WS-004' }])),
}))

import { StoriesView } from './StoriesView'
import { apiPost } from '../api/client'

const WAIT = { timeout: 8000 }
const TEST_TIMEOUT = 30_000 // jsdom and fake-indexeddb are slow on a first render
const T0 = Date.UTC(2026, 8, 4, 8, 26)
const kase: Case = { id: 1, name: 'Lab', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }

const step = (id: number, minutes: number, extra: Partial<StoryStep>): StoryStep => ({
  id: `event:${id}`,
  refs: [`event:${id}`],
  source: 'events',
  ts: T0 + minutes * 60_000,
  tsEnd: T0 + minutes * 60_000,
  count: 1,
  title: `record ${id}`,
  host: 'ws-004',
  ip: null,
  origin: 'host',
  phase: null,
  phaseBasis: '',
  findings: [],
  severity: null,
  tie: { kind: 'flag', basis: 'the record names them (target)', confidence: 'strong' },
  notes: [],
  accounts: ['id:daniel'],
  session: null,
  process: null,
  hops: [],
  routine: false,
  ...extra,
})

function snapshot(): StoryResult {
  const steps = [
    step(1, 0, {
      title: 'Logon RemoteInteractive as NORTHSTAR\\daniel.roy from 203.0.113.69',
      ip: '203.0.113.69',
      phase: 'initial-access',
      phaseBasis: 'an RDP logon from outside',
      findings: [{ ruleId: 'win-rdp-logon-external', title: 'RDP logon from a non-internal address', severity: 'high', key: 'k1' }],
      severity: 'high',
      session: 'ses:1',
      hops: ['hop:1'],
    }),
    step(2, 16, {
      title: 'The audit log was cleared by NORTHSTAR\\daniel.roy',
      phase: 'defense-impairment',
      phaseBasis: 'rule tag defense-evasion, technique T1685.005',
      findings: [{ ruleId: 'win-audit-log-cleared', title: 'Security audit log cleared (1102)', severity: 'critical', key: 'k2' }],
      severity: 'critical',
      session: 'ses:1',
      tie: { kind: 'flag', basis: 'the record names them (subject)', confidence: 'medium' },
    }),
    step(3, 20, {
      title: 'Failed logon as employee019',
      refs: ['event:3', 'event:4', 'event:5'],
      count: 3,
      phase: 'credential-access',
      routine: true,
      tie: { kind: 'address', basis: 'the same source, 203.0.113.69, in the same days; it tried another account', confidence: 'medium' },
    }),
  ]
  const story: Story = {
    id: 'story-1',
    kind: 'person',
    subject: { kind: 'person', id: 'id:daniel', label: 'daniel.roy@northstar.example', org: 'northstar.example' },
    title: 'daniel.roy@northstar.example',
    headline: 'RDP logon from a non-internal address → Security audit log cleared (1102)',
    summary: 'It starts with: an RDP logon.',
    start: T0,
    end: T0 + 20 * 60_000,
    severity: 'critical',
    score: 90,
    confidence: 'medium',
    phases: [
      { phase: 'initial-access', label: 'Initial access', first: T0, last: T0, steps: 1, records: 1, findings: 1, severity: 'high' },
      { phase: 'defense-impairment', label: 'Defense impairment', first: T0 + 960_000, last: T0 + 960_000, steps: 1, records: 1, findings: 1, severity: 'critical' },
      { phase: 'credential-access', label: 'Credential access', first: T0 + 1_200_000, last: T0 + 1_200_000, steps: 1, records: 3, findings: 0, severity: null },
    ],
    steps,
    records: 5,
    hosts: ['ws-004'],
    accounts: ['id:daniel'],
    ips: ['203.0.113.69'],
    attackerAddresses: ['203.0.113.69'],
    chains: [],
    findings: ['k1', 'k2'],
    campaigns: ['campaign-1'],
    gaps: ['What ran on WS-004 is not in the evidence: it has no Sysmon process creation (1) and no process creation audit (4688).'],
    lineage: {
      sessions: [
        {
          id: 'ses:1',
          host: 'ws-004',
          logonId: '0x9a01',
          account: 'NORTHSTAR\\daniel.roy',
          type: 10,
          typeName: 'remote interactive (RDP)',
          ip: '203.0.113.69',
          workstation: null,
          from: null,
          start: T0,
          end: null,
          logonRef: 'event:1',
          logoffRef: null,
          logonSeen: true,
          rdp: true,
          privileged: false,
          elevated: false,
          reconnects: [],
          activity: 1,
          activityKinds: { '1102': 1 },
          actions: {},
        },
      ],
      hops: [
        {
          id: 'hop:1',
          kind: 'rdp',
          from: { host: null, ip: '203.0.113.69', workstation: null, external: true, basis: null },
          to: 'ws-004',
          account: 'NORTHSTAR\\daniel.roy',
          ts: T0,
          tsEnd: T0,
          count: 1,
          session: 'ses:1',
          refs: ['event:1'],
          evidence: [],
          basis: 'an RDP logon (4624 type 10) came from it',
          confidence: 'strong',
        },
      ],
      processes: [],
    },
  }
  return {
    version: 1,
    stories: [story],
    campaigns: [
      {
        id: 'campaign-1',
        label: '203.0.113.69',
        labelKind: 'ip',
        artifacts: [{ kind: 'ip', value: '203.0.113.69', stories: ['story-1'] }],
        stories: ['story-1'],
        people: ['id:daniel'],
        targets: [{ id: 'id:e19', account: 'northstar\\employee019', how: ['failed logon'], via: ['203.0.113.69'], refs: ['event:3'] }],
        start: T0,
        end: T0 + 20 * 60_000,
        severity: 'critical',
      },
    ],
    chains: { chains: [], stats: {} },
    identities: [
      {
        id: 'id:daniel',
        label: 'daniel.roy@northstar.example',
        kind: 'person',
        org: 'northstar.example',
        forms: [
          { kind: 'addr', value: 'daniel.roy@northstar.example', seen: 81, ref: null, confidence: 'strong' },
          { kind: 'netbios', value: 'northstar\\daniel.roy', seen: 93, ref: null, confidence: 'medium' },
        ],
        joins: [
          {
            a: 'daniel.roy@northstar.example',
            b: 'northstar\\daniel.roy',
            kinds: ['addr', 'netbios'],
            basis: 'the same account in its organisation (the NetBIOS name of its domain)',
            confidence: 'medium',
            ref: null,
            count: 1,
          },
        ],
        possibly: [],
        namesakes: [],
        conflicts: [],
        notes: [],
      },
    ],
    hosts: [],
    unstoried: [],
    stats: { events: 5, mails: 0, truncated: [] },
    builtAt: T0,
  }
}

let db: RemnDB
beforeEach(async () => {
  db = new RemnDB(`storiesview-${Math.random()}`)
  setDb(db)
  useStore.setState({ currentCase: kase, view: 'stories', focusChain: null })
  vi.mocked(apiPost).mockReset()
})
afterEach(async () => {
  cleanup()
  await db.delete()
})

describe('the Stories page', () => {
  it(
    'reads a story along its phases, and a step says why it is there and what its rule is worth',
    async () => {
      await db.kv.put({ key: 'stories-1', value: snapshot() })
      render(<StoriesView />)
      await screen.findByRole('button', { name: 'Story daniel.roy@northstar.example' }, WAIT)
      expect(screen.getByText('1 story · 1 critical · 1 campaign(s)', { exact: false })).toBeTruthy()
      // the phase rail: three phases lit, in the story's own order
      const rail = screen.getByRole('list', { name: 'ATT&CK phases of the story' })
      const lit = within(rail)
        .getAllByRole('listitem')
        .filter((b) => !(b as HTMLButtonElement).disabled)
      expect(lit.map((b) => b.textContent)).toEqual(['IAInitial access1', 'DIDefense impairment2', 'CACredential access3'])
      // picking a phase filters the timeline
      fireEvent.click(lit[1])
      expect(screen.queryByText('Logon RemoteInteractive as NORTHSTAR\\daniel.roy from 203.0.113.69')).toBeNull()
      fireEvent.click(lit[1])
      // a step: its tie and the measure of its rule
      fireEvent.click(await screen.findByText('Logon RemoteInteractive as NORTHSTAR\\daniel.roy from 203.0.113.69'))
      expect(await screen.findByText('Why it is in the story')).toBeTruthy()
      expect(screen.getByText('Fires on 12 of 13 recorded attacks of what it looks for.', { exact: false })).toBeTruthy()
      expect(screen.getAllByText(/an RDP logon \(4624 type 10\) came from it/).length).toBeGreaterThan(0)
      expect(screen.getByText('Build relationships in Explore', { exact: false })).toBeTruthy()
      // the folded run of another account's failures says so
      expect(screen.getByText('×3', { exact: false })).toBeTruthy()
    },
    TEST_TIMEOUT,
  )

  it(
    'shows who is who, where the story stops, and checks a note against the story’s records',
    async () => {
      await db.kv.put({ key: 'stories-1', value: snapshot() })
      render(<StoriesView />)
      await screen.findByRole('button', { name: 'Story daniel.roy@northstar.example' }, WAIT)
      fireEvent.click(screen.getByText('Who is who'))
      expect(await screen.findByText('the same account in its organisation (the NetBIOS name of its domain)', { exact: false })).toBeTruthy()
      fireEvent.click(screen.getByText(/Where it stops/))
      expect(await screen.findByText(/What ran on WS-004 is not in the evidence/)).toBeTruthy()
      expect(screen.getByText(/Security.evtx: 12 records are missing/)).toBeTruthy()
      // a note naming an address the records do not hold is unsupported
      fireEvent.change(screen.getByLabelText('Story note'), { target: { value: 'The attacker came from 203.0.113.69 and 198.51.100.77.' } })
      fireEvent.click(screen.getByText('Save note'))
      expect(await screen.findByText(/it names 198.51.100.77/, {}, WAIT)).toBeTruthy()
      const saved = (await db.kv.get('story-notes-1'))?.value as Record<string, { text: string }>
      expect(Object.keys(saved)).toEqual(['person|daniel.roy@northstar.example|2026-09-04'])
    },
    TEST_TIMEOUT,
  )

  it(
    'lists the campaigns with the other accounts their sources reached, and explores the graph with its link reviews',
    async () => {
      await db.kv.put({ key: 'stories-1', value: snapshot() })
      const graph: RelationshipResult = {
        nodes: [
          { id: 'record:events:1:9', kind: 'record', value: 'events:1:9', scope: '', label: 'logon' },
          { id: 'host::ws-004', kind: 'host', value: 'ws-004', scope: '', label: 'ws-004' },
        ],
        edges: [
          {
            source: 'record:events:1:9',
            target: 'host::ws-004',
            relation: 'observed on',
            reason: 'Host explicitly named by this record',
            confidence: 'high',
            refs: [{ id: 1, evidenceId: 9, source: 'events', sourceFile: 'Security.evtx', sourceSha256: null, sourceIndex: 0, recordKind: 'event', ts: T0, observedAt: null, title: 'logon' }],
            count: 1,
          },
        ],
        stats: { events: 1, mails: 0, truncated: false, rowCap: 20_000, referenceCap: 30 },
      }
      await db.evidence.add({ id: 9, caseId: 1, name: 'Security.evtx', size: 1, kind: 'evtx', integrity: 'verified', addedAt: 1 } as never)
      const evidence = await db.evidence.toArray()
      await db.kv.put({
        key: 'relationship-cache-1',
        value: { version: 2, fingerprint: JSON.stringify(evidence.map((e) => [e.id, e.sha256Client, e.count, e.status])), result: graph, aliases: {}, scope: '' },
      })
      render(<StoriesView />)
      await screen.findByRole('button', { name: 'Story daniel.roy@northstar.example' }, WAIT)
      // a step shows the links its records support once the graph is built
      fireEvent.click(screen.getByText('Logon RemoteInteractive as NORTHSTAR\\daniel.roy from 203.0.113.69'))
      expect(await screen.findByText('observed on', {}, WAIT)).toBeTruthy()
      fireEvent.click(screen.getByText('Campaigns'))
      fireEvent.click(await screen.findByRole('button', { name: 'Campaign 203.0.113.69' }))
      expect(await screen.findByText('northstar\\employee019')).toBeTruthy()
      expect(screen.getByText('failed logon')).toBeTruthy()
      fireEvent.click(screen.getByText('Explore'))
      expect(await screen.findByRole('img', { name: 'Connections around the selected entity' }, WAIT)).toBeTruthy()
      expect(screen.getByLabelText('Entity type')).toBeTruthy()
    },
    TEST_TIMEOUT,
  )

  it(
    'reads a case with findings and no snapshot into stories at once, and opens the story of a chain',
    async () => {
      const built = snapshot()
      built.stories[0].chains = ['chain-daniel-1']
      vi.mocked(apiPost).mockResolvedValue(built)
      await db.findings.add({
        caseId: 1,
        ruleId: 'r',
        key: 'r|1',
        title: 'x',
        severity: 'high',
        source: 'events',
        ts: T0,
        entities: {},
        count: 1,
        refs: [1],
        attack: [],
        tags: [],
        status: 'new',
        createdAt: 1,
      } as never)
      render(<StoriesView />)
      await screen.findByRole('button', { name: 'Story daniel.roy@northstar.example' }, WAIT)
      expect(vi.mocked(apiPost).mock.calls[0][0]).toBe('/api/stories/build')
      expect((await db.kv.get('stories-1'))?.value).toBeTruthy()
      cleanup()
      useStore.setState({ focusChain: 'chain-daniel-1' })
      render(<StoriesView />)
      await waitFor(() => expect(screen.getByText('review the chain')).toBeTruthy(), WAIT)
      expect(useStore.getState().focusChain).toBeNull()
    },
    TEST_TIMEOUT,
  )
})
