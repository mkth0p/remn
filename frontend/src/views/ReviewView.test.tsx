// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case, type Finding } from '../db/schema'
import { useStore } from '../state/store'

vi.mock('../api/client', () => ({ apiPost: vi.fn(), apiGet: vi.fn(), API_HEADERS: {} }))
vi.mock('../ai/chat', () => ({ runAgent: vi.fn() }))
vi.mock('../data/source', () => ({ getSource: () => ({ kind: 'browser' }) }))

import { ReviewView } from './ReviewView'

const WAIT = { timeout: 8000 }
const TEST_TIMEOUT = 30_000
const kase: Case = { id: 1, name: 'Lab', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
let db: RemnDB
const T0 = 1_700_000_000_000
const f = (p: Partial<Finding> & { ruleId: string; severity: Finding['severity'] }): Finding => ({
  caseId: 1,
  key: `${p.ruleId}|${p.refs?.join(',') ?? ''}`,
  title: p.ruleId,
  source: 'events',
  ts: T0,
  entities: {},
  count: 1,
  refs: [1],
  attack: [],
  status: 'new',
  createdAt: 5,
  ...p,
})

beforeEach(async () => {
  db = new RemnDB(`review-${Math.random()}`)
  setDb(db)
  useStore.setState({ currentCase: kase, view: 'review', rulesVersion: 0, aiStatus: { reachable: false, checkedAt: 0 } })
  await db.evidence.add({ caseId: 1, name: 'pkg.zip', kind: 'package', size: 1, addedAt: 10, status: 'done', count: 3, integrity: 'verified', progress: 1 } as never)
  await db.findings.bulkAdd([
    f({
      ruleId: 'win-scheduled-task-suspicious-content',
      severity: 'high',
      title: 'Scheduled task with suspicious command',
      refs: [1],
      attack: ['T1053.005'],
      entities: { computer: 'WS-1', taskName: '\\Shift\\Updater' },
    }),
    f({
      ruleId: 'win-new-firewall-rule',
      severity: 'medium',
      title: 'Firewall rules added',
      refs: [2],
      ts: T0 + 60_000,
      attack: ['T1562.004'],
      entities: { computer: 'WS-1', applicationPath: 'c:\\shift\\shift.exe' },
    }),
  ])
})
afterEach(async () => {
  cleanup()
  await db.delete()
})

describe('ReviewView', () => {
  it(
    'opens on the verdict bar, lists the queue with its facts, and a keyboard decision moves the verdict',
    async () => {
      await act(async () => {
        render(<ReviewView />)
      })
      await waitFor(() => expect(document.querySelectorAll('.review-rail .item').length).toBe(1), WAIT)
      // one incident (same host, inside the six-hour gap), undecided: the seal says the review is incomplete
      expect(document.querySelector('.verdict-bar .seal.pending')).toBeTruthy()
      expect(screen.getByText('Review incomplete')).toBeTruthy()
      expect(document.querySelector('.review-rail .group-head')?.textContent).toContain('to decide')
      // the facts table names the rule and what it matched
      await waitFor(() => expect(document.querySelectorAll('.facts tbody tr').length).toBe(2), WAIT)
      expect(screen.getByText('\\Shift\\Updater')).toBeTruthy()
      expect(screen.getByText('c:\\shift\\shift.exe')).toBeTruthy()
      // the decision bar says what confirming would do to the verdict
      expect(document.querySelector('.decide .effect')?.textContent).toContain('confirmed → Compromise confirmed')
      fireEvent.keyDown(window, { key: 'e' })
      await waitFor(() => expect(document.querySelector('.verdict-bar .seal.compromise')).toBeTruthy(), WAIT)
      expect(screen.getAllByText('Compromise confirmed').length).toBeGreaterThan(0)
      const stored = await db.findings.toArray()
      expect(stored.every((x) => x.status === 'escalated' && x.decidedBy === 'analyst')).toBe(true)
      // the item moved to the confirmed group and the done panel points at the report
      await waitFor(
        () => expect(Array.from(document.querySelectorAll('.review-rail .group-head')).map((el) => el.textContent)).toEqual(expect.arrayContaining([expect.stringContaining('confirmed')])),
        WAIT,
      )
      expect(screen.getByText('print the report')).toBeTruthy()
      // the persistence badge is filled now that a confirmed item carries T1053
      expect(document.querySelector('.verdict-badges .hex.confirmed')).toBeTruthy()
    },
    TEST_TIMEOUT,
  )

  it(
    'counts a story the analyst confirmed on the Stories page in the verdict, as the report does',
    async () => {
      await db.findings.toCollection().modify({ status: 'reviewed' })
      const step = {
        id: 'event:1',
        refs: ['event:1'],
        source: 'events',
        ts: T0,
        tsEnd: T0,
        count: 1,
        title: 'task created',
        host: 'ws-1',
        ip: null,
        origin: 'host',
        phase: 'persistence',
        phaseBasis: '',
        findings: [{ ruleId: 'win-scheduled-task-suspicious-content', title: 'Scheduled task with suspicious command', severity: 'high', key: 'win-scheduled-task-suspicious-content|1' }],
        severity: 'high',
        tie: { kind: 'flag', basis: '', confidence: 'strong' },
        notes: [],
        accounts: [],
        session: null,
        process: null,
        hops: [],
        routine: false,
      }
      const story = {
        id: 'story-1',
        kind: 'host',
        subject: { kind: 'host', id: 'ws-1', label: 'ws-1', org: null },
        title: 'ws-1',
        headline: '',
        summary: '',
        start: T0,
        end: T0,
        severity: 'high',
        score: 40,
        confidence: 'strong',
        phases: [],
        steps: [step],
        records: 1,
        hosts: ['ws-1'],
        accounts: [],
        ips: [],
        attackerAddresses: [],
        chains: [],
        findings: ['win-scheduled-task-suspicious-content|1'],
        campaigns: [],
        gaps: [],
        lineage: { sessions: [], hops: [], processes: [] },
      }
      await db.kv.put({ key: 'stories-1', value: { version: 1, stories: [story], campaigns: [], chains: { chains: [], stats: {} }, identities: [], hosts: [], unstoried: [], stats: {} } })
      await act(async () => {
        render(<ReviewView />)
      })
      // the incident was reviewed, nothing confirmed
      await waitFor(() => expect(document.querySelector('.verdict-bar .seal.unconfirmed')).toBeTruthy(), WAIT)
      cleanup()
      await db.kv.put({
        key: 'story-decisions-1',
        value: {
          'story-1': {
            anchor: { kind: 'host', subject: ['host:ws-1'], findings: [], title: 'ws-1', start: T0 },
            updatedAt: 1,
            call: { verdict: 'confirmed', reason: 'the task is theirs', decidedAt: 1 },
          },
        },
      })
      await act(async () => {
        render(<ReviewView />)
      })
      await waitFor(() => expect(document.querySelector('.verdict-bar .seal.compromise')).toBeTruthy(), WAIT)
      // its finding fills the persistence badge as a confirmed incident's would
      expect(document.querySelector('.verdict-badges .hex.confirmed')).toBeTruthy()
    },
    TEST_TIMEOUT,
  )
})
