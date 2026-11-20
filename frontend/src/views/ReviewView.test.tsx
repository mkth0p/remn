// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case, type Finding } from '../db/schema'
import { useStore } from '../state/store'
import type { Chain } from '../data/chains'
import type { TriageRun } from '../data/aiReview'

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
  // an action's last reads (the chain reviews, the findings, the proposals) can still be on their way
  // when a test has seen what it checks; they settle before the database goes
  await new Promise((r) => setTimeout(r, 100))
  await db.delete()
})

/** the switch beside a label (the Toggle primitive) */
const toggle = (label: string | RegExp) => screen.getByText(label).closest('label')!.querySelector('[role=switch]') as HTMLElement
const button = (name: string | RegExp) => screen.getByRole('button', { name })
async function openReview() {
  await act(async () => {
    render(<ReviewView />)
  })
  await waitFor(() => expect(document.querySelectorAll('.facts tbody tr').length).toBeGreaterThan(0), WAIT)
}
// an invented attack chain whose one step is the firewall rule's row: that finding is decided with the chain
const firewallChain: Chain = {
  id: 'chain-1',
  identity: 'alice@northstar.example',
  identityLabel: 'alice@northstar.example',
  seed: { source: 'mails', id: 9, ts: T0 - 60_000, subject: 'Invoice', fromAddr: 'billing@evil.example', risk: 85, flags: [], findings: [], urlDomains: [], attachments: [] },
  steps: [
    {
      kind: 'event',
      source: 'events',
      id: 2,
      refs: [2],
      ts: T0 + 60_000,
      tsEnd: T0 + 60_000,
      count: 1,
      title: 'Firewall rule added on WS-1',
      weight: 10,
      artifacts: ['host WS-1'],
      findings: [{ ruleId: 'win-new-firewall-rule', title: 'Firewall rules added', severity: 'medium' }],
      offsetMin: 1,
      computer: 'WS-1',
      origin: 'host',
    },
  ],
  start: T0 - 60_000,
  end: T0 + 60_000,
  score: 70,
  severity: 'high',
  artifactLinks: 1,
  entities: { user: 'alice@northstar.example', ips: [], hosts: ['WS-1'], attackerAddresses: ['billing@evil.example'], domains: [] },
  summary: 'alice opened the invoice and a firewall rule was added on WS-1',
}

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

  it(
    'decides an incident from its card: its severity, whether the report carries it, its note, and reviewed on the way to the next',
    async () => {
      await openReview()
      const severity = (s: string) => Array.from(document.querySelectorAll('.decide .controls .segmented button')).find((b) => b.textContent === s) as HTMLElement
      fireEvent.click(severity('critical'))
      await waitFor(async () => expect((await db.findings.toArray()).some((x) => x.severityOverride === 'critical')).toBe(true), WAIT)
      fireEvent.click(await screen.findByRole('button', { name: 'reset' }, WAIT))
      await waitFor(async () => expect((await db.findings.toArray()).every((x) => !x.severityOverride)).toBe(true), WAIT)
      expect(screen.getByText('in the report')).toBeTruthy()
      fireEvent.click(toggle('in the report'))
      await waitFor(async () => expect((await db.findings.toArray()).every((x) => x.reportExclude)).toBe(true), WAIT)
      await waitFor(() => expect(screen.getByText('not in the report')).toBeTruthy(), WAIT)
      const note = screen.getByPlaceholderText('what this is, what was checked, what was decided…')
      fireEvent.change(note, { target: { value: 'the updater of a known vendor' } })
      fireEvent.blur(note)
      await waitFor(async () => expect((await db.findings.toArray()).find((x) => x.notes)?.notes).toBe('the updater of a known vendor'), WAIT)
      expect((await db.findings.toArray()).find((x) => x.notes)?.notesBy).toBe('analyst')
      fireEvent.click(button(/mark reviewed and next/))
      await waitFor(async () => expect((await db.findings.toArray()).every((x) => x.status === 'reviewed' && x.decidedBy === 'analyst')).toBe(true), WAIT)
    },
    TEST_TIMEOUT,
  )

  it(
    'asks the analyst about an incident, and opens its rows on the Events page',
    async () => {
      useStore.setState({ aiPrompt: null, eventsFilter: {} })
      await openReview()
      fireEvent.click(button(/ask the analyst/))
      expect(useStore.getState().view).toBe('ai')
      expect(useStore.getState().aiPrompt).toContain('finding:1 high Scheduled task with suspicious command')
      useStore.setState({ view: 'review' })
      fireEvent.click(button('open the rows'))
      expect(useStore.getState().view).toBe('events')
      expect(useStore.getState().eventsFilter).toEqual({ conditions: [{ field: 'id', op: 'in', value: [1, 2] }], sort: { field: 'ts', dir: 'asc' } })
    },
    TEST_TIMEOUT,
  )

  it(
    'keeps what the report carries, as chosen under its contents',
    async () => {
      await openReview()
      const summary = () => document.querySelector('.report-contents summary')?.textContent ?? ''
      const before = (await db.kv.get('report-settings-1'))?.value as { includeTasks?: boolean } | undefined
      fireEvent.click(toggle('tasks'))
      await waitFor(async () => expect(((await db.kv.get('report-settings-1'))?.value as { includeTasks: boolean }).includeTasks).toBe(!(before?.includeTasks ?? true)), WAIT)
      const from = document.querySelector('.report-contents select') as HTMLSelectElement
      fireEvent.change(from, { target: { value: 'high' } })
      await waitFor(() => expect(summary()).toContain('from high up'), WAIT)
      expect(((await db.kv.get('report-settings-1'))?.value as { minSeverity: string }).minSeverity).toBe('high')
      fireEvent.click(toggle('only what was reviewed'))
      await waitFor(() => expect(summary()).toContain('reviewed items only'), WAIT)
    },
    TEST_TIMEOUT,
  )

  it(
    'decides an attack chain with its verdict, keeps its narrative, unlinks a finding from it and opens its story',
    async () => {
      await db.kv.put({ key: 'chains-1', value: { chains: [firewallChain], stats: {} } })
      await openReview()
      const openChain = async () => {
        fireEvent.click(Array.from(document.querySelectorAll('.review-rail .item')).find((el) => el.textContent?.includes('alice@northstar.example')) as HTMLElement)
        await waitFor(() => expect(screen.getByText(/Attack chain · alice@northstar.example/)).toBeTruthy(), WAIT)
      }
      await openChain()
      expect(document.querySelector('.review-card')?.textContent).toContain('Firewall rules added')
      const narrative = screen.getByPlaceholderText('what happened, in order, and what tied it to the mail…')
      fireEvent.change(narrative, { target: { value: 'Alice opened the invoice; a firewall rule followed.' } })
      fireEvent.blur(narrative)
      await waitFor(
        async () =>
          expect(((await db.kv.get('chain-reviews-1'))?.value as Record<string, { narrative: string; narrativeBy: string }>)['chain-1']).toMatchObject({
            narrative: 'Alice opened the invoice; a firewall rule followed.',
            narrativeBy: 'analyst',
          }),
        WAIT,
      )
      fireEvent.click(button('open its story'))
      expect(useStore.getState().focusChain).toBe('chain-1')
      expect(useStore.getState().view).toBe('stories')
      fireEvent.click(Array.from(document.querySelectorAll('.decide .choices button')).find((b) => b.textContent?.startsWith('confirmed')) as HTMLElement)
      await waitFor(async () => expect(((await db.kv.get('chain-reviews-1'))?.value as Record<string, { verdict: string }>)['chain-1'].verdict).toBe('confirmed'), WAIT)
      await waitFor(async () => expect((await db.findings.get(2))?.status).toBe('escalated'), WAIT)
      // the decided chain moved down the rail; open it again to unlink its finding
      await openChain()
      fireEvent.click(button('unlink'))
      await waitFor(async () => expect((await db.findings.get(2))?.chainUnlinked).toBe(true), WAIT)
      expect(useStore.getState().toasts.map((t) => t.text)).toContain('1 finding unlinked from the chain: now in the queue on its own')
    },
    TEST_TIMEOUT,
  )

  it(
    'says what a triage with the model would send before it starts, and starts nothing while the model is unreachable',
    async () => {
      useStore.setState({ toasts: [] })
      await openReview()
      fireEvent.click(button(/triage with the model/))
      expect(await screen.findByText('Triage with the model', undefined, WAIT)).toBeTruthy()
      expect(document.querySelector('.modal')?.textContent).toContain('1 item will be sent.')
      expect(document.querySelector('.modal')?.textContent).toContain('4 items per call')
      fireEvent.click(button(/start/))
      expect(useStore.getState().toasts.map((t) => t.text)).toContain('the analyst model is not reachable (see the AI section in Settings)')
      // the dialog stays, for the analyst to fix the model or cancel
      expect(screen.getByText('Triage with the model')).toBeTruthy()
    },
    TEST_TIMEOUT,
  )

  it(
    'lists the last triage with what each entry did, and undoes a decision of a run that wrote them',
    async () => {
      await db.findings.toCollection().modify({ status: 'escalated', decidedBy: 'ai', aiReason: 'persistence by a task' })
      const run: TriageRun = {
        at: T0,
        model: 'invented-model',
        transport: 'browser',
        asked: 2,
        errors: [],
        rejected: ['incident:9: unknown id'],
        cut: ['batch 1 of 1: its items came to 91,204 characters and the prompt carries 90,000, so the model read 1 of its 2 item(s) in part or not at all: Scheduled task with suspicious command'],
        proposed: false,
        entries: [
          {
            id: 'incident:a',
            kind: 'incident',
            title: 'Scheduled task with suspicious command',
            decision: 'escalated',
            severityBefore: 'high',
            severityAfter: 'high',
            includeBefore: true,
            includeAfter: true,
            unlinked: [],
            reason: 'persistence by a task',
            before: {
              findings: [
                { id: 1, status: 'new' },
                { id: 2, status: 'new' },
              ] as never,
            },
          },
        ],
      }
      await db.kv.put({ key: 'ai-triage-1', value: run })
      await openReview()
      fireEvent.click(button('last AI triage'))
      await waitFor(() => expect(document.querySelector('.triage-table')).toBeTruthy(), WAIT)
      const modal = () => document.querySelector('.modal')?.textContent ?? ''
      expect(modal()).toContain('incidents confirmed')
      expect(modal()).toContain('persistence by a task')
      expect(modal()).toContain('1 of 2 item(s) got no decision')
      expect(modal()).toContain('not applied: incident:9: unknown id')
      expect(modal()).toContain('so the model read 1 of its 2 item(s) in part or not at all: Scheduled task with suspicious command')
      fireEvent.click(button('undo'))
      await waitFor(async () => expect((await db.findings.toArray()).map((x) => x.status)).toEqual(['new', 'new']), WAIT)
      await waitFor(() => expect(document.querySelector('.triage-table')?.textContent).toContain('undone'), WAIT)
      expect(((await db.kv.get('ai-triage-1'))?.value as TriageRun).entries[0].undone).toBe(true)
    },
    TEST_TIMEOUT,
  )

  it(
    'shows the model’s proposal on its item, and applies or dismisses it',
    async () => {
      const { saveSuggestion } = await import('../data/aiReview')
      await saveSuggestion(1, { target: 'finding:1', decision: 'false_positive', reason: 'the vendor’s own updater', at: T0, by: 'triage', model: 'invented-model' })
      await openReview()
      await waitFor(() => expect(document.querySelector('.suggestion')).toBeTruthy(), WAIT)
      expect(document.querySelector('.suggestion')?.textContent).toContain('the model proposes')
      expect(document.querySelector('.suggestion')?.textContent).toContain('on finding #1')
      expect(document.querySelector('.suggestion')?.textContent).toContain('the vendor’s own updater')
      expect(document.querySelector('.review-rail .ai-tag.proposal')).toBeTruthy()
      fireEvent.click(button('dismiss'))
      await waitFor(() => expect(document.querySelector('.suggestion')).toBeNull(), WAIT)
      await saveSuggestion(1, { target: 'finding:1', decision: 'false_positive', reason: 'the vendor’s own updater', at: T0, by: 'triage' })
      cleanup()
      await openReview()
      await waitFor(() => expect(document.querySelector('.suggestion')).toBeTruthy(), WAIT)
      fireEvent.click(button('apply'))
      await waitFor(async () => expect((await db.findings.get(1))?.status).toBe('false_positive'), WAIT)
      // the proposal leaves its item once applied
      await waitFor(() => expect(document.querySelector('.suggestion')).toBeNull(), WAIT)
    },
    TEST_TIMEOUT,
  )
})
