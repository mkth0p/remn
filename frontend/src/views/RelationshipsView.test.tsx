// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { RelationshipEdge, RelationshipNode, RelationshipRef, RelationshipResult } from '../data/relationships'
import type { RelationshipReview } from '../data/relationshipReviews'
import { defaultSettings, RemnDB, setDb, type Case, type Finding } from '../db/schema'
import { useStore } from '../state/store'

vi.mock('../api/client', () => ({ apiPost: vi.fn(), apiGet: vi.fn(), API_HEADERS: {} }))
vi.mock('../data/source', () => ({ getSource: () => ({ kind: 'browser', getEvent: async () => null, getMail: async () => null }) }))
// the ECharts renderer needs a canvas; the view only has to hand it the story graph
vi.mock('../components/ChainGraph', () => ({ ChainGraph: () => 'story graph placeholder' }))
vi.mock('../ai/chat', () => ({ runAgent: vi.fn() }))

import { RelationshipsView } from './RelationshipsView'
import { runAgent } from '../ai/chat'

const WAIT = { timeout: 8000 }
const TEST_TIMEOUT = 30_000 // jsdom + fake-indexeddb are slow on first render
const T0 = Date.UTC(2026, 7, 19, 8, 0, 0)
const H = 3_600_000
const kase: Case = { id: 1, name: 'Lab', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
const DIGEST = 'sha256:' + 'ab12'.repeat(16)
const HASH = `hash::${DIGEST}`
const SENDER = 'account::billing@evil.test'
const HOST = 'host::ws01'
const MAIL = 'record:mails:1:9'
const PROC = 'record:events:10:9'

const ref = (source: 'events' | 'mails', id: number, title: string, sourceFile: string, ts: number | null, observedAt: number | null = null): RelationshipRef => ({
  id,
  evidenceId: 9,
  source,
  sourceFile,
  sourceSha256: null,
  sourceIndex: id,
  recordKind: observedAt != null ? 'observation' : 'event',
  ts,
  observedAt,
  title,
})
const edge = (source: string, target: string, relation: string, r: RelationshipRef, confidence = 'high'): RelationshipEdge => ({
  source,
  target,
  relation,
  reason: `${relation}: the record reports it`,
  confidence,
  refs: [r],
  count: 1,
})
const stats = { events: 1, mails: 1, truncated: false, rowCap: 20_000, referenceCap: 30 }

/** A mail with an attachment digest and a collected process reporting the same digest: one story, one bridge. */
function graph(): RelationshipResult {
  const mail = ref('mails', 1, 'Invoice 2026-08', 'mailbox/invoice.eml', T0)
  const proc = ref('events', 10, 'process upd.exe', 'Processes/processes.csv', null, T0 + 30 * H)
  const nodes: RelationshipNode[] = [
    { id: MAIL, kind: 'record', value: 'mails:1:9', scope: '', label: 'Invoice 2026-08' },
    { id: PROC, kind: 'record', value: 'events:10:9', scope: '', label: 'process upd.exe' },
    { id: HASH, kind: 'hash', value: DIGEST, scope: '', label: DIGEST },
    { id: SENDER, kind: 'account', value: 'billing@evil.test', scope: '', label: 'billing@evil.test' },
    { id: HOST, kind: 'host', value: 'ws01', scope: '', label: 'ws01' },
  ]
  const edges = [edge(MAIL, HASH, 'attachment digest', mail), edge(MAIL, SENDER, 'sent by', mail, 'contextual'), edge(PROC, HASH, 'reports hash', proc), edge(PROC, HOST, 'observed on', proc)]
  return { nodes, edges, stats }
}

/** One event naming only its host: nothing seeds a story. */
function lonelyGraph(): RelationshipResult {
  const logon = ref('events', 21, 'logon alice', 'Security.evtx', T0)
  return {
    nodes: [
      { id: 'record:events:21:9', kind: 'record', value: 'events:21:9', scope: '', label: 'logon alice' },
      { id: HOST, kind: 'host', value: 'ws01', scope: '', label: 'ws01' },
    ],
    edges: [edge('record:events:21:9', HOST, 'observed on', logon)],
    stats,
  }
}

const phishing: Finding = {
  caseId: 1,
  ruleId: 'mail-phish',
  key: 'mail-phish|1',
  title: 'Credential phishing',
  severity: 'high',
  source: 'mails',
  ts: T0,
  entities: {},
  count: 1,
  refs: [1],
  attack: [],
  status: 'new',
  createdAt: T0,
}

let db: RemnDB
beforeEach(async () => {
  db = new RemnDB(`relationships-${Math.random()}`)
  setDb(db)
  useStore.setState({ currentCase: kase, view: 'relationships', rulesVersion: 0, entity: null, aiPrompt: null })
  await db.evidence.add({ id: 9, caseId: 1, name: 'package.zip', kind: 'package', size: 1, sha256Client: 'abc', addedAt: 10, status: 'done', count: 2, integrity: 'verified', progress: 1 })
})
afterEach(async () => {
  cleanup()
  await db.delete()
})

/** The cache the view reads on mount, keyed by the same evidence fingerprint the view computes. */
async function cache(result: RelationshipResult) {
  const fingerprint = JSON.stringify([[9, 'abc', 2, 'done']])
  await db.kv.put({ key: 'relationship-cache-1', value: { version: 2, fingerprint, result, aliases: {}, scope: '' } })
}

const sub = () => document.querySelector('.view-header .sub')?.textContent ?? ''
const steps = () => document.querySelectorAll('.story .step')

async function loadStory() {
  await cache(graph())
  await db.findings.add(phishing)
  await act(async () => {
    render(<RelationshipsView />)
  })
  await waitFor(() => expect(document.querySelectorAll('.story-row').length).toBe(1), WAIT)
}

describe('RelationshipsView', () => {
  it(
    'shows investigation evidence and makes no automatic AI request',
    async () => {
      await loadStory()
      fireEvent.click(screen.getByRole('button', { name: /^Investigate$/ }))
      await waitFor(() => expect(screen.getByText('Evidence-bound AI review')).toBeTruthy(), WAIT)
      expect(screen.getByText('Contradictions, alternatives and gaps')).toBeTruthy()
      expect(screen.getByText('Next useful checks')).toBeTruthy()
      expect(screen.getByRole('button', { name: 'Review selected story with AI' })).toBeTruthy()
      expect(runAgent).not.toHaveBeenCalled()
    },
    TEST_TIMEOUT,
  )
  it(
    'lists the story a finding seeds and reads it as a timeline with the finding badge and the anchor',
    async () => {
      await loadStory()
      expect(sub()).toBe('1 stories · 2 records in 2 sources')
      expect(screen.getByRole('button', { name: 'Rebuild relationships' })).toBeTruthy()
      const row = document.querySelector('.story-row.active')!
      expect(row.querySelector('.name')?.textContent).toBe('Credential phishing')
      expect(row.querySelector('.meta')?.textContent).toContain('2 records')
      expect(row.querySelector('.meta')?.textContent).toContain('1 links')
      // the first story is selected: its header, breakdown and records are shown
      expect(screen.getByText(/^priority \d+ = findings \d+\/40 · links \d+\/30 · sources \d+\/15 · marks \d+\/15$/)).toBeTruthy()
      await waitFor(() => expect(steps().length).toBe(2), WAIT)
      const titles = Array.from(document.querySelectorAll('.story .step .title')).map((el) => el.textContent)
      expect(titles).toEqual(['Invoice 2026-08', 'process upd.exe'])
      expect(screen.getByTitle('Credential phishing').textContent).toBe('mail-phish')
      // the mail the finding cites is the anchor; the process entered through the digest both sources name
      expect(steps()[0].querySelector('.t')?.textContent).toContain('anchor')
      expect(steps()[1].querySelector('.t')?.textContent).toContain('collected')
      expect(screen.getByText('cross-source')).toBeTruthy()
      // the collected process is drawn as a host record without an event time
      expect(document.querySelector('.story .step .n.host.collected')).toBeTruthy()
      expect(steps()[1].querySelector('.sub')?.textContent).toContain('processes.csv · via hash')
    },
    TEST_TIMEOUT,
  )

  it(
    'opens the record pane on click, moves with j / k and explains why the record is in the story',
    async () => {
      await loadStory()
      await waitFor(() => expect(steps().length).toBe(2), WAIT)
      fireEvent.click(steps()[0])
      await waitFor(() => expect(screen.getByText('Record 1 of 2')).toBeTruthy(), WAIT)
      expect(screen.getByText('Why it is in the story')).toBeTruthy()
      expect(screen.getByText('started the story: finding')).toBeTruthy()
      expect(screen.getByRole('button', { name: 'open the row' })).toBeTruthy()
      fireEvent.keyDown(window, { key: 'j' })
      await waitFor(() => expect(screen.getByText('Record 2 of 2')).toBeTruthy(), WAIT)
      expect(screen.getByText(/reports hash hash sha256:.*, from Invoice 2026-08/)).toBeTruthy()
      expect(document.querySelectorAll('.story .step.active')).toHaveLength(1)
      fireEvent.keyDown(window, { key: 'k' })
      await waitFor(() => expect(screen.getByText('Record 1 of 2')).toBeTruthy(), WAIT)
      fireEvent.click(screen.getByRole('button', { name: 'close' }))
      await waitFor(() => expect(screen.queryByText('Record 1 of 2')).toBeNull(), WAIT)
      // the graph tab draws the story graph and keeps the record pane beside it
      fireEvent.click(screen.getByRole('button', { name: 'Graph' }))
      await waitFor(() => expect(screen.getByText('story graph placeholder')).toBeTruthy(), WAIT)
    },
    TEST_TIMEOUT,
  )

  it(
    'reviews a link of the story from the Links tab and lists the entities with their role',
    async () => {
      await loadStory()
      fireEvent.click(screen.getByRole('button', { name: 'Links' }))
      await waitFor(() => expect(screen.getAllByLabelText('Relationship decision').length).toBeGreaterThan(0), WAIT)
      expect(screen.getByText('attachment digest', { exact: true })).toBeTruthy()
      expect(screen.getAllByText('Include accepted link in report').length).toBeGreaterThan(0)
      expect(screen.getAllByLabelText('Relationship notes').length).toBeGreaterThan(0)
      const link = screen.getByText('attachment digest', { exact: true }).closest('details')!
      fireEvent.change(link.querySelector('select[aria-label="Relationship decision"]')!, { target: { value: 'accepted' } })
      fireEvent.change(link.querySelector('textarea[aria-label="Relationship notes"]')!, { target: { value: 'Same SHA-256 in the mail and the process snapshot.' } })
      fireEvent.click(Array.from(link.querySelectorAll('button')).find((b) => b.textContent === 'Save relationship review')!)
      await waitFor(() => expect(link.querySelector('[role=status]')?.textContent).toBe('Saved'), WAIT)
      const saved = Object.values(((await db.kv.get('relationship-reviews-1'))?.value ?? {}) as Record<string, RelationshipReview>)
      expect(saved).toHaveLength(1)
      expect(saved[0]).toMatchObject({ status: 'accepted', relation: 'attachment digest', notes: 'Same SHA-256 in the mail and the process snapshot.' })
      fireEvent.click(screen.getByRole('button', { name: 'Entities' }))
      await waitFor(() => expect(document.querySelectorAll('table.table.compact tbody tr').length).toBe(3), WAIT)
      const roles = Array.from(document.querySelectorAll('table.table.compact tbody tr')).map((tr) => [tr.children[0].textContent, tr.children[4].textContent])
      expect(roles).toEqual([
        ['hash', 'bridge'],
        ['account', 'context'],
        ['host', 'context'],
      ])
      // a row hands the entity to Explore
      fireEvent.click(document.querySelector('table.table.compact tbody tr')!)
      await waitFor(() => expect(screen.getByRole('img', { name: 'Connections around the selected entity' })).toBeTruthy(), WAIT)
      expect(document.querySelector('.segmented button.active')?.textContent).toBe('Explore')
    },
    TEST_TIMEOUT,
  )

  it(
    'Explore lists the entities by kind and browses the selected one',
    async () => {
      await loadStory()
      fireEvent.click(screen.getByRole('button', { name: 'Explore' }))
      await waitFor(() => expect(screen.getByLabelText('Search entities')).toBeTruthy(), WAIT)
      const kinds = Array.from((screen.getByLabelText('Entity type') as HTMLSelectElement).options).map((o) => o.textContent)
      expect(kinds).toEqual(['All types', 'account', 'hash', 'host', 'record'])
      const entities = screen.getAllByRole('button').filter((b) => /^(hash|host|account|record) · /.test(b.textContent ?? ''))
      expect(entities.length).toBe(5)
      expect(entities.some((b) => b.textContent?.startsWith(`hash · ${DIGEST}`))).toBe(true)
      // the cross-source digest is selected first: its wheel, its timeline and its links
      expect(screen.getByRole('img', { name: 'Connections around the selected entity' })).toBeTruthy()
      expect(screen.getByText(/Related evidence timeline · 2 records/)).toBeTruthy()
      expect(screen.getByText('attachment digest', { exact: true })).toBeTruthy()
      expect(screen.getByText('reports hash', { exact: true })).toBeTruthy()
      fireEvent.change(screen.getByLabelText('Entity type'), { target: { value: 'host' } })
      await waitFor(() => expect(screen.getAllByRole('button').filter((b) => /^host · /.test(b.textContent ?? ''))).toHaveLength(1), WAIT)
      fireEvent.click(screen.getAllByRole('button').filter((b) => /^host · /.test(b.textContent ?? ''))[0])
      await waitFor(() => expect(screen.getByText('observed on', { exact: true })).toBeTruthy(), WAIT)
      expect(screen.getAllByLabelText('Relationship decision')).toHaveLength(1)
    },
    TEST_TIMEOUT,
  )

  it(
    'says why there is no story when nothing seeds one',
    async () => {
      await cache(lonelyGraph())
      await act(async () => {
        render(<RelationshipsView />)
      })
      await waitFor(
        () => expect(screen.getByText(/^No story: no finding cites a scanned record, no row is marked relevant or pivot, and no specific entity appears in two source files/)).toBeTruthy(),
        WAIT,
      )
      expect(sub()).toBe('0 stories · 0 records in 0 sources')
      expect(document.querySelectorAll('.story-row')).toHaveLength(0)
    },
    TEST_TIMEOUT,
  )

  it(
    'explains what a story is before a graph exists',
    async () => {
      await act(async () => {
        render(<RelationshipsView />)
      })
      await waitFor(() => expect(screen.getByRole('button', { name: 'Build relationships' })).toBeTruthy(), WAIT)
      expect(sub()).toBe('not built yet')
      expect(screen.getByText(/A story is a group of records tied together/)).toBeTruthy()
      expect((screen.getByLabelText('Story window (hours)') as HTMLInputElement).value).toBe('72')
    },
    TEST_TIMEOUT,
  )
})
