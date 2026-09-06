// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case, type Finding } from '../db/schema'
import { useStore } from '../state/store'

vi.mock('../api/client', () => ({ apiPost: vi.fn(), apiGet: vi.fn(), API_HEADERS: {} }))
vi.mock('../data/rules', () => ({ loadRules: vi.fn(async () => []), runRulesFor: vi.fn(), settingsForRules: () => ({}) }))
vi.mock('../data/source', () => ({ getSource: () => ({ countEvents: async () => 3, countMails: async () => 2, kind: 'browser' }) }))
vi.mock('../components/RescoreButton', () => ({ RescoreButton: () => null }))
vi.mock('../data/ingest', () => ({ refreshCounts: vi.fn(async () => undefined) }))

import { FindingsView } from './FindingsView'

const WAIT = { timeout: 8000 }
const TEST_TIMEOUT = 30_000  // jsdom + fake-indexeddb are slow on first render
const kase: Case = { id: 1, name: 'Lab', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
let db: RemnDB
const f = (p: Partial<Finding> & { ruleId: string; severity: Finding['severity'] }): Finding =>
  ({ caseId: 1, key: `${p.ruleId}|${Math.random()}`, title: p.ruleId, source: 'mails', ts: 1_700_000_000_000, entities: {}, count: 1, refs: [1], attack: [], status: 'new', createdAt: 5, ...p })

beforeEach(async () => {
  db = new RemnDB(`findings-${Math.random()}`)
  setDb(db)
  useStore.setState({ currentCase: kase, view: 'findings', rulesRun: null, rulesVersion: 0 })
  await db.findings.bulkAdd([
    f({ ruleId: 'mail-credential-phishing', severity: 'critical', title: 'Credential phishing', refs: [7], entities: { fromAddr: 'x@evil.test', subject: 'Urgent invoice' } }),
    f({ ruleId: 'mail-html-attachment', severity: 'low', title: 'HTML attachment', refs: [7], entities: { fromAddr: 'x@evil.test', subject: 'Urgent invoice' } }),
    f({ ruleId: 'mail-critical-risk-score', severity: 'high', title: 'Critical overall risk score', refs: [7], entities: { subject: 'Urgent invoice' } }),
    f({ ruleId: 'win-log-cleared', severity: 'critical', title: 'Security audit log cleared', source: 'events', refs: [42], entities: { computer: 'WS-1', subjectUser: 'bob' } }),
  ])
  await db.evidence.add({ caseId: 1, name: 'box.mbox', kind: 'mail', size: 1, addedAt: 10, status: 'done', count: 3, integrity: 'verified', progress: 1 } as never)
})
afterEach(async () => {
  cleanup()
  await db.delete()
})

const sub = () => document.querySelector('.view-header .sub')?.textContent ?? ''

describe('FindingsView', () => {
  it('groups four findings into two incidents and flags that rules never ran on the evidence', async () => {
    await act(async () => {
      render(<FindingsView />)
    })
    await waitFor(() => expect(sub()).toContain('2 incident(s) · 4 finding(s)'), WAIT)
    // findings exist but no run is recorded and one evidence file finished: the banner says so
    await waitFor(() => expect(screen.getByText(/Findings are behind the evidence/)).toBeTruthy(), WAIT)
    expect(screen.getByText(/1 evidence file added since the last run/)).toBeTruthy()
    // severity tiles count incidents in the default view: both incidents are critical
    const tile = document.querySelector('.kpi.critical')!
    expect(tile.textContent).toContain('2')
  }, TEST_TIMEOUT)

  it('switches to the rule grouping and expands a rule to its findings', async () => {
    await act(async () => {
      render(<FindingsView />)
    })
    await waitFor(() => expect(sub()).toContain('4 finding(s)'), WAIT)
    fireEvent.click(screen.getByRole('button', { name: 'rule' }))
    await waitFor(() => expect(document.querySelectorAll('.group-row').length).toBe(4), WAIT)
    const names = Array.from(document.querySelectorAll('.group-row .name')).map((el) => el.textContent)
    expect(names).toContain('Credential phishing')
    fireEvent.click(screen.getByText('Credential phishing'))
    await waitFor(() => expect(document.querySelector('.group-row + table')).toBeTruthy(), WAIT)
  }, TEST_TIMEOUT)

  it('opens a finding from the rule grouping and writes a status change to the database', async () => {
    await act(async () => {
      render(<FindingsView />)
    })
    await waitFor(() => expect(sub()).toContain('4 finding(s)'), WAIT)
    fireEvent.click(screen.getByRole('button', { name: 'rule' }))
    await waitFor(() => expect(document.querySelectorAll('.group-row').length).toBe(4), WAIT)
    fireEvent.click(screen.getByText('Security audit log cleared'))
    await waitFor(() => expect(document.querySelector('.group-row + table tr')).toBeTruthy(), WAIT)
    fireEvent.click(document.querySelector('.group-row + table tr')!)
    await waitFor(() => expect(document.querySelector('.flyout')).toBeTruthy(), WAIT)
    const fp = Array.from(document.querySelectorAll('.flyout-f .segmented button')).find((b) => b.textContent === 'false positive')!
    fireEvent.click(fp)
    await waitFor(async () => {
      const row = await db.findings.where('ruleId').equals('win-log-cleared').first()
      expect(row?.status).toBe('false_positive')
    }, WAIT)
    // a false positive leaves the queue and the counts: one incident remains, the toggle offers it back
    fireEvent.click(screen.getByRole('button', { name: 'incidents' }))
    await waitFor(() => expect(sub()).toContain('1 incident(s) · 3 finding(s)'), WAIT)
    expect(sub()).toContain('1 false positive hidden')
    fireEvent.click(screen.getByText(/show 1 false positive/))
    await waitFor(() => {
      expect(sub()).toContain('1 false positive')
      expect(sub()).not.toContain('hidden')
    }, WAIT)
  }, TEST_TIMEOUT)
})
