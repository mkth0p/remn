// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case, type Finding } from '../db/schema'
import { useStore } from '../state/store'
import { validateRule } from '../rules/engine'

// an invented rule with a Sigma header naming its author, as a community pack carries it
const sigma = validateRule({ id: 'sigma-0001', title: 'Encoded PowerShell', severity: 'high', source: 'events', where: { eventId: 4104 }, sigma: { id: 'x', author: 'A. Rule-Writer' } })
vi.mock('../api/client', () => ({ apiPost: vi.fn(), apiGet: vi.fn(), API_HEADERS: {} }))
vi.mock('../data/rules', () => ({
  loadRules: vi.fn(async () => (sigma.ok ? [{ rule: sigma.rule, yaml: '', file: 'pack.yaml', origin: 'pack', enabled: true }] : [])),
  runRulesFor: vi.fn(),
  settingsForRules: () => ({}),
}))
vi.mock('../data/source', () => ({ getSource: () => ({ countEvents: async () => 3, countMails: async () => 2, kind: 'browser' }) }))
vi.mock('../components/RescoreButton', () => ({ RescoreButton: () => null }))
vi.mock('../data/ingest', () => ({ refreshCounts: vi.fn(async () => undefined) }))
const exportCsv = vi.fn()
vi.mock('../util/export', async (load) => ({ ...(await load<typeof import('../util/export')>()), exportCsv: (...a: unknown[]) => exportCsv(...a) }))

import { FindingsView } from './FindingsView'

const WAIT = { timeout: 8000 }
const TEST_TIMEOUT = 30_000
const kase: Case = { id: 1, name: 'Lab', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
let db: RemnDB
const f = (p: Partial<Finding> & { ruleId: string }): Finding => ({
  caseId: 1,
  key: `${p.ruleId}|1`,
  title: p.ruleId,
  source: 'events',
  severity: 'high',
  ts: 1_700_000_000_000,
  entities: { computer: 'WS-1' },
  count: 1,
  refs: [1],
  attack: [],
  status: 'new',
  createdAt: 5,
  ...p,
})
let ids: Record<string, number> = {}

beforeEach(async () => {
  db = new RemnDB(`findings-authors-${Math.random()}`)
  setDb(db)
  useStore.setState({ currentCase: kase, view: 'findings', rulesRun: null, rulesVersion: 0, focusFinding: null })
  const rows = [f({ ruleId: 'sigma-0001', title: 'Encoded PowerShell' }), f({ ruleId: 'engine:hayabusa:Mimikatz Use', title: 'Mimikatz Use' }), f({ ruleId: 'win-rdp-logon', title: 'RDP logon' })]
  const keys = (await db.findings.bulkAdd(rows, { allKeys: true })) as number[]
  ids = Object.fromEntries(rows.map((r, i) => [r.ruleId, keys[i]]))
})
afterEach(async () => {
  cleanup()
  exportCsv.mockReset()
  await db.delete()
})

async function open(ruleId: string) {
  useStore.setState({ focusFinding: ids[ruleId] })
  await act(async () => {
    render(<FindingsView />)
  })
  await waitFor(() => expect(document.querySelector('.flyout-h')?.textContent).toContain(ruleId === 'sigma-0001' ? 'Encoded PowerShell' : 'Mimikatz Use'), WAIT)
}

describe('the author of a finding on the Findings page', () => {
  it(
    'names the author of the rule in the finding',
    async () => {
      await open('sigma-0001')
      await waitFor(() => expect(screen.getByText('rule author: A. Rule-Writer')).toBeTruthy(), WAIT)
    },
    TEST_TIMEOUT,
  )

  it(
    'says Hayabusa did not record one for its detections',
    async () => {
      await open('engine:hayabusa:Mimikatz Use')
      await waitFor(() => expect(screen.getByText('rule author: not recorded by Hayabusa, whose output REMN reads does not carry it')).toBeTruthy(), WAIT)
    },
    TEST_TIMEOUT,
  )

  it(
    'carries the author in the CSV export, and says when Hayabusa recorded none',
    async () => {
      await open('sigma-0001')
      await waitFor(() => expect(screen.getByText('rule author: A. Rule-Writer')).toBeTruthy(), WAIT)
      fireEvent.click(screen.getByRole('button', { name: 'csv' }))
      const rows = exportCsv.mock.calls[0][1] as Record<string, unknown>[]
      expect(Object.fromEntries(rows.map((r) => [r.ruleId, r.ruleAuthor]))).toEqual({
        'sigma-0001': 'A. Rule-Writer',
        'engine:hayabusa:Mimikatz Use': 'not recorded by Hayabusa, whose output REMN reads does not carry it',
        'win-rdp-logon': '',
      })
    },
    TEST_TIMEOUT,
  )
})
