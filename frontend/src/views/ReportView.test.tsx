// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case } from '../db/schema'
import { useStore } from '../state/store'
import type { ReportSettings } from '../data/review'

vi.mock('../api/client', () => ({ apiPost: vi.fn(), apiGet: vi.fn(), API_HEADERS: {} }))
vi.mock('../ai/chat', () => ({ runAgent: vi.fn() }))
// the case's evidence names one host and two accounts (invented)
vi.mock('../data/source', () => ({
  getSource: () => ({
    kind: 'browser',
    listIocs: async () => ({ rows: [], total: 0 }),
    facets: async (_source: string, field: string) =>
      field === 'computer'
        ? [{ value: 'WS-017', count: 9 }]
        : field === 'targetUser'
          ? [
              { value: 'CORP\\jdoe', count: 4 },
              { value: 'SYSTEM', count: 40 },
            ]
          : [],
  }),
}))

import { ReportView } from './ReportView'

const WAIT = { timeout: 8000 }
const TEST_TIMEOUT = 30_000
const kase: Case = { id: 1, name: 'Lab', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
let db: RemnDB

beforeEach(async () => {
  db = new RemnDB(`report-${Math.random()}`)
  setDb(db)
  useStore.setState({ currentCase: kase, view: 'report', rulesVersion: 0, aiStatus: { reachable: false, checkedAt: 0 } })
})
afterEach(async () => {
  cleanup()
  await db.delete()
})
const stored = async () => (await db.kv.get('report-settings-1'))?.value as ReportSettings | undefined
const preview = () => (document.querySelector('iframe[title="report preview"]') as HTMLIFrameElement).getAttribute('srcdoc') ?? ''

describe('ReportView', () => {
  it(
    'keeps what the analyst writes for the client with the case settings and prints it',
    async () => {
      await act(async () => {
        render(<ReportView />)
      })
      await waitFor(() => expect(screen.getByTestId('client-panel')).toBeTruthy(), WAIT)
      // the scope says what the evidence covers until the analyst writes their own
      await waitFor(() => expect((screen.getByLabelText('systems in scope') as HTMLTextAreaElement).placeholder).toContain('from the evidence: WS-017'), WAIT)
      expect((screen.getByLabelText('accounts in scope') as HTMLTextAreaElement).placeholder).toBe('from the evidence: CORP\\jdoe')
      const client = screen.getByLabelText('client') as HTMLInputElement
      fireEvent.change(client, { target: { value: 'Example Holdings' } })
      fireEvent.blur(client)
      await waitFor(async () => expect((await stored())?.client.client).toBe('Example Holdings'), WAIT)
      fireEvent.change(screen.getByLabelText('TLP'), { target: { value: 'amber' } })
      await waitFor(async () => expect((await stored())?.client.tlp).toBe('amber'), WAIT)
      // the other report settings are kept as they were
      expect((await stored())?.minSeverity).toBe('medium')
      await waitFor(() => expect(preview()).toContain('Prepared for Example Holdings'), WAIT)
      expect(preview()).toContain('TLP:AMBER')
      // the containment actions are rows the analyst adds
      fireEvent.click(screen.getAllByText('add a row')[1])
      const action = await screen.findByPlaceholderText('action')
      fireEvent.change(action, { target: { value: 'Isolated WS-017' } })
      fireEvent.blur(action)
      await waitFor(async () => expect((await stored())?.client.containment).toEqual([{ date: '', action: 'Isolated WS-017', by: '' }]), WAIT)
    },
    TEST_TIMEOUT,
  )
})
