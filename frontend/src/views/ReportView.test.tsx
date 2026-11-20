// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case, type Finding } from '../db/schema'
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

// the files the page hands to the browser, and the bundle it moves, stay in the test
vi.mock('../util/export', async (orig) => ({
  ...(await orig<typeof import('../util/export')>()),
  downloadBlob: vi.fn(),
  exportCaseBundle: vi.fn(async (_k: unknown, progress: (m: string) => void) => progress('bundle written')),
  importCaseBundle: vi.fn(async () => 7),
}))
vi.mock('../data/stories', async (orig) => ({ ...(await orig<typeof import('../data/stories')>()), buildStories: vi.fn(async () => undefined) }))

import { ReportView } from './ReportView'
import { downloadBlob, exportCaseBundle, importCaseBundle } from '../util/export'
import { buildStories } from '../data/stories'

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

  it(
    'writes the report in the language chosen and under the firm set, and refuses a logo over the cap, saying the cap',
    async () => {
      await act(async () => {
        render(<ReportView />)
      })
      await waitFor(() => expect(screen.getByTestId('client-panel')).toBeTruthy(), WAIT)
      // the page itself stays English
      fireEvent.change(screen.getByLabelText(/report language/), { target: { value: 'fr' } })
      await waitFor(async () => expect((await stored())?.language).toBe('fr'), WAIT)
      await waitFor(() => expect(preview()).toContain('<html lang="fr">'), WAIT)
      expect(screen.getByText('client report')).toBeTruthy()
      const firm = screen.getByLabelText('firm name') as HTMLInputElement
      fireEvent.change(firm, { target: { value: 'Example Response' } })
      fireEvent.blur(firm)
      await waitFor(async () => expect((await stored())?.branding.firmName).toBe('Example Response'), WAIT)
      await waitFor(() => expect(preview()).toContain('<span class="firm">Example Response</span>'), WAIT)
      expect(screen.getByText(/PNG or JPEG, 200 KB at most/)).toBeTruthy()
      const big = new File([new Uint8Array(300 * 1024)], 'logo.png', { type: 'image/png' })
      fireEvent.change(screen.getByLabelText('logo'), { target: { files: [big] } })
      expect(await screen.findByText('logo.png is 300 KB; the logo can be 200 KB at most')).toBeTruthy()
      expect((await stored())?.branding.logo).toBe('')
    },
    TEST_TIMEOUT,
  )
})

const T0 = 1_700_000_000_000
const finding = (p: Partial<Finding> & { ruleId: string; severity: Finding['severity'] }): Finding => ({
  caseId: 1,
  key: `${p.ruleId}|1`,
  title: p.ruleId,
  source: 'events',
  ts: T0,
  entities: {},
  count: 1,
  refs: [1],
  attack: ['T1078'],
  status: 'new',
  createdAt: 5,
  ...p,
})
const toasts = () => useStore.getState().toasts.map((t) => t.text)
const button = (name: string) => screen.getByText((_, el) => el?.tagName === 'BUTTON' && el.textContent?.trim() === name) as HTMLButtonElement
const panel = (title: RegExp) => Array.from(document.querySelectorAll('.panel')).find((p) => title.test(p.querySelector('.panel-h')?.textContent ?? '')) as HTMLElement

describe('the parts of the Report page', () => {
  beforeEach(() => {
    vi.mocked(downloadBlob).mockClear()
    useStore.setState({ toasts: [] })
  })

  it(
    'counts what it prints, sends an undecided case to Review, and lists the preflight checks that keep it a draft',
    async () => {
      await db.findings.bulkAdd([
        finding({ ruleId: 'win-logon-external', title: 'Logon from outside', severity: 'high' }),
        finding({ ruleId: 'win-task', severity: 'low', status: 'reviewed', key: 'k2' }),
      ])
      await act(async () => {
        render(<ReportView />)
      })
      await waitFor(() => expect(screen.getByText(/1 incident\(s\) · 1 finding\(s\)\s*from medium up/)).toBeTruthy(), WAIT)
      expect(screen.getByText(/1 item\(s\) not yet reviewed/)).toBeTruthy()
      expect(screen.getByText('1 item(s) have no decision yet.')).toBeTruthy()
      // the contents as Review set them
      const contents = panel(/^contents/)
      expect(contents.textContent).toContain('from medium up')
      expect(contents.textContent).toContain('high 1')
      // the report stays a draft while a check is open, and says why
      const preflight = panel(/^preflight/)
      expect(preflight.textContent).toContain('the report is a draft')
      expect(preflight.textContent).toContain('the detection rules have not run on this case')
      expect(preflight.textContent).toContain('1 item(s) without a decision')
      expect(button('issue as final').disabled).toBe(true)
      fireEvent.click(button('go to Review'))
      expect(useStore.getState().view).toBe('review')
    },
    TEST_TIMEOUT,
  )

  it(
    'waives the open checks with a reason, issues the report as final and takes it back to draft',
    async () => {
      await act(async () => {
        render(<ReportView />)
      })
      await waitFor(() => expect(panel(/^preflight/)).toBeTruthy(), WAIT)
      const waivers = () => Array.from(panel(/^preflight/).querySelectorAll('input')) as HTMLInputElement[]
      await waitFor(() => expect(waivers().length).toBeGreaterThan(0), WAIT)
      for (const w of waivers()) {
        fireEvent.change(w, { target: { value: 'checked by hand' } })
        fireEvent.blur(w)
      }
      await waitFor(() => expect(button('issue as final').disabled).toBe(false), WAIT)
      fireEvent.click(button('issue as final'))
      await waitFor(() => expect(panel(/^preflight/).textContent).toContain('the report is final'), WAIT)
      const issue = (await db.kv.get('report-final-1'))?.value as { finalAt?: number; waivers: Record<string, string> }
      expect(issue.finalAt).toBeGreaterThan(0)
      expect(Object.values(issue.waivers).every((w) => w === 'checked by hand')).toBe(true)
      await waitFor(() => expect(preview()).toContain('<span class="issue final">'), WAIT)
      expect(preview()).not.toContain('DRAFT, not issued')
      fireEvent.click(button('back to draft'))
      await waitFor(() => expect(panel(/^preflight/).textContent).toContain('the report is a draft'), WAIT)
    },
    TEST_TIMEOUT,
  )

  it(
    'keeps the executive summary the analyst writes and asks for the model only when it answers',
    async () => {
      await act(async () => {
        render(<ReportView />)
      })
      const box = (await screen.findByPlaceholderText('edit the summary…', {}, WAIT)) as HTMLTextAreaElement
      fireEvent.change(box, { target: { value: 'The intruder used **one** account.' } })
      expect(panel(/^executive summary/).querySelector('.md strong')?.textContent).toBe('one')
      fireEvent.blur(box)
      await waitFor(async () => expect((await db.kv.get('report-summary-1'))?.value).toBe('The intruder used **one** account.'), WAIT)
      expect((await db.kv.get('report-summary-by-1'))?.value).toBe('analyst')
      expect((await db.kv.get('report-summary-at-1'))?.value).toBeGreaterThan(0)
      fireEvent.click(screen.getByText('AI executive summary'))
      expect(toasts()).toContain('the analyst model is not reachable (see the AI section in Settings)')
    },
    TEST_TIMEOUT,
  )

  it(
    'downloads the report as HTML and Word, opens it in a tab, and prints it from a frame that runs no script',
    async () => {
      await act(async () => {
        render(<ReportView />)
      })
      await waitFor(() => expect(preview()).toContain('Lab'), WAIT)
      fireEvent.click(screen.getByText('download HTML'))
      fireEvent.click(screen.getByText('Word'))
      const names = vi.mocked(downloadBlob).mock.calls.map((c) => c[0])
      expect(names).toEqual(['Lab-report.html', 'Lab-report.docx'])
      expect(await (vi.mocked(downloadBlob).mock.calls[0][1] as Blob).text()).toContain('<!doctype html>')
      const open = vi.fn(() => null)
      vi.stubGlobal('open', open)
      URL.createObjectURL = vi.fn(() => 'blob:report')
      fireEvent.click(screen.getByText('open in a tab'))
      expect(open).toHaveBeenCalledWith('blob:report', '_blank')
      expect(toasts()).toContain('the browser blocked the new tab: allow pop-ups for this site, or use "download HTML"')
      vi.unstubAllGlobals()
      fireEvent.click(screen.getByText('print / PDF'))
      const frame = Array.from(document.body.querySelectorAll('iframe')).find((f) => f.getAttribute('title') !== 'report preview')!
      expect(frame.getAttribute('sandbox')).toBe('allow-same-origin allow-modals')
      expect(frame.getAttribute('srcdoc')).toContain('<!doctype html>')
      frame.remove()
    },
    TEST_TIMEOUT,
  )

  it(
    'exports the timeline and the ATT&CK layer for responders, leaving the false positives out',
    async () => {
      await db.findings.bulkAdd([
        finding({ ruleId: 'win-logon-external', severity: 'high' }),
        finding({ ruleId: 'win-noise', severity: 'low', status: 'false_positive', key: 'k2', attack: ['T1059'] }),
      ])
      await act(async () => {
        render(<ReportView />)
      })
      await waitFor(() => expect(screen.getByText(/1 incident\(s\)/)).toBeTruthy(), WAIT)
      fireEvent.click(screen.getByText('timeline for Timesketch (.jsonl)'))
      fireEvent.click(screen.getByText('timeline for Timeline Explorer (.csv)'))
      fireEvent.click(screen.getByText('ATT&CK Navigator layer'))
      const calls = vi.mocked(downloadBlob).mock.calls
      expect(calls.map((c) => c[0])).toEqual(['Lab-timeline.jsonl', 'Lab-timeline.csv', 'Lab-attack-layer.json'])
      const jsonl = await (calls[0][1] as Blob).text()
      expect(jsonl).toContain('win-logon-external')
      expect(jsonl).not.toContain('win-noise')
      const layer = JSON.parse(await (calls[2][1] as Blob).text()) as { techniques: { techniqueID: string }[] }
      expect(layer.techniques.map((t) => t.techniqueID)).toEqual(['T1078'])
    },
    TEST_TIMEOUT,
  )

  it(
    'exports the case bundle and imports one dropped on the case bundle panel',
    async () => {
      await act(async () => {
        render(<ReportView />)
      })
      const bundle = await waitFor(() => screen.getByText(/case bundle \(move the case/).closest('.panel') as HTMLElement, WAIT)
      fireEvent.click(screen.getByText('export case bundle (.remn.ndjson)'))
      expect(vi.mocked(exportCaseBundle)).toHaveBeenCalledTimes(1)
      expect(await screen.findByText('bundle written')).toBeTruthy()
      const input = bundle.querySelector('.dropzone input[type=file]') as HTMLInputElement
      fireEvent.change(input, { target: { files: [new File(['{}'], 'case.remn.ndjson')] } })
      await waitFor(() => expect(vi.mocked(importCaseBundle)).toHaveBeenCalledTimes(1), WAIT)
      await waitFor(() => expect(toasts().some((t) => t.startsWith('case imported (#7)'))).toBe(true), WAIT)
    },
    TEST_TIMEOUT,
  )

  it(
    'says when the stories are out of date and builds them again',
    async () => {
      await db.kv.put({
        key: 'stories-1',
        value: { version: 1, stories: [], campaigns: [], chains: { chains: [], stats: {} }, identities: [], hosts: [], unstoried: [], stats: { events: 0, mails: 0, truncated: [] }, builtAt: 1 },
      })
      await act(async () => {
        render(<ReportView />)
      })
      expect(await screen.findByText('The stories are out of date.', {}, WAIT)).toBeTruthy()
      const before = useStore.getState().rulesVersion
      fireEvent.click(screen.getByText('rebuild stories'))
      await waitFor(() => expect(useStore.getState().rulesVersion).toBe(before + 1), WAIT)
      expect(vi.mocked(buildStories)).toHaveBeenCalledTimes(1)
    },
    TEST_TIMEOUT,
  )
})
