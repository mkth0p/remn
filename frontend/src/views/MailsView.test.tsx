// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case, type MailRow } from '../db/schema'
import type { Filter } from '../rules/filter'

// the case's mailbox, as its store would answer for it, and the queries the page sent
const store = vi.hoisted(() => ({
  mails: [] as MailRow[],
  truncated: false,
  error: null as string | null,
  filters: [] as Filter[],
  signals: [] as AbortSignal[],
}))
vi.mock('../data/source', () => ({
  getSource: () => ({
    kind: 'browser',
    searchMails: async (f: Filter, _limit: number, signal: AbortSignal) => {
      store.filters.push(f)
      store.signals.push(signal)
      if (store.error) throw new Error(store.error)
      return { rows: store.mails, truncated: store.truncated }
    },
    countMails: async () => store.mails.length,
    getMail: async (id: number) => {
      const row = store.mails.find((m) => m.id === id)
      return row ? { row, body: { caseId: 1, mailId: id, bodyText: `body of ${row.subject}`, bodyHtml: null, headersText: '', visibleText: null } } : null
    },
    facets: async (_source: string, field: string) =>
      field === 'riskBand'
        ? [
            { value: 'high', count: 2 },
            { value: 'critical', count: 1 },
          ]
        : field === 'flags'
          ? [
              { value: 'reply_to_mismatch', count: 2 },
              { value: 'urgent_language', count: 1 },
            ]
          : [],
    timelineMails: async () => [],
  }),
}))
const exported = vi.hoisted(() => [] as { name: string; rows: unknown[] }[])
vi.mock('../util/export', () => ({
  exportCsv: (name: string, rows: unknown[]) => exported.push({ name, rows }),
  exportJson: (name: string, rows: unknown[]) => exported.push({ name, rows }),
}))

const { MailsView } = await import('./MailsView')
const { riskSev } = await import('./mailRisk')
const { useStore } = await import('../state/store')

let db: RemnDB
const kase: Case = { id: 1, name: 'c', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
const T0 = Date.UTC(2026, 2, 3, 9, 0)
// invented mails: a lure, a payroll notice and a newsletter
const mail = (id: number, subject: string, risk: number, flags: string[] = []): MailRow =>
  ({
    id,
    caseId: 1,
    evidenceId: 2,
    subject,
    date: T0 + id * 60_000,
    risk,
    flags,
    fromName: '',
    fromAddr: `sender${id}@lure.example`,
    fromDomain: 'lure.example',
    to: [{ name: '', addr: 'm.durand@corp.example', domain: 'corp.example' }],
    replyTo: [],
    hops: [],
    auth: {},
    urls: [],
    attachments: [],
    attachmentCount: 0,
    maxAttachmentRisk: 0,
  }) as unknown as MailRow
const settle = () => act(() => new Promise((r) => setTimeout(r, 30)))
const filter = () => useStore.getState().mailsFilter
const rowOf = (subject: string) => screen.getAllByRole('row').find((r) => r.textContent?.includes(subject)) as HTMLElement

beforeEach(async () => {
  db = new RemnDB(`mails-view-${Math.random()}`)
  setDb(db)
  await db.cases.add(kase)
  store.mails = [mail(1, 'Invoice overdue', 85, ['reply_to_mismatch']), mail(2, 'Payroll update', 62), mail(3, 'Weekly digest', 5)]
  store.truncated = false
  store.error = null
  store.filters = []
  store.signals = []
  exported.length = 0
  useStore.setState({ currentCase: kase, mailsFilter: {}, focusId: null, entity: null, jobs: [] })
  // jsdom lays nothing out: the table's body is given room for every row, as a browser would
  vi.spyOn(HTMLElement.prototype, 'clientHeight', 'get').mockReturnValue(600)
  vi.spyOn(HTMLElement.prototype, 'scrollHeight', 'get').mockReturnValue(600)
  vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockReturnValue(1000)
  Element.prototype.scrollTo = () => {}
})
afterEach(async () => {
  cleanup()
  vi.restoreAllMocks()
  db.close()
  await db.delete()
})

describe('the Mails page', () => {
  it('reads a risk score as a severity band', () => {
    expect([85, 62, 45, 20, 5].map(riskSev)).toEqual(['critical', 'high', 'medium', 'low', 'info'])
  })

  it('lists the mails of the filter, the riskiest marked, and opens one in the pane', async () => {
    render(<MailsView />)
    const table = await screen.findByRole('table', { name: 'Mails' })
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(4))
    expect(rowOf('Invoice overdue').className).toContain('sev-critical')
    expect(rowOf('Payroll update').className).toContain('sev-high')
    expect(rowOf('Weekly digest').className).not.toContain('sev-')
    fireEvent.click(rowOf('Payroll update'))
    expect(await screen.findByText('body of Payroll update')).toBeTruthy()
  })

  it('moves the selection with j and k, and closes the pane on Escape', async () => {
    render(<MailsView />)
    await screen.findByText('Weekly digest')
    fireEvent.keyDown(window, { key: 'j' })
    await waitFor(() => expect(rowOf('Invoice overdue').getAttribute('aria-current')).toBe('true'))
    fireEvent.keyDown(window, { key: 'j' })
    await waitFor(() => expect(rowOf('Payroll update').getAttribute('aria-current')).toBe('true'))
    fireEvent.keyDown(window, { key: 'k' })
    await waitFor(() => expect(rowOf('Invoice overdue').getAttribute('aria-current')).toBe('true'))
    expect(await screen.findByText('body of Invoice overdue')).toBeTruthy()
    fireEvent.keyDown(window, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByText('body of Invoice overdue')).toBeNull())
  })

  it('says when the list is cut at 3,000 rows', async () => {
    store.truncated = true
    render(<MailsView />)
    expect(await screen.findByText('showing the first 3,000 rows - narrow the filter or change the sort')).toBeTruthy()
  })

  it('shows why a search failed, and says when nothing matches', async () => {
    store.error = 'the store is not reachable'
    render(<MailsView />)
    expect(await screen.findByText('the store is not reachable')).toBeTruthy()
    expect(screen.getByText('no mails match - load a mailbox in Evidence or relax the filter')).toBeTruthy()
  })

  it('filters a risk band as a range of scores, and lets it go when picked again', async () => {
    render(<MailsView />)
    fireEvent.click(await screen.findByTitle(/^high .* click to filter/))
    expect(filter().conditions).toEqual([
      { field: 'risk', op: 'gte', value: 60 },
      { field: 'risk', op: 'lt', value: 80 },
    ])
    // the critical band has no upper bound to state
    fireEvent.click(screen.getByTitle(/^critical .* click to filter/))
    expect(filter().conditions).toEqual([{ field: 'risk', op: 'gte', value: 80 }])
    fireEvent.click(screen.getByTitle(/^critical .* click to filter/))
    expect(filter().conditions).toEqual([])
  })

  it('takes two flags as both, one excluded with alt, and stops the search the filter left', async () => {
    render(<MailsView />)
    fireEvent.click(await screen.findByTitle(/^reply_to_mismatch .* click to filter/))
    fireEvent.click(screen.getByTitle(/^urgent_language .* click to filter/), { altKey: true })
    expect(filter().conditions).toEqual([
      { field: 'flags', op: 'contains', value: 'reply_to_mismatch' },
      { field: 'flags', op: 'not_contains', value: 'urgent_language' },
    ])
    await settle()
    expect(store.signals.slice(0, -1).every((s) => s.aborted)).toBe(true)
    expect(store.filters[store.filters.length - 1].conditions).toHaveLength(2)
  })

  it('filters on a sender from its cell, and exports the rows shown', async () => {
    render(<MailsView />)
    fireEvent.click(await screen.findByTitle(/<sender3@lure\.example>$/))
    expect(filter().conditions).toEqual([{ field: 'fromAddr', op: 'eq', value: 'sender3@lure.example' }])
    await settle()
    fireEvent.click(screen.getByRole('button', { name: 'export' }))
    fireEvent.click(screen.getByRole('button', { name: 'export CSV (3)' }))
    expect(exported[0].name).toBe('mails.csv')
    expect(exported[0].rows[0]).toMatchObject({ id: 1, risk: 85, from: 'sender1@lure.example', flags: 'reply_to_mismatch' })
  })

  it('opens the mail another page points to, and lets the pointer go', async () => {
    useStore.setState({ focusId: { source: 'mails', id: 3 } })
    render(<MailsView />)
    expect(await screen.findByText('body of Weekly digest')).toBeTruthy()
    expect(useStore.getState().focusId).toBeNull()
  })
})
