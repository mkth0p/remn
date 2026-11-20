// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case, type EventRow, type MailRow } from '../db/schema'
import type { Filter } from '../rules/filter'

// the case's rows, as its store would answer for them
const store = vi.hoisted(() => ({
  events: [] as EventRow[],
  mails: [] as MailRow[],
  signals: [] as AbortSignal[],
  filters: [] as Filter[],
}))
vi.mock('../data/source', () => ({
  getSource: () => ({
    kind: 'browser',
    searchEvents: async (f: Filter, _limit: number, signal: AbortSignal) => {
      store.filters.push(f)
      store.signals.push(signal)
      return { rows: store.events, truncated: false }
    },
    searchMails: async () => ({ rows: store.mails, truncated: false }),
    countEvents: async () => store.events.length + 1_000,
    countMails: async () => store.mails.length,
    aggregateEvents: async (_f: Filter, field: string) => ({ groups: field === 'computer' ? [{ value: 'WS-017', count: 2, first: null, last: null }] : [], total: 2, distinct: 1 }),
  }),
}))

const { EntityPanel, entityKind } = await import('./EntityPanel')
const { useStore } = await import('../state/store')

let db: RemnDB
const kase: Case = { id: 1, name: 'c', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
const T0 = Date.UTC(2026, 2, 3, 9, 0)
const mail = (id: number, subject: string, ts: number, risk: number): MailRow =>
  ({ id, caseId: 1, evidenceId: 2, subject, date: ts, risk, fromAddr: 'billing@lure.example', to: [{ name: '', addr: 'm.durand@corp.example', domain: 'corp.example' }] }) as MailRow

beforeEach(async () => {
  db = new RemnDB(`entity-${Math.random()}`)
  setDb(db)
  await db.cases.add(kase)
  store.events = [
    { id: 11, caseId: 1, evidenceId: 1, ts: T0 + 30 * 60_000, eventId: 4624, computer: 'WS-017', ipAddress: '10.0.0.5', summary: 'logon of m.durand' },
    { id: 12, caseId: 1, evidenceId: 1, ts: T0 + 5 * 60_000, eventId: 4625, computer: 'WS-017', summary: 'failed logon of m.durand' },
  ]
  store.mails = [mail(21, 'Invoice overdue', T0 + 10 * 60_000, 85)]
  store.signals = []
  store.filters = []
  await db.findings.add({
    caseId: 1,
    key: 'k',
    ruleId: 'win-brute-force',
    title: 'Password guessing',
    source: 'events',
    severity: 'high',
    refs: [12],
    entities: { targetUser: 'm.durand' },
    count: 6,
    attack: [],
    ts: T0,
    status: 'new',
    createdAt: 1,
  })
  useStore.setState({ currentCase: kase, entity: { kind: 'user', value: 'm.durand@corp.example' }, view: 'stories', focusId: null, aiPrompt: null, eventsFilter: {}, mailsFilter: {} })
})
afterEach(async () => {
  cleanup()
  db.close()
  await db.delete()
})

describe('an entity page', () => {
  it('knows which fields name an entity', () => {
    expect(entityKind('targetUser')).toBe('user')
    expect(entityKind('Computer')).toBe('host')
    expect(entityKind('originIp')).toBe('ip')
    expect(entityKind('replyTo')).toBe('address')
    expect(entityKind('fromRegistrable')).toBe('domain')
    expect(entityKind('commandLine')).toBeNull()
  })

  it("lists the entity's findings, mails and events newest first, with the counts of the whole case", async () => {
    render(<EntityPanel />)
    await waitFor(() => expect(document.querySelectorAll('.story .step')).toHaveLength(4))
    const titles = [...document.querySelectorAll('.story .step .title')].map((t) => t.textContent)
    expect(titles).toEqual(['logon of m.durand', 'Invoice overdue', 'failed logon of m.durand', 'Password guessingfinding'])
    expect(await screen.findByText('1,002 event(s)')).toBeTruthy()
    expect(screen.getByText('1 finding(s)')).toBeTruthy()
    // a user is looked for by the part before the domain too
    expect(store.filters[0].conditions).toContainEqual({ field: 'targetUser', op: 'eq', value: 'm.durand' })
  })

  it('opens a mail of the timeline in the Mails view, and closes', async () => {
    render(<EntityPanel />)
    fireEvent.click(await screen.findByText('Invoice overdue'))
    expect(useStore.getState()).toMatchObject({ view: 'mails', focusId: { source: 'mails', id: 21 }, entity: null })
  })

  it('shows what else was seen with the entity, and turns the page into a filter of the events', async () => {
    render(<EntityPanel />)
    fireEvent.click(screen.getByRole('button', { name: 'Insights' }))
    const section = (await screen.findByText('computer seen with this user')).closest('.section') as HTMLElement
    expect(within(section).getByText('WS-017')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'filter events' }))
    expect(useStore.getState()).toMatchObject({ view: 'events', entity: null, eventsFilter: { logic: 'or' } })
  })

  it('asks the AI analyst about the entity with what the page counted', async () => {
    render(<EntityPanel />)
    await screen.findByText('1,002 event(s)')
    fireEvent.click(screen.getByRole('button', { name: /ask the analyst/ }))
    expect(useStore.getState().view).toBe('ai')
    expect(useStore.getState().aiPrompt).toContain('m.durand@corp.example. 1 finding(s), 1002 event(s), 1 mail(s)')
  })

  it('says when nothing in the case references the entity, and stops the queries of the one it leaves', async () => {
    store.events = []
    store.mails = []
    render(<EntityPanel />)
    await waitFor(() => expect(store.signals).toHaveLength(1))
    act(() => useStore.setState({ entity: { kind: 'ip', value: '198.51.100.4' } }))
    expect(await screen.findByText('nothing in this case references 198.51.100.4')).toBeTruthy()
    expect(store.signals[0].aborted).toBe(true)
  })
})
