// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case } from '../db/schema'
import { loadAnswers, saveScenarioChoice } from '../data/questions/answers'
import { useStore } from '../state/store'
import { QuestionsView } from './QuestionsView'

vi.mock('../data/source', () => ({
  getSource: () => ({
    facets: async (_s: string, field: string) => (field === 'channel' ? [{ value: 'Security', count: 12 }] : []),
    countEvents: async () => 3,
    countMails: async () => 0,
    aggregateEvents: async () => ({ groups: [], total: 0, distinct: 0 }),
    getEvent: async () => null,
    getMail: async () => null,
    searchEvents: async () => ({ rows: [], truncated: false }),
    searchMails: async () => ({ rows: [], truncated: false }),
  }),
}))
vi.mock('../data/rules', () => ({ loadRules: async () => [] }))

const kase: Case = { id: 1, name: 'Lab', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
let db: RemnDB
beforeEach(() => {
  db = new RemnDB(`questionsview-${Math.random()}`)
  setDb(db)
  useStore.setState({ currentCase: kase, view: 'questions', activeQuestion: null })
})
afterEach(async () => {
  cleanup()
  await db.delete()
})

it('asks for scenarios first, then lists their questions', async () => {
  await act(async () => {
    render(<QuestionsView />)
  })
  await waitFor(() => expect(screen.getByText('Host Persistence Audit')).toBeTruthy())
  fireEvent.click(screen.getByRole('checkbox', { name: /Host Persistence Audit/ }))
  await waitFor(() => expect(screen.getByRole('list', { name: 'Questions' })).toBeTruthy())
  expect(screen.getAllByText('What Scheduled Tasks are configured?').length).toBeGreaterThan(0)
})

it('shows what answers a question and saves the analyst answer', async () => {
  await saveScenarioChoice(1, ['S1001'])
  useStore.setState({ activeQuestion: 'Q1074' })
  await act(async () => {
    render(<QuestionsView />)
  })
  await waitFor(() => expect(screen.getByText('covered by the Security log (12 rows)')).toBeTruthy())
  await waitFor(() => expect(screen.getByText('3 row(s)')).toBeTruthy())
  fireEvent.click(screen.getByRole('button', { name: 'answered' }))
  const box = screen.getByRole('textbox', { name: 'Answer' })
  fireEvent.change(box, { target: { value: 'Cleared at 02:14 on DC01.' } })
  fireEvent.blur(box)
  await waitFor(async () => expect((await loadAnswers(1)).get('Q1074')).toMatchObject({ status: 'answered', text: 'Cleared at 02:14 on DC01.' }))
  // the search opens the Events page with its filter, and the question stays the one rows are cited for
  fireEvent.click(screen.getAllByRole('button', { name: /Events/ })[0])
  expect(useStore.getState().view).toBe('events')
  expect(useStore.getState().eventsFilter).toEqual({ conditions: [{ field: 'eventId', op: 'in', value: [1102, 104] }] })
  expect(useStore.getState().activeQuestion).toBe('Q1074')
})
