// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { useState } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case } from '../db/schema'
import type { Filter } from '../rules/filter'
import { useStore } from '../state/store'
import { FilterBar } from './FilterBar'

const transport = vi.hoisted(() => ({ queryJson: vi.fn() }))
vi.mock('../ai/transport', () => ({ getTransport: () => transport }))

const kase: Case = { id: 1, name: 'Lab', storage: 'browser', createdAt: 1, updatedAt: 1, settings: { ...defaultSettings(), businessHours: { start: 9, end: 17, tz: 'UTC' } } }
const FIELDS = ['eventId', 'targetUser', 'ipAddress']

let db: RemnDB
let changes: Filter[]
beforeEach(() => {
  db = new RemnDB(`filterbar-${Math.random()}`)
  setDb(db)
  changes = []
  transport.queryJson.mockReset()
  useStore.setState({ currentCase: kase, toasts: [] })
})
afterEach(async () => {
  cleanup()
  vi.useRealTimers()
  db.close()
  await db.delete()
})

/** The bar with its filter held in state, as the Events and Mails pages hold it. */
function Harness({ initial = {}, source = 'events', total, loading }: { initial?: Filter; source?: 'events' | 'mails'; total?: number | null; loading?: boolean }) {
  const [filter, setFilter] = useState<Filter>(initial)
  return (
    <FilterBar
      source={source}
      filter={filter}
      fields={FIELDS}
      total={total}
      loading={loading}
      onChange={(f) => {
        changes.push(f)
        setFilter(f)
      }}
    />
  )
}
const last = () => changes[changes.length - 1]
const toasts = () => useStore.getState().toasts.map((t) => `${t.kind}: ${t.text}`)

describe('the search field', () => {
  it('applies the trimmed text on Enter and on leaving the field, once', () => {
    render(<Harness />)
    const input = screen.getByPlaceholderText(/search summary, users/)
    fireEvent.change(input, { target: { value: '  mimikatz  ' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(last()).toEqual({ text: 'mimikatz' })
    fireEvent.blur(input)
    expect(changes).toHaveLength(1)
    expect(screen.getByText('"mimikatz"')).toBeTruthy()
  })

  it('clears the text with its clear button', () => {
    render(<Harness initial={{ text: 'abc' }} />)
    fireEvent.click(screen.getByTitle('clear search'))
    expect(last()).toEqual({ text: undefined })
    expect((screen.getByPlaceholderText(/search summary, users/) as HTMLInputElement).value).toBe('')
  })

  it('offers the mail fields to search on the Mails page', () => {
    render(<Harness source="mails" />)
    expect(screen.getByPlaceholderText(/search subject, sender/)).toBeTruthy()
  })
})

describe('the time range', () => {
  it('sets a range from the presets, from the inputs in UTC, and back to any time', () => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date('2026-06-10T12:00:00Z'))
    render(<Harness />)
    fireEvent.click(screen.getByTitle('time range (UTC)'))
    fireEvent.click(screen.getByText('24h'))
    expect(last().timeRange).toEqual({ from: '2026-06-09T12:00:00.000Z', to: '2026-06-10T12:00:00.000Z' })
    expect(screen.getByTitle('time range (UTC)').textContent).toContain('2026-06-09 12:00')
    fireEvent.click(screen.getByText('7d'))
    expect(last().timeRange?.from).toBe('2026-06-03T12:00:00.000Z')
    fireEvent.click(screen.getByText('30d'))
    expect(last().timeRange?.from).toBe('2026-05-11T12:00:00.000Z')
    fireEvent.change(screen.getByTitle('from (UTC)'), { target: { value: '2026-06-01T08:30' } })
    expect(last().timeRange?.from).toBe('2026-06-01T08:30:00Z')
    fireEvent.change(screen.getByTitle('to (UTC)'), { target: { value: '' } })
    expect(last().timeRange).toEqual({ from: '2026-06-01T08:30:00Z', to: undefined })
    expect(screen.getByTitle('time range (UTC)').textContent).toContain('2026-06-01 08:30')
    fireEvent.click(screen.getByText('any'))
    expect(last().timeRange).toBeUndefined()
    expect(screen.getByTitle('time range (UTC)').textContent).toContain('any time')
  })

  it('removes the range from its chip and shows nothing for a value that is not a time', () => {
    render(<Harness initial={{ timeRange: { from: 'not a time', to: '2026-06-01T00:00:00Z' } }} />)
    const chip = screen.getByText(/^time /)
    expect(chip.textContent).toContain('… → 2026-06-01 00:00')
    fireEvent.click(chip.querySelector('[aria-label="remove"]')!)
    expect(last().timeRange).toBeUndefined()
  })
})

describe('conditions', () => {
  function addCondition(field: string, op: string, value?: string) {
    fireEvent.click(screen.getByTitle('add a field condition'))
    const [fieldSelect, opSelect] = screen.getAllByRole('combobox').slice(-2)
    fireEvent.change(fieldSelect, { target: { value: field } })
    fireEvent.change(opSelect, { target: { value: op } })
    if (value !== undefined) fireEvent.change(screen.getByPlaceholderText(op === 'in' || op === 'nin' ? 'comma-separated values' : 'value'), { target: { value } })
    fireEvent.click(screen.getByText('add'))
  }

  it('adds conditions with numbers read as numbers, lists split on commas and no value for exists', () => {
    render(<Harness />)
    addCondition('eventId', 'eq', '4625')
    addCondition('targetUser', 'in', 'user1, user2,, ')
    addCondition('ipAddress', 'exists')
    addCondition('targetUser', 'contains', '12')
    expect(last().conditions).toEqual([
      { field: 'eventId', op: 'eq', value: 4625 },
      { field: 'targetUser', op: 'in', value: ['user1', 'user2'] },
      { field: 'ipAddress', op: 'exists', value: undefined },
      { field: 'targetUser', op: 'contains', value: '12' },
    ])
    expect(screen.getByTitle('add a field condition').textContent).toContain('4 conditions')
    expect(screen.queryByText('Add condition')).toBeNull()
  })

  it('closes the dialog without adding on cancel, and adds nothing without a field', () => {
    render(<Harness />)
    fireEvent.click(screen.getByTitle('add a field condition'))
    fireEvent.click(screen.getByText('cancel'))
    expect(screen.queryByText('Add condition')).toBeNull()
    cleanup()
    const Empty = () => <FilterBar source="events" filter={{}} fields={[]} onChange={(f) => changes.push(f)} />
    render(<Empty />)
    fireEvent.click(screen.getByTitle('add a field condition'))
    fireEvent.click(screen.getByText('add'))
    expect(changes).toEqual([])
  })

  it('removes a condition from its chip and switches between AND and OR when there are two or more', () => {
    render(
      <Harness
        initial={{
          conditions: [
            { field: 'eventId', op: 'eq', value: 4625 },
            { field: 'targetUser', op: 'nin', value: ['a', 'b'] },
          ],
        }}
      />,
    )
    expect(screen.getByText('logic: AND')).toBeTruthy()
    fireEvent.click(screen.getByText('logic: AND'))
    expect(last().logic).toBe('or')
    expect(screen.getByText('OR')).toBeTruthy()
    const negated = screen.getByText('nin').closest('.chip')!
    expect(negated.className).toContain('neg')
    expect(negated.textContent).toContain('a, b')
    fireEvent.click(negated.querySelector('[aria-label="remove"]')!)
    expect(last().conditions).toEqual([{ field: 'eventId', op: 'eq', value: 4625 }])
    expect(screen.queryByText(/^logic:/)).toBeNull()
    expect(screen.getByTitle('add a field condition').textContent).toContain('1 condition')
  })
})

describe('business hours and regex', () => {
  it('limits to rows outside the case business hours and lifts it again', () => {
    render(<Harness />)
    fireEvent.click(screen.getByTitle('only rows outside business hours (Settings)'))
    expect(last().hourRange).toEqual({ from: 9, to: 17, outside: true, tz: 'UTC' })
    expect(screen.getByText(/^outside 9h.17h/)).toBeTruthy()
    fireEvent.click(screen.getByTitle('only rows outside business hours (Settings)'))
    expect(last().hourRange).toBeUndefined()
  })

  it('names an hour range within hours as such', () => {
    render(<Harness initial={{ hourRange: { from: 1, to: 5, outside: false } }} />)
    expect(screen.getByText(/^within 1h.5h/)).toBeTruthy()
  })

  it('applies a regular expression on a field, refuses one that does not compile and removes an empty one', () => {
    render(<Harness />)
    fireEvent.click(screen.getByTitle('regular expression on a field'))
    const input = screen.getByPlaceholderText(/JavaScript regular expression/)
    fireEvent.change(screen.getByTitle('regex target field'), { target: { value: 'targetUser' } })
    fireEvent.change(input, { target: { value: '([a-z' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(changes).toEqual([])
    expect(toasts()[0]).toMatch(/^err: invalid regex/)
    fireEvent.change(input, { target: { value: '^adm' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(last().regex).toEqual({ field: 'targetUser', pattern: '^adm', flags: 'i' })
    expect(screen.getByText('/^adm/ on targetUser')).toBeTruthy()
    fireEvent.blur(input)
    expect(changes).toHaveLength(1)
    fireEvent.change(input, { target: { value: ' ' } })
    fireEvent.blur(input)
    expect(last().regex).toBeUndefined()
  })

  it('opens the regex row for a filter that has one, and removes it from its chip', () => {
    render(<Harness initial={{ regex: { field: '', pattern: 'x' } }} />)
    expect((screen.getByPlaceholderText(/JavaScript regular expression/) as HTMLInputElement).value).toBe('x')
    fireEvent.click(screen.getByText('/x/ on *').querySelector('[aria-label="remove"]')!)
    expect(last().regex).toBeUndefined()
  })
})

describe('saved searches and clearing', () => {
  it('saves the filter under a name and offers it again for this case and page only', async () => {
    await db.savedSearches.bulkAdd([
      { caseId: 1, name: 'mail one', source: 'mails', filter: { text: 'm' }, createdAt: 1 },
      { caseId: 2, name: 'other case', source: 'events', filter: { text: 'o' }, createdAt: 1 },
    ])
    render(<Harness initial={{ text: 'mimikatz', sort: { field: 'ts', dir: 'desc' } }} />)
    fireEvent.click(screen.getByTitle('save this search'))
    fireEvent.change(screen.getByPlaceholderText('name'), { target: { value: '  tools  ' } })
    fireEvent.click(screen.getByText('save'))
    await waitFor(() => expect(screen.getByText('saved (1)')).toBeTruthy())
    expect(toasts()).toContain('ok: search saved')
    const stored = await db.savedSearches.where('caseId').equals(1).toArray()
    expect(stored.map((s) => [s.name, s.source, s.filter])).toEqual([
      ['mail one', 'mails', { text: 'm' }],
      ['tools', 'events', { text: 'mimikatz', sort: { field: 'ts', dir: 'desc' } }],
    ])
    fireEvent.click(screen.getByTitle('clear every filter'))
    expect(last()).toEqual({ sort: { field: 'ts', dir: 'desc' } })
    const select = screen.getByTitle('saved searches').querySelector('select')!
    fireEvent.change(select, { target: { value: String(stored[1].id) } })
    expect(last()).toEqual({ text: 'mimikatz', sort: { field: 'ts', dir: 'desc' } })
  })

  it('does not save without a name', async () => {
    render(<Harness initial={{ text: 'x' }} />)
    fireEvent.click(screen.getByTitle('save this search'))
    fireEvent.keyDown(screen.getByPlaceholderText('name'), { key: 'Enter' })
    await act(async () => {})
    expect(await db.savedSearches.count()).toBe(0)
    expect(screen.getByText('Save search')).toBeTruthy()
  })

  it('shows the match count, or a spinner while loading', () => {
    const { rerender } = render(<Harness total={1} />)
    expect(screen.getByText('1 match')).toBeTruthy()
    rerender(<Harness total={1234} />)
    expect(screen.getByText('1,234 matches')).toBeTruthy()
    cleanup()
    render(<Harness total={5} loading />)
    expect(screen.queryByText('5 matches')).toBeNull()
  })
})

describe('the plain-language query', () => {
  function ask(question: string) {
    fireEvent.click(screen.getByTitle(/describe what you want in plain language/))
    const input = screen.getByPlaceholderText(/failed logons on the admin account/)
    fireEvent.change(input, { target: { value: question } })
    fireEvent.keyDown(input, { key: 'Enter' })
  }

  it('applies the filter built from a plain-language question, without empty conditions, keeping the sort, and says when the other page is suggested', async () => {
    transport.queryJson.mockResolvedValue({
      query: {
        source: 'mails',
        explanation: 'failed logons at night',
        filter: {
          conditions: [
            { field: 'eventId', op: 'eq', value: 4625 },
            { field: '', op: 'eq', value: 1 },
          ],
          logic: 'and',
          text: '',
          regex: { field: '*', pattern: '' },
        },
      },
    })
    render(<Harness initial={{ sort: { field: 'ts', dir: 'asc' } }} />)
    ask('failed logons last night')
    await waitFor(() => expect(screen.getByText('failed logons at night')).toBeTruthy())
    expect(transport.queryJson).toHaveBeenCalledWith('failed logons last night', expect.objectContaining({ source: 'events', businessHours: { start: 9, end: 17, tz: 'UTC' }, facets: {} }))
    expect(last()).toEqual({
      conditions: [{ field: 'eventId', op: 'eq', value: 4625 }],
      logic: 'and',
      timeRange: undefined,
      hourRange: undefined,
      regex: undefined,
      text: undefined,
      sort: { field: 'ts', dir: 'asc' },
    })
    expect(toasts().some((t) => t.startsWith('warn:') && t.endsWith('suggested the "mails" view for this question'))).toBe(true)
  })

  it('shows the answer when no filter comes back, and the error when the call fails', async () => {
    transport.queryJson.mockResolvedValueOnce({ query: null, raw: 'I cannot help with that' })
    render(<Harness />)
    ask('anything')
    await waitFor(() => expect(screen.getByText('I cannot help with that')).toBeTruthy())
    expect(toasts().some((t) => t.startsWith('err:') && t.endsWith('did not return a usable filter'))).toBe(true)
    transport.queryJson.mockRejectedValueOnce(new Error('service offline'))
    fireEvent.click(screen.getByText('build filter'))
    await waitFor(() => expect(toasts().some((t) => t.startsWith('err:') && t.endsWith('query failed: service offline'))).toBe(true))
    expect(changes).toEqual([])
  })

  it('does not ask with an empty question', () => {
    render(<Harness />)
    ask('   ')
    expect(transport.queryJson).not.toHaveBeenCalled()
  })
})
