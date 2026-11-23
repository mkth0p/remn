// @vitest-environment jsdom
import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { DataSource } from '../data/source'
import { TimeHistogram } from './TimeHistogram'

afterEach(cleanup)

const HOUR = 3_600_000
const T0 = Date.UTC(2026, 7, 19)
// invented counts over two days: hourly bars, three of them holding events
const POINTS = [
  { t: T0, count: 4 },
  { t: T0 + 5 * HOUR, count: 2 },
  { t: T0 + 40 * HOUR, count: 9 },
]
const source = { timelineEvents: vi.fn(async () => POINTS), timelineMails: vi.fn(async () => []) } as unknown as DataSource

describe('TimeHistogram', () => {
  it('lets the keyboard reach the bars that hold events, in one Tab stop, and narrow the range with Enter', async () => {
    const user = userEvent.setup()
    const onRange = vi.fn()
    render(
      <>
        <button>query bar</button>
        <TimeHistogram ds={source} source="events" filter={{}} version={0} onRange={onRange} />
        <button>table</button>
      </>,
    )
    const bars = within(await screen.findByRole('toolbar', { name: /results over time/i })).getAllByRole('button')
    // only the bars that hold events can be pressed; the empty hours between them are not buttons
    expect(bars).toHaveLength(3)
    screen.getByText('query bar').focus()
    await user.tab()
    expect(document.activeElement).toBe(bars[0])
    await user.tab()
    expect(document.activeElement).toBe(screen.getByText('table'))
    await user.tab({ shift: true })
    expect(document.activeElement).toBe(bars[0])
    await user.keyboard('{ArrowRight}')
    expect(document.activeElement).toBe(bars[1])
    await user.keyboard('{End}')
    expect(document.activeElement).toBe(bars[2])
    await user.keyboard('{Enter}')
    expect(onRange).toHaveBeenCalledWith(T0 + 40 * HOUR, T0 + 41 * HOUR)
    await user.keyboard('{Home} ')
    expect(onRange).toHaveBeenLastCalledWith(T0, T0 + HOUR)
  })

  it('names each bar by its time span and its count', async () => {
    render(<TimeHistogram ds={source} source="events" filter={{}} version={0} onRange={() => {}} />)
    const bars = within(await screen.findByRole('toolbar')).getAllByRole('button')
    expect(bars[2].getAttribute('aria-label')).toMatch(/ to .* · 9$/)
  })

  it('offers no buttons where a bar narrows nothing', async () => {
    render(<TimeHistogram ds={source} source="events" filter={{}} version={0} />)
    expect(await screen.findByText(/15 in view/)).toBeTruthy()
    expect(screen.queryByRole('toolbar')).toBeNull()
    expect(screen.queryAllByRole('button')).toHaveLength(0)
  })
})
