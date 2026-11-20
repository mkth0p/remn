// @vitest-environment jsdom
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { VirtualTable, type Column } from './VirtualTable'

// invented rows: a few logons on invented hosts
interface Row {
  id: number
  host: string
  eventId: number
}
const ROWS: Row[] = Array.from({ length: 40 }, (_, i) => ({ id: i + 1, host: `ws-${String(i + 1).padStart(2, '0')}`, eventId: 4624 }))
const COLUMNS: Column<Row>[] = [
  { key: 'host', label: 'Host', width: 120 },
  { key: 'eventId', label: 'Event', width: 80 },
]

/** A table as a page holds it: its sort, its open row and its selection. */
function Page({ onOpen = () => {}, select = false }: { onOpen?: (r: Row) => void; select?: boolean }) {
  const [sort, setSort] = useState<{ field: string; dir: 'asc' | 'desc' }>({ field: 'host', dir: 'asc' })
  const [open, setOpen] = useState<number | null>(null)
  const [picked, setPicked] = useState(new Set<string | number>())
  const rows = sort.dir === 'asc' ? ROWS : [...ROWS].reverse()
  return (
    <VirtualTable
      label="Events"
      rows={rows}
      columns={COLUMNS}
      rowKey={(r) => r.id}
      selectedKey={open}
      onRowClick={(r) => {
        setOpen(r.id)
        onOpen(r)
      }}
      sort={sort}
      onSort={(field) => setSort((s) => ({ field, dir: s.field === field && s.dir === 'asc' ? 'desc' : 'asc' }))}
      {...(select
        ? {
            selectedKeys: picked,
            onToggleSelect: (k: string | number) =>
              setPicked((p) => {
                const n = new Set(p)
                if (!n.delete(k)) n.add(k)
                return n
              }),
            onToggleAll: () => {},
          }
        : {})}
    />
  )
}

const rowOf = (host: string) => screen.getByRole('row', { name: new RegExp(`\\b${host} 4624$`) })

beforeEach(() => {
  // jsdom lays nothing out and scrolls nothing: the scrolling body is given the height of ten rows
  // and holds all forty, and a scroll moves it and says so, as a browser does
  vi.spyOn(HTMLElement.prototype, 'clientHeight', 'get').mockReturnValue(300)
  vi.spyOn(HTMLElement.prototype, 'scrollHeight', 'get').mockReturnValue(30 * ROWS.length)
  vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockReturnValue(800)
  Element.prototype.scrollTo = function (this: Element, opts?: ScrollToOptions | number) {
    this.scrollTop = typeof opts === 'object' ? (opts.top ?? 0) : 0
    this.dispatchEvent(new Event('scroll'))
  }
})
afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

describe('VirtualTable', () => {
  it('is a table to a screen reader: named, with its row count, column headers, rows and cells', () => {
    render(<Page />)
    const table = screen.getByRole('table', { name: 'Events' })
    // every row is counted, drawn or not, and the header row with them
    expect(table.getAttribute('aria-rowcount')).toBe('41')
    expect(screen.getAllByRole('columnheader').map((h) => h.textContent)).toEqual(['Host▲', 'Event'])
    expect(screen.getByRole('columnheader', { name: 'Host' }).getAttribute('aria-sort')).toBe('ascending')
    const first = rowOf('ws-01')
    expect(first.getAttribute('aria-rowindex')).toBe('2')
    expect(
      within(first)
        .getAllByRole('cell')
        .map((c) => c.textContent),
    ).toEqual(['ws-01', '4624'])
    // only the rows in view are drawn
    expect(screen.getAllByRole('row').length).toBeLessThan(ROWS.length + 1)
  })

  it('sorts from a header button the keyboard reaches', async () => {
    const user = userEvent.setup()
    render(<Page />)
    const sortHost = screen.getByRole('button', { name: 'Host' })
    sortHost.focus()
    await user.keyboard('{Enter}')
    expect(screen.getByRole('columnheader', { name: 'Host' }).getAttribute('aria-sort')).toBe('descending')
    expect(rowOf('ws-40').getAttribute('aria-rowindex')).toBe('2')
  })

  it('takes the keyboard into its rows: one Tab stop, the arrows, Home and End move, Enter opens', async () => {
    const user = userEvent.setup()
    const onOpen = vi.fn()
    render(<Page onOpen={onOpen} />)
    await user.tab() // the Host header
    await user.tab() // the Event header
    await user.tab()
    expect(document.activeElement).toBe(rowOf('ws-01'))
    await user.keyboard('{ArrowDown}{ArrowDown}')
    expect(document.activeElement).toBe(rowOf('ws-03'))
    await user.keyboard('{ArrowUp}')
    expect(document.activeElement).toBe(rowOf('ws-02'))
    await user.keyboard('{Enter}')
    expect(onOpen).toHaveBeenLastCalledWith(ROWS[1])
    expect(rowOf('ws-02').getAttribute('aria-current')).toBe('true')
    // the last row is not drawn until the body scrolls to it
    await user.keyboard('{End}')
    await waitFor(() => expect(document.activeElement).toBe(rowOf('ws-40')))
    await user.keyboard('{Home}')
    await waitFor(() => expect(document.activeElement).toBe(rowOf('ws-01')))
    // the rows are one stop: Tab leaves the table, Shift+Tab comes back to the row last used
    await user.tab()
    expect(document.activeElement).toBe(document.body)
    await user.tab({ shift: true })
    expect(document.activeElement).toBe(rowOf('ws-01'))
    expect(screen.getAllByRole('row').filter((r) => r.tabIndex === 0)).toEqual([rowOf('ws-01')])
  })

  it('selects a row with Space where the table selects rows, and opens it with Enter', async () => {
    const user = userEvent.setup()
    const onOpen = vi.fn()
    render(<Page onOpen={onOpen} select />)
    const row = rowOf('ws-01')
    row.focus()
    await user.keyboard(' ')
    expect((within(row).getByRole('checkbox', { name: 'select this row' }) as HTMLInputElement).checked).toBe(true)
    expect(onOpen).not.toHaveBeenCalled()
    await user.keyboard('{Enter}')
    expect(onOpen).toHaveBeenCalledWith(ROWS[0])
    expect(screen.getByRole('checkbox', { name: 'select all shown' })).toBeTruthy()
  })
})
