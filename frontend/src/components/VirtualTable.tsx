import { useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { classNames } from '../util/format'

export interface Column<T> {
  key: string
  label: string
  width: number | string
  render?: (row: T) => ReactNode
  click?: (row: T, value: unknown) => void
  title?: (row: T) => string | undefined
}

interface Props<T> {
  rows: T[]
  columns: Column<T>[]
  rowHeight?: number
  rowKey: (row: T) => string | number
  onRowClick?: (row: T) => void
  selectedKey?: string | number | null
  rowClass?: (row: T) => string | undefined
  sort?: { field: string; dir: 'asc' | 'desc' }
  onSort?: (field: string) => void
  empty?: ReactNode
  /** bulk selection: a leading checkbox column appears when onToggleSelect is given */
  selectedKeys?: Set<string | number>
  onToggleSelect?: (key: string | number, row: T) => void
  onToggleAll?: (all: boolean) => void
  /** what the table lists, for a screen reader ("Events", "Mails") */
  label?: string
}

/**
 * A table of many rows that draws only the rows in view. It is a table to a screen reader (its row
 * count and each row's place in it included, since most rows are not drawn), a sortable column
 * header is a button, and the rows are reached from the keyboard: Tab enters the table on the
 * row last used, the arrows, Page Up, Page Down, Home and End move between rows, Enter opens one and
 * Space selects it when the table selects rows (opens it otherwise).
 */
export function VirtualTable<T extends object>({
  rows,
  columns,
  rowHeight = 30,
  rowKey,
  onRowClick,
  selectedKey,
  rowClass,
  sort,
  onSort,
  empty,
  selectedKeys,
  onToggleSelect,
  onToggleAll,
  label,
}: Props<T>) {
  const parentRef = useRef<HTMLDivElement>(null)
  const virtualizer = useVirtualizer({ count: rows.length, getScrollElement: () => parentRef.current, estimateSize: () => rowHeight, overscan: 12 })
  const selectable = !!onToggleSelect
  const template = (selectable ? '32px ' : '') + columns.map((c) => (typeof c.width === 'number' ? `${c.width}px` : c.width)).join(' ')
  const items = virtualizer.getVirtualItems()
  const allSelected = selectable && rows.length > 0 && rows.every((r) => selectedKeys?.has(rowKey(r)))
  // the row the keyboard was last on, and one it is moving to that may not be drawn yet
  const [focused, setFocused] = useState(0)
  const moveTo = useRef<number | null>(null)
  useEffect(() => {
    if (moveTo.current == null) return
    const el = parentRef.current?.querySelector<HTMLElement>(`[data-index="${moveTo.current}"]`)
    if (!el) return
    moveTo.current = null
    el.focus({ preventScroll: true })
  })
  const keyboard = !!onRowClick || selectable
  // one row is in the Tab order: the last one the keyboard or the mouse was on while it is drawn, else
  // the selected one, else the first drawn
  const drawn = (i: number) => items.some((vi) => vi.index === i)
  const selectedAt = selectedKey == null ? undefined : items.find((vi) => rowKey(rows[vi.index]) === selectedKey)?.index
  const tabStop = drawn(focused) ? focused : (selectedAt ?? items[0]?.index)
  const go = (i: number) => {
    const to = Math.max(0, Math.min(rows.length - 1, i))
    setFocused(to)
    moveTo.current = to
    virtualizer.scrollToIndex(to)
  }
  const onRowKey = (e: KeyboardEvent<HTMLDivElement>, index: number, row: T) => {
    if (e.target !== e.currentTarget) return
    const page = Math.max(1, Math.floor((parentRef.current?.clientHeight ?? rowHeight * 10) / rowHeight) - 1)
    const moves: Record<string, number> = { ArrowDown: index + 1, ArrowUp: index - 1, PageDown: index + page, PageUp: index - page, Home: 0, End: rows.length - 1 }
    const to = moves[e.key] as number | undefined
    if (to != null) {
      e.preventDefault()
      go(to)
    } else if (e.key === 'Enter') {
      e.preventDefault()
      onRowClick?.(row)
    } else if (e.key === ' ') {
      e.preventDefault()
      if (selectable) onToggleSelect!(rowKey(row), row)
      else onRowClick?.(row)
    }
  }
  return (
    <div className="vtable" role="table" aria-label={label} aria-rowcount={rows.length + 1}>
      <div className="vtable-head" role="row" aria-rowindex={1} style={{ gridTemplateColumns: template }}>
        {selectable && (
          <div role="columnheader" onClick={(e) => e.stopPropagation()} style={{ cursor: 'default' }}>
            <input
              type="checkbox"
              checked={allSelected}
              onChange={(e) => onToggleAll?.(e.target.checked)}
              title="select all shown"
              aria-label="select all shown"
              style={{ accentColor: 'var(--accent)' }}
            />
          </div>
        )}
        {columns.map((c) => (
          <div key={c.key} role="columnheader" aria-sort={sort?.field === c.key ? (sort.dir === 'asc' ? 'ascending' : 'descending') : undefined} title={c.label}>
            {onSort ? (
              <button type="button" className="vtable-sort" onClick={() => onSort(c.key)}>
                {c.label}
                {sort?.field === c.key && (
                  <span className="sort" aria-hidden="true">
                    {sort.dir === 'asc' ? '▲' : '▼'}
                  </span>
                )}
              </button>
            ) : (
              c.label
            )}
          </div>
        ))}
      </div>
      <div className="vtable-body" ref={parentRef}>
        {!rows.length && <div className="vtable-empty">{empty ?? 'no rows'}</div>}
        <div role="rowgroup" style={{ height: virtualizer.getTotalSize(), position: 'relative', width: '100%' }}>
          {items.map((vi) => {
            const row = rows[vi.index]
            const key = rowKey(row)
            return (
              <div
                key={key}
                role="row"
                aria-rowindex={vi.index + 2}
                aria-current={selectedKey === key ? 'true' : undefined}
                data-index={vi.index}
                tabIndex={keyboard ? (vi.index === tabStop ? 0 : -1) : undefined}
                className={classNames('vrow', selectedKey === key && 'selected', rowClass?.(row))}
                style={{ transform: `translateY(${vi.start}px)`, height: vi.size, gridTemplateColumns: template }}
                onClick={() => {
                  setFocused(vi.index)
                  onRowClick?.(row)
                }}
                onKeyDown={keyboard ? (e) => onRowKey(e, vi.index, row) : undefined}
                onFocus={(e) => e.target === e.currentTarget && setFocused(vi.index)}
              >
                {selectable && (
                  <div
                    role="cell"
                    onClick={(e) => {
                      e.stopPropagation()
                      onToggleSelect!(key, row)
                    }}
                  >
                    <input type="checkbox" checked={!!selectedKeys?.has(key)} readOnly tabIndex={-1} aria-label="select this row" style={{ accentColor: 'var(--accent)' }} />
                  </div>
                )}
                {columns.map((c) => {
                  const value = (row as Record<string, unknown>)[c.key]
                  const content = c.render ? c.render(row) : value == null ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value)
                  return (
                    <div
                      key={c.key}
                      role="cell"
                      className={classNames(c.click && value != null && value !== '' && 'click')}
                      title={c.title ? c.title(row) : typeof content === 'string' ? content : undefined}
                      onClick={(e) => {
                        if (c.click && value != null && value !== '') {
                          e.stopPropagation()
                          c.click(row, value)
                        }
                      }}
                    >
                      {content}
                    </div>
                  )
                })}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
