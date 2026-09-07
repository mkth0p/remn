import { useRef, type ReactNode } from 'react'
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
}

export function VirtualTable<T extends object>({ rows, columns, rowHeight = 30, rowKey, onRowClick, selectedKey, rowClass, sort, onSort, empty, selectedKeys, onToggleSelect, onToggleAll }: Props<T>) {
  const parentRef = useRef<HTMLDivElement>(null)
  const virtualizer = useVirtualizer({ count: rows.length, getScrollElement: () => parentRef.current, estimateSize: () => rowHeight, overscan: 12 })
  const selectable = !!onToggleSelect
  const template = (selectable ? '32px ' : '') + columns.map((c) => (typeof c.width === 'number' ? `${c.width}px` : c.width)).join(' ')
  const items = virtualizer.getVirtualItems()
  const allSelected = selectable && rows.length > 0 && rows.every((r) => selectedKeys?.has(rowKey(r)))
  return (
    <div className="vtable">
      <div className="vtable-head" style={{ gridTemplateColumns: template }}>
        {selectable && (
          <div onClick={(e) => e.stopPropagation()} style={{ cursor: 'default' }}>
            <input type="checkbox" checked={allSelected} onChange={(e) => onToggleAll?.(e.target.checked)} title="select all shown" style={{ accentColor: 'var(--accent)' }} />
          </div>
        )}
        {columns.map((c) => (
          <div key={c.key} onClick={() => onSort?.(c.key)} title={c.label}>
            {c.label}
            {sort?.field === c.key && <span className="sort">{sort.dir === 'asc' ? '▲' : '▼'}</span>}
          </div>
        ))}
      </div>
      <div className="vtable-body" ref={parentRef}>
        {!rows.length && <div className="vtable-empty">{empty ?? 'no rows'}</div>}
        <div style={{ height: virtualizer.getTotalSize(), position: 'relative', width: '100%' }}>
          {items.map((vi) => {
            const row = rows[vi.index]
            const key = rowKey(row)
            return (
              <div
                key={key}
                className={classNames('vrow', selectedKey === key && 'selected', rowClass?.(row))}
                style={{ transform: `translateY(${vi.start}px)`, height: vi.size, gridTemplateColumns: template }}
                onClick={() => onRowClick?.(row)}
              >
                {selectable && (
                  <div
                    onClick={(e) => {
                      e.stopPropagation()
                      onToggleSelect!(key, row)
                    }}
                  >
                    <input type="checkbox" checked={!!selectedKeys?.has(key)} readOnly style={{ accentColor: 'var(--accent)' }} />
                  </div>
                )}
                {columns.map((c) => {
                  const value = (row as Record<string, unknown>)[c.key]
                  const content = c.render ? c.render(row) : value == null ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value)
                  return (
                    <div
                      key={c.key}
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
