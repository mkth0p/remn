import { useEffect, useState } from 'react'
import type { DataSource, FacetItem } from '../data/source'
import type { Condition } from '../rules/filter'
import { classNames, fmtNum } from '../util/format'
import { getDb } from '../db/schema'
import { useStore } from '../state/store'

const LOAD = 500

export interface FacetDef {
  field: string
  label: string
  open?: boolean
}

interface Props {
  ds: DataSource
  source: 'events' | 'mails'
  fields: FacetDef[]
  conditions: Condition[]
  onToggle: (field: string, value: string, negate?: boolean) => void
  version: number
}

function FacetBlock({
  ds,
  source,
  def,
  conditions,
  onToggle,
  version,
}: {
  ds: DataSource
  source: 'events' | 'mails'
  def: FacetDef
  conditions: Condition[]
  onToggle: Props['onToggle']
  version: number
}) {
  const [open, setOpen] = useState(!!def.open)
  const [items, setItems] = useState<FacetItem[]>([])
  const [q, setQ] = useState('')
  const [limit, setLimit] = useState(15)
  const [loading, setLoading] = useState(false)
  const [capped, setCapped] = useState(false)
  const caseId = useStore((s) => s.currentCase?.id)
  useEffect(() => {
    if (!open) return
    let alive = true
    setLoading(true)
    // a search goes to every stored value (debounced), so a rare value outside the most frequent is reachable
    const t = setTimeout(
      () =>
        ds
          .facets(source, def.field, LOAD, q || undefined)
          .then((f) => alive && setItems(f))
          .catch(() => alive && setItems([]))
          .finally(() => alive && setLoading(false)),
      q ? 250 : 0,
    )
    if (caseId != null)
      getDb()
        .kv.get(`facets-capped-${caseId}`)
        .then((k) => alive && setCapped(((k?.value as string[] | undefined) ?? []).includes(`${source}:${def.field}`)))
        .catch(() => undefined)
    return () => {
      alive = false
      clearTimeout(t)
    }
  }, [open, ds, source, def.field, version, q, caseId])
  const active = new Set(
    conditions
      .filter((c) => c.field === def.field && (c.op === 'eq' || c.op === 'in' || c.op === 'contains'))
      .flatMap((c) => (Array.isArray(c.value) ? c.value : [c.value]))
      .map((v) => String(v).toLowerCase()),
  )
  const negated = new Set(
    conditions
      .filter((c) => c.field === def.field && (c.op === 'ne' || c.op === 'nin' || c.op === 'not_contains'))
      .flatMap((c) => (Array.isArray(c.value) ? c.value : [c.value]))
      .map((v) => String(v).toLowerCase()),
  )
  const shown = items.slice(0, limit)
  const max = items[0]?.count ?? 1
  return (
    <div className="facet">
      <div className="facet-h" onClick={() => setOpen(!open)}>
        {def.label}
        {items.length > 0 && (
          <span className="muted" title={items.length >= LOAD ? `the ${LOAD} most frequent values; type to search all of them` : undefined}>
            ({fmtNum(items.length)}
            {items.length >= LOAD ? '+' : ''})
          </span>
        )}
        {loading && <span className="spinner" style={{ width: 10, height: 10 }} />}
        <span className="caret">{open ? '▾' : '▸'}</span>
      </div>
      {open && (
        <>
          {capped && (
            <div className="small" style={{ padding: '2px 6px', color: 'var(--warn)' }}>
              more distinct values than one import counts: rare ones may be missing here; search Events for them
            </div>
          )}
          {(items.length > 8 || q) && <input className="input mono facet-filter" placeholder="filter…" value={q} onChange={(e) => setQ(e.target.value)} style={{ padding: '3px 8px', fontSize: 11 }} />}
          <div className="facet-list">
            {!items.length && !loading && (
              <div className="muted small" style={{ padding: '2px 6px' }}>
                no values
              </div>
            )}
            {shown.map((it) => {
              const key = it.value.toLowerCase()
              return (
                <div
                  key={it.value}
                  className={classNames('facet-item', active.has(key) && 'active', negated.has(key) && 'neg')}
                  onClick={(e) => onToggle(def.field, it.value, e.altKey)}
                  title={`${it.value} — click to filter, alt+click to exclude`}
                >
                  <span className="box" />
                  <span className="val">{it.value}</span>
                  <span className="cnt">{fmtNum(it.count)}</span>
                  <span className="bar" style={{ width: `${(it.count / max) * 100}%` }} />
                </div>
              )
            })}
            {items.length > limit && (
              <button className="btn link xs" style={{ alignSelf: 'flex-start', margin: '4px 6px' }} onClick={() => setLimit(limit + 30)}>
                show more ({fmtNum(items.length - limit)})
              </button>
            )}
          </div>
        </>
      )}
    </div>
  )
}

export function Facets(props: Props) {
  return (
    <div>
      {props.fields.map((f) => (
        <FacetBlock key={f.field} {...props} def={f} />
      ))}
    </div>
  )
}
