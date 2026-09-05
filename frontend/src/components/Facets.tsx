import { useEffect, useState } from 'react'
import type { DataSource, FacetItem } from '../data/source'
import type { Condition } from '../rules/filter'
import { classNames, fmtNum } from '../util/format'

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

function FacetBlock({ ds, source, def, conditions, onToggle, version }: { ds: DataSource; source: 'events' | 'mails'; def: FacetDef; conditions: Condition[]; onToggle: Props['onToggle']; version: number }) {
  const [open, setOpen] = useState(!!def.open)
  const [items, setItems] = useState<FacetItem[]>([])
  const [q, setQ] = useState('')
  const [limit, setLimit] = useState(15)
  const [loading, setLoading] = useState(false)
  useEffect(() => {
    if (!open) return
    let alive = true
    setLoading(true)
    ds.facets(source, def.field, 500)
      .then((f) => alive && setItems(f))
      .catch(() => alive && setItems([]))
      .finally(() => alive && setLoading(false))
    return () => {
      alive = false
    }
  }, [open, ds, source, def.field, version])
  const active = new Set(conditions.filter((c) => c.field === def.field && (c.op === 'eq' || c.op === 'in' || c.op === 'contains')).flatMap((c) => (Array.isArray(c.value) ? c.value : [c.value])).map((v) => String(v).toLowerCase()))
  const negated = new Set(conditions.filter((c) => c.field === def.field && (c.op === 'ne' || c.op === 'nin' || c.op === 'not_contains')).flatMap((c) => (Array.isArray(c.value) ? c.value : [c.value])).map((v) => String(v).toLowerCase()))
  const shown = items.filter((i) => !q || i.value.toLowerCase().includes(q.toLowerCase())).slice(0, limit)
  const max = items[0]?.count ?? 1
  return (
    <div className="facet">
      <div className="facet-h" onClick={() => setOpen(!open)}>
        {def.label}
        {items.length > 0 && <span className="muted">({fmtNum(items.length)})</span>}
        {loading && <span className="spinner" style={{ width: 10, height: 10 }} />}
        <span className="caret">{open ? '▾' : '▸'}</span>
      </div>
      {open && (
        <>
          {items.length > 8 && <input className="input mono facet-filter" placeholder="filter…" value={q} onChange={(e) => setQ(e.target.value)} style={{ padding: '3px 8px', fontSize: 11 }} />}
          <div className="facet-list">
            {!items.length && !loading && <div className="muted small" style={{ padding: '2px 6px' }}>no values</div>}
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
