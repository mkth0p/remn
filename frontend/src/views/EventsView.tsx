import { useCallback, useEffect, useMemo, useState } from 'react'
import { Facets, type FacetDef } from '../components/Facets'
import { FilterBar } from '../components/FilterBar'
import { TimeHistogram } from '../components/TimeHistogram'
import { IconMore } from '../components/Icons'
import { VirtualTable, type Column } from '../components/VirtualTable'
import { RowMarkBar } from '../components/RowMarkBar'
import { loadRowMarks, markedRowIds } from '../data/rowMarks'
import { EventDetail } from '../components/Detail'
import { getSource } from '../data/source'
import type { EventRow, RowMark } from '../db/schema'
import type { Condition, Filter } from '../rules/filter'
import { useStore } from '../state/store'
import { fmtTs } from '../util/format'
import { exportCsv, exportJson } from '../util/export'
import { Badge } from '../components/ui'

const FACETS: FacetDef[] = [
  { field: 'recordKind', label: 'Events / observations', open: true },
  { field: 'artifactType', label: 'Collection artifact' },
  { field: 'eventId', label: 'Event ID', open: true },
  { field: 'channel', label: 'Channel', open: true },
  { field: 'provider', label: 'Provider' },
  { field: 'computer', label: 'Computer' },
  { field: 'sourceFile', label: 'Source file' },
  { field: 'targetUser', label: 'Target user' },
  { field: 'subjectUser', label: 'Subject user' },
  { field: 'ipAddress', label: 'IP address' },
  { field: 'logonType', label: 'Logon type' },
  { field: 'category', label: 'Category' },
  { field: 'levelName', label: 'Level' },
  { field: 'processName', label: 'Process' },
  { field: 'serviceName', label: 'Service' },
]
const FIELDS = [
  'recordKind',
  'artifactType',
  'observedAt',
  'eventId',
  'provider',
  'channel',
  'computer',
  'sourceFile',
  'summary',
  'targetUser',
  'targetDomain',
  'subjectUser',
  'logonType',
  'ipAddress',
  'ipPort',
  'workstation',
  'status',
  'subStatus',
  'statusText',
  'authPackage',
  'processName',
  'commandLine',
  'parentProcessName',
  'serviceName',
  'serviceFile',
  'taskName',
  'memberName',
  'groupName',
  'shareName',
  'relativeTargetName',
  'objectName',
  'scriptBlockText',
  'image',
  'parentImage',
  'destinationIp',
  'destinationPort',
  'query',
  'targetFilename',
  'targetObject',
  'threatName',
  'path',
  'message',
  'category',
  'levelName',
  'recordId',
]
const LIMIT = 3000

export function EventsView() {
  const kase = useStore((s) => s.currentCase)
  const filter = useStore((s) => s.eventsFilter)
  const setFilter = useStore((s) => s.setEventsFilter)
  const focus = useStore((s) => s.focusId)
  const setFocus = useStore((s) => s.setFocus)
  const jobs = useStore((s) => s.jobs)
  const [rows, setRows] = useState<EventRow[]>([])
  const [truncated, setTruncated] = useState(false)
  const [total, setTotal] = useState<number | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<EventRow | null>(null)
  const [picked, setPicked] = useState<Set<string | number>>(new Set())
  const [marks, setMarks] = useState<Map<number, RowMark>>(new Map())
  const [markedOnly, setMarkedOnly] = useState(false)
  const [marksVersion, setMarksVersion] = useState(0)
  const [version, setVersion] = useState(0)
  const [menu, setMenu] = useState(false)
  const ds = useMemo(() => (kase ? getSource(kase) : null), [kase])
  useEffect(() => {
    if (jobs.every((j) => j.phase === 'done' || j.phase === 'error')) setVersion((v) => v + 1)
  }, [jobs])

  useEffect(() => {
    if (!ds) return
    let alive = true
    setLoading(true)
    setError(null)
    const t0 = Date.now()
    ds.searchEvents(filter, LIMIT)
      .then((r) => {
        if (!alive) return
        setRows(r.rows)
        setTruncated(r.truncated)
        useStore.getState().log('info', `events: ${r.rows.length}${r.truncated ? '+' : ''} rows in ${Date.now() - t0} ms (${ds.kind})`)
      })
      .catch((e) => alive && setError((e as Error).message))
      .finally(() => alive && setLoading(false))
    setTotal(null)
    ds.countEvents(filter)
      .then((n) => alive && setTotal(n))
      .catch(() => undefined)
    return () => {
      alive = false
    }
  }, [ds, filter, version])

  useEffect(() => {
    if (!kase?.id || !rows.length) {
      setMarks(new Map())
      return
    }
    let alive = true
    loadRowMarks(
      kase.id,
      'events',
      rows.map((r) => r.id!),
    )
      .then((m) => alive && setMarks(m))
      .catch(() => alive && setMarks(new Map()))
    return () => {
      alive = false
    }
  }, [kase?.id, rows, marksVersion])

  // "marked only" is a row-id filter, the same mechanism a finding uses to open its rows
  useEffect(() => {
    if (!kase?.id) return
    if (!markedOnly) {
      setFilter((prev: Filter) => ({ ...prev, conditions: (prev.conditions ?? []).filter((c) => c.field !== 'id') }))
      return
    }
    markedRowIds(kase.id, 'events').then(({ ids }) => {
      setFilter((prev: Filter) => ({
        ...prev,
        conditions: [...(prev.conditions ?? []).filter((c) => c.field !== 'id'), { field: 'id', op: 'in', value: ids.length ? ids : [-1] } as Condition],
      }))
    })
  }, [markedOnly, kase?.id, setFilter, marksVersion])

  useEffect(() => {
    if (focus?.source === 'events' && ds) {
      ds.getEvent(focus.id).then((r) => r && setSelected(r))
      setFocus(null)
    }
  }, [focus, setFocus, ds])

  const toggleFacet = useCallback(
    (field: string, value: string, negate?: boolean) => {
      setFilter((prev: Filter) => {
        const conds = prev.conditions ?? []
        const num = /^-?\d+$/.test(value) && ['eventId', 'logonType'].includes(field) ? Number(value) : value
        const op = negate ? 'ne' : 'eq'
        const idx = conds.findIndex((c) => c.field === field && c.op === op && String(c.value).toLowerCase() === value.toLowerCase())
        if (idx >= 0) return { ...prev, conditions: conds.filter((_, i) => i !== idx) }
        const same = conds.find((c) => c.field === field && c.op === op)
        if (same && !negate) {
          const vals = Array.isArray(same.value) ? same.value : [same.value]
          const next: Condition = { field, op: 'in', value: [...vals, num] }
          return { ...prev, conditions: conds.map((c) => (c === same ? next : c)) }
        }
        return { ...prev, conditions: [...conds, { field, op, value: num }] }
      })
    },
    [setFilter],
  )

  const columns: Column<EventRow>[] = useMemo(
    () => [
      { key: 'ts', label: 'event time', width: 160, render: (r) => (r.recordKind === 'observation' ? <span title={`Collected: ${fmtTs(r.observedAt)}`}>snapshot (no event time)</span> : fmtTs(r.ts)) },
      {
        key: 'eventId',
        label: 'id',
        width: 60,
        click: (r) => toggleFacet('eventId', String(r.eventId)),
        render: (r) => <Badge sev="accent">{r.eventId ?? (r.operation ? String(r.operation).replace(/\.$/, '').slice(0, 22) : '')}</Badge>,
      },
      { key: 'computer', label: 'computer', width: 130, click: (r) => toggleFacet('computer', String(r.computer)) },
      { key: 'targetUser', label: 'user', width: 130, click: (r) => toggleFacet('targetUser', String(r.targetUser)), render: (r) => String(r.targetUser ?? r.subjectUser ?? '') },
      { key: 'ipAddress', label: 'ip', width: 120, click: (r) => toggleFacet('ipAddress', String(r.ipAddress)) },
      { key: 'summary', label: 'summary', width: 'minmax(300px, 1fr)' },
      { key: 'channel', label: 'channel', width: 130 },
    ],
    [toggleFacet],
  )
  if (!kase || !ds) return null
  const sort = filter.sort ?? { field: 'ts', dir: 'desc' as const }
  return (
    <div className="view">
      <div className="split">
        <div className="left">
          <div className="panel-h">
            Filters <span className="muted">({ds.kind === 'server' ? 'server store' : 'browser store'})</span>
          </div>
          <Facets ds={ds} source="events" fields={FACETS} conditions={filter.conditions ?? []} onToggle={toggleFacet} version={version} />
        </div>
        <div className="right relative">
          <FilterBar
            source="events"
            filter={filter}
            onChange={setFilter}
            fields={FIELDS}
            total={total}
            loading={loading}
            extra={
              <span className="row relative" style={{ gap: 4 }}>
                <button className={markedOnly ? 'btn xs primary' : 'btn xs ghost'} title="Show only the rows you marked" onClick={() => setMarkedOnly((on) => !on)}>
                  marked
                </button>
                <button className="btn icon ghost sm" title="export" onClick={() => setMenu(!menu)}>
                  <IconMore />
                </button>
                {menu && (
                  <div className="menu" style={{ position: 'absolute', right: 0, top: '100%', zIndex: 25 }} onMouseLeave={() => setMenu(false)}>
                    <button
                      className="btn ghost sm"
                      onClick={() => {
                        exportCsv(
                          'events.csv',
                          rows.map(({ raw, data, ...r }) => {
                            void raw
                            void data
                            return r
                          }),
                          [
                            'id',
                            'tsIso',
                            'eventId',
                            'provider',
                            'channel',
                            'computer',
                            'sourceFile',
                            'levelName',
                            'summary',
                            'targetUser',
                            'targetDomain',
                            'subjectUser',
                            'logonType',
                            'ipAddress',
                            'workstation',
                            'statusText',
                            'processName',
                            'commandLine',
                            'serviceName',
                            'serviceFile',
                          ],
                        )
                        setMenu(false)
                      }}
                    >
                      export CSV ({rows.length})
                    </button>
                    <button
                      className="btn ghost sm"
                      onClick={() => {
                        exportJson('events.json', rows)
                        setMenu(false)
                      }}
                    >
                      export JSON ({rows.length})
                    </button>
                  </div>
                )}
              </span>
            }
          />
          <TimeHistogram
            ds={ds}
            source="events"
            filter={filter}
            version={version}
            onRange={(from, to) => setFilter({ ...filter, timeRange: { from: new Date(from).toISOString(), to: new Date(to).toISOString() } })}
          />
          {(truncated || error) && (
            <div className="row small dim" style={{ padding: '3px 16px', gap: 12, borderBottom: '1px solid var(--line)' }}>
              {truncated && <span className="mono">showing the first {LIMIT.toLocaleString('en-US')} rows - narrow the filter or change the sort</span>}
              {error && <span style={{ color: 'var(--danger)' }}>{error}</span>}
            </div>
          )}
          {kase?.id != null && (
            <RowMarkBar
              caseId={kase.id}
              source="events"
              rows={rows as unknown as Record<string, unknown>[]}
              picked={picked}
              onClear={() => setPicked(new Set())}
              onChanged={() => setMarksVersion((v) => v + 1)}
            />
          )}
          <VirtualTable
            rows={rows}
            columns={columns}
            rowKey={(r) => r.id!}
            onRowClick={setSelected}
            selectedKey={selected?.id ?? null}
            selectedKeys={picked}
            onToggleSelect={(k) =>
              setPicked((prev) => {
                const next = new Set(prev)
                if (next.has(k)) next.delete(k)
                else next.add(k)
                return next
              })
            }
            onToggleAll={(on) => setPicked(on ? new Set(rows.map((r) => r.id!)) : new Set())}
            sort={sort}
            onSort={(field) => setFilter({ ...filter, sort: { field, dir: sort.field === field && sort.dir === 'desc' ? 'asc' : 'desc' } })}
            rowClass={(r) =>
              marks.get(r.id!)?.verdict === 'noise'
                ? 'row-noise'
                : marks.get(r.id!)
                  ? 'row-marked'
                  : r.category === 'log-tampering' || r.category === 'defender-tampering'
                    ? 'sev-critical'
                    : r.eventId === 4625 || r.category === 'defender'
                      ? 'sev-medium'
                      : undefined
            }
            empty={loading ? 'loading…' : 'no events match - load an EVTX file in Evidence or relax the filter'}
          />
          {selected && <EventDetail row={selected} onClose={() => setSelected(null)} />}
        </div>
      </div>
    </div>
  )
}
