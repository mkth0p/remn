import { useCallback, useEffect, useMemo, useState } from 'react'
import { Facets, type FacetDef } from '../components/Facets'
import { FilterBar } from '../components/FilterBar'
import { TimeHistogram } from '../components/TimeHistogram'
import { IconMore } from '../components/Icons'
import { VirtualTable, type Column } from '../components/VirtualTable'
import { EventDetail } from '../components/Detail'
import { getSource } from '../data/source'
import type { EventRow } from '../db/schema'
import type { Condition, Filter } from '../rules/filter'
import { useStore } from '../state/store'
import { fmtTs } from '../util/format'
import { exportCsv, exportJson } from '../util/export'
import { Badge } from '../components/ui'

const FACETS: FacetDef[] = [
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
      { key: 'ts', label: 'time (UTC)', width: 160, render: (r) => fmtTs(r.ts) },
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
          <VirtualTable
            rows={rows}
            columns={columns}
            rowKey={(r) => r.id!}
            onRowClick={setSelected}
            selectedKey={selected?.id ?? null}
            sort={sort}
            onSort={(field) => setFilter({ ...filter, sort: { field, dir: sort.field === field && sort.dir === 'desc' ? 'asc' : 'desc' } })}
            rowClass={(r) => (r.category === 'log-tampering' || r.category === 'defender-tampering' ? 'sev-critical' : r.eventId === 4625 || r.category === 'defender' ? 'sev-medium' : undefined)}
            empty={loading ? 'loading…' : 'no events match - load an EVTX file in Evidence or relax the filter'}
          />
          {selected && <EventDetail row={selected} onClose={() => setSelected(null)} />}
        </div>
      </div>
    </div>
  )
}
