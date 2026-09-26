import { useEffect, useState } from 'react'
import type { DataSource } from '../data/source'
import type { Stack, StackField } from '../data/queries'
import type { Filter } from '../rules/filter'
import { fmtNum, fmtTs, tzLabel } from '../util/format'
import { Spinner } from './ui'

/**
 * Stacking (least-frequency analysis) on the Events page: every value of one field among the rows
 * the filter keeps, the rarest first, on how few hosts and in how few events it was seen. The
 * same query runs in both stores (data/queries.ts stackEvents, services/store/queries.py stack).
 */
const STACK_LABELS: Record<StackField, string> = {
  image: 'Image (process path)',
  parentImage: 'Parent image',
  processName: 'Process name',
  parentProcessName: 'Parent process name',
  commandLine: 'Command line',
  parentCommandLine: 'Parent command line',
  path: 'Path',
  serviceName: 'Service name',
  serviceFile: 'Service file',
  taskName: 'Scheduled task',
  objectName: 'Object name',
  targetFilename: 'File created',
  imageLoaded: 'Image loaded (DLL)',
  subjectUser: 'Subject user',
  targetUser: 'Target user',
  workstation: 'Workstation',
  ipAddress: 'IP address',
  destinationIp: 'Destination IP',
  query: 'DNS query',
  providerEventId: 'Provider / event ID',
}

const LIMIT = 500
const ALL = 5000

export function StackPanel({ ds, filter, version, onPick }: { ds: DataSource; filter: Filter; version: number; onPick: (field: StackField, value: string) => void }) {
  const [field, setField] = useState<StackField>('image')
  const [order, setOrder] = useState<'rare' | 'common'>('rare')
  const [limit, setLimit] = useState(LIMIT)
  const [stack, setStack] = useState<Stack | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let alive = true
    const ac = new AbortController()
    setLoading(true)
    setError(null)
    ds.stackEvents(filter, field, order, limit, ac.signal)
      .then((s) => alive && setStack(s))
      .catch((e) => alive && setError((e as Error).message))
      .finally(() => alive && setLoading(false))
    return () => {
      alive = false
      ac.abort()
    }
  }, [ds, filter, field, order, limit, version])

  const label = STACK_LABELS[field]
  return (
    <div className="col" style={{ flex: 1, minHeight: 0 }}>
      <div className="row wrap small" style={{ gap: 8, padding: '6px 16px', borderBottom: '1px solid var(--line)' }}>
        <select
          className="select"
          aria-label="Field to stack"
          value={field}
          onChange={(e) => {
            setField(e.target.value as StackField)
            setLimit(LIMIT)
          }}
          style={{ maxWidth: 220 }}
        >
          {Object.entries(STACK_LABELS).map(([f, l]) => (
            <option key={f} value={f}>
              {l}
            </option>
          ))}
        </select>
        <span className="row" style={{ gap: 4 }}>
          <button className={order === 'rare' ? 'btn xs primary' : 'btn xs ghost'} title="Fewest hosts first, then fewest events" onClick={() => setOrder('rare')}>
            rarest first
          </button>
          <button className={order === 'common' ? 'btn xs primary' : 'btn xs ghost'} title="Most hosts first, then most events" onClick={() => setOrder('common')}>
            most frequent first
          </button>
        </span>
        {loading && <Spinner />}
        {stack && !loading && (
          <span className="muted">
            {fmtNum(stack.distinct)} distinct value{stack.distinct === 1 ? '' : 's'} in {fmtNum(stack.events)} event{stack.events === 1 ? '' : 's'} on {fmtNum(stack.hosts)} host
            {stack.hosts === 1 ? '' : 's'}
            {stack.blank > 0 && ` · ${fmtNum(stack.blank)} matching event${stack.blank === 1 ? ' has' : 's have'} no ${label.toLowerCase()}`}
          </span>
        )}
      </div>
      {(stack?.truncated || error) && (
        <div className="row small" style={{ padding: '3px 16px', gap: 12, borderBottom: '1px solid var(--line)' }}>
          {stack?.truncated && (
            <span className="mono" style={{ color: 'var(--warn)' }}>
              showing the {order === 'rare' ? 'rarest' : 'most frequent'} {fmtNum(stack.rows.length)} of {fmtNum(stack.distinct)} values - narrow the filter to see the rest
            </span>
          )}
          {stack?.truncated && limit < ALL && (
            <button className="btn xs ghost" onClick={() => setLimit(ALL)}>
              show up to {fmtNum(ALL)}
            </button>
          )}
          {error && <span style={{ color: 'var(--danger)' }}>{error}</span>}
        </div>
      )}
      <div style={{ flex: 1, minHeight: 0, overflow: 'auto' }}>
        <table className="table compact">
          <thead>
            <tr>
              <th>{label}</th>
              <th>events</th>
              <th>hosts</th>
              <th>first ({tzLabel()})</th>
              <th>last ({tzLabel()})</th>
            </tr>
          </thead>
          <tbody>
            {(stack?.rows ?? []).map((r) => (
              <tr key={r.value}>
                <td className="click" style={{ wordBreak: 'break-all' }} title="Show these events" onClick={() => onPick(field, r.value)}>
                  {r.value}
                </td>
                <td>{fmtNum(r.count)}</td>
                <td className="sans">
                  on {fmtNum(r.hosts)} of {fmtNum(stack?.hosts ?? 0)} host{stack?.hosts === 1 ? '' : 's'}
                  {r.hostList && r.hostList.length > 0 && <div className="mono muted">{r.hostList.join(', ')}</div>}
                </td>
                <td className="nowrap">{fmtTs(r.first)}</td>
                <td className="nowrap">{fmtTs(r.last)}</td>
              </tr>
            ))}
            {stack && !stack.rows.length && (
              <tr>
                <td colSpan={5} className="muted sans">
                  no event that matches the filter has a {label.toLowerCase()}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
