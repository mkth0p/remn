import { useState } from 'react'
import { Badge } from './ui'
import { fmtBytes, fmtNum } from '../util/format'

export function PackageCoverage({ stats }: { stats: Record<string, unknown> }) {
  const [query, setQuery] = useState('')
  const [issuesOnly, setIssuesOnly] = useState(false)
  const [limit, setLimit] = useState(100)
  const members = (Array.isArray(stats.files) ? stats.files : []).filter((f): f is Record<string, unknown> => !!f && typeof f === 'object' && 'status' in f)
  // A member that was repaired, filtered or truncated still parsed, so it carries a note rather
  // than an error status. Without it here, the one view an analyst uses to review a large package
  // is the one view that hides what the parser had to compromise on.
  const filtered = members.filter(
    (m) => (!issuesOnly || !!m.note || !['parsed', 'metadata'].includes(String(m.status))) && String(m.name).toLowerCase().includes(query.toLowerCase()),
  )
  const checks = (Array.isArray(stats.reconciliation) ? stats.reconciliation : []) as { name: string; status: string; expected?: number; actual?: number; reason?: string }[]
  return (
    <section className="col" style={{ gap: 10 }}>
      <h3>Package coverage</h3>
      <div className="row">
        <Badge sev="accent">{fmtNum(members.length)} members</Badge>
        <span>
          {Number(stats.events ?? 0)} events · {Number(stats.observations ?? 0)} observations · {Number(stats.mails ?? 0)} mails
        </span>
      </div>
      <div className="hint">
        {Number(stats.unsupported ?? 0)} unsupported · {Number(stats.errors ?? 0)} failed · {Number(stats.skipped ?? 0)} skipped. Unsupported files are inventoried and hashed; their contents are not
        searchable. Partial parser output is kept and identified below.
      </div>
      {checks.length > 0 && (
        <details className="card">
          <summary>Collection summary checks · {checks.filter((c) => c.status !== 'matched').length} discrepancies or unresolved entries</summary>
          <div style={{ maxHeight: 300, overflow: 'auto' }}>
            {checks.map((c, i) => (
              <p key={i}>
                <strong>{c.name}</strong> · {c.status} · expected {c.expected ?? '?'} / parsed {c.actual ?? '?'} {c.reason && `· ${c.reason}`}
              </p>
            ))}
          </div>
        </details>
      )}
      {stats.inventoryComplete === false && (
        <div role="alert" className="hint">
          The inventory stopped before the whole package was enumerated. Split the package and import the remaining files.
        </div>
      )}
      <div className="row">
        <input className="input" aria-label="Search package members" placeholder="Search member paths" value={query} onChange={(e) => setQuery(e.target.value)} />
        <label>
          <input type="checkbox" checked={issuesOnly} onChange={(e) => setIssuesOnly(e.target.checked)} /> Show issues only
        </label>
      </div>
      <div style={{ overflowX: 'auto', maxHeight: 450 }}>
        <table className="table">
          <thead>
            <tr>
              <th>Member / SHA-256</th>
              <th>Status</th>
              <th>Rows</th>
              <th>Size</th>
              <th>Parser / reason</th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, limit).map((m, i) => (
              <tr key={i}>
                <td style={{ maxWidth: 360, overflowWrap: 'anywhere' }}>
                  {String(m.name)}
                  <div className="small mono muted">{String(m.sha256 ?? 'hash unavailable')}</div>
                </td>
                <td>
                  <Badge sev={m.note ? 'medium' : m.status === 'parsed' || m.status === 'metadata' ? 'ok' : 'medium'}>
                    {String(m.status)}
                    {m.note ? ' (partial)' : ''}
                  </Badge>
                </td>
                <td>{Number(m.count ?? 0)}</td>
                <td>{fmtBytes(Number(m.size ?? 0))}</td>
                <td>
                  {String(m.format ?? '')}
                  <div className="small">{[m.reason, m.note].filter(Boolean).map(String).join(' · ')}</div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {filtered.length > limit && (
        <button className="btn sm" onClick={() => setLimit(limit + 100)}>
          Show more ({filtered.length - limit} remaining)
        </button>
      )}
    </section>
  )
}
