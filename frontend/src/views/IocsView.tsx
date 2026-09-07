import { useEffect, useMemo, useState } from 'react'
import { VirtualTable, type Column } from '../components/VirtualTable'
import { Drawer, usePivot } from '../components/Detail'
import { Badge, JsonView, Progress, Toggle } from '../components/ui'
import { checkReputation } from '../data/iocs'
import { getSource } from '../data/source'
import { getDb, type Ioc } from '../db/schema'
import { toast, useStore } from '../state/store'
import { defang, fmtNum, fmtTs } from '../util/format'
import { safeHref } from '../util/safe'
import { exportCsv, exportJson, iocsToStix } from '../util/export'
import { IconShield } from '../components/Icons'
import { refreshCounts } from '../data/ingest'

const PAGE = 2000

export function IocsView() {
  const kase = useStore((s) => s.currentCase)
  const updateSettings = useStore((s) => s.updateSettings)
  const health = useStore((s) => s.health)
  const jobs = useStore((s) => s.jobs)
  const [rows, setRows] = useState<Ioc[]>([])
  const [total, setTotal] = useState(0)
  const [kinds, setKinds] = useState<Record<string, number>>({})
  const [kind, setKind] = useState('')
  const [q, setQ] = useState('')
  const [onlyBad, setOnlyBad] = useState(false)
  const [selected, setSelected] = useState<Ioc | null>(null)
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null)
  const [version, setVersion] = useState(0)
  const pivot = usePivot()
  const ds = useMemo(() => (kase ? getSource(kase) : null), [kase])
  useEffect(() => {
    if (!ds) return
    let alive = true
    ds.listIocs({ kind: kind || undefined, q: q.trim() || undefined, onlyBad, limit: PAGE })
      .then((r) => {
        if (!alive) return
        setRows(r.rows)
        setTotal(r.total)
        setKinds(r.kinds)
      })
      .catch((e) => toast('err', `indicators: ${(e as Error).message}`))
    return () => {
      alive = false
    }
  }, [ds, kind, q, onlyBad, version, jobs.length])
  if (!kase || !ds) return null
  const rank = (v: string | null | undefined) => ({ malicious: 3, suspicious: 2, clean: 1 })[v ?? ''] ?? 0
  const check = async (items: Ioc[]) => {
    if (!kase.settings.networkAllowed) return toast('warn', 'Enable external lookups first (toggle above). Each lookup discloses the indicator to the provider.')
    const todo = items.filter((i) => ['ip', 'domain', 'url', 'hash'].includes(i.kind))
    if (!todo.length) return toast('warn', 'nothing to check (ip / domain / url / hash only)')
    if (todo.length > 300 && !confirm(`Check ${todo.length} indicators? This may take a while and hit rate limits.`)) return
    setProgress({ done: 0, total: todo.length })
    await checkReputation(kase, todo, (done, total) => setProgress({ done, total }))
    setProgress(null)
    setVersion((v) => v + 1)
    refreshCounts(kase)
  }
  const columns: Column<Ioc>[] = [
    { key: 'kind', label: 'kind', width: 80, render: (r) => <Badge>{r.kind}</Badge> },
    { key: 'value', label: 'indicator (defanged)', width: 'minmax(280px, 1.5fr)', render: (r) => (r.kind === 'url' || r.kind === 'domain' || r.kind === 'ip' ? defang(r.value) : r.value) },
    {
      key: 'verdict',
      label: 'verdict',
      width: 110,
      render: (r) =>
        r.verdict ? (
          <Badge sev={r.verdict === 'malicious' ? 'critical' : r.verdict === 'suspicious' ? 'high' : r.verdict === 'clean' ? 'ok' : 'info'}>{r.verdict}</Badge>
        ) : r.checkedAt ? (
          <Badge>unknown</Badge>
        ) : (
          <span className="muted">—</span>
        ),
    },
    {
      key: 'tags',
      label: 'tags / geo',
      width: 'minmax(160px, 1fr)',
      render: (r) => {
        const sum = (r.reputation as { summary?: { geo?: { country?: string; org?: string }; asn?: string } } | undefined)?.summary
        return [...(r.tags ?? []).slice(0, 4), sum?.geo?.country, sum?.geo?.org].filter(Boolean).join(' · ')
      },
    },
    { key: 'count', label: 'seen', width: 60, render: (r) => fmtNum(r.count) },
    { key: 'sources', label: 'sources', width: 180, render: (r) => (r.sources ?? []).join(', ') },
    { key: 'firstSeen', label: 'first', width: 150, render: (r) => fmtTs(r.firstSeen) },
    { key: 'lastSeen', label: 'last', width: 150, render: (r) => fmtTs(r.lastSeen) },
  ]
  const configured = health?.providers.filter((p) => p.configured) ?? []
  const uncheckedCount = rows.filter((i) => !i.checkedAt && ['ip', 'domain', 'url', 'hash'].includes(i.kind)).length
  return (
    <div className="view">
      <div className="view-header">
        <h1>Indicators</h1>
        <span className="sub">
          {fmtNum(total)} unique{rows.length < total ? ` (showing ${fmtNum(rows.length)})` : ''} ·{' '}
          {Object.entries(kinds)
            .map(([k, v]) => `${v} ${k}`)
            .join(' · ')}
        </span>
        <span className="spacer" />
        <Toggle
          on={kase.settings.networkAllowed}
          onChange={(v) => {
            updateSettings({ networkAllowed: v })
            getDb().cases.update(kase.id!, { settings: { ...kase.settings, networkAllowed: v } })
            if (v) toast('warn', 'External lookups enabled: indicators will be sent to the selected providers.', 6000)
          }}
          label="allow external lookups"
        />
        <button className="btn primary sm" disabled={!!progress} onClick={() => check(rows.filter((i) => !i.checkedAt))}>
          <IconShield /> check unchecked ({uncheckedCount})
        </button>
        <button className="btn sm" disabled={!!progress} onClick={() => check(rows)}>
          re-check shown
        </button>
        <button
          className="btn ghost sm"
          onClick={() =>
            exportCsv(
              'iocs.csv',
              rows.map((i) => ({
                kind: i.kind,
                value: i.value,
                verdict: i.verdict,
                tags: (i.tags ?? []).join(' '),
                count: i.count,
                sources: (i.sources ?? []).join(' '),
                first: i.firstSeen ? new Date(i.firstSeen).toISOString() : '',
                last: i.lastSeen ? new Date(i.lastSeen).toISOString() : '',
              })),
            )
          }
        >
          csv
        </button>
        <button className="btn ghost sm" onClick={() => exportJson('iocs.stix.json', iocsToStix(kase, rows))}>
          stix 2.1
        </button>
      </div>
      {progress && (
        <div style={{ padding: '6px 16px' }}>
          <Progress value={progress.done / Math.max(1, progress.total)} />
          <div className="small dim mono">
            {progress.done}/{progress.total}
          </div>
        </div>
      )}
      <div className="row" style={{ padding: '8px 16px', borderBottom: '1px solid var(--line)', gap: 8 }}>
        <input className="input mono" placeholder="search…" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 260 }} />
        <select className="select" value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="">all kinds</option>
          {Object.keys(kinds).map((k) => (
            <option key={k} value={k}>
              {k}
            </option>
          ))}
        </select>
        <label className="checkbox small">
          <input type="checkbox" checked={onlyBad} onChange={(e) => setOnlyBad(e.target.checked)} /> malicious / suspicious only
        </label>
        <span className="spacer" />
        <span className="small dim">
          providers: {configured.length ? configured.map((p) => p.name).join(', ') : 'none configured (see .env.example) — offline lists: drop files in backend/data/lists'}
        </span>
      </div>
      <div className="relative" style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
        <VirtualTable
          rows={rows}
          columns={columns}
          rowKey={(r) => `${r.kind}:${r.value}`}
          onRowClick={setSelected}
          selectedKey={selected ? `${selected.kind}:${selected.value}` : null}
          rowClass={(r) => (r.verdict === 'malicious' ? 'sev-critical' : r.verdict === 'suspicious' ? 'sev-high' : undefined)}
          empty="no indicators yet - they are extracted at ingestion (IPs, domains, URLs, hashes, senders)"
        />
        {selected && (
          <Drawer
            title={
              <span className="mono">
                <Badge>{selected.kind}</Badge> {defang(selected.value)}
              </span>
            }
            onClose={() => setSelected(null)}
          >
            <div className="row wrap" style={{ gap: 6 }}>
              <button className="btn sm" onClick={() => pivot(selected.value, undefined, 'events')}>
                events mentioning it
              </button>
              <button className="btn sm" onClick={() => pivot(selected.value, undefined, 'mails')}>
                mails mentioning it
              </button>
              <button className="btn sm primary" onClick={() => check([selected])}>
                check reputation
              </button>
            </div>
            <div className="kv">
              <div className="k">seen</div>
              <div className="v">
                {selected.count} × · {(selected.sources ?? []).join(', ')}
              </div>
              <div className="k">first / last</div>
              <div className="v">
                {fmtTs(selected.firstSeen)} → {fmtTs(selected.lastSeen)}
              </div>
              <div className="k">checked</div>
              <div className="v">{selected.checkedAt ? fmtTs(selected.checkedAt) : 'never'}</div>
            </div>
            {selected.reputation ? (
              <div className="col">
                {(
                  (selected.reputation as { verdicts?: { provider: string; verdict: string; score: number | null; tags: string[]; details: Record<string, unknown>; link: string | null }[] })
                    .verdicts ?? []
                ).map((v) => (
                  <div key={v.provider} className="card">
                    <div className="row">
                      <b>{v.provider}</b>
                      <Badge sev={v.verdict === 'malicious' ? 'critical' : v.verdict === 'suspicious' ? 'high' : v.verdict === 'clean' ? 'ok' : 'info'}>{v.verdict}</Badge>
                      {v.score != null && <span className="mono small">score {v.score}</span>}
                      <span className="spacer" />
                      {safeHref(v.link) && (
                        <a href={safeHref(v.link)} target="_blank" rel="noreferrer noopener" className="small">
                          open ↗
                        </a>
                      )}
                    </div>
                    {v.tags?.length > 0 && <div className="small dim">{v.tags.join(' · ')}</div>}
                    <JsonView value={v.details} />
                  </div>
                ))}
              </div>
            ) : (
              <div className="muted small">not checked yet{rank(selected.verdict) ? '' : ''}</div>
            )}
          </Drawer>
        )}
      </div>
    </div>
  )
}
