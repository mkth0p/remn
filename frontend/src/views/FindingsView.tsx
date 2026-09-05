import { useEffect, useMemo, useState } from 'react'
import { VirtualTable, type Column } from '../components/VirtualTable'
import { Drawer } from '../components/Detail'
import { Badge, JsonView, Progress, SevBar } from '../components/ui'
import { loadRules, runRulesFor, type LoadedRule } from '../data/rules'
import { getDb, type Finding, type Severity } from '../db/schema'
import { toast, useStore } from '../state/store'
import { fmtNum, fmtTs } from '../util/format'
import { exportCsv, exportJson } from '../util/export'
import { IconPlay } from '../components/Icons'
import { refreshCounts } from '../data/ingest'

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export function FindingsView() {
  const kase = useStore((s) => s.currentCase)
  const rulesVersion = useStore((s) => s.rulesVersion)
  const setFocus = useStore((s) => s.setFocus)
  const setView = useStore((s) => s.setView)
  const setEventsFilter = useStore((s) => s.setEventsFilter)
  const setMailsFilter = useStore((s) => s.setMailsFilter)
  const [all, setAll] = useState<Finding[]>([])
  const [sev, setSev] = useState<string>('')
  const [status, setStatus] = useState<string>('')
  const [source, setSource] = useState<string>('')
  const [q, setQ] = useState('')
  const [selected, setSelected] = useState<Finding | null>(null)
  const [running, setRunning] = useState<{ done: number; total: number; rule: string } | null>(null)
  const [rules, setRules] = useState<LoadedRule[]>([])
  const reload = () => kase?.id && getDb().findings.where('caseId').equals(kase.id).toArray().then((f) => setAll(f.sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity) || (b.ts ?? 0) - (a.ts ?? 0))))
  useEffect(() => {
    reload()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kase?.id, rulesVersion])
  useEffect(() => {
    if (kase) loadRules(kase.id!).then(setRules)
  }, [kase, rulesVersion])
  const rows = useMemo(() => all.filter((f) => (!sev || f.severity === sev) && (!status || f.status === status) && (!source || f.source === source) && (!q || `${f.title} ${f.ruleId} ${JSON.stringify(f.entities)}`.toLowerCase().includes(q.toLowerCase()))), [all, sev, status, source, q])
  const counts = useMemo(() => all.reduce((acc, f) => ((acc[f.severity] = (acc[f.severity] ?? 0) + 1), acc), {} as Record<string, number>), [all])
  if (!kase) return null
  const run = async () => {
    const enabled = rules.filter((r) => r.enabled && !r.error).map((r) => r.rule)
    if (!enabled.length) return toast('warn', 'no enabled rules')
    setRunning({ done: 0, total: enabled.length, rule: '' })
    try {
      await runRulesFor(kase, enabled, (done, total, rule) => setRunning({ done, total, rule }))
    } catch (e) {
      toast('err', `rules failed: ${(e as Error).message}`, 0)
    }
    setRunning(null)
    reload()
    refreshCounts(kase)
  }
  const setFindingStatus = async (f: Finding, s: Finding['status']) => {
    await getDb().findings.update(f.id!, { status: s })
    setSelected({ ...f, status: s })
    reload()
  }
  const openRefs = (f: Finding) => {
    if (!f.refs.length) return
    if (f.source === 'events') setEventsFilter({ conditions: [{ field: 'id', op: 'in', value: f.refs.slice(0, 500) }], sort: { field: 'ts', dir: 'asc' } })
    else setMailsFilter({ conditions: [{ field: 'id', op: 'in', value: f.refs.slice(0, 500) }] })
    setView(f.source)
  }
  const columns: Column<Finding>[] = [
    { key: 'severity', label: 'priority', width: 90, render: (r) => <Badge sev={r.severity}>{r.severity}</Badge> },
    { key: 'confidence', label: 'evidence', width: 85, render: (r) => <span title="Rule confidence: support for the attack hypothesis, separate from priority. Not specified means the rule has not declared confidence.">{r.confidence ?? 'unspecified'}</span> },
    { key: 'title', label: 'finding', width: 'minmax(260px, 1.4fr)', render: (r) => <span>{r.title}{r.escalation ? <span className="muted"> · {r.escalation}</span> : null}</span> },
    { key: 'entities', label: 'entities', width: 'minmax(220px, 1fr)', render: (r) => Object.entries(r.entities).map(([k, v]) => `${k}=${v}`).join(' · ') },
    { key: 'count', label: 'n', width: 60, render: (r) => fmtNum(r.count) },
    { key: 'ts', label: 'first (UTC)', width: 150, render: (r) => fmtTs(r.ts) },
    { key: 'source', label: 'src', width: 60 },
    { key: 'status', label: 'status', width: 100, render: (r) => <Badge sev={r.status === 'false_positive' ? 'info' : r.status === 'escalated' ? 'critical' : r.status === 'reviewed' ? 'ok' : 'accent'}>{r.status}</Badge> },
    { key: 'attack', label: 'att&ck', width: 120, render: (r) => r.attack.join(' ') },
  ]
  return (
    <div className="view">
      <div className="view-header">
        <h1>Findings</h1>
        <span className="sub">{fmtNum(all.length)} finding(s) from {rules.filter((r) => r.enabled).length} enabled rule(s)</span>
        <div style={{ width: 160 }}><SevBar counts={counts} /></div>
        <span className="spacer" />
        <button className="btn primary" onClick={run} disabled={!!running}><IconPlay /> run rules</button>
        <button className="btn ghost sm" onClick={() => setView('rules')}>manage rules</button>
        <button className="btn ghost sm" onClick={() => exportCsv('findings.csv', rows.map((f) => ({ severity: f.severity, title: f.title, ruleId: f.ruleId, entities: JSON.stringify(f.entities), count: f.count, first: f.ts ? new Date(f.ts).toISOString() : '', last: f.tsEnd ? new Date(f.tsEnd).toISOString() : '', source: f.source, status: f.status, attack: f.attack.join(' '), refs: f.refs.slice(0, 50).join(' '), notes: f.notes })))}>csv</button>
        <button className="btn ghost sm" onClick={() => exportJson('findings.json', rows)}>json</button>
      </div>
      {running && <div style={{ padding: '6px 16px' }} className="col"><div className="small dim mono">{running.done}/{running.total} · {running.rule}</div><Progress value={running.done / Math.max(1, running.total)} /></div>}
      <div className="row" style={{ padding: '8px 16px', borderBottom: '1px solid var(--line)', gap: 8 }}>
        <input className="input mono" placeholder="search title / entities…" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 280 }} />
        <select className="select" value={sev} onChange={(e) => setSev(e.target.value)}><option value="">any severity</option>{ORDER.map((s) => <option key={s} value={s}>{s} ({counts[s] ?? 0})</option>)}</select>
        <select className="select" value={status} onChange={(e) => setStatus(e.target.value)}><option value="">any status</option><option value="new">new</option><option value="reviewed">reviewed</option><option value="escalated">escalated</option><option value="false_positive">false positive</option></select>
        <select className="select" value={source} onChange={(e) => setSource(e.target.value)}><option value="">events + mails</option><option value="events">events</option><option value="mails">mails</option></select>
        <span className="mono small dim">{rows.length} shown</span>
      </div>
      <div className="relative" style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
        <VirtualTable rows={rows} columns={columns} rowKey={(r) => r.id!} onRowClick={setSelected} selectedKey={selected?.id ?? null} rowClass={(r) => `sev-${r.severity}`} empty={all.length ? 'no finding matches the filters' : 'no findings yet - click "run rules"'} />
        {selected && (
          <Drawer title={<span><Badge sev={selected.severity}>{selected.severity}</Badge> {selected.title}</span>} onClose={() => setSelected(null)}>
            <div className="card glow col">
              <div className="small dim">{selected.description}</div>
              <div className="kv">
                <div className="k">rule</div><div className="v">{selected.ruleId}</div>
                <div className="k">source</div><div className="v">{selected.source}</div>
                <div className="k">first</div><div className="v">{fmtTs(selected.ts)}</div>
                {selected.tsEnd && <><div className="k">last</div><div className="v">{fmtTs(selected.tsEnd)}</div></>}
                <div className="k">count</div><div className="v">{fmtNum(selected.count)}</div>
                <div className="k">att&amp;ck</div><div className="v">{selected.attack.map((t) => <a key={t} href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`} target="_blank" rel="noreferrer" style={{ marginRight: 6 }}>{t}</a>)}</div>
                {selected.escalation && <><div className="k">escalation</div><div className="v" style={{ color: 'var(--danger)' }}>{selected.escalation}</div></>}
              </div>
              <div className="row wrap" style={{ gap: 6 }}>
                <button className="btn sm primary" onClick={() => openRefs(selected)}>open {Math.min(selected.refs.length, 500)} referenced row(s)</button>
                {selected.refs.slice(0, 1).map((id) => <button key={id} className="btn sm" onClick={() => { setFocus({ source: selected.source, id }); setView(selected.source) }}>first row</button>)}
              </div>
            </div>
            <div>
              <h3>entities</h3>
              <div className="kv" style={{ marginTop: 6 }}>{Object.entries(selected.entities).map(([k, v]) => <><div className="k" key={k}>{k}</div><div className="v" key={k + 'v'}>{v}</div></>)}</div>
            </div>
            <div>
              <h3>triage</h3>
              <div className="row wrap" style={{ gap: 6, marginTop: 6 }}>
                {(['new', 'reviewed', 'escalated', 'false_positive'] as const).map((s) => <button key={s} className={`btn sm ${selected.status === s ? 'primary' : ''}`} onClick={() => setFindingStatus(selected, s)}>{s}</button>)}
              </div>
              <textarea className="textarea" style={{ marginTop: 8 }} placeholder="analyst notes…" defaultValue={selected.notes ?? ''} onBlur={(e) => { getDb().findings.update(selected.id!, { notes: e.target.value }); reload() }} />
            </div>
            <details><summary className="small dim" style={{ cursor: 'pointer' }}>raw finding</summary><JsonView value={selected} /></details>
          </Drawer>
        )}
      </div>
    </div>
  )
}
