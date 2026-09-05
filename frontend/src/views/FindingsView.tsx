import { useCallback, useEffect, useMemo, useState } from 'react'
import { VirtualTable, type Column } from '../components/VirtualTable'
import { usePivot } from '../components/Detail'
import { entityKind } from '../components/EntityPanel'
import { AddToTimeline } from '../components/AddToTimeline'
import { Badge, Dot, Flyout, JsonView, Kpi, Progress, Sev, SevBar, Tabs } from '../components/ui'
import { IconCircle, IconFindings, IconInfo, IconPlay, IconSearch, IconTarget } from '../components/Icons'
import { RescoreButton } from '../components/RescoreButton'
import { loadRules, runRulesFor, type LoadedRule } from '../data/rules'
import { pruneOrphanFindings } from '../data/findingReviews'
import { getSource } from '../data/source'
import { refreshCounts } from '../data/ingest'
import { getDb, type Finding, type Severity } from '../db/schema'
import { toast, useStore } from '../state/store'
import { classNames, fmtNum, fmtTs } from '../util/format'
import { exportCsv, exportJson } from '../util/export'

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const STATUSES = ['new', 'reviewed', 'escalated', 'false_positive'] as const
type Status = (typeof STATUSES)[number]
type Group = '' | 'ruleId' | 'entity' | 'source'

const STATUS_LABEL: Record<Status, string> = { new: 'new', reviewed: 'reviewed', escalated: 'escalated', false_positive: 'false positive' }
const STATUS_SEV: Record<Status, string> = { new: 'accent', reviewed: 'ok', escalated: 'critical', false_positive: 'info' }

interface LastRun {
  ts: number
  byRule: Record<string, number>
  errors?: string[]
}

function sevCounts(rows: Finding[]): Record<string, number> {
  const c: Record<string, number> = {}
  for (const f of rows) c[f.severity] = (c[f.severity] ?? 0) + 1
  return c
}

/** Findings referencing the same seed mail or the same identity as this one. */
function relatedChains(f: Finding, all: Finding[]): Finding[] {
  if (f.ruleId === 'chain') return []
  const ents = new Set(Object.values(f.entities).map((v) => String(v).toLowerCase()))
  return all.filter((c) => c.ruleId === 'chain' && (c.refs.some((r) => f.refs.includes(r)) || Object.values(c.entities).some((v) => ents.has(String(v).toLowerCase()))))
}

export function FindingsView() {
  const kase = useStore((s) => s.currentCase)
  const rulesVersion = useStore((s) => s.rulesVersion)
  const setFocus = useStore((s) => s.setFocus)
  const setView = useStore((s) => s.setView)
  const setEventsFilter = useStore((s) => s.setEventsFilter)
  const setMailsFilter = useStore((s) => s.setMailsFilter)
  const setAiPrompt = useStore((s) => s.setAiPrompt)
  const pivot = usePivot()
  const setEntity = useStore((s) => s.setEntity)
  const openEntity = (k: string, v: string, source: 'events' | 'mails') => { const kind = entityKind(k); if (kind && v && !v.includes(',')) setEntity({ kind, value: v }); else pivot(v, k, source) }
  const [all, setAll] = useState<Finding[]>([])
  const [sev, setSev] = useState('')
  const [status, setStatus] = useState('')
  const [source, setSource] = useState('')
  const [q, setQ] = useState('')
  const [group, setGroup] = useState<Group>('')
  const [openGroups, setOpenGroups] = useState<Set<string>>(new Set())
  const [tab, setTab] = useState<'findings' | 'attack'>('findings')
  const [selected, setSelected] = useState<Finding | null>(null)
  const [flyTab, setFlyTab] = useState<'overview' | 'table' | 'json'>('overview')
  const [picked, setPicked] = useState<Set<string | number>>(new Set())
  const [running, setRunning] = useState<{ done: number; total: number; rule: string } | null>(null)
  const [rules, setRules] = useState<LoadedRule[]>([])
  const [lastRun, setLastRun] = useState<LastRun | null>(null)
  const [previous, setPrevious] = useState<Record<string, number> | null>(null)
  const [prevalence, setPrevalence] = useState<Record<string, number | null>>({})

  const reload = useCallback(() => {
    if (!kase?.id) return
    const db = getDb()
    db.findings.where('caseId').equals(kase.id).toArray().then((f) => setAll(f.sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity) || (b.ts ?? 0) - (a.ts ?? 0))))
    db.kv.get(`ruleDiags-${kase.id}`).then((k) => setLastRun((k?.value as LastRun) ?? null))
    db.kv.get(`findingCounts-${kase.id}`).then((k) => setPrevious(((k?.value as { previous?: Record<string, number> }) ?? {}).previous ?? null))
  }, [kase?.id])
  useEffect(() => {
    reload()
  }, [reload, rulesVersion])
  useEffect(() => {
    if (kase) loadRules(kase.id!).then(setRules)
  }, [kase, rulesVersion])
  useEffect(() => {
    setSelected(null)
    setPicked(new Set())
  }, [kase?.id])

  const counts = useMemo(() => sevCounts(all), [all])
  const rows = useMemo(() => {
    const needle = q.toLowerCase()
    return all.filter((f) => (!sev || f.severity === sev) && (!status || f.status === status) && (!source || f.source === source) && (!needle || `${f.title} ${f.ruleId} ${JSON.stringify(f.entities)} ${f.attack.join(' ')}`.toLowerCase().includes(needle)))
  }, [all, sev, status, source, q])
  const groups = useMemo(() => {
    if (!group) return []
    const m = new Map<string, { key: string; label: string; items: Finding[] }>()
    for (const f of rows) {
      const key = group === 'ruleId' ? f.ruleId : group === 'source' ? f.source : (Object.values(f.entities)[0] ?? '(no entity)')
      const label = group === 'ruleId' ? f.title : key
      const g = m.get(key) ?? { key, label, items: [] }
      g.items.push(f)
      m.set(key, g)
    }
    return Array.from(m.values()).sort((a, b) => b.items.length - a.items.length)
  }, [rows, group])
  const attack = useMemo(() => {
    const m = new Map<string, { id: string; findings: number; rules: Set<string>; worst: Severity }>()
    for (const f of all) {
      for (const t of f.attack) {
        const e = m.get(t) ?? { id: t, findings: 0, rules: new Set<string>(), worst: 'info' as Severity }
        e.findings++
        e.rules.add(f.ruleId)
        if (ORDER.indexOf(f.severity) < ORDER.indexOf(e.worst)) e.worst = f.severity
        m.set(t, e)
      }
    }
    const enabledByTechnique = new Map<string, number>()
    for (const r of rules) if (r.enabled) for (const t of r.rule.attack ?? []) enabledByTechnique.set(t, (enabledByTechnique.get(t) ?? 0) + 1)
    return { hits: Array.from(m.values()).sort((a, b) => b.findings - a.findings), enabledByTechnique }
  }, [all, rules])

  // prevalence of the selected finding's entities in the case (Insights section)
  useEffect(() => {
    if (!selected || !kase) return
    let alive = true
    const ds = getSource(kase)
    const entries = Object.entries(selected.entities).slice(0, 4)
    setPrevalence({})
    Promise.all(
      entries.map(async ([k, v]) => {
        try {
          const n = selected.source === 'events' ? await ds.countEvents({ conditions: [{ field: k, op: 'eq', value: v }] }) : await ds.countMails({ conditions: [{ field: k, op: 'eq', value: v }] })
          return [k, n] as [string, number | null]
        } catch {
          return [k, null] as [string, number | null]
        }
      }),
    ).then((pairs) => alive && setPrevalence(Object.fromEntries(pairs)))
    return () => {
      alive = false
    }
  }, [selected, kase])

  // keyboard: j / k move, o or Enter open, Escape close, / focus search
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null
      if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable)) return
      if (e.key === '/') {
        e.preventDefault()
        ;(document.querySelector('[data-findings-search]') as HTMLInputElement | null)?.focus()
        return
      }
      if (group || tab !== 'findings' || !rows.length) return
      if (e.key === 'j' || e.key === 'k') {
        const i = selected ? rows.findIndex((r) => r.id === selected.id) : -1
        const next = e.key === 'j' ? Math.min(rows.length - 1, i + 1) : Math.max(0, i - 1)
        setSelected(rows[next])
      }
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [rows, selected, group, tab])

  if (!kase) return null

  const run = async () => {
    const enabled = rules.filter((r) => r.enabled && !r.error).map((r) => r.rule)
    if (!enabled.length) return toast('warn', 'no enabled rules')
    const before = sevCounts(all)
    setRunning({ done: 0, total: enabled.length, rule: '' })
    try {
      await runRulesFor(kase, enabled, (done, total, rule) => setRunning({ done, total, rule }))
      const pruned = await pruneOrphanFindings(kase.id!, rules.map((r) => r.rule.id))
      if (pruned) toast('info', `${pruned} finding(s) of rules that no longer exist were removed`)
      await getDb().kv.put({ key: `findingCounts-${kase.id}`, value: { previous: before, at: Date.now() } })
    } catch (e) {
      toast('err', `rules failed: ${(e as Error).message}`, 0)
    }
    setRunning(null)
    reload()
    refreshCounts(kase)
  }
  const setStatusFor = async (ids: number[], s: Status) => {
    const db = getDb()
    await Promise.all(ids.map((id) => db.findings.update(id, { status: s })))
    if (selected && ids.includes(selected.id!)) setSelected({ ...selected, status: s })
    setPicked(new Set())
    reload()
  }
  const openRefs = (f: Finding) => {
    if (!f.refs.length) return
    if (f.source === 'events') setEventsFilter({ conditions: [{ field: 'id', op: 'in', value: f.refs.slice(0, 500) }], sort: { field: 'ts', dir: 'asc' } })
    else setMailsFilter({ conditions: [{ field: 'id', op: 'in', value: f.refs.slice(0, 500) }] })
    setView(f.source)
  }
  const explain = (f: Finding) => {
    setAiPrompt(`Explain this finding and propose the next investigation steps. Rule ${f.ruleId} (${f.severity}): ${f.title}. ${f.description ?? ''} Entities: ${JSON.stringify(f.entities)}. ${f.count} matching row(s) in ${f.source}, first ${f.ts ? new Date(f.ts).toISOString() : 'n/a'}. Use the tools to look at the referenced rows (ids ${f.refs.slice(0, 20).join(', ')}).`)
    setView('ai')
  }
  const toggleGroup = (key: string) => setOpenGroups((s) => { const n = new Set(s); if (n.has(key)) n.delete(key); else n.add(key); return n })
  const delta = (s: Severity) => (previous ? (counts[s] ?? 0) - (previous[s] ?? 0) : null)
  const enabledCount = rules.filter((r) => r.enabled).length
  const pickedIds = Array.from(picked).map(Number)

  const columns: Column<Finding>[] = [
    { key: 'severity', label: 'severity', width: 104, render: (r) => <Sev sev={r.severity} /> },
    { key: 'title', label: 'finding', width: 'minmax(280px, 1.6fr)', render: (r) => <span className="sans ellipsis" title={r.description}>{r.title}{r.escalation ? <span className="muted"> · {r.escalation}</span> : null}</span> },
    { key: 'entities', label: 'entities', width: 'minmax(220px, 1fr)', render: (r) => Object.entries(r.entities).map(([k, v]) => `${k}=${v}`).join(' · ') },
    { key: 'attack', label: 'att&ck', width: 130, render: (r) => <span className="row" style={{ gap: 4 }}>{r.attack.slice(0, 2).map((t) => <Badge key={t} sev="outline">{t}</Badge>)}{r.attack.length > 2 ? <span className="muted">+{r.attack.length - 2}</span> : null}</span> },
    { key: 'source', label: 'source', width: 70 },
    { key: 'count', label: 'rows', width: 64, render: (r) => fmtNum(r.count) },
    { key: 'ts', label: 'first seen (UTC)', width: 150, render: (r) => fmtTs(r.ts) },
    { key: 'status', label: 'status', width: 110, render: (r) => <Badge sev={STATUS_SEV[r.status as Status] ?? 'info'}>{STATUS_LABEL[r.status as Status] ?? r.status}</Badge> },
  ]

  return (
    <div className="view">
      <div className="view-header">
        <div className="desc">
          <h1>Findings</h1>
          <span className="sub">{fmtNum(all.length)} finding(s) from {enabledCount} enabled rule(s){lastRun ? ` · last run ${fmtTs(lastRun.ts)}` : ' · rules not run yet'}</span>
        </div>
        <span className="spacer" />
        <button className="btn ghost sm" onClick={() => setView('rules')}>manage rules</button>
        <button className="btn ghost sm" onClick={() => exportCsv('findings.csv', rows.map((f) => ({ severity: f.severity, title: f.title, ruleId: f.ruleId, entities: JSON.stringify(f.entities), count: f.count, first: f.ts ? new Date(f.ts).toISOString() : '', last: f.tsEnd ? new Date(f.tsEnd).toISOString() : '', source: f.source, status: f.status, attack: f.attack.join(' '), refs: f.refs.slice(0, 50).join(' '), notes: f.notes })))}>csv</button>
        <button className="btn ghost sm" onClick={() => exportJson('findings.json', rows)}>json</button>
        <RescoreButton key={kase.id} />
        <button className="btn primary" onClick={run} disabled={!!running}><IconPlay /> run rules</button>
      </div>
      {running && <div style={{ padding: '6px 16px', background: 'var(--surface)' }} className="col"><div className="small dim mono">{running.done}/{running.total} · {running.rule}</div><Progress value={running.done / Math.max(1, running.total)} /></div>}
      <div className="grid-5" style={{ padding: '12px 16px 0' }}>
        <Kpi tone="critical" icon={<IconFindings />} value={fmtNum(counts.critical ?? 0)} label="critical" delta={delta('critical')} onClick={() => setSev(sev === 'critical' ? '' : 'critical')} />
        <Kpi tone="high" icon={<IconFindings />} value={fmtNum(counts.high ?? 0)} label="high" delta={delta('high')} onClick={() => setSev(sev === 'high' ? '' : 'high')} />
        <Kpi tone="medium" icon={<IconTarget />} value={fmtNum(counts.medium ?? 0)} label="medium" delta={delta('medium')} onClick={() => setSev(sev === 'medium' ? '' : 'medium')} />
        <Kpi tone="low" icon={<IconCircle />} value={fmtNum(counts.low ?? 0)} label="low" delta={delta('low')} onClick={() => setSev(sev === 'low' ? '' : 'low')} />
        <Kpi tone="info" icon={<IconInfo />} value={fmtNum(counts.info ?? 0)} label="informational" delta={delta('info')} onClick={() => setSev(sev === 'info' ? '' : 'info')} />
      </div>
      <div style={{ padding: '10px 16px 0' }}>
        <Tabs
          tabs={[
            { id: 'findings', label: <span>Findings <span className="n">{fmtNum(rows.length)}</span></span> },
            { id: 'attack', label: <span>ATT&amp;CK <span className="n">{attack.hits.length}</span></span> },
          ]}
          active={tab}
          onChange={setTab}
        />
      </div>
      {tab === 'findings' && (
        <>
          <div className="querybar">
            <div className="row wrap">
              <div className="search">
                <IconSearch />
                <input data-findings-search placeholder="search title, rule, entities, technique…   ( / )" value={q} onChange={(e) => setQ(e.target.value)} />
              </div>
              <label className={classNames('pill', sev && 'active')}>severity <select value={sev} onChange={(e) => setSev(e.target.value)}><option value="">any</option>{ORDER.map((s) => <option key={s} value={s}>{s} ({counts[s] ?? 0})</option>)}</select></label>
              <label className={classNames('pill', status && 'active')}>status <select value={status} onChange={(e) => setStatus(e.target.value)}><option value="">any</option>{STATUSES.map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}</select></label>
              <label className={classNames('pill', source && 'active')}>source <select value={source} onChange={(e) => setSource(e.target.value)}><option value="">events + mails</option><option value="events">events</option><option value="mails">mails</option></select></label>
              <div className="segmented" title="group by">
                {([['', 'flat'], ['ruleId', 'rule'], ['entity', 'entity'], ['source', 'source']] as [Group, string][]).map(([g, label]) => (
                  <button key={g} className={classNames(group === g && 'active')} onClick={() => setGroup(g)}>{label}</button>
                ))}
              </div>
              <span className="spacer" />
              <span className="mono small dim">{fmtNum(rows.length)} shown</span>
            </div>
          </div>
          {picked.size > 0 && (
            <div className="bulkbar">
              <b>{picked.size} selected</b>
              <span className="muted">set status:</span>
              {STATUSES.map((s) => <button key={s} className="btn xs" onClick={() => setStatusFor(pickedIds, s)}>{STATUS_LABEL[s]}</button>)}
              <span className="spacer" />
              <button className="btn xs ghost" onClick={() => setPicked(new Set())}>clear</button>
            </div>
          )}
          <div className="relative" style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
            {!group && (
              <VirtualTable
                rows={rows}
                columns={columns}
                rowKey={(r) => r.id!}
                onRowClick={(r) => { setSelected(r); setFlyTab('overview') }}
                selectedKey={selected?.id ?? null}
                selectedKeys={picked}
                onToggleSelect={(k) => setPicked((s) => { const n = new Set(s); if (n.has(k)) n.delete(k); else n.add(k); return n })}
                onToggleAll={(on) => setPicked(on ? new Set(rows.map((r) => r.id!)) : new Set())}
                empty={all.length ? 'no finding matches the filters' : 'no findings yet - run the rules'}
              />
            )}
            {group && (
              <div style={{ flex: 1, overflow: 'auto', background: 'var(--surface)' }}>
                {groups.map((g) => (
                  <div key={g.key}>
                    <div className="group-row" onClick={() => toggleGroup(g.key)}>
                      <span className="caret">{openGroups.has(g.key) ? '▾' : '▸'}</span>
                      <Dot sev={g.items[0].severity} />
                      <span className="name ellipsis" style={{ maxWidth: 520 }}>{g.label}</span>
                      {group === 'ruleId' && <span className="mono small muted">{g.key}</span>}
                      <span className="count">{fmtNum(g.items.length)}</span>
                      <span style={{ width: 120 }}><SevBar counts={sevCounts(g.items)} /></span>
                      <span className="spacer" />
                      <button className="btn xs ghost" onClick={(e) => { e.stopPropagation(); setPicked(new Set(g.items.map((f) => f.id!))) }}>select all</button>
                    </div>
                    {openGroups.has(g.key) && (
                      <table className="table compact">
                        <tbody>
                          {g.items.slice(0, 300).map((f) => (
                            <tr key={f.id} onClick={() => { setSelected(f); setFlyTab('overview') }} style={{ cursor: 'pointer' }}>
                              <td style={{ width: 100 }}><Sev sev={f.severity} /></td>
                              <td className="sans">{f.title}{f.escalation ? <span className="muted"> · {f.escalation}</span> : null}</td>
                              <td className="muted">{Object.entries(f.entities).map(([k, v]) => `${k}=${v}`).join(' · ')}</td>
                              <td style={{ width: 60 }}>{fmtNum(f.count)}</td>
                              <td style={{ width: 150 }}>{fmtTs(f.ts)}</td>
                              <td style={{ width: 110 }}><Badge sev={STATUS_SEV[f.status as Status] ?? 'info'}>{STATUS_LABEL[f.status as Status] ?? f.status}</Badge></td>
                            </tr>
                          ))}
                          {g.items.length > 300 && <tr><td colSpan={6} className="muted sans">{fmtNum(g.items.length - 300)} more - switch to the flat view with a filter</td></tr>}
                        </tbody>
                      </table>
                    )}
                  </div>
                ))}
                {!groups.length && <div className="vtable-empty">{all.length ? 'no finding matches the filters' : 'no findings yet - run the rules'}</div>}
              </div>
            )}
            {selected && (
              <Flyout
                title={<span className="row" style={{ gap: 8 }}><Sev sev={selected.severity} /><span>{selected.title}</span></span>}
                meta={<>
                  <span className="mono">{selected.ruleId}</span>
                  <span>{selected.source}</span>
                  <span>{fmtTs(selected.ts)}{selected.tsEnd && selected.tsEnd !== selected.ts ? ` → ${fmtTs(selected.tsEnd)}` : ''}</span>
                  <span>{fmtNum(selected.count)} row(s)</span>
                  <Badge sev={STATUS_SEV[selected.status as Status] ?? 'info'}>{STATUS_LABEL[selected.status as Status] ?? selected.status}</Badge>
                  {selected.confidence && <span title="rule confidence">confidence {selected.confidence}</span>}
                </>}
                tabs={<Tabs tabs={[{ id: 'overview', label: 'Overview' }, { id: 'table', label: 'Table' }, { id: 'json', label: 'JSON' }]} active={flyTab} onChange={setFlyTab} />}
                onClose={() => setSelected(null)}
                footer={<>
                  <AddToTimeline ts={selected.ts} text={selected.title} link={{ source: 'findings', id: selected.id!, label: selected.ruleId }} severity={selected.severity} />
                  <span className="small muted">status</span>
                  <div className="segmented">{STATUSES.map((s) => <button key={s} className={classNames(selected.status === s && 'active')} onClick={() => setStatusFor([selected.id!], s)}>{STATUS_LABEL[s]}</button>)}</div>
                  <span className="spacer" />
                  <button className="btn sm" onClick={() => explain(selected)}>ask the analyst</button>
                  <button className="btn sm primary" onClick={() => openRefs(selected)}>open {Math.min(selected.refs.length, 500)} row(s)</button>
                </>}
              >
                {flyTab === 'overview' && (
                  <>
                    <div className="section">
                      <h3>About</h3>
                      <div>{selected.description || <span className="muted">the rule has no description</span>}</div>
                      <div className="row wrap" style={{ gap: 6 }}>
                        {selected.attack.map((t) => <a key={t} className="badge outline" href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`} target="_blank" rel="noreferrer">{t}</a>)}
                        {(selected.tags ?? []).map((t) => <Badge key={t}>{t}</Badge>)}
                      </div>
                      {selected.escalation && <div className="small" style={{ color: 'var(--danger)' }}>escalated by: {selected.escalation}</div>}
                      {lastRun?.errors?.some((e) => e.startsWith(selected.ruleId)) && <div className="small" style={{ color: 'var(--warn)' }}>this rule reported an error in the last run; the finding may be from an earlier run</div>}
                    </div>
                    <div className="section">
                      <h3>Investigation</h3>
                      <div className="highlight">
                        {Object.entries(selected.entities).map(([k, v]) => (
                          <div className="f" key={k}>
                            <span className="k">{k}</span>
                            <span className="v" onClick={() => openEntity(k, String(v), selected.source)} title={entityKind(k) ? `open the ${entityKind(k)} page` : `pivot on ${k}`}>{String(v)}</span>
                          </div>
                        ))}
                        <div className="f"><span className="k">referenced rows</span><span className="v" onClick={() => openRefs(selected)}>{fmtNum(selected.refs.length)}{selected.refs.length > 500 ? ' (first 500)' : ''}</span></div>
                        {selected.refs.slice(0, 1).map((id) => <div className="f" key={id}><span className="k">first row</span><span className="v" onClick={() => { setFocus({ source: selected.source, id }); setView(selected.source) }}>#{id}</span></div>)}
                      </div>
                    </div>
                    <div className="section">
                      <h3>Insights</h3>
                      <div className="kv">
                        {Object.entries(selected.entities).slice(0, 4).map(([k, v]) => (
                          <div key={k} style={{ display: 'contents' }}>
                            <div className="k">{k} in this case</div>
                            <div className="v">{prevalence[k] == null ? <span className="muted">…</span> : `${fmtNum(prevalence[k]!)} ${selected.source === 'events' ? 'event(s)' : 'mail(s)'} with ${String(v)}`}</div>
                          </div>
                        ))}
                        {(() => { const rc = relatedChains(selected, all); return rc.length ? <><div className="k">attack chains</div><div className="v">{rc.map((c) => <button key={c.id} className="btn link" style={{ display: 'block' }} onClick={() => setView('chains')}>{c.title}</button>)}</div></> : null })()}
                        <div className="k">same rule</div>
                        <div className="v">{fmtNum(all.filter((f) => f.ruleId === selected.ruleId).length)} finding(s) · {fmtNum(all.filter((f) => f.ruleId === selected.ruleId && f.status === 'false_positive').length)} marked false positive</div>
                      </div>
                    </div>
                    <div className="section">
                      <h3>Notes</h3>
                      <textarea className="textarea" placeholder="analyst notes…" defaultValue={selected.notes ?? ''} onBlur={(e) => { getDb().findings.update(selected.id!, { notes: e.target.value }); reload() }} />
                    </div>
                  </>
                )}
                {flyTab === 'table' && (
                  <div className="kv">
                    {Object.entries(selected).filter(([k, v]) => !['id', 'caseId', 'entities', 'refs'].includes(k) && v != null && v !== '' && !(Array.isArray(v) && !v.length)).map(([k, v]) => (
                      <div key={k} style={{ display: 'contents' }}><div className="k">{k}</div><div className="v">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</div></div>
                    ))}
                    {Object.entries(selected.entities).map(([k, v]) => <div key={'e' + k} style={{ display: 'contents' }}><div className="k">entity.{k}</div><div className="v click" onClick={() => pivot(String(v), k, selected.source)}>{String(v)}</div></div>)}
                  </div>
                )}
                {flyTab === 'json' && <JsonView value={selected} />}
              </Flyout>
            )}
          </div>
        </>
      )}
      {tab === 'attack' && (
        <div className="view-body" style={{ paddingTop: 12 }}>
          <div className="panel">
            <div className="panel-h">Techniques observed <span className="muted">· {attack.hits.length} technique(s) across {fmtNum(all.length)} finding(s)</span></div>
            <table className="table">
              <thead><tr><th>technique</th><th>worst severity</th><th>findings</th><th>rules that fired</th><th>enabled rules mapped</th><th></th></tr></thead>
              <tbody>
                {attack.hits.map((h) => (
                  <tr key={h.id}>
                    <td>{h.id}</td>
                    <td><Sev sev={h.worst} /></td>
                    <td>{fmtNum(h.findings)}</td>
                    <td>{h.rules.size}</td>
                    <td>{attack.enabledByTechnique.get(h.id) ?? 0}</td>
                    <td className="sans"><a href={`https://attack.mitre.org/techniques/${h.id.replace('.', '/')}/`} target="_blank" rel="noreferrer">attack.mitre.org</a> · <button className="btn link" onClick={() => { setTab('findings'); setQ(h.id) }}>show findings</button></td>
                  </tr>
                ))}
                {!attack.hits.length && <tr><td colSpan={6} className="muted sans">no technique yet - run the rules</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
