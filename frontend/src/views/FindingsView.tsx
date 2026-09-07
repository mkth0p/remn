import { useCallback, useEffect, useMemo, useState } from 'react'
import { VirtualTable, type Column } from '../components/VirtualTable'
import { usePivot } from '../components/Detail'
import { entityKind } from '../components/EntityPanel'
import { AddToTimeline } from '../components/AddToTimeline'
import { Badge, Dot, Flyout, JsonView, Kpi, Progress, Sev, SevBar, Tabs } from '../components/ui'
import { IconArrowLeft, IconCircle, IconFindings, IconInfo, IconPlay, IconSearch, IconTarget } from '../components/Icons'
import { RescoreButton } from '../components/RescoreButton'
import { loadRules, type LoadedRule } from '../data/rules'
import { findingsStaleness, runEnabledRules, type Staleness } from '../data/findingsState'
import { resetFindingSeverityOverrides } from '../data/findingReviews'
import { getSource } from '../data/source'
import { getDb, type Finding, type Severity } from '../db/schema'
import { buildIncidents, chainMembership, effectiveSeverity, sevCounts, type Incident } from '../rules/incidents'
import { loadChains, type Chain } from '../data/chains'
import { chainSeverity, loadChainReviews, type ChainReview } from '../data/review'
import { toast, useStore } from '../state/store'
import { classNames, fmtNum, fmtTs } from '../util/format'
import { exportCsv, exportJson } from '../util/export'
import { attackHref } from '../util/safe'

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
const STATUSES = ['new', 'reviewed', 'escalated', 'false_positive'] as const
type Status = (typeof STATUSES)[number]
type Group = 'incident' | '' | 'ruleId' | 'entity' | 'source'
const REFS_OPEN = 2000

const STATUS_LABEL: Record<Status, string> = { new: 'new', reviewed: 'reviewed', escalated: 'escalated', false_positive: 'false positive' }
const STATUS_SEV: Record<Status, string> = { new: 'accent', reviewed: 'ok', escalated: 'critical', false_positive: 'info' }
const KIND_LABEL: Record<Incident['kind'], string> = { chain: 'chain', mail: 'mail', entity: 'entity', group: 'grouped' }

interface LastRun {
  ts: number
  byRule: Record<string, number>
  errors?: string[]
}

/** Findings referencing the same seed mail or the same identity as this one. */
function relatedChains(f: Finding, all: Finding[]): Finding[] {
  if (f.ruleId === 'chain') return []
  const ents = new Set(Object.values(f.entities).map((v) => String(v).toLowerCase()))
  return all.filter((c) => c.ruleId === 'chain' && (c.refs.some((r) => f.refs.includes(r)) || Object.values(c.entities).some((v) => ents.has(String(v).toLowerCase()))))
}

const StatusBadge = ({ s }: { s: string }) => <Badge sev={STATUS_SEV[s as Status] ?? 'info'}>{STATUS_LABEL[s as Status] ?? s}</Badge>
const FindingSeverity = ({ finding }: { finding: Finding }) => <span title={finding.severityOverride ? `Review severity override: ${finding.severityOverride}; rule: ${finding.severity}` : undefined}><Sev sev={effectiveSeverity(finding)}>{effectiveSeverity(finding)}{finding.severityOverride ? '*' : ''}</Sev></span>
const OverrideLabel = ({ finding }: { finding: Finding }) => finding.severityOverride ? <span className="small muted">review override; rule: {finding.severity}</span> : null

function SeverityOverrideNotice({ findings, busy, onReset, chain = false }: { findings: Finding[]; busy: boolean; onReset: () => void; chain?: boolean }) {
  if (!findings.some((f) => f.severityOverride)) return null
  return <div className="section">
    <h3>Review severity override</h3>
    <p className="small muted">A saved review overrides the rule severity for the findings marked with *. Rule refreshes preserve these overrides. Resetting keeps review status and notes.{chain ? ' Chain severity is managed separately on the Review page.' : ''}</p>
    <button className="btn sm" disabled={busy} onClick={onReset}>{busy ? 'resetting…' : chain ? 'reset finding overrides' : 'reset to rule severity'}</button>
  </div>
}

/**
 * Findings triage. The default view is incidents: every finding on one mail, or about one
 * user / host / IP within a few hours, is one line. Flat and grouped views keep the per-rule
 * detail. The banner above the queue says when the findings are behind the evidence.
 */
export function FindingsView() {
  const kase = useStore((s) => s.currentCase)
  const rulesVersion = useStore((s) => s.rulesVersion)
  const running = useStore((s) => s.rulesRun)
  const setFocus = useStore((s) => s.setFocus)
  const setView = useStore((s) => s.setView)
  const setEventsFilter = useStore((s) => s.setEventsFilter)
  const setMailsFilter = useStore((s) => s.setMailsFilter)
  const setAiPrompt = useStore((s) => s.setAiPrompt)
  const pivot = usePivot()
  const setEntity = useStore((s) => s.setEntity)
  const openEntity = (k: string, v: string, source: 'events' | 'mails') => { const kind = entityKind(k); if (kind && v && !v.includes(',')) setEntity({ kind, value: v }); else pivot(v, k, source) }
  const [all, setAll] = useState<Finding[]>([])
  const [chains, setChains] = useState<Chain[]>([])
  const [chainReviews, setChainReviews] = useState<Record<string, ChainReview>>({})
  const [sev, setSev] = useState('')
  const [status, setStatus] = useState('')
  const [source, setSource] = useState('')
  const [showFp, setShowFp] = useState(false)
  const [q, setQ] = useState('')
  const [group, setGroup] = useState<Group>('incident')
  const [openGroups, setOpenGroups] = useState<Set<string>>(new Set())
  const [tab, setTab] = useState<'findings' | 'attack'>('findings')
  const [selected, setSelected] = useState<Finding | null>(null)
  const [incident, setIncident] = useState<Incident | null>(null)
  const [parent, setParent] = useState<Incident | null>(null)
  const [flyTab, setFlyTab] = useState<'overview' | 'table' | 'json'>('overview')
  const [picked, setPicked] = useState<Set<string | number>>(new Set())
  const [rules, setRules] = useState<LoadedRule[]>([])
  const [lastRun, setLastRun] = useState<LastRun | null>(null)
  const [previous, setPrevious] = useState<Record<string, number> | null>(null)
  const [stale, setStale] = useState<Staleness | null>(null)
  const [prevalence, setPrevalence] = useState<Record<string, number | null>>({})
  const [resettingSeverity, setResettingSeverity] = useState(false)

  const reload = useCallback(() => {
    if (!kase?.id) return
    const db = getDb()
    db.findings.where('caseId').equals(kase.id).toArray().then((f) => setAll(f.sort((a, b) => ORDER.indexOf(effectiveSeverity(a)) - ORDER.indexOf(effectiveSeverity(b)) || (b.ts ?? 0) - (a.ts ?? 0))))
    db.kv.get(`ruleDiags-${kase.id}`).then((k) => setLastRun((k?.value as LastRun) ?? null))
    loadChains(kase.id).then((r) => setChains(r?.chains ?? []))
    loadChainReviews(kase.id).then(setChainReviews)
    db.kv.get(`findingCounts-${kase.id}`).then((k) => setPrevious(((k?.value as { previous?: Record<string, number> }) ?? {}).previous ?? null))
    findingsStaleness(kase.id).then(setStale).catch(() => setStale(null))
  }, [kase?.id])
  useEffect(() => {
    reload()
  }, [reload, rulesVersion])
  useEffect(() => {
    if (kase) loadRules(kase.id!).then(setRules)
  }, [kase, rulesVersion])
  useEffect(() => {
    setSelected(null)
    setIncident(null)
    setParent(null)
    setPicked(new Set())
  }, [kase?.id])
  // a rule run just finished elsewhere (auto-run after ingest): refresh the staleness banner
  useEffect(() => {
    if (!running && kase?.id) findingsStaleness(kase.id).then(setStale).catch(() => undefined)
  }, [running, kase?.id])

  // false positives leave the queue and the counts unless asked for (status filter or the toggle)
  const active = useMemo(() => all.filter((f) => f.status !== 'false_positive'), [all])
  const fpCount = all.length - active.length
  const rows = useMemo(() => {
    const needle = q.toLowerCase()
    const base = status === 'false_positive' || showFp ? all : active
    return base.filter((f) => (group === 'incident' || !sev || effectiveSeverity(f) === sev) && (!status || f.status === status) && (!source || f.source === source) && (!needle || `${f.title} ${f.ruleId} ${JSON.stringify(f.entities)} ${f.attack.join(' ')}`.toLowerCase().includes(needle)))
  }, [all, active, sev, status, source, q, showFp, group])
  const incidentOpts = useMemo(() => ({ chains, severityOf: (c: Chain) => chainSeverity(c, chainReviews[c.id]) }), [chains, chainReviews])
  const incidents = useMemo(() => (group === 'incident' ? buildIncidents(rows, incidentOpts).filter((i) => !sev || i.severity === sev) : []), [rows, group, incidentOpts, sev])
  const shownRows = useMemo(() => group === 'incident' ? [...new Map(incidents.flatMap((i) => i.findings).map((f) => [f.id, f])).values()] : rows, [group, incidents, rows])
  const allIncidents = useMemo(() => buildIncidents(active, incidentOpts), [active, incidentOpts])
  const membership = useMemo(() => chainMembership(all, chains), [all, chains])
  const counts = useMemo(() => (group === 'incident' ? sevCounts(allIncidents) : sevCounts(active)), [active, allIncidents, group])
  // Open details must follow a reset or rule refresh, including replacement row IDs.
  useEffect(() => {
    setSelected((prev) => prev ? all.find((f) => f.key === prev.key) ?? null : null)
    const current = buildIncidents(all, incidentOpts)
    setIncident((prev) => prev ? current.find((i) => i.id === prev.id) ?? null : null)
    setParent((prev) => prev ? current.find((i) => i.id === prev.id) ?? null : null)
  }, [all, incidentOpts])
  const groups = useMemo(() => {
    if (!group || group === 'incident') return []
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
    for (const f of active) {
      for (const t of f.attack) {
        const e = m.get(t) ?? { id: t, findings: 0, rules: new Set<string>(), worst: 'info' as Severity }
        e.findings++
        e.rules.add(f.ruleId)
        if (ORDER.indexOf(effectiveSeverity(f)) < ORDER.indexOf(e.worst)) e.worst = effectiveSeverity(f)
        m.set(t, e)
      }
    }
    const enabledByTechnique = new Map<string, number>()
    for (const r of rules) if (r.enabled) for (const t of r.rule.attack ?? []) enabledByTechnique.set(t, (enabledByTechnique.get(t) ?? 0) + 1)
    return { hits: Array.from(m.values()).sort((a, b) => b.findings - a.findings), enabledByTechnique }
  }, [active, rules])

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

  // keyboard: j / k move, Escape close, / focus search
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null
      if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable)) return
      if (e.key === '/') {
        e.preventDefault()
        ;(document.querySelector('[data-findings-search]') as HTMLInputElement | null)?.focus()
        return
      }
      if (tab !== 'findings' || (e.key !== 'j' && e.key !== 'k')) return
      if (group === 'incident' && incidents.length) {
        const i = incident ? incidents.findIndex((r) => r.id === incident.id) : -1
        const next = e.key === 'j' ? Math.min(incidents.length - 1, i + 1) : Math.max(0, i - 1)
        setSelected(null)
        setIncident(incidents[next])
      } else if (!group && rows.length) {
        const i = selected ? rows.findIndex((r) => r.id === selected.id) : -1
        const next = e.key === 'j' ? Math.min(rows.length - 1, i + 1) : Math.max(0, i - 1)
        setSelected(rows[next])
      }
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [rows, incidents, selected, incident, group, tab])

  if (!kase) return null

  const run = async () => {
    await runEnabledRules(kase, 'manual')
    reload()
  }
  const setStatusFor = async (ids: number[], s: Status) => {
    const db = getDb()
    await Promise.all(ids.map((id) => db.findings.update(id, { status: s })))
    if (selected && ids.includes(selected.id!)) setSelected({ ...selected, status: s })
    if (incident) setIncident({ ...incident, status: s, findings: incident.findings.map((f) => (ids.includes(f.id!) ? { ...f, status: s } : f)) })
    setPicked(new Set())
    reload()
  }
  const resetSeverityFor = async (findings: Finding[]) => {
    if (resettingSeverity) return
    setResettingSeverity(true)
    try {
      await resetFindingSeverityOverrides(kase.id!, findings.filter((f) => f.severityOverride).map((f) => f.id!))
      useStore.getState().bumpRules()
      toast('ok', 'Rule severity restored. Review status and notes kept.')
    } catch (e) {
      toast('err', `Severity reset failed: ${(e as Error).message}`)
    } finally {
      setResettingSeverity(false)
    }
  }
  const openRefs = (source: 'events' | 'mails' | 'mixed', refs: number[]) => {
    if (!refs.length || source === 'mixed') return
    if (source === 'events') setEventsFilter({ conditions: [{ field: 'id', op: 'in', value: refs.slice(0, REFS_OPEN) }], sort: { field: 'ts', dir: 'asc' } })
    else setMailsFilter({ conditions: [{ field: 'id', op: 'in', value: refs.slice(0, REFS_OPEN) }] })
    setView(source)
  }
  const explain = (f: Finding) => {
    setAiPrompt(`Explain this finding and propose the next investigation steps. Rule ${f.ruleId} (${f.severity}): ${f.title}. ${f.description ?? ''} Entities: ${JSON.stringify(f.entities)}. ${f.count} matching row(s) in ${f.source}, first ${f.ts ? new Date(f.ts).toISOString() : 'n/a'}. Use the tools to look at the referenced rows (ids ${f.refs.slice(0, 20).join(', ')}).`)
    setView('ai')
  }
  const explainIncident = (i: Incident) => {
    setAiPrompt(`Assess this incident and propose the next investigation steps. ${i.kind === 'mail' ? 'Mail' : 'Entity'} "${i.title}" (${i.severity}), ${i.findings.length} finding(s) from ${i.rules.length} rule(s), ${i.ts ? new Date(i.ts).toISOString() : 'n/a'} to ${i.tsEnd ? new Date(i.tsEnd).toISOString() : 'n/a'}. Entities: ${JSON.stringify(i.entities)}. Findings: ${i.findings.slice(0, 20).map((f) => `${f.severity} ${f.ruleId}: ${f.title}`).join(' | ')}. Referenced rows (${i.source}): ${i.refs.slice(0, 20).join(', ')}.`)
    setView('ai')
  }
  const toggleGroup = (key: string) => setOpenGroups((s) => { const n = new Set(s); if (n.has(key)) n.delete(key); else n.add(key); return n })
  const delta = (s: Severity) => (group !== 'incident' && previous ? (counts[s] ?? 0) - (previous[s] ?? 0) : null)
  const enabledCount = rules.filter((r) => r.enabled).length
  const pickedFindingIds = group === 'incident' ? incidents.filter((i) => picked.has(i.id)).flatMap((i) => i.findings.map((f) => f.id!)) : Array.from(picked).map(Number)
  const openFinding = (f: Finding, from: Incident | null) => {
    setParent(from)
    setIncident(null)
    setSelected(f)
    setFlyTab('overview')
  }
  const inheritedReview = (f: Finding) => lastRun && f.status !== 'new' && f.createdAt < lastRun.ts
  const staleParts: string[] = []
  if (stale) {
    if (stale.lastRun == null && all.length === 0 && stale.evidenceAfter > 0) staleParts.push('rules have not run on this evidence yet')
    else if (stale.evidenceAfter > 0) staleParts.push(`${stale.evidenceAfter} evidence file${stale.evidenceAfter === 1 ? '' : 's'} added since the last run`)
    if (stale.rescoreIncomplete) staleParts.push('mail scores changed but the findings refresh did not finish')
    if (stale.baselineAfter) staleParts.push('sender baseline ran after the last run')
  }

  const columns: Column<Finding>[] = [
    { key: 'severity', label: 'severity', width: 104, render: (r) => <FindingSeverity finding={r} /> },
    { key: 'title', label: 'finding', width: 'minmax(280px, 1.6fr)', render: (r) => <span className="sans ellipsis" title={r.description}>{r.title}{r.escalation ? <span className="muted"> · {r.escalation}</span> : null}{r.id != null && membership.has(r.id) && r.ruleId !== 'chain' ? <> <Badge sev="outline" title="its rows are steps of an attack chain: decided with the chain on the Review page">chain</Badge></> : null}{r.chainUnlinked ? <> <Badge sev="outline" title="taken out of its attack chain: decided on its own">unlinked</Badge></> : null}</span> },
    { key: 'entities', label: 'entities', width: 'minmax(220px, 1fr)', render: (r) => Object.entries(r.entities).map(([k, v]) => `${k}=${v}`).join(' · ') },
    { key: 'attack', label: 'att&ck', width: 130, render: (r) => <span className="row" style={{ gap: 4 }}>{r.attack.slice(0, 2).map((t) => <Badge key={t} sev="outline">{t}</Badge>)}{r.attack.length > 2 ? <span className="muted">+{r.attack.length - 2}</span> : null}</span> },
    { key: 'source', label: 'source', width: 70 },
    { key: 'count', label: 'rows', width: 64, render: (r) => fmtNum(r.count) },
    { key: 'ts', label: 'first seen (UTC)', width: 150, render: (r) => fmtTs(r.ts) },
    { key: 'status', label: 'status', width: 110, render: (r) => <StatusBadge s={r.status} /> },
  ]
  const incidentColumns: Column<Incident>[] = [
    { key: 'severity', label: 'severity', width: 104, render: (r) => <span title={r.kind !== 'chain' && r.findings.some((f) => f.severityOverride) ? 'Includes review severity overrides; open the incident to see the rule severities or reset.' : undefined}><Sev sev={r.severity}>{r.severity}{r.kind !== 'chain' && r.findings.some((f) => f.severityOverride) ? '*' : ''}</Sev></span> },
    { key: 'title', label: 'incident', width: 'minmax(300px, 1.8fr)', render: (r) => <span className="sans ellipsis" title={r.subtitle}><span style={{ color: 'var(--fg-1)' }}>{r.title}</span><span className="muted"> · {r.subtitle}</span></span> },
    { key: 'kind', label: 'kind', width: 74, render: (r) => KIND_LABEL[r.kind] },
    { key: 'findings', label: 'findings', width: 130, render: (r) => <span className="row" style={{ gap: 6 }}><span className="mono">{fmtNum(r.findings.length)}</span><span style={{ width: 70 }}><SevBar counts={sevCounts(r.findings)} /></span></span> },
    { key: 'rules', label: 'rules', width: 56, render: (r) => fmtNum(r.rules.length) },
    { key: 'ts', label: 'first seen (UTC)', width: 150, render: (r) => fmtTs(r.ts) },
    { key: 'tsEnd', label: 'last (UTC)', width: 150, render: (r) => (r.tsEnd && r.tsEnd !== r.ts ? fmtTs(r.tsEnd) : '') },
    { key: 'status', label: 'status', width: 110, render: (r) => <StatusBadge s={r.status} /> },
  ]

  const memberRow = (f: Finding, from: Incident | null) => (
    <tr key={f.id} onClick={() => openFinding(f, from)} style={{ cursor: 'pointer' }}>
      <td style={{ width: 100 }}><FindingSeverity finding={f} /></td>
      <td className="sans">{f.title}{f.escalation ? <span className="muted"> · {f.escalation}</span> : null}{f.severityOverride && <div><OverrideLabel finding={f} /></div>}</td>
      <td className="muted">{f.ruleId}</td>
      <td style={{ width: 60 }}>{fmtNum(f.count)}</td>
      <td style={{ width: 150 }} className="nowrap">{fmtTs(f.ts)}</td>
      <td style={{ width: 110 }}><StatusBadge s={f.status} /></td>
    </tr>
  )

  return (
    <div className="view">
      <div className="view-header">
        <div className="desc">
          <h1>Findings</h1>
          <span className="sub">{fmtNum(allIncidents.length)} incident(s) · {fmtNum(active.length)} finding(s) from {enabledCount} enabled rule(s){fpCount ? ` · ${fmtNum(fpCount)} false positive${fpCount === 1 ? '' : 's'}${showFp || status === 'false_positive' ? '' : ' hidden'}` : ''}{lastRun ? ` · last run ${fmtTs(lastRun.ts)}` : ' · rules not run yet'}</span>
        </div>
        <span className="spacer" />
        <button className="btn ghost sm" onClick={() => setView('rules')}>manage rules</button>
        <button className="btn ghost sm" onClick={() => exportCsv('findings.csv', shownRows.map((f) => ({ severity: f.severity, severityOverride: f.severityOverride, title: f.title, ruleId: f.ruleId, entities: JSON.stringify(f.entities), count: f.count, first: f.ts ? new Date(f.ts).toISOString() : '', last: f.tsEnd ? new Date(f.tsEnd).toISOString() : '', source: f.source, status: f.status, attack: f.attack.join(' '), refs: f.refs.slice(0, 50).join(' '), notes: f.notes })))}>csv</button>
        <button className="btn ghost sm" onClick={() => exportJson('findings.json', shownRows)}>json</button>
        <RescoreButton key={kase.id} />
        <button className="btn primary" onClick={run} disabled={!!running}><IconPlay /> run rules</button>
      </div>
      {running && <div style={{ padding: '6px 16px', background: 'var(--surface)' }} className="col"><div className="small dim mono">{running.reason === 'ingest' ? 'refreshing findings after ingest · ' : ''}{running.done}/{running.total} · {running.rule}</div><Progress value={running.done / Math.max(1, running.total)} /></div>}
      {!running && staleParts.length > 0 && (
        <div className="bulkbar" style={{ background: 'var(--sev-medium-bg)', borderColor: 'rgba(217,130,43,0.35)', color: 'var(--sev-medium)' }}>
          <b>Findings are behind the evidence:</b>
          <span>{staleParts.join(' · ')}</span>
          <span className="spacer" />
          <button className="btn xs" onClick={run}>run rules now</button>
        </div>
      )}
      {!running && stale && stale.errors.length > 0 && (
        <div className="bulkbar" style={{ background: 'var(--sev-high-bg)', borderColor: 'rgba(209,64,63,0.35)', color: 'var(--sev-high)' }}>
          <b>{stale.errors.length} rule{stale.errors.length === 1 ? '' : 's'} failed in the last run</b>
          <span className="ellipsis" title={stale.errors.join('\n')}>{stale.errors.slice(0, 3).map((e) => e.split(':')[0]).join(', ')}{stale.errors.length > 3 ? ` +${stale.errors.length - 3}` : ''} · their findings are from an earlier run or missing</span>
          <span className="spacer" />
          <button className="btn xs" onClick={() => setView('rules')}>see diagnostics</button>
        </div>
      )}
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
            { id: 'findings', label: <span>{group === 'incident' ? 'Incidents' : 'Findings'} <span className="n">{fmtNum(group === 'incident' ? incidents.length : rows.length)}</span></span> },
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
              {fpCount > 0 && <button className={classNames('pill', showFp && 'active')} onClick={() => setShowFp(!showFp)} title="false positives are hidden from the queue and the counts by default">{showFp ? 'hiding' : 'show'} {fmtNum(fpCount)} false positive{fpCount === 1 ? '' : 's'}</button>}
              <label className={classNames('pill', source && 'active')}>source <select value={source} onChange={(e) => setSource(e.target.value)}><option value="">events + mails</option><option value="events">events</option><option value="mails">mails</option></select></label>
              <div className="segmented" title="how the queue is grouped">
                {([['incident', 'incidents'], ['', 'flat'], ['ruleId', 'rule'], ['entity', 'entity'], ['source', 'source']] as [Group, string][]).map(([g, label]) => (
                  <button key={g} className={classNames(group === g && 'active')} onClick={() => { setGroup(g); setPicked(new Set()); setIncident(null) }}>{label}</button>
                ))}
              </div>
              <span className="spacer" />
              <span className="mono small dim">{group === 'incident' ? `${fmtNum(incidents.length)} incident(s) · ${fmtNum(shownRows.length)} finding(s)` : `${fmtNum(rows.length)} shown`}</span>
            </div>
          </div>
          {picked.size > 0 && (
            <div className="bulkbar">
              <b>{picked.size} selected{group === 'incident' ? ` · ${pickedFindingIds.length} finding(s)` : ''}</b>
              <span className="muted">set status:</span>
              {STATUSES.map((s) => <button key={s} className="btn xs" onClick={() => setStatusFor(pickedFindingIds, s)}>{STATUS_LABEL[s]}</button>)}
              <span className="spacer" />
              <button className="btn xs ghost" onClick={() => setPicked(new Set())}>clear</button>
            </div>
          )}
          <div className="relative" style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
            {group === 'incident' && (
              <VirtualTable
                rows={incidents}
                columns={incidentColumns}
                rowKey={(r) => r.id}
                onRowClick={(r) => { setSelected(null); setParent(null); setIncident(r) }}
                selectedKey={incident?.id ?? null}
                selectedKeys={picked}
                onToggleSelect={(k) => setPicked((s) => { const n = new Set(s); if (n.has(k)) n.delete(k); else n.add(k); return n })}
                onToggleAll={(on) => setPicked(on ? new Set(incidents.map((r) => r.id)) : new Set())}
                empty={all.length ? 'no incident matches the filters' : 'no findings yet - run the rules'}
              />
            )}
            {!group && (
              <VirtualTable
                rows={rows}
                columns={columns}
                rowKey={(r) => r.id!}
                onRowClick={(r) => openFinding(r, null)}
                selectedKey={selected?.id ?? null}
                selectedKeys={picked}
                onToggleSelect={(k) => setPicked((s) => { const n = new Set(s); if (n.has(k)) n.delete(k); else n.add(k); return n })}
                onToggleAll={(on) => setPicked(on ? new Set(rows.map((r) => r.id!)) : new Set())}
                empty={all.length ? 'no finding matches the filters' : 'no findings yet - run the rules'}
              />
            )}
            {group && group !== 'incident' && (
              <div style={{ flex: 1, overflow: 'auto', background: 'var(--surface)' }}>
                {groups.map((g) => (
                  <div key={g.key}>
                    <div className="group-row" onClick={() => toggleGroup(g.key)}>
                      <span className="caret">{openGroups.has(g.key) ? '▾' : '▸'}</span>
                      <Dot sev={effectiveSeverity(g.items[0])} />
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
                          {g.items.slice(0, 300).map((f) => memberRow(f, null))}
                          {g.items.length > 300 && <tr><td colSpan={6} className="muted sans">{fmtNum(g.items.length - 300)} more - switch to the flat view with a filter</td></tr>}
                        </tbody>
                      </table>
                    )}
                  </div>
                ))}
                {!groups.length && <div className="vtable-empty">{all.length ? 'no finding matches the filters' : 'no findings yet - run the rules'}</div>}
              </div>
            )}
            {incident && !selected && (
              <Flyout
                title={<span className="row" style={{ gap: 8 }}><Sev sev={incident.severity} /><span>{incident.title}</span></span>}
                meta={<>
                  <Badge>{KIND_LABEL[incident.kind]}</Badge>
                  <span>{fmtNum(incident.findings.length)} finding(s) from {incident.rules.length} rule(s)</span>
                  <span>{fmtTs(incident.ts)}{incident.tsEnd && incident.tsEnd !== incident.ts ? ` → ${fmtTs(incident.tsEnd)}` : ''}</span>
                  <span>{fmtNum(incident.refs.length)} row(s)</span>
                  <StatusBadge s={incident.status} />
                  {incident.findings.some((f) => f.severityOverride) && <Badge>review severity override</Badge>}
                </>}
                onClose={() => setIncident(null)}
                footer={<>
                  <AddToTimeline ts={incident.ts} text={`${incident.title}: ${incident.lead.title}`} link={{ source: 'findings', id: incident.lead.id!, label: incident.lead.ruleId }} severity={incident.severity} />
                  <span className="small muted">status</span>
                  <div className="segmented">{STATUSES.map((s) => <button key={s} className={classNames(incident.status === s && 'active')} onClick={() => setStatusFor(incident.findings.map((f) => f.id!), s)}>{STATUS_LABEL[s]}</button>)}</div>
                  <span className="spacer" />
                  <button className="btn sm" onClick={() => explainIncident(incident)}>ask the analyst</button>
                  {incident.source !== 'mixed' && <button className="btn sm primary" onClick={() => openRefs(incident.source, incident.refs)}>open {fmtNum(Math.min(incident.refs.length, REFS_OPEN))} row(s)</button>}
                </>}
              >
                <SeverityOverrideNotice findings={incident.findings} busy={resettingSeverity} onReset={() => resetSeverityFor(incident.findings)} chain={incident.kind === 'chain'} />
                <div className="section">
                  <h3>Findings</h3>
                  <div className="small muted">{incident.subtitle}. {incident.kind === 'chain' ? 'These findings have their rows among the steps of the attack chain: the verdict on the Review page decides them together, and a finding can be unlinked there to be decided on its own.' : 'The status of the incident is set on every finding below; open one for its own detail.'}</div>
                  <table className="table compact">
                    <tbody>{incident.findings.map((f) => memberRow(f, incident))}</tbody>
                  </table>
                </div>
                <div className="section">
                  <h3>Investigation</h3>
                  <div className="highlight">
                    {Object.entries(incident.entities).slice(0, 12).map(([k, v]) => (
                      <div className="f" key={k}>
                        <span className="k">{k}</span>
                        <span className="v" onClick={() => openEntity(k, String(v), incident.source === 'mails' ? 'mails' : 'events')} title={entityKind(k) ? `open the ${entityKind(k)} page` : `pivot on ${k}`}>{String(v)}</span>
                      </div>
                    ))}
                    {incident.kind === 'mail' && <div className="f"><span className="k">mail</span><span className="v" onClick={() => { setFocus({ source: 'mails', id: incident.refs[0] }); setView('mails') }}>open #{incident.refs[0]}</span></div>}
                  </div>
                  {incident.attack.length > 0 && <div className="row wrap" style={{ gap: 6 }}>{incident.attack.map((t) => attackHref(t) ? <a key={t} className="badge outline" href={attackHref(t)} target="_blank" rel="noreferrer noopener">{t}</a> : <Badge key={t} sev="outline">{t}</Badge>)}</div>}
                </div>
              </Flyout>
            )}
            {selected && (
              <Flyout
                title={<span className="row" style={{ gap: 8 }}>{parent && <button className="btn icon ghost sm" title="back to the incident" onClick={() => { setSelected(null); setIncident(parent); setParent(null) }}><IconArrowLeft /></button>}<FindingSeverity finding={selected} /><span>{selected.title}</span></span>}
                meta={<>
                  <span className="mono">{selected.ruleId}</span>
                  <span>{selected.source}</span>
                  <span>{fmtTs(selected.ts)}{selected.tsEnd && selected.tsEnd !== selected.ts ? ` → ${fmtTs(selected.tsEnd)}` : ''}</span>
                  <span>{fmtNum(selected.count)} row(s)</span>
                  <StatusBadge s={selected.status} />
                  <OverrideLabel finding={selected} />
                  {selected.confidence && <span title="rule confidence">confidence {selected.confidence}</span>}
                  {inheritedReview(selected) && <span title="the status was set on an earlier evaluation of this finding key and carried over by the last run">status carried over from {fmtTs(selected.createdAt)}</span>}
                </>}
                tabs={<Tabs tabs={[{ id: 'overview', label: 'Overview' }, { id: 'table', label: 'Table' }, { id: 'json', label: 'JSON' }]} active={flyTab} onChange={setFlyTab} />}
                onClose={() => { setSelected(null); setParent(null) }}
                footer={<>
                  <AddToTimeline ts={selected.ts} text={selected.title} link={{ source: 'findings', id: selected.id!, label: selected.ruleId }} severity={effectiveSeverity(selected)} />
                  <span className="small muted">status</span>
                  <div className="segmented">{STATUSES.map((s) => <button key={s} className={classNames(selected.status === s && 'active')} onClick={() => setStatusFor([selected.id!], s)}>{STATUS_LABEL[s]}</button>)}</div>
                  <span className="spacer" />
                  <button className="btn sm" onClick={() => explain(selected)}>ask the analyst</button>
                  <button className="btn sm primary" onClick={() => openRefs(selected.source, selected.refs)}>open {fmtNum(Math.min(selected.refs.length, REFS_OPEN))} row(s)</button>
                </>}
              >
                <SeverityOverrideNotice findings={[selected]} busy={resettingSeverity} onReset={() => resetSeverityFor([selected])} />
                {flyTab === 'overview' && (
                  <>
                    <div className="section">
                      <h3>About</h3>
                      <div>{selected.description || <span className="muted">the rule has no description</span>}</div>
                      <div className="row wrap" style={{ gap: 6 }}>
                        {selected.attack.map((t) => attackHref(t) ? <a key={t} className="badge outline" href={attackHref(t)} target="_blank" rel="noreferrer noopener">{t}</a> : <Badge key={t} sev="outline">{t}</Badge>)}
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
                        <div className="f"><span className="k">referenced rows</span><span className="v" onClick={() => openRefs(selected.source, selected.refs)}>{fmtNum(selected.refs.length)}{selected.refs.length > REFS_OPEN ? ` (first ${REFS_OPEN} open)` : ''}</span></div>
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
                        {(() => { const inc = buildIncidents(all).find((i) => i.findings.some((f) => f.id === selected.id)); return inc && inc.findings.length > 1 ? <><div className="k">incident</div><div className="v click" onClick={() => { setSelected(null); setParent(null); setIncident(inc) }}>{inc.title} · {inc.findings.length} finding(s)</div></> : null })()}
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
                    <td className="sans">{attackHref(h.id) ? <a href={attackHref(h.id)} target="_blank" rel="noreferrer noopener">attack.mitre.org</a> : <span className="muted">not a technique id</span>} · <button className="btn link" onClick={() => { setTab('findings'); setQ(h.id) }}>show findings</button></td>
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
