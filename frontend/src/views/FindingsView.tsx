import { useEffect, useMemo, useState } from 'react'
import { VirtualTable } from '../components/VirtualTable'
import { usePivot } from '../components/Detail'
import { entityKind } from '../components/EntityPanel'
import { Kpi, Tabs } from '../components/ui'
import { IconCircle, IconFindings, IconInfo, IconPlay, IconTarget } from '../components/Icons'
import { RescoreButton } from '../components/RescoreButton'
import { runEnabledRules } from '../data/findingsState'
import { resetFindingSeverityOverrides } from '../data/findingReviews'
import { getDb, type Finding, type Severity } from '../db/schema'
import { buildIncidents, type Incident } from '../rules/incidents'
import { toast, useStore } from '../state/store'
import { useRouteItem } from '../state/route'
import { fmtNum, fmtTs } from '../util/format'
import { exportCsv, exportJson } from '../util/export'
import { cutRules, explainFindingPrompt, explainIncidentPrompt, REFS_OPEN, staleParts as staleReasons, STATUSES, STATUS_LABEL, type Group, type Status } from './findings/model'
import { useFindingsData } from './findings/useFindingsData'
import { useFindingsQueue, type QueueFilters } from './findings/useFindingsQueue'
import { findingColumns, incidentColumns } from './findings/columns'
import { FindingsBanners } from './findings/FindingsBanners'
import { FindingsQueryBar } from './findings/FindingsQueryBar'
import { GroupedFindings } from './findings/GroupedFindings'
import { IncidentFlyout } from './findings/IncidentFlyout'
import { FindingFlyout, type FlyTab } from './findings/FindingFlyout'
import { AttackTab } from './findings/AttackTab'

/**
 * Findings triage. The default view is incidents: every finding on one mail, or about one
 * user / host / IP within a few hours, is one line. Flat and grouped views keep the per-rule
 * detail. The banner above the queue says when the findings are behind the evidence.
 */
export function FindingsView() {
  const kase = useStore((s) => s.currentCase)
  const running = useStore((s) => s.rulesRun)
  const setView = useStore((s) => s.setView)
  const setEventsFilter = useStore((s) => s.setEventsFilter)
  const setMailsFilter = useStore((s) => s.setMailsFilter)
  const setAiPrompt = useStore((s) => s.setAiPrompt)
  const pivot = usePivot()
  const setEntity = useStore((s) => s.setEntity)
  const openEntity = (k: string, v: string, source: 'events' | 'mails') => {
    const kind = entityKind(k)
    if (kind && v && !v.includes(',')) setEntity({ kind, value: v })
    else pivot(v, k, source)
  }
  const data = useFindingsData(kase)
  const { all, rules, lastRun, previous, stale, otherCases, sources, chooseSource, reload } = data
  const [filters, setFilters] = useState<QueueFilters>({ sev: '', status: '', source: '', q: '', showFp: false, group: 'incident', sort: 'priority' })
  const setFilter = (patch: Partial<QueueFilters>) => setFilters((f) => ({ ...f, ...patch }))
  const { sev, status, showFp, group } = filters
  const [pickSources, setPickSources] = useState(false)
  const [openGroups, setOpenGroups] = useState<Set<string>>(new Set())
  const [tab, setTab] = useState<'findings' | 'attack'>('findings')
  const [selected, setSelected] = useState<Finding | null>(null)
  useRouteItem('finding', selected?.id)
  // a finding cited in an AI answer opens here
  const focusFinding = useStore((s) => s.focusFinding)
  useEffect(() => {
    if (focusFinding == null) return
    getDb()
      .findings.get(focusFinding)
      .then((f) => f && setSelected(f))
    useStore.getState().setFocusFinding(null)
  }, [focusFinding])
  const [incident, setIncident] = useState<Incident | null>(null)
  const [parent, setParent] = useState<Incident | null>(null)
  const [flyTab, setFlyTab] = useState<FlyTab>('overview')
  const [picked, setPicked] = useState<Set<string | number>>(new Set())
  const [resettingSeverity, setResettingSeverity] = useState(false)

  useEffect(() => {
    setSelected(null)
    setIncident(null)
    setParent(null)
    setPicked(new Set())
    setPickSources(false)
  }, [kase?.id])

  const queue = useFindingsQueue(data, filters)
  const { active, fpCount, scores, sortFindings, rows, incidentOpts, incidents, shownRows, allIncidents, membership, readings, counts, groups, attack } = queue
  // Open details must follow a reset or rule refresh, including replacement row IDs.
  useEffect(() => {
    setSelected((prev) => (prev ? (all.find((f) => f.key === prev.key) ?? null) : null))
    const current = buildIncidents(all, incidentOpts)
    setIncident((prev) => (prev ? (current.find((i) => i.id === prev.id) ?? null) : null))
    setParent((prev) => (prev ? (current.find((i) => i.id === prev.id) ?? null) : null))
  }, [all, incidentOpts])

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

  const columns = useMemo(() => findingColumns({ scores, membership, readings }), [scores, membership, readings])
  const incColumns = useMemo(() => incidentColumns({ scores }), [scores])

  if (!kase) return null

  const run = async () => {
    await runEnabledRules(kase, 'manual')
    reload()
  }
  const setStatusFor = async (ids: number[], s: Status) => {
    const db = getDb()
    await Promise.all(ids.map((id) => db.findings.update(id, { status: s, decidedBy: 'analyst', decidedAt: Date.now() })))
    if (selected && ids.includes(selected.id!)) setSelected({ ...selected, status: s })
    if (incident) setIncident({ ...incident, status: s, findings: incident.findings.map((f) => (ids.includes(f.id!) ? { ...f, status: s } : f)) })
    setPicked(new Set())
    reload()
  }
  const resetSeverityFor = async (findings: Finding[]) => {
    if (resettingSeverity) return
    setResettingSeverity(true)
    try {
      await resetFindingSeverityOverrides(
        kase.id!,
        findings.filter((f) => f.severityOverride).map((f) => f.id!),
      )
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
    setAiPrompt(explainFindingPrompt(f))
    setView('ai')
  }
  const explainIncident = (i: Incident) => {
    setAiPrompt(explainIncidentPrompt(i))
    setView('ai')
  }
  const toggleGroup = (key: string) =>
    setOpenGroups((s) => {
      const n = new Set(s)
      if (n.has(key)) n.delete(key)
      else n.add(key)
      return n
    })
  const togglePicked = (k: string | number) =>
    setPicked((s) => {
      const n = new Set(s)
      if (n.has(k)) n.delete(k)
      else n.add(k)
      return n
    })
  const delta = (s: Severity) => (group !== 'incident' && previous ? (counts[s] ?? 0) - (previous[s] ?? 0) : null)
  const enabledCount = rules.filter((r) => r.enabled).length
  const pickedFindingIds = group === 'incident' ? incidents.filter((i) => picked.has(i.id)).flatMap((i) => i.findings.map((f) => f.id!)) : Array.from(picked).map(Number)
  const openFinding = (f: Finding, from: Incident | null) => {
    setParent(from)
    setIncident(null)
    setSelected(f)
    setFlyTab('overview')
  }
  const openIncident = (i: Incident) => {
    setSelected(null)
    setParent(null)
    setIncident(i)
  }
  const cuts = cutRules(lastRun)
  const staleParts = staleReasons(stale, all.length)
  const noneYet = 'no findings yet - run the rules'

  return (
    <div className="view">
      <div className="view-header">
        <div className="desc">
          <h1>Findings</h1>
          <span className="sub">
            {fmtNum(allIncidents.length)} incident(s) · {fmtNum(active.length)} finding(s) from {enabledCount} enabled rule(s)
            {fpCount ? ` · ${fmtNum(fpCount)} false positive${fpCount === 1 ? '' : 's'}${showFp || status === 'false_positive' ? '' : ' hidden'}` : ''}
            {lastRun ? ` · last run ${fmtTs(lastRun.ts)}` : ' · rules not run yet'}
          </span>
        </div>
        <span className="spacer" />
        <button className="btn ghost sm" onClick={() => setView('rules')}>
          manage rules
        </button>
        <button
          className="btn ghost sm"
          onClick={() =>
            exportCsv(
              'findings.csv',
              shownRows.map((f) => ({
                priority: scores.get(f.key)?.score,
                severity: f.severity,
                severityOverride: f.severityOverride,
                title: f.title,
                ruleId: f.ruleId,
                entities: JSON.stringify(f.entities),
                count: f.count,
                first: f.ts ? new Date(f.ts).toISOString() : '',
                last: f.tsEnd ? new Date(f.tsEnd).toISOString() : '',
                source: f.source,
                status: f.status,
                attack: f.attack.join(' '),
                refs: f.refs.slice(0, 50).join(' '),
                notes: f.notes,
              })),
            )
          }
        >
          csv
        </button>
        <button className="btn ghost sm" onClick={() => exportJson('findings.json', shownRows)}>
          json
        </button>
        <RescoreButton key={kase.id} />
        <button className="btn primary" onClick={run} disabled={!!running}>
          <IconPlay /> run rules
        </button>
      </div>
      <FindingsBanners stale={stale} staleParts={staleParts} cuts={cuts} onRun={run} />
      <div className="grid-5" style={{ padding: '12px 16px 0' }}>
        <Kpi
          tone="critical"
          icon={<IconFindings />}
          value={fmtNum(counts.critical ?? 0)}
          label="critical"
          delta={delta('critical')}
          onClick={() => setFilter({ sev: sev === 'critical' ? '' : 'critical' })}
        />
        <Kpi tone="high" icon={<IconFindings />} value={fmtNum(counts.high ?? 0)} label="high" delta={delta('high')} onClick={() => setFilter({ sev: sev === 'high' ? '' : 'high' })} />
        <Kpi tone="medium" icon={<IconTarget />} value={fmtNum(counts.medium ?? 0)} label="medium" delta={delta('medium')} onClick={() => setFilter({ sev: sev === 'medium' ? '' : 'medium' })} />
        <Kpi tone="low" icon={<IconCircle />} value={fmtNum(counts.low ?? 0)} label="low" delta={delta('low')} onClick={() => setFilter({ sev: sev === 'low' ? '' : 'low' })} />
        <Kpi tone="info" icon={<IconInfo />} value={fmtNum(counts.info ?? 0)} label="informational" delta={delta('info')} onClick={() => setFilter({ sev: sev === 'info' ? '' : 'info' })} />
      </div>
      <div style={{ padding: '10px 16px 0' }}>
        <Tabs
          tabs={[
            {
              id: 'findings',
              label: (
                <span>
                  {group === 'incident' ? 'Incidents' : 'Findings'} <span className="n">{fmtNum(group === 'incident' ? incidents.length : rows.length)}</span>
                </span>
              ),
            },
            {
              id: 'attack',
              label: (
                <span>
                  ATT&amp;CK <span className="n">{attack.hits.length}</span>
                </span>
              ),
            },
          ]}
          active={tab}
          onChange={setTab}
        />
      </div>
      {tab === 'findings' && (
        <>
          <FindingsQueryBar
            filters={filters}
            set={setFilter}
            counts={counts}
            fpCount={fpCount}
            summary={group === 'incident' ? `${fmtNum(incidents.length)} incident(s) · ${fmtNum(shownRows.length)} finding(s)` : `${fmtNum(rows.length)} shown`}
            sources={sources}
            otherCases={otherCases}
            chooseSource={chooseSource}
            pickSources={pickSources}
            setPickSources={setPickSources}
            onGroup={(g: Group) => {
              setFilter({ group: g })
              setPicked(new Set())
              setIncident(null)
            }}
          />
          {picked.size > 0 && (
            <BulkStatusBar
              picked={picked.size}
              findings={group === 'incident' ? pickedFindingIds.length : null}
              onStatus={(s) => setStatusFor(pickedFindingIds, s)}
              onClear={() => setPicked(new Set())}
            />
          )}
          <div className="relative" style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
            {group === 'incident' && (
              <VirtualTable
                rows={incidents}
                columns={incColumns}
                rowKey={(r) => r.id}
                onRowClick={openIncident}
                selectedKey={incident?.id ?? null}
                selectedKeys={picked}
                onToggleSelect={togglePicked}
                onToggleAll={(on) => setPicked(on ? new Set(incidents.map((r) => r.id)) : new Set())}
                empty={all.length ? 'no incident matches the filters' : noneYet}
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
                onToggleSelect={togglePicked}
                onToggleAll={(on) => setPicked(on ? new Set(rows.map((r) => r.id!)) : new Set())}
                empty={all.length ? 'no finding matches the filters' : noneYet}
              />
            )}
            {group && group !== 'incident' && (
              <GroupedFindings
                groups={groups}
                group={group}
                open={openGroups}
                onToggle={toggleGroup}
                onPickAll={(items) => setPicked(new Set(items.map((f) => f.id!)))}
                onOpen={(f) => openFinding(f, null)}
                scores={scores}
                readings={readings}
                empty={all.length ? 'no finding matches the filters' : noneYet}
              />
            )}
            {incident && !selected && (
              <IncidentFlyout
                incident={incident}
                ordered={sortFindings(incident.findings)}
                scores={scores}
                readings={readings}
                resetting={resettingSeverity}
                onClose={() => setIncident(null)}
                onOpenFinding={(f) => openFinding(f, incident)}
                onStatus={setStatusFor}
                onResetSeverity={resetSeverityFor}
                onExplain={explainIncident}
                onOpenRefs={openRefs}
                onEntity={openEntity}
              />
            )}
            {selected && (
              <FindingFlyout
                selected={selected}
                parent={parent}
                all={all}
                priority={scores.get(selected.key)}
                readings={readings}
                lastRun={lastRun}
                cuts={cuts}
                tab={flyTab}
                setTab={setFlyTab}
                resetting={resettingSeverity}
                onBack={() => {
                  setSelected(null)
                  setIncident(parent)
                  setParent(null)
                }}
                onClose={() => {
                  setSelected(null)
                  setParent(null)
                }}
                onStatus={setStatusFor}
                onResetSeverity={resetSeverityFor}
                onExplain={explain}
                onOpenRefs={openRefs}
                onEntity={openEntity}
                onOpenIncident={openIncident}
                reload={reload}
              />
            )}
          </div>
        </>
      )}
      {tab === 'attack' && (
        <AttackTab
          attack={attack}
          findings={all.length}
          onShow={(technique) => {
            setTab('findings')
            setFilter({ q: technique })
          }}
        />
      )}
    </div>
  )
}

/** The status every picked line takes at once; with incidents, every finding of them. */
function BulkStatusBar({ picked, findings, onStatus, onClear }: { picked: number; findings: number | null; onStatus: (s: Status) => void; onClear: () => void }) {
  return (
    <div className="bulkbar">
      <b>
        {picked} selected{findings != null ? ` · ${findings} finding(s)` : ''}
      </b>
      <span className="muted">set status:</span>
      {STATUSES.map((s) => (
        <button key={s} className="btn xs" onClick={() => onStatus(s)}>
          {STATUS_LABEL[s]}
        </button>
      ))}
      <span className="spacer" />
      <button className="btn xs ghost" onClick={onClear}>
        clear
      </button>
    </div>
  )
}
