import { useEffect, useMemo, useRef, useState } from 'react'
import * as echarts from 'echarts/core'
import { BarChart, ScatterChart } from 'echarts/charts'
import { BrushComponent, DataZoomComponent, GridComponent, LegendComponent, MarkLineComponent, ToolboxComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import type { Bucket } from '../data/queries'
import { getSource } from '../data/source'
import { listNotes } from '../data/caseNotes'
import { getDb, type CaseNote, type Finding } from '../db/schema'
import { useStore } from '../state/store'
import { classNames, fmtNum, fmtTs } from '../util/format'
import { Badge, Dot, Sev } from '../components/ui'
import { IconClock } from '../components/Icons'

echarts.use([BarChart, ScatterChart, GridComponent, TooltipComponent, DataZoomComponent, BrushComponent, LegendComponent, MarkLineComponent, ToolboxComponent, CanvasRenderer])

const BUCKET_MS: Record<Bucket, number> = { minute: 60_000, hour: 3_600_000, day: 86_400_000 }

/** Theme tokens read from the document so the chart follows the light / dark switch. */
function tokens() {
  const cs = getComputedStyle(document.documentElement)
  const v = (name: string, fallback: string) => cs.getPropertyValue(name).trim() || fallback
  return {
    accent: v('--accent', '#1b7f66'),
    mails: v('--sev-low', '#2f6fdb'),
    line: v('--line', '#e3e6ea'),
    line2: v('--line-2', '#cfd5dc'),
    fg2: v('--fg-2', '#5b6876'),
    fg3: v('--fg-3', '#8a95a3'),
    surface: v('--surface', '#ffffff'),
    fg1: v('--fg-1', '#111820'),
    sev: {
      critical: v('--sev-critical', '#a8231f'),
      high: v('--sev-high', '#d1403f'),
      medium: v('--sev-medium', '#d9822b'),
      low: v('--sev-low', '#2f6fdb'),
      info: v('--sev-info', '#8a95a3'),
    } as Record<string, string>,
    mono: v('--mono', 'monospace'),
  }
}

interface Marker {
  ts: number
  kind: 'finding' | 'note'
  severity: string
  title: string
  sub?: string
  open: () => void
}

/**
 * Timeline: events and mails per bucket with the findings and the curated case timeline drawn
 * over them. Drag on the chart to select a range: the list below narrows to it and the range can
 * be pushed to the Events or Mails page as a time filter.
 */
export function TimelineView() {
  const kase = useStore((s) => s.currentCase)
  const eventsFilter = useStore((s) => s.eventsFilter)
  const mailsFilter = useStore((s) => s.mailsFilter)
  const setEventsFilter = useStore((s) => s.setEventsFilter)
  const setMailsFilter = useStore((s) => s.setMailsFilter)
  const setView = useStore((s) => s.setView)
  const setFocus = useStore((s) => s.setFocus)
  const rulesVersion = useStore((s) => s.rulesVersion)
  const jobs = useStore((s) => s.jobs)
  const [bucket, setBucket] = useState<Bucket>('hour')
  const [useFilters, setUseFilters] = useState(true)
  const [showNotes, setShowNotes] = useState(true)
  const [sel, setSel] = useState<{ from: number; to: number } | null>(null)
  const [stats, setStats] = useState<{ events: number; mails: number; findings: number; notes: number; span: [number, number] | null }>({ events: 0, mails: 0, findings: 0, notes: 0, span: null })
  const [markers, setMarkers] = useState<Marker[]>([])
  const [theme, setTheme] = useState(0)
  const ref = useRef<HTMLDivElement>(null)
  const chart = useRef<echarts.ECharts | null>(null)

  // re-render on theme switch
  useEffect(() => {
    const obs = new MutationObserver(() => setTheme((t) => t + 1))
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] })
    return () => obs.disconnect()
  }, [])

  useEffect(() => {
    if (!kase?.id || !ref.current) return
    if (!chart.current) chart.current = echarts.init(ref.current, undefined, { renderer: 'canvas' })
    const c = chart.current
    let alive = true
    const ds = getSource(kase)
    const caseId = kase.id
    Promise.all([
      ds.timelineEvents(useFilters ? eventsFilter : {}, bucket).catch(() => []),
      ds.timelineMails(useFilters ? mailsFilter : {}, bucket).catch(() => []),
      getDb()
        .findings.where('caseId')
        .equals(caseId)
        .filter((f) => f.ts != null && f.status !== 'false_positive')
        .toArray(),
      listNotes(caseId, 'timeline').catch(() => [] as CaseNote[]),
    ]).then(([ev, ml, fd, notes]) => {
      if (!alive) return
      const t = tokens()
      const allT = [...ev.map((b) => b.t), ...ml.map((b) => b.t), ...fd.map((f) => f.ts as number), ...notes.map((n) => n.ts)]
      const tMin = allT.length ? Math.min(...allT) : undefined
      const tMax = allT.length ? Math.max(...allT) + BUCKET_MS[bucket] : undefined
      setStats({
        events: ev.reduce((s, b) => s + b.count, 0),
        mails: ml.reduce((s, b) => s + b.count, 0),
        findings: fd.length,
        notes: notes.length,
        span: tMin != null && tMax != null ? [tMin, tMax] : null,
      })
      const fm: Marker[] = fd.map((f: Finding) => ({
        ts: f.ts as number,
        kind: 'finding',
        severity: f.severity,
        title: f.title,
        sub: `${f.ruleId} · ${fmtNum(f.count)} row(s)`,
        open: () => setView('findings'),
      }))
      const nm: Marker[] = notes.map((n) => ({
        ts: n.ts,
        kind: 'note',
        severity: n.severity ?? 'info',
        title: n.text,
        sub: n.link ? `${n.link.source} ${n.link.label ?? n.link.id}` : 'case timeline',
        open: () => {
          if (n.link && (n.link.source === 'events' || n.link.source === 'mails')) {
            setFocus({ source: n.link.source, id: Number(n.link.id) })
            setView(n.link.source)
          } else setView('case')
        },
      }))
      setMarkers([...fm, ...nm].sort((a, b) => a.ts - b.ts))
      const hasEv = ev.length > 0
      const hasMl = ml.length > 0
      const both = hasEv && hasMl
      // the source with data gets the main grid (findings and case-timeline markers sit on it);
      // a mail-only or events-only case gets one grid instead of an empty half
      const primary: 'events' | 'mails' = hasEv || !hasMl ? 'events' : 'mails'
      const pMax = Math.max(1, ...(primary === 'events' ? ev : ml).map((b) => b.count))
      const grids = both
        ? [
            { left: 56, right: 16, top: 30, height: '52%' },
            { left: 56, right: 16, top: '68%', height: '20%' },
          ]
        : [{ left: 56, right: 16, top: 30, height: '76%' }]
      const axis = { axisLine: { lineStyle: { color: t.line2 } }, axisLabel: { color: t.fg3, fontFamily: t.mono, fontSize: 10 }, splitLine: { show: false } }
      const yFor = (i: number, name: string) => ({
        type: 'value',
        gridIndex: i,
        name,
        nameTextStyle: { color: t.fg3, fontSize: 10 },
        minInterval: 1,
        axisLabel: axis.axisLabel,
        splitLine: { lineStyle: { color: t.line } },
      })
      const evGrid = primary === 'events' ? 0 : 1
      const mlGrid = primary === 'mails' ? 0 : 1
      const series: Record<string, unknown>[] = []
      if (hasEv)
        series.push({
          name: 'events',
          type: 'bar',
          xAxisIndex: evGrid,
          yAxisIndex: evGrid,
          data: ev.map((b) => [b.t, b.count]),
          itemStyle: { color: t.accent, opacity: 0.85 },
          large: true,
          barMaxWidth: 12,
        })
      series.push({
        name: 'findings',
        type: 'scatter',
        xAxisIndex: 0,
        yAxisIndex: 0,
        symbolSize: 8,
        z: 5,
        data: fd.map((f) => ({ value: [f.ts, pMax * 1.04, `${f.severity}: ${f.title}`], itemStyle: { color: t.sev[f.severity] ?? t.fg2 } })),
      })
      if (showNotes && notes.length)
        series.push({
          name: 'case timeline',
          type: 'scatter',
          xAxisIndex: 0,
          yAxisIndex: 0,
          symbol: 'diamond',
          symbolSize: 11,
          z: 6,
          data: notes.map((n) => ({ value: [n.ts, pMax * 1.12, n.text.slice(0, 80)], itemStyle: { color: t.sev[n.severity ?? 'info'] ?? t.fg1, borderColor: t.fg1, borderWidth: 1 } })),
        })
      if (hasMl) series.push({ name: 'mails', type: 'bar', xAxisIndex: mlGrid, yAxisIndex: mlGrid, data: ml.map((b) => [b.t, b.count]), itemStyle: { color: t.mails, opacity: 0.85 }, barMaxWidth: 12 })
      const zoomAxes = grids.map((_, i) => i)
      c.setOption(
        {
          backgroundColor: 'transparent',
          animation: false,
          textStyle: { fontFamily: t.mono, color: t.fg2 },
          tooltip: {
            trigger: 'axis',
            axisPointer: { type: 'shadow' },
            backgroundColor: t.surface,
            borderColor: t.line2,
            textStyle: { color: t.fg1, fontSize: 11 },
            formatter: (params: { seriesName: string; value: [number, number, ...unknown[]]; marker: string }[]) => {
              const ts = params[0]?.value?.[0]
              return (
                `<b>${fmtTs(ts as number)}</b><br/>` +
                params.map((p) => `${p.marker} ${p.seriesName}: ${p.seriesName === 'findings' || p.seriesName === 'case timeline' ? String(p.value[2] ?? '') : fmtNum(p.value[1])}`).join('<br/>')
              )
            },
          },
          legend: { top: 2, textStyle: { color: t.fg2, fontSize: 11 }, itemWidth: 12, itemHeight: 8 },
          grid: grids,
          xAxis: grids.map((_, i) => ({ type: 'time', gridIndex: i, min: tMin, max: tMax, ...axis })),
          yAxis: both ? [yFor(0, primary), yFor(1, primary === 'events' ? 'mails' : 'events')] : [yFor(0, primary)],
          dataZoom: [
            {
              type: 'slider',
              xAxisIndex: zoomAxes,
              bottom: 6,
              height: 16,
              borderColor: t.line2,
              backgroundColor: t.surface,
              fillerColor: `${t.accent}22`,
              handleStyle: { color: t.accent },
              textStyle: { color: t.fg3, fontSize: 10 },
            },
            { type: 'inside', xAxisIndex: zoomAxes },
          ],
          toolbox: { show: false },
          brush: { xAxisIndex: zoomAxes, brushType: 'lineX', brushStyle: { color: `${t.accent}1f`, borderColor: t.accent }, throttleType: 'debounce', throttleDelay: 200 },
          series,
        },
        true,
      )
      c.dispatchAction({ type: 'takeGlobalCursor', key: 'brush', brushOption: { brushType: 'lineX' } })
    })
    const onBrush = (p: { areas?: { coordRange: [number, number] }[] }) => {
      const area = p.areas?.[0]
      setSel(area ? { from: area.coordRange[0], to: area.coordRange[1] } : null)
    }
    c.on('brushEnd', onBrush as never)
    const onResize = () => c.resize()
    window.addEventListener('resize', onResize)
    return () => {
      alive = false
      c.off('brushEnd', onBrush as never)
      window.removeEventListener('resize', onResize)
    }
  }, [kase, bucket, useFilters, showNotes, eventsFilter, mailsFilter, rulesVersion, jobs.length, theme, setView, setFocus])
  useEffect(
    () => () => {
      chart.current?.dispose()
      chart.current = null
    },
    [],
  )

  const inRange = useMemo(() => (sel ? markers.filter((m) => m.ts >= sel.from && m.ts <= sel.to) : markers), [markers, sel])
  if (!kase) return null
  const apply = (target: 'events' | 'mails') => {
    if (!sel) return
    const tr = { from: new Date(sel.from).toISOString(), to: new Date(sel.to).toISOString() }
    if (target === 'events') setEventsFilter((f) => ({ ...f, timeRange: tr }))
    else setMailsFilter((f) => ({ ...f, timeRange: tr }))
    setView(target)
  }
  const clear = () => {
    setSel(null)
    chart.current?.dispatchAction({ type: 'brush', areas: [] })
  }
  return (
    <div className="view">
      <div className="view-header">
        <div className="desc">
          <h1>Timeline</h1>
          <span className="sub">
            {fmtNum(stats.events)} events · {fmtNum(stats.mails)} mails · {fmtNum(stats.findings)} findings · {fmtNum(stats.notes)} case timeline entr{stats.notes === 1 ? 'y' : 'ies'}
            {stats.span ? ` · ${fmtTs(stats.span[0])} → ${fmtTs(stats.span[1])}` : ''} · drag on the chart to select a range
          </span>
        </div>
        <span className="spacer" />
        <div className="segmented" title="bucket">
          {(['minute', 'hour', 'day'] as Bucket[]).map((b) => (
            <button key={b} className={classNames(bucket === b && 'active')} onClick={() => setBucket(b)}>
              {b}
            </button>
          ))}
        </div>
        <button className={classNames('pill', useFilters && 'active')} onClick={() => setUseFilters(!useFilters)} title="apply the Events and Mails page filters to the histograms">
          page filters
        </button>
        <button className={classNames('pill', showNotes && 'active')} onClick={() => setShowNotes(!showNotes)} title="draw the curated case timeline entries">
          <IconClock /> case timeline
        </button>
      </div>
      {sel && (
        <div className="bulkbar">
          <b>
            {fmtTs(sel.from)} → {fmtTs(sel.to)}
          </b>
          <span className="muted">{fmtNum(inRange.length)} marker(s) in range</span>
          <span className="spacer" />
          <button className="btn xs" onClick={() => apply('events')}>
            events in range
          </button>
          <button className="btn xs" onClick={() => apply('mails')}>
            mails in range
          </button>
          <button className="btn xs ghost" onClick={clear}>
            clear
          </button>
        </div>
      )}
      <div className="pane" style={{ flex: 1, height: 'auto', borderTop: 0, gridTemplateColumns: '1fr 360px' }}>
        <div className="pane-main" style={{ padding: '4px 8px 0' }}>
          <div ref={ref} className="timeline-chart" style={{ flex: 1, minHeight: 240 }} title="drag to select a range · scroll to zoom · dots are findings, diamonds are case timeline entries" />
        </div>
        <div className="pane-side" style={{ padding: 0 }}>
          <div className="panel-h">
            {sel ? 'In the selected range' : 'Findings and case timeline'} <span className="muted">({fmtNum(inRange.length)})</span>
          </div>
          <div className="story">
            {!inRange.length && (
              <div className="muted small" style={{ padding: 14 }}>
                {markers.length ? 'nothing in this range' : 'run the rules or add entries to the case timeline'}
              </div>
            )}
            {inRange.slice(0, 400).map((m, i) => (
              <div key={i} className="step" style={{ gridTemplateColumns: '150px 14px 1fr' }} onClick={m.open}>
                <span className="t">{fmtTs(m.ts)}</span>
                <Dot sev={m.severity} />
                <span>
                  <div className="title ellipsis" title={m.title}>
                    {m.title}
                    {m.kind === 'note' && (
                      <Badge className="small" title="curated case timeline entry">
                        timeline
                      </Badge>
                    )}
                  </div>
                  {m.sub && (
                    <div className="sub">
                      {m.kind === 'finding' ? <Sev sev={m.severity} /> : null} {m.sub}
                    </div>
                  )}
                </span>
              </div>
            ))}
            {inRange.length > 400 && (
              <div className="muted small" style={{ padding: 8 }}>
                {fmtNum(inRange.length - 400)} more - narrow the range
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
