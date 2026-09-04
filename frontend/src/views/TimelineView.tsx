import { useEffect, useRef, useState } from 'react'
import * as echarts from 'echarts/core'
import { BarChart, ScatterChart } from 'echarts/charts'
import { BrushComponent, DataZoomComponent, GridComponent, LegendComponent, MarkLineComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import type { Bucket } from '../data/queries'
import { getSource } from '../data/source'
import { getDb } from '../db/schema'
import { useStore } from '../state/store'
import { fmtTs } from '../util/format'

echarts.use([BarChart, ScatterChart, GridComponent, TooltipComponent, DataZoomComponent, BrushComponent, LegendComponent, MarkLineComponent, CanvasRenderer])

export function TimelineView() {
  const kase = useStore((s) => s.currentCase)
  const eventsFilter = useStore((s) => s.eventsFilter)
  const mailsFilter = useStore((s) => s.mailsFilter)
  const setEventsFilter = useStore((s) => s.setEventsFilter)
  const setMailsFilter = useStore((s) => s.setMailsFilter)
  const setView = useStore((s) => s.setView)
  const rulesVersion = useStore((s) => s.rulesVersion)
  const jobs = useStore((s) => s.jobs)
  const [bucket, setBucket] = useState<Bucket>('hour')
  const [useFilters, setUseFilters] = useState(true)
  const [sel, setSel] = useState<{ from: number; to: number } | null>(null)
  const [stats, setStats] = useState<{ events: number; mails: number; findings: number }>({ events: 0, mails: 0, findings: 0 })
  const ref = useRef<HTMLDivElement>(null)
  const chart = useRef<echarts.ECharts | null>(null)
  useEffect(() => {
    if (!kase?.id || !ref.current) return
    if (!chart.current) chart.current = echarts.init(ref.current, undefined, { renderer: 'canvas' })
    const c = chart.current
    let alive = true
    const ds = getSource(kase)
    Promise.all([
      ds.timelineEvents(useFilters ? eventsFilter : {}, bucket).catch(() => []),
      ds.timelineMails(useFilters ? mailsFilter : {}, bucket).catch(() => []),
      getDb().findings.where('caseId').equals(kase.id).filter((f) => f.ts != null && f.status !== 'false_positive').toArray(),
    ]).then(([ev, ml, fd]) => {
      if (!alive) return
      setStats({ events: ev.reduce((s, b) => s + b.count, 0), mails: ml.reduce((s, b) => s + b.count, 0), findings: fd.length })
      const sevColor: Record<string, string> = { critical: '#ff3366', high: '#ff7b4f', medium: '#f5b942', low: '#4fa3ff', info: '#6b7a8c' }
      const maxEv = Math.max(1, ...ev.map((b) => b.count))
      const allT = [...ev.map((b) => b.t), ...ml.map((b) => b.t), ...fd.map((f) => f.ts as number)]
      const tMin = allT.length ? Math.min(...allT) : undefined
      const tMax = allT.length ? Math.max(...allT) + (bucket === 'day' ? 86_400_000 : bucket === 'hour' ? 3_600_000 : 60_000) : undefined
      c.setOption(
        {
          backgroundColor: 'transparent',
          animation: false,
          textStyle: { fontFamily: 'JetBrains Mono Variable, monospace', color: '#97a3b3' },
          tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' }, backgroundColor: '#10161f', borderColor: '#2a3648', textStyle: { color: '#e8edf3', fontSize: 11 }, formatter: (params: { seriesName: string; value: [number, number, ...unknown[]]; marker: string }[]) => { const t = params[0]?.value?.[0]; return `<b>${fmtTs(t as number)}</b><br/>` + params.map((p) => `${p.marker} ${p.seriesName}: ${p.seriesName === 'findings' ? String(p.value[2] ?? '') : p.value[1]}`).join('<br/>') } },
          legend: { top: 4, textStyle: { color: '#97a3b3' } },
          grid: [{ left: 60, right: 20, top: 40, height: '55%' }, { left: 60, right: 20, top: '72%', height: '18%' }],
          xAxis: [{ type: 'time', gridIndex: 0, min: tMin, max: tMax, axisLine: { lineStyle: { color: '#2a3648' } }, splitLine: { show: false } }, { type: 'time', gridIndex: 1, min: tMin, max: tMax, axisLine: { lineStyle: { color: '#2a3648' } } }],
          yAxis: [{ type: 'value', gridIndex: 0, name: 'events', minInterval: 1, splitLine: { lineStyle: { color: '#1d2836' } } }, { type: 'value', gridIndex: 1, name: 'mails', minInterval: 1, splitLine: { lineStyle: { color: '#1d2836' } } }],
          dataZoom: [{ type: 'slider', xAxisIndex: [0, 1], bottom: 8, height: 18, borderColor: '#2a3648', backgroundColor: '#0b0f15', fillerColor: 'rgba(57,211,255,0.15)', textStyle: { color: '#97a3b3' } }, { type: 'inside', xAxisIndex: [0, 1] }],
          brush: { xAxisIndex: [0, 1], brushType: 'lineX', brushStyle: { color: 'rgba(57,211,255,0.12)', borderColor: '#39d3ff' }, throttleType: 'debounce', throttleDelay: 200 },
          series: [
            { name: 'events', type: 'bar', xAxisIndex: 0, yAxisIndex: 0, data: ev.map((b) => [b.t, b.count]), itemStyle: { color: '#39d3ff' }, large: true, barMaxWidth: 12 },
            { name: 'findings', type: 'scatter', xAxisIndex: 0, yAxisIndex: 0, symbolSize: 9, data: fd.map((f) => ({ value: [f.ts, maxEv * 1.05, `${f.severity}: ${f.title}`], itemStyle: { color: sevColor[f.severity] ?? '#fff' } })), tooltip: { formatter: (p: { value: [number, number, string] }) => `${fmtTs(p.value[0])}<br/>${p.value[2]}` } },
            { name: 'mails', type: 'bar', xAxisIndex: 1, yAxisIndex: 1, data: ml.map((b) => [b.t, b.count]), itemStyle: { color: '#a78bfa' }, barMaxWidth: 12 },
          ],
        },
        true,
      )
      c.dispatchAction({ type: 'takeGlobalCursor', key: 'brush', brushOption: { brushType: 'lineX' } })
    })
    const onBrush = (p: { areas?: { coordRange: [number, number] }[] }) => {
      const area = p.areas?.[0]
      if (area) setSel({ from: area.coordRange[0], to: area.coordRange[1] })
    }
    c.on('brushEnd', onBrush as never)
    const onResize = () => c.resize()
    window.addEventListener('resize', onResize)
    return () => {
      alive = false
      c.off('brushEnd', onBrush as never)
      window.removeEventListener('resize', onResize)
    }
  }, [kase, bucket, useFilters, eventsFilter, mailsFilter, rulesVersion, jobs.length])
  useEffect(() => () => { chart.current?.dispose(); chart.current = null }, [])
  if (!kase) return null
  const apply = (target: 'events' | 'mails') => {
    if (!sel) return
    const tr = { from: new Date(sel.from).toISOString(), to: new Date(sel.to).toISOString() }
    if (target === 'events') setEventsFilter((f) => ({ ...f, timeRange: tr }))
    else setMailsFilter((f) => ({ ...f, timeRange: tr }))
    setView(target)
  }
  const fd = stats.findings
  return (
    <div className="view">
      <div className="view-header">
        <h1>Timeline</h1>
        <span className="sub">{stats.events.toLocaleString('en-US')} events · {stats.mails.toLocaleString('en-US')} mails · {fd} finding markers</span>
        <span className="spacer" />
        <label className="checkbox small"><input type="checkbox" checked={useFilters} onChange={(e) => setUseFilters(e.target.checked)} /> apply current view filters</label>
        <select className="select" value={bucket} onChange={(e) => setBucket(e.target.value as Bucket)}><option value="minute">per minute</option><option value="hour">per hour</option><option value="day">per day</option></select>
        {sel && (<><span className="mono small dim">{fmtTs(sel.from)} → {fmtTs(sel.to)}</span><button className="btn sm primary" onClick={() => apply('events')}>events in range</button><button className="btn sm primary" onClick={() => apply('mails')}>mails in range</button></>)}
      </div>
      <div className="view-body" style={{ padding: 8 }}>
        <div ref={ref} className="timeline-chart" style={{ height: '100%' }} />
        <div className="hint" style={{ padding: '0 8px' }}>drag on the chart to select a time range · scroll to zoom · finding markers use the rule severity colour</div>
      </div>
    </div>
  )
}
