import { useEffect, useMemo, useRef } from 'react'
import * as echarts from 'echarts/core'
import { GraphChart } from 'echarts/charts'
import { GraphicComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import type { Chain } from '../data/chains'
import { buildCampaignGraph, buildChainGraph, LANE_LABEL, LANES, type GNode, type Graph } from '../data/chainGraph'
import type { EntityRef } from '../state/store'
import { fmtTs } from '../util/format'

echarts.use([GraphChart, TooltipComponent, LegendComponent, GraphicComponent, CanvasRenderer])

function tokens() {
  const cs = getComputedStyle(document.documentElement)
  const v = (name: string, fallback: string) => cs.getPropertyValue(name).trim() || fallback
  return {
    accent: v('--accent', '#1b7f66'), line: v('--line', '#e3e6ea'), line2: v('--line-2', '#cfd5dc'), fg1: v('--fg-1', '#111820'), fg2: v('--fg-2', '#5b6876'), fg3: v('--fg-3', '#8a95a3'),
    surface: v('--surface', '#fff'), surface2: v('--surface-2', '#f8f9fa'), mono: v('--mono', 'monospace'), sans: v('--sans', 'sans-serif'),
    sev: { critical: v('--sev-critical', '#a8231f'), high: v('--sev-high', '#d1403f'), medium: v('--sev-medium', '#d9822b'), low: v('--sev-low', '#2f6fdb'), info: v('--sev-info', '#8a95a3') } as Record<string, string>,
  }
}

const trunc = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + '…' : s)

interface Props {
  mode: 'chain' | 'campaign'
  chain: Chain | null
  chains: Chain[]
  selectedStep: number | null
  onStep: (i: number) => void
  onEntity: (e: EntityRef) => void
  onChain: (id: string) => void
}

/** ECharts renderer for the chain and campaign graphs (see data/chainGraph.ts for the models). */
export function ChainGraph({ mode, chain, chains, selectedStep, onStep, onEntity, onChain }: Props) {
  const ref = useRef<HTMLDivElement>(null)
  const chartRef = useRef<echarts.ECharts | null>(null)
  const graph: (Graph & { insights?: { text: string }[] }) | null = useMemo(() => (mode === 'chain' ? (chain ? buildChainGraph(chain) : null) : buildCampaignGraph(chains)), [mode, chain, chains])

  useEffect(() => {
    if (!ref.current || !graph) return
    if (!chartRef.current) chartRef.current = echarts.init(ref.current, undefined, { renderer: 'canvas' })
    const c = chartRef.current
    const t = tokens()
    const W = Math.max(480, c.getWidth())
    const H = Math.max(320, c.getHeight())
    const colorOf = (n: GNode): string => {
      if (n.kind === 'routine') return t.fg3
      if (n.severity) return t.sev[n.severity] ?? t.fg2
      if (n.kind === 'user' || n.kind === 'chain') return t.accent
      if (n.lane === 'attacker') return t.sev.high
      if (n.lane === 'infra') return t.sev.low
      return n.linked ? t.accent : t.fg3
    }
    const sizeOf = (n: GNode): number | [number, number] => {
      if (n.kind === 'seed') return 26
      if (n.kind === 'chain') return 18 + Math.min(20, (n.score ?? 0) / 5)
      if (n.kind === 'step') return 14 + Math.min(8, n.weight) * 1.5
      if (n.kind === 'routine') return 14
      if (n.kind === 'user') return 20
      return 10 + Math.min(4, n.degree ?? 0) * 3
    }
    const symbolOf = (n: GNode) => (n.kind === 'seed' ? 'diamond' : n.kind === 'step' || n.kind === 'chain' ? 'roundRect' : n.kind === 'user' ? 'circle' : n.kind === 'attachment' ? 'rect' : n.kind === 'routine' ? 'circle' : 'circle')
    const lanes = LANES.filter((l) => graph.nodes.some((n) => n.lane === l))
    const laneH = mode === 'chain' ? (H - 70) / Math.max(1, lanes.length) : 0
    const colW = mode === 'chain' ? Math.min(220, Math.max(96, (W - 200) / Math.max(1, graph.columns))) : 0
    const maxChars = Math.max(14, Math.floor(colW / 5.5))
    const data = graph.nodes.map((n) => {
      const li = lanes.indexOf(n.lane)
      const base = {
        id: n.id,
        name: n.label,
        value: n.sub ?? '',
        symbol: symbolOf(n),
        symbolSize: sizeOf(n),
        itemStyle: { color: colorOf(n), borderColor: n.id === (selectedStep != null ? `step:${selectedStep}` : '') ? t.fg1 : n.linked ? t.fg1 : 'transparent', borderWidth: n.id === (selectedStep != null ? `step:${selectedStep}` : '') ? 3 : n.linked && n.kind !== 'seed' ? 1 : 0, opacity: n.kind === 'routine' ? 0.7 : 1 },
        label: { show: true, position: n.lane === 'attacker' || n.lane === 'mail' ? 'top' : n.lane === 'infra' ? 'bottom' : mode === 'chain' && Math.round(n.x) % 2 === 1 ? 'top' : 'bottom', formatter: () => `{a|${trunc(n.label, mode === 'chain' ? maxChars : 26)}}${n.sub ? `\n{s|${trunc(n.sub, maxChars + 4)}}` : ''}`, rich: { a: { color: t.fg1, fontSize: 11, fontFamily: t.sans, lineHeight: 14 }, s: { color: t.fg3, fontSize: 10, fontFamily: t.mono, lineHeight: 13 } } },
        node: n,
      }
      return mode === 'chain' ? { ...base, x: 120 + n.x * colW, y: 40 + li * laneH + laneH / 2 + (n.lane === 'infra' ? 4 : 0), fixed: true } : base
    })
    const links = graph.edges.map((e) => ({
      source: e.source,
      target: e.target,
      value: e.label ?? '',
      lineStyle: e.kind === 'artifact' ? { color: t.accent, width: 2, curveness: 0.25, type: 'solid' } : e.kind === 'sequence' ? { color: t.fg2, width: 1.5, curveness: 0.1 } : e.kind === 'recipient' ? { color: t.fg2, width: 1.5, curveness: 0 } : { color: t.line2, width: 1, type: 'dashed', curveness: 0.15 },
      symbol: e.kind === 'sequence' || e.kind === 'recipient' || e.kind === 'artifact' ? ['none', 'arrow'] : ['none', 'none'],
      symbolSize: 7,
      label: { show: !!e.label, formatter: e.label ?? '', fontSize: 9, fontFamily: t.mono, color: e.kind === 'artifact' ? t.accent : t.fg3, backgroundColor: t.surface, padding: [1, 3] },
    }))
    const graphic = mode === 'chain'
      ? lanes.flatMap((l, i) => [
          { type: 'text', left: 10, top: 40 + i * laneH + 6, style: { text: LANE_LABEL[l], fill: t.fg3, font: `10px ${t.mono}` }, silent: true },
          { type: 'line', shape: { x1: 0, y1: 40 + i * laneH, x2: W, y2: 40 + i * laneH }, style: { stroke: t.line, lineWidth: 1 }, silent: true },
        ])
      : []
    c.setOption(
      {
        backgroundColor: 'transparent',
        animation: mode !== 'chain',
        tooltip: {
          trigger: 'item', backgroundColor: t.surface, borderColor: t.line2, textStyle: { color: t.fg1, fontSize: 11 }, confine: true,
          formatter: (p: { dataType: string; data: { node?: GNode; value?: string; source?: string; target?: string } }) => {
            if (p.dataType === 'edge') return String(p.data.value || '')
            const n = p.data.node
            if (!n) return ''
            const lines = [`<b>${n.label}</b>`, n.sub ?? '', n.ts ? fmtTs(n.ts) : '', ...(n.detail ?? []).slice(0, 8)]
            if (n.degree) lines.push(`in ${n.degree} chain(s)`)
            return lines.filter(Boolean).map((s) => String(s).replace(/</g, '&lt;')).join('<br/>')
          },
        },
        graphic,
        series: [{
          type: 'graph',
          layout: mode === 'chain' ? 'none' : 'force',
          force: { repulsion: 320, edgeLength: [60, 140], gravity: 0.08 },
          roam: true,
          zoom: 1,
          draggable: mode !== 'chain',
          data,
          links,
          edgeSymbol: ['none', 'none'],
          lineStyle: { opacity: 0.9 },
          emphasis: { focus: 'adjacency', lineStyle: { width: 3 } },
          labelLayout: { hideOverlap: false },
        }],
      },
      true,
    )
    const onClick = (p: { dataType?: string; data?: { node?: GNode } }) => {
      const n = p.dataType === 'node' ? p.data?.node : undefined
      if (!n) return
      if (n.kind === 'chain' && n.chainId) return onChain(n.chainId)
      if (n.stepIdx != null) return onStep(n.stepIdx)
      if (n.stepIdxs?.length) return onStep(n.stepIdxs[0])
      if (n.entity) onEntity(n.entity)
    }
    c.on('click', onClick as never)
    const onResize = () => c.resize()
    window.addEventListener('resize', onResize)
    const obs = new ResizeObserver(() => c.resize())
    obs.observe(ref.current)
    return () => {
      c.off('click', onClick as never)
      window.removeEventListener('resize', onResize)
      obs.disconnect()
    }
  }, [graph, mode, selectedStep, onStep, onEntity, onChain])
  useEffect(() => () => { chartRef.current?.dispose(); chartRef.current = null }, [])

  return (
    <div className="chain-graph-wrap">
      <div ref={ref} className="chain-graph" />
      {mode === 'campaign' && graph?.insights && (
        <div className="chain-graph-insights">
          {graph.insights.length ? graph.insights.slice(0, 6).map((i) => <div key={i.text} className="small">{i.text}</div>) : <div className="small muted">no sender, domain, IP or host is shared between chains</div>}
        </div>
      )}
      {mode === 'chain' && <div className="chain-graph-key small muted">diamond = seed mail · box = step (size = weight, colour = worst finding) · grey dot = collapsed routine steps · green edges = ties to the mail · scroll to zoom, drag to pan, click a node</div>}
    </div>
  )
}
