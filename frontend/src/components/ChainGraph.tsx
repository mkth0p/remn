import { useEffect, useMemo, useRef } from 'react'
import * as echarts from 'echarts/core'
import { GraphChart } from 'echarts/charts'
import { LegendComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import type { Chain } from '../data/chains'
import { buildCampaignGraph, buildChainGraph, LANE_LABEL, LANES, type GNode, type Graph } from '../data/chainGraph'
import type { EntityRef } from '../state/store'
import { escapeHtml, fmtTs } from '../util/format'

echarts.use([GraphChart, TooltipComponent, LegendComponent, CanvasRenderer])

export interface GraphTokens {
  accent: string
  line: string
  line2: string
  fg1: string
  fg2: string
  fg3: string
  surface: string
  surface2: string
  mono: string
  sans: string
  sev: Record<string, string>
}

/** the light palette the printed report uses, whatever the app theme */
export const PRINT_TOKENS: GraphTokens = {
  accent: '#1b7f66',
  line: '#e3e6ea',
  line2: '#cfd5dc',
  fg1: '#111820',
  fg2: '#5b6876',
  fg3: '#8a95a3',
  surface: '#ffffff',
  surface2: '#f8f9fa',
  mono: 'Consolas, monospace',
  sans: 'Segoe UI, Arial, sans-serif',
  sev: { critical: '#a8231f', high: '#d1403f', medium: '#d9822b', low: '#2f6fdb', info: '#8a95a3' },
}

function tokens(): GraphTokens {
  const cs = getComputedStyle(document.documentElement)
  const v = (name: string, fallback: string) => cs.getPropertyValue(name).trim() || fallback
  return {
    accent: v('--accent', '#1b7f66'),
    line: v('--line', '#e3e6ea'),
    line2: v('--line-2', '#cfd5dc'),
    fg1: v('--fg-1', '#111820'),
    fg2: v('--fg-2', '#5b6876'),
    fg3: v('--fg-3', '#8a95a3'),
    surface: v('--surface', '#fff'),
    surface2: v('--surface-2', '#f8f9fa'),
    mono: v('--mono', 'monospace'),
    sans: v('--sans', 'sans-serif'),
    sev: {
      critical: v('--sev-critical', '#a8231f'),
      high: v('--sev-high', '#d1403f'),
      medium: v('--sev-medium', '#d9822b'),
      low: v('--sev-low', '#2f6fdb'),
      info: v('--sev-info', '#8a95a3'),
    } as Record<string, string>,
  }
}

const trunc = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + '…' : s)

/** The ECharts option for a chain (swimlanes, fixed positions) or campaign graph; `print` = static picture for the report. */
export function graphOption(
  graph: Graph,
  mode: 'chain' | 'campaign',
  W: number,
  H: number,
  t: GraphTokens,
  selectedStep: number | null,
  print = false,
  selectedNode: string | null = null,
): Record<string, unknown> {
  const colorOf = (n: GNode): string => {
    if (n.kind === 'routine') return t.fg3
    if (n.severity) return t.sev[n.severity] ?? t.fg2
    if (n.kind === 'user' || n.kind === 'chain') return t.accent
    if (n.lane === 'attacker') return t.sev.high
    if (n.lane === 'infra') return t.sev.low
    if (n.lane === 'artifact') return n.linked ? t.accent : t.fg2
    return n.linked ? t.accent : t.fg3
  }
  const sizeOf = (n: GNode): number | [number, number] => {
    if (n.kind === 'seed') return 26
    if (n.kind === 'chain') return 18 + Math.min(20, (n.score ?? 0) / 5)
    if (n.kind === 'step') return 14 + Math.min(8, n.weight) * 1.5
    if (n.kind === 'routine') return 14
    if (n.kind === 'user') return 20
    if (n.lane === 'artifact') return (n.linked ? 14 : 10) + Math.min(4, Math.log2(1 + (n.degree ?? 0))) * 2
    return 10 + Math.min(4, n.degree ?? 0) * 3
  }
  const symbolOf = (n: GNode) =>
    n.kind === 'seed'
      ? 'diamond'
      : n.kind === 'step' || n.kind === 'chain'
        ? 'roundRect'
        : n.kind === 'attachment' || n.kind === 'file'
          ? 'rect'
          : n.kind === 'hash'
            ? 'triangle'
            : n.kind === 'process' || n.kind === 'config'
              ? 'roundRect'
              : 'circle'
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
      itemStyle: {
        color: colorOf(n),
        borderColor: n.id === (selectedStep != null ? `step:${selectedStep}` : '') || n.id === selectedNode ? t.fg1 : n.linked ? t.fg1 : 'transparent',
        borderWidth: n.id === (selectedStep != null ? `step:${selectedStep}` : '') || n.id === selectedNode ? 3 : n.linked && n.kind !== 'seed' ? 1 : 0,
        opacity: n.kind === 'routine' ? 0.7 : 1,
      },
      label: {
        show: true,
        position: n.lane === 'attacker' || n.lane === 'mail' ? 'top' : n.lane === 'infra' ? 'bottom' : mode === 'chain' && Math.round(n.x) % 2 === 1 ? 'top' : 'bottom',
        formatter: () => `{a|${trunc(n.label, mode === 'chain' ? maxChars : 26)}}${n.sub ? `\n{s|${trunc(n.sub, maxChars + 4)}}` : ''}`,
        rich: { a: { color: t.fg1, fontSize: 11, fontFamily: t.sans, lineHeight: 14 }, s: { color: t.fg3, fontSize: 10, fontFamily: t.mono, lineHeight: 13 } },
      },
      node: n,
    }
    return mode === 'chain' ? { ...base, x: 120 + n.x * colW, y: 40 + li * laneH + laneH / 2 + (n.lane === 'infra' ? 4 : 0), fixed: true } : base
  })
  const links = graph.edges.map((e) => ({
    source: e.source,
    target: e.target,
    value: e.label ?? '',
    lineStyle:
      e.kind === 'artifact'
        ? { color: t.accent, width: 2, curveness: 0.25, type: 'solid' }
        : e.kind === 'sequence'
          ? { color: t.fg2, width: 1.5, curveness: 0.1 }
          : e.kind === 'recipient'
            ? { color: t.fg2, width: 1.5, curveness: 0 }
            : { color: t.line2, width: 1, type: 'dashed', curveness: 0.15 },
    symbol: e.kind === 'sequence' || e.kind === 'recipient' || e.kind === 'artifact' ? ['none', 'arrow'] : ['none', 'none'],
    symbolSize: 7,
    label: { show: !!e.label, formatter: e.label ?? '', fontSize: 9, fontFamily: t.mono, color: e.kind === 'artifact' ? t.accent : t.fg3, backgroundColor: t.surface, padding: [1, 3] },
  }))
  // lane names and separators live inside the graph (anchor nodes and edges) so they pan and zoom with it
  const right = mode === 'chain' ? 120 + Math.max(1, ...graph.nodes.map((n) => n.x)) * colW + 160 : 0
  const laneNodes =
    mode === 'chain'
      ? lanes.flatMap((l, i) => {
          const yTop = 40 + i * laneH
          const anchor = (id: string, x: number, y: number, label?: string) => ({
            id,
            name: label ?? '',
            x,
            y,
            fixed: true,
            symbol: 'circle',
            symbolSize: 1,
            itemStyle: { color: 'transparent', borderWidth: 0 },
            label: label ? { show: true, position: 'right', formatter: label, color: t.fg3, fontSize: 10, fontFamily: t.mono, distance: 4, opacity: 1 } : { show: false },
            tooltip: { show: false },
            emphasis: { disabled: true },
            blur: { label: { opacity: 1 } },
            silent: true,
          })
          return [anchor(`lane:${l}`, 8, yTop + 12, LANE_LABEL[l]), anchor(`lane:${l}:l`, 0, yTop), anchor(`lane:${l}:r`, right, yTop)]
        })
      : []
  const laneLinks =
    mode === 'chain'
      ? lanes.map((l) => ({
          source: `lane:${l}:l`,
          target: `lane:${l}:r`,
          lineStyle: { color: t.line, width: 1, type: 'solid', curveness: 0 },
          symbol: ['none', 'none'],
          label: { show: false },
          tooltip: { show: false },
          emphasis: { disabled: true },
          blur: { lineStyle: { opacity: 1 } },
          silent: true,
        }))
      : []
  return {
    backgroundColor: 'transparent',
    animation: !print && mode !== 'chain',
    tooltip: {
      show: !print,
      trigger: 'item',
      backgroundColor: t.surface,
      borderColor: t.line2,
      textStyle: { color: t.fg1, fontSize: 11 },
      confine: true,
      formatter: (p: { dataType: string; data: { node?: GNode; value?: string; source?: string; target?: string } }) => {
        // ECharts writes this as HTML, and labels, edge values and details come from the evidence
        if (p.dataType === 'edge') return escapeHtml(String(p.data.value || ''))
        const n = p.data.node
        if (!n) return ''
        const lines = [n.sub ?? '', n.ts ? fmtTs(n.ts) : '', ...(n.detail ?? []).slice(0, 8)]
        if (n.degree) lines.push(`in ${n.degree} chain(s)`)
        return [`<b>${escapeHtml(String(n.label))}</b>`, ...lines.filter(Boolean).map((s) => escapeHtml(String(s)))].join('<br/>')
      },
    },
    series: [
      {
        type: 'graph',
        layout: mode === 'chain' ? 'none' : print ? 'circular' : 'force',
        circular: { rotateLabel: false },
        ...(print ? { left: 24, right: 24, top: 28, bottom: 28 } : {}),
        force: { repulsion: 320, edgeLength: [60, 140], gravity: 0.08 },
        roam: !print,
        zoom: 1,
        draggable: !print && mode !== 'chain',
        data: [...laneNodes, ...data],
        links: [...laneLinks, ...links],
        edgeSymbol: ['none', 'none'],
        lineStyle: { opacity: 0.9 },
        emphasis: { focus: 'adjacency', lineStyle: { width: 3 } },
        labelLayout: { hideOverlap: false },
      },
    ],
  }
}

/** Render a chain, campaign or story graph to a PNG data URL (light palette, no animation) for the report; null when there is nothing to draw. */
export function renderGraphPng(arg: { mode: 'chain'; chain: Chain } | { mode: 'campaign'; chains: Chain[] } | { mode: 'story'; graph: Graph }): string | null {
  const graph = arg.mode === 'chain' ? buildChainGraph(arg.chain) : arg.mode === 'story' ? arg.graph : buildCampaignGraph(arg.chains)
  if (!graph.nodes.length || typeof document === 'undefined') return null
  const lanes = LANES.filter((l) => graph.nodes.some((n) => n.lane === l))
  const laid = arg.mode !== 'campaign'
  const W = laid ? Math.min(2200, Math.max(900, 300 + graph.columns * 150)) : 1200
  const H = laid ? 100 + lanes.length * 120 : 760
  const host = document.createElement('div')
  host.style.cssText = `position:fixed;left:-30000px;top:0;width:${W}px;height:${H}px;pointer-events:none;`
  document.body.appendChild(host)
  const chart = echarts.init(host, undefined, { renderer: 'canvas', devicePixelRatio: 2, width: W, height: H })
  try {
    chart.setOption(graphOption(graph, laid ? 'chain' : 'campaign', W, H, PRINT_TOKENS, null, true), true)
    return chart.getDataURL({ type: 'png', pixelRatio: 2, backgroundColor: '#ffffff' })
  } catch {
    return null
  } finally {
    chart.dispose()
    host.remove()
  }
}

interface Props {
  mode: 'chain' | 'campaign'
  chain: Chain | null
  chains: Chain[]
  /** a graph laid out by someone else (a story), drawn with the swimlane layout instead of the chain's */
  graph?: Graph | null
  selectedStep: number | null
  onStep: (i: number) => void
  onEntity: (e: EntityRef) => void
  onChain: (id: string) => void
  /** story graph: a record node was clicked; the ids are relationship record node ids */
  onRecords?: (ids: string[]) => void
  /** story graph: an entity node without a flyout page was clicked (a file, a digest, a process, a service); the id is the relationship node id */
  onEntityNode?: (id: string) => void
  /** story graph: the node to outline */
  selectedNode?: string | null
}

/** ECharts renderer for the chain, campaign and story graphs (see data/chainGraph.ts and data/storyGraph.ts for the models). */
export function ChainGraph({ mode, chain, chains, graph: given, selectedStep, onStep, onEntity, onChain, onRecords, onEntityNode, selectedNode }: Props) {
  const ref = useRef<HTMLDivElement>(null)
  const chartRef = useRef<echarts.ECharts | null>(null)
  const graph: (Graph & { insights?: { text: string }[] }) | null = useMemo(
    () => (given !== undefined ? given : mode === 'chain' ? (chain ? buildChainGraph(chain) : null) : buildCampaignGraph(chains)),
    [given, mode, chain, chains],
  )

  useEffect(() => {
    if (!ref.current || !graph) return
    if (!chartRef.current) chartRef.current = echarts.init(ref.current, undefined, { renderer: 'canvas' })
    const c = chartRef.current
    const t = tokens()
    const W = Math.max(480, c.getWidth())
    const H = Math.max(320, c.getHeight())
    c.setOption(graphOption(graph, mode, W, H, t, selectedStep, false, selectedNode ?? null), true)
    const onClick = (p: { dataType?: string; data?: { node?: GNode } }) => {
      const n = p.dataType === 'node' ? p.data?.node : undefined
      if (!n) return
      if (n.kind === 'chain' && n.chainId) return onChain(n.chainId)
      if (n.recordIds?.length && onRecords) return onRecords(n.recordIds)
      if (n.stepIdx != null) return onStep(n.stepIdx)
      if (n.stepIdxs?.length) return onStep(n.stepIdxs[0])
      if (n.entity) return onEntity(n.entity)
      if (n.entityId && onEntityNode) onEntityNode(n.entityId)
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
  }, [graph, mode, selectedStep, selectedNode, onStep, onEntity, onChain, onRecords, onEntityNode])
  useEffect(
    () => () => {
      chartRef.current?.dispose()
      chartRef.current = null
    },
    [],
  )

  return (
    <div className="chain-graph-wrap">
      <div ref={ref} className="chain-graph" />
      {mode === 'campaign' && graph?.insights && (
        <div className="chain-graph-insights">
          {graph.insights.length ? (
            graph.insights.slice(0, 6).map((i) => (
              <div key={i.text} className="small">
                {i.text}
              </div>
            ))
          ) : (
            <div className="small muted">no sender, domain, IP or host is shared between chains</div>
          )}
        </div>
      )}
      {mode === 'chain' && !given && (
        <div className="chain-graph-key small muted">
          diamond = seed mail · box = step (size = weight, colour = worst finding) · grey dot = collapsed routine steps · green edges = ties to the mail · scroll to zoom, drag to pan, click a node
        </div>
      )}
      {given && (
        <div className="chain-graph-key small muted">
          diamond = record that started the story · box = record with a finding or a mark · grey dot = folded plain records · triangle = digest, square = file · green edges = entities shared across
          source files · scroll to zoom, drag to pan, click a record or an entity
        </div>
      )}
    </div>
  )
}
