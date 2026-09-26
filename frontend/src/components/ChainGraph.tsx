import { useEffect, useMemo, useRef } from 'react'
import * as echarts from 'echarts/core'
import { GraphChart } from 'echarts/charts'
import { LegendComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import type { Chain } from '../data/chains'
import { buildCampaignGraph, buildChainGraph, LANE_LABEL, LANES, type GNode, type Graph, type Lane } from '../data/chainGraph'
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

/** where the lane names sit and where column 0 starts in the chain layout */
const GUTTER = 190
/** vertical room for one node in a column of the campaign layout */
const ROW = 46
const CHAIN_ROW = 84
const CAMPAIGN_COLS: { lane: Lane; title: string }[] = [
  { lane: 'attacker', title: 'attacker side' },
  { lane: 'identity', title: 'people' },
  { lane: 'infra', title: 'machines & IPs' },
]

/** height the campaign layout needs so no column is squeezed below one row per node */
function campaignHeight(graph: Graph): number {
  const count = (l: Lane) => graph.nodes.filter((n) => n.lane === l).length
  return Math.max(420, 90 + Math.max(count('attacker') * ROW, count('infra') * ROW, count('identity') * CHAIN_ROW))
}

/** a side column longer than this folds the entities only one chain touches into one node per chain */
const FOLD_ABOVE = 12

/** Campaign graph with, in a crowded column, each chain's unshared senders, domains, machines or IPs folded into one "N more" node (the tooltip lists them). */
function foldCampaign(graph: Graph): Graph {
  const crowded = (['attacker', 'infra'] as Lane[]).filter((l) => graph.nodes.filter((n) => n.lane === l).length > FOLD_ABOVE)
  if (!crowded.length) return graph
  const folded = new Map<string, { chain: string; lane: Lane; nodes: GNode[] }>()
  const into = new Map<string, string>()
  for (const n of graph.nodes) {
    if (!crowded.includes(n.lane) || (n.degree ?? 0) >= 2) continue
    const chain = graph.edges.find((e) => e.target === n.id)?.source
    if (!chain) continue
    const id = `fold:${n.lane}:${chain}`
    const f = folded.get(id) ?? { chain, lane: n.lane, nodes: [] }
    f.nodes.push(n)
    folded.set(id, f)
    into.set(n.id, id)
  }
  const nodes = graph.nodes.filter((n) => !into.has(n.id))
  for (const [id, f] of folded)
    nodes.push({
      id,
      label: `${f.nodes.length} more`,
      sub: f.lane === 'attacker' ? 'senders & domains' : 'machines & IPs',
      lane: f.lane,
      kind: 'routine',
      x: 0,
      weight: 1,
      linked: false,
      degree: 1,
      detail: [...f.nodes.slice(0, 12).map((n) => `${n.label} (${n.sub ?? n.kind})`), ...(f.nodes.length > 12 ? [`… ${f.nodes.length - 12} more`] : [])],
    })
  const seen = new Set<string>()
  const edges = graph.edges
    .map((e) => (into.has(e.target) ? { ...e, target: into.get(e.target)!, label: undefined } : e))
    .filter((e) => {
      const k = `${e.source}>${e.target}`
      if (seen.has(k)) return false
      seen.add(k)
      return true
    })
  return { ...graph, nodes, edges }
}

/** Campaign positions: attacker entities left, the chains (people) in the middle, machines and IPs right, each column ordered to keep edges short. */
function campaignLayout(graph: Graph, W: number, H: number): { pos: Map<string, [number, number]>; titleY: number } {
  const pos = new Map<string, [number, number]>()
  let titleY = H
  const chains = graph.nodes.filter((n) => n.kind === 'chain').sort((a, b) => (b.score ?? 0) - (a.score ?? 0))
  const place = (nodes: GNode[], x: number, row: number) => {
    const top = 60 + Math.max(0, (H - 90 - nodes.length * row) / 2)
    if (nodes.length) titleY = Math.min(titleY, top - 24)
    nodes.forEach((n, i) => pos.set(n.id, [x, top + i * row + row / 2]))
  }
  place(chains, W / 2, CHAIN_ROW)
  const rank = new Map(chains.map((c, i) => [c.id, i]))
  const bary = (n: GNode) => {
    const r = graph.edges.filter((e) => e.target === n.id || e.source === n.id).map((e) => rank.get(e.source === n.id ? e.target : e.source) ?? 0)
    return r.length ? r.reduce((a, b) => a + b, 0) / r.length : 0
  }
  for (const [lane, x] of [
    ['attacker', W * 0.2],
    ['infra', W * 0.8],
  ] as const) {
    const col = graph.nodes
      .filter((n) => n.lane === lane)
      .map((n) => ({ n, b: bary(n) }))
      .sort((a, b) => a.b - b.b || (b.n.degree ?? 0) - (a.n.degree ?? 0) || a.n.label.localeCompare(b.n.label))
      .map((x) => x.n)
    place(col, x, ROW)
  }
  return { pos, titleY }
}

/** a label that sits outside the graph data: lane names, column titles, lane separators */
const anchor = (t: GraphTokens, id: string, x: number, y: number, label?: string, position = 'right') => ({
  id,
  name: label ?? '',
  x,
  y,
  fixed: true,
  symbol: 'circle',
  symbolSize: 1,
  itemStyle: { color: 'transparent', borderWidth: 0, shadowBlur: 0 },
  label: label
    ? {
        show: true,
        position,
        formatter: label,
        color: t.fg2,
        fontSize: 10,
        fontWeight: 600,
        fontFamily: t.sans,
        backgroundColor: t.surface2,
        borderColor: t.line,
        borderWidth: 1,
        borderRadius: 10,
        padding: [3, 8],
        distance: 0,
      }
    : { show: false },
  tooltip: { show: false },
  emphasis: { disabled: true },
  blur: { itemStyle: { opacity: 0 }, label: { opacity: 1 } },
  silent: true,
})

/** The ECharts option for a chain (swimlanes, fixed positions) or campaign graph (three columns); `print` = static picture for the report. */
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
  if (mode === 'campaign') {
    graph = foldCampaign(graph)
    H = Math.max(H, campaignHeight(graph))
  }
  const colorOf = (n: GNode): string => {
    if (n.kind === 'routine') return t.fg3
    if (n.severity) return t.sev[n.severity] ?? t.fg2
    if (n.kind === 'user' || n.kind === 'chain') return t.accent
    if (mode === 'campaign' && (n.degree ?? 0) < 2) return t.fg3
    if (n.lane === 'attacker') return t.sev.high
    if (n.lane === 'infra') return t.sev.low
    if (n.lane === 'artifact') return n.linked ? t.accent : t.fg2
    return n.linked ? t.accent : t.fg3
  }
  const sizeOf = (n: GNode): number => {
    if (n.kind === 'seed') return 30
    if (n.kind === 'chain') return 22 + Math.min(18, (n.score ?? 0) / 6)
    if (n.kind === 'step') return 18 + Math.min(8, n.weight) * 1.5
    if (n.kind === 'routine') return 16
    if (n.kind === 'user') return 24
    if (n.lane === 'artifact') return (n.linked ? 16 : 12) + Math.min(4, Math.log2(1 + (n.degree ?? 0))) * 2
    return 13 + Math.min(4, n.degree ?? 0) * 3
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
  const selectedId = selectedStep != null ? `step:${selectedStep}` : selectedNode
  const lanes = LANES.filter((l) => graph.nodes.some((n) => n.lane === l))
  const laneH = mode === 'chain' ? (H - 60) / Math.max(1, lanes.length) : 0
  const colW = mode === 'chain' ? Math.min(220, Math.max(110, (W - GUTTER - 120) / Math.max(1, graph.columns))) : 0
  const maxChars = mode === 'chain' ? Math.max(14, Math.floor(colW / 7)) : 30
  const xOf = (n: GNode) => GUTTER + 40 + n.x * colW
  const yOf = (n: GNode) => 30 + lanes.indexOf(n.lane) * laneH + laneH / 2
  const camp = mode === 'campaign' ? campaignLayout(graph, W, H) : null
  // labels: attacker-side names above, machines below; neighbours in a lane that sit closer than a column take turns above and below
  const labelPos = new Map<string, string>()
  if (camp) for (const n of graph.nodes) labelPos.set(n.id, n.lane === 'attacker' ? 'left' : n.lane === 'infra' ? 'right' : 'bottom')
  else
    for (const l of lanes) {
      const row = graph.nodes.filter((n) => n.lane === l).sort((a, b) => a.x - b.x)
      const home = l === 'attacker' || l === 'mail' ? 'top' : 'bottom'
      const away = home === 'top' ? 'bottom' : 'top'
      let prev: { x: number; level: number } | null = null
      for (const n of row) {
        // neighbours closer than about a column would print over each other: the next one's label moves
        const level: number = prev && (n.x - prev.x) * colW < colW * 1.05 ? (prev.level + 1) % 3 : 0
        // the outer lanes have no room on the far side, so their labels stack higher (or lower) instead of flipping
        labelPos.set(n.id, level === 0 ? home : l === 'attacker' || l === 'infra' ? `${home}+${level}` : level === 1 ? away : `${away}+1`)
        prev = { x: n.x, level }
      }
    }
  const data = graph.nodes.map((n) => {
    const selected = n.id === selectedId
    const color = colorOf(n)
    const routine = n.kind === 'routine'
    const faded = camp && n.kind !== 'chain' && (n.degree ?? 0) < 2
    const placed = labelPos.get(n.id) ?? 'bottom'
    const [pos, level = '0'] = placed.split('+')
    const chars = camp ? (n.kind === 'chain' ? 34 : 28) : maxChars
    const base = {
      id: n.id,
      name: n.label,
      value: n.sub ?? '',
      symbol: symbolOf(n),
      symbolSize: sizeOf(n),
      itemStyle: {
        color: routine ? t.surface : color,
        borderColor: selected ? t.fg1 : routine ? t.fg3 : t.surface,
        borderWidth: selected ? 3 : routine ? 1.5 : 2,
        borderType: routine ? 'dashed' : 'solid',
        shadowBlur: selected ? 16 : 6,
        shadowColor: selected ? color : 'rgba(0, 0, 0, 0.22)',
        shadowOffsetY: selected ? 0 : 1,
        opacity: faded ? 0.75 : 1,
      },
      label: {
        show: true,
        position: pos,
        distance: 6 + Number(level) * (print ? 34 : 28),
        align: pos === 'left' ? 'right' : pos === 'right' ? 'left' : 'center',
        formatter: () => `{a|${trunc(n.label, chars)}}${n.sub ? `\n{s|${trunc(n.sub, chars + 4)}}` : ''}`,
        backgroundColor: t.surface,
        borderRadius: 4,
        padding: [2, 5],
        rich: {
          a: {
            color: faded ? t.fg2 : t.fg1,
            fontSize: print ? 13 : 11,
            fontWeight: n.kind === 'seed' || n.kind === 'chain' || n.kind === 'user' || selected ? 600 : 500,
            fontFamily: t.sans,
            lineHeight: print ? 17 : 15,
            align: pos === 'left' ? 'right' : pos === 'right' ? 'left' : 'center',
          },
          s: { color: t.fg3, fontSize: print ? 11 : 9.5, fontFamily: t.mono, lineHeight: print ? 15 : 13, align: pos === 'left' ? 'right' : pos === 'right' ? 'left' : 'center' },
        },
      },
      node: n,
    }
    if (camp) {
      const [x, y] = camp.pos.get(n.id) ?? [W / 2, H / 2]
      return { ...base, x, y, fixed: true }
    }
    return { ...base, x: xOf(n), y: yOf(n) + (n.lane === 'infra' ? 4 : 0), fixed: true }
  })
  const byId = new Map(graph.nodes.map((n) => [n.id, n]))
  const links = graph.edges.map((e) => {
    const other = byId.get(e.target)
    const shared = camp && (other?.degree ?? 0) >= 2
    const lineStyle =
      e.kind === 'artifact'
        ? { color: t.accent, width: 2.2, curveness: 0.25, type: 'solid', opacity: 0.95 }
        : e.kind === 'sequence' || e.kind === 'recipient'
          ? { color: t.fg2, width: 1.6, curveness: e.kind === 'sequence' ? 0.12 : 0, opacity: 0.6 }
          : camp
            ? { color: shared && other ? colorOf(other) : t.line2, width: shared ? 1.8 : 1, type: shared ? 'solid' : 'dashed', curveness: 0.08, opacity: shared ? 0.6 : 0.9 }
            : { color: t.line2, width: 1, type: 'dashed', curveness: 0.15, opacity: 0.9 }
    return {
      source: e.source,
      target: e.target,
      value: e.label ?? '',
      lineStyle,
      symbol: e.kind === 'sequence' || e.kind === 'recipient' || e.kind === 'artifact' ? ['none', 'arrow'] : ['none', 'none'],
      symbolSize: 8,
      label: {
        // only the ties to the mail are named on the edge: the other labels ("from", "delivered to", "seed from") crowd the seed and are in the tooltip
        show: !!e.label && e.kind === 'artifact',
        formatter: e.label ?? '',
        fontSize: print ? 11 : 9,
        fontFamily: t.mono,
        color: e.kind === 'artifact' ? t.accent : t.fg3,
        backgroundColor: t.surface,
        borderRadius: 3,
        padding: [1, 4],
      },
    }
  })
  // lane names, column titles and lane separators live inside the graph (anchor nodes and edges) so they pan and zoom with it
  const right = mode === 'chain' ? xOf({ x: Math.max(1, ...graph.nodes.map((n) => n.x)) } as GNode) + 170 : 0
  const guideNodes = camp
    ? CAMPAIGN_COLS.filter((c) => graph.nodes.some((n) => n.lane === c.lane)).map((c) =>
        anchor(t, `col:${c.lane}`, c.lane === 'attacker' ? W * 0.2 : c.lane === 'infra' ? W * 0.8 : W / 2, camp.titleY, c.title, 'inside'),
      )
    : lanes.flatMap((l, i) => {
        const yTop = 30 + i * laneH
        return [anchor(t, `lane:${l}`, 10, yTop + laneH / 2, LANE_LABEL[l]), anchor(t, `lane:${l}:l`, 0, yTop), anchor(t, `lane:${l}:r`, right, yTop)]
      })
  const guideLinks = camp
    ? []
    : lanes.slice(1).map((l) => ({
        source: `lane:${l}:l`,
        target: `lane:${l}:r`,
        lineStyle: { color: t.line, width: 1, type: [4, 4], curveness: 0, opacity: 1 },
        symbol: ['none', 'none'],
        label: { show: false },
        tooltip: { show: false },
        emphasis: { disabled: true },
        blur: { lineStyle: { opacity: 1 } },
        silent: true,
      }))
  return {
    backgroundColor: 'transparent',
    animation: !print,
    animationDuration: 400,
    tooltip: {
      show: !print,
      trigger: 'item',
      backgroundColor: t.surface,
      borderColor: t.line2,
      borderRadius: 8,
      padding: [8, 10],
      extraCssText: 'box-shadow: 0 6px 20px rgba(0,0,0,.18); max-width: 360px; white-space: normal;',
      textStyle: { color: t.fg1, fontSize: 11, fontFamily: t.sans },
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
        layout: 'none',
        // room for the labels that hang outside the outermost nodes: stacked names above and below the lanes, names beside the campaign's side columns
        ...(camp ? { left: 200, right: 200, top: 24, bottom: 64 } : { left: 16, right: 16, top: 72, bottom: 72 }),
        roam: !print,
        zoom: 1,
        draggable: !print && mode !== 'chain',
        data: [...guideNodes, ...data],
        links: [...guideLinks, ...links],
        edgeSymbol: ['none', 'none'],
        emphasis: { focus: 'adjacency', lineStyle: { width: 3, opacity: 1 }, label: { show: true } },
        blur: { itemStyle: { opacity: 0.25 }, lineStyle: { opacity: 0.08 }, label: { opacity: 0.35 } },
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
  const W = laid ? Math.min(1700, Math.max(1000, GUTTER + 200 + graph.columns * 140)) : 1200
  const H = laid ? 60 + lanes.length * 110 : campaignHeight(foldCampaign(graph))
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
        <GraphKey
          items={[
            ['diamond', 'var(--sev-critical)', 'seed mail'],
            ['box', 'var(--sev-high)', 'step, coloured by its worst finding'],
            ['ring', 'var(--fg-3)', 'folded routine steps'],
            ['line', 'var(--accent)', 'tie to the mail'],
          ]}
          hint="scroll to zoom, drag to pan, click a node"
        />
      )}
      {mode === 'campaign' && !given && (
        <GraphKey
          items={[
            ['box', 'var(--sev-high)', 'person, coloured by the chain'],
            ['dot', 'var(--sev-high)', 'shared sender or domain'],
            ['dot', 'var(--sev-low)', 'shared machine or IP'],
            ['dot', 'var(--fg-3)', 'in one chain only'],
          ]}
          hint="hover to trace, drag a node, click a person to open the chain"
        />
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

type KeyShape = 'diamond' | 'box' | 'dot' | 'ring' | 'line'

/** the legend under a graph: the same shapes and colours the graph draws */
function GraphKey({ items, hint }: { items: [KeyShape, string, string][]; hint: string }) {
  return (
    <div className="chain-graph-key small muted">
      {items.map(([shape, color, label]) => (
        <span key={label} className="graph-key-item">
          <i className={`graph-key-${shape}`} style={{ '--k': color } as React.CSSProperties} />
          {label}
        </span>
      ))}
      <span className="graph-key-hint">{hint}</span>
    </div>
  )
}
