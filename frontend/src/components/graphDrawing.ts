/**
 * How a chain, campaign or story graph is drawn with ECharts: the theme's colours, the layout at a
 * size, the chart option, and the picture the report embeds. The page's component is ChainGraph.tsx.
 */
import * as echarts from 'echarts/core'
import { GraphChart } from 'echarts/charts'
import { LegendComponent, TooltipComponent } from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'
import type { Chain } from '../data/chains'
import { buildCampaignGraph, buildChainGraph, type GNode, type Graph, type Lane } from '../data/chainGraph'
import { escapeHtml, fmtTs } from '../util/format'
import { LANE_PILL, layoutCampaign, layoutLanes, type GraphLayout, type LabelFonts } from './graphLayout'

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

/** the app theme's colours and type, read from its CSS variables */
export function tokens(): GraphTokens {
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

/** label type in the app, and larger in the report, whose picture is shrunk to the page */
const fontsFor = (t: GraphTokens, print: boolean): LabelFonts =>
  print
    ? { sans: t.sans, mono: t.mono, title: 13, titleLine: 17, sub: 11, subLine: 15, padX: 5, padY: 2 }
    : { sans: t.sans, mono: t.mono, title: 11, titleLine: 14, sub: 9.5, subLine: 13, padX: 5, padY: 2 }

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

/** symbol size of a node: steps grow with their weight, chains with their score, shared entities with the chains they touch */
function sizeOf(n: GNode): number {
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

/** A graph as it will be drawn: the campaign folded, every node placed at its size in pixels. */
export interface Drawing {
  mode: 'chain' | 'campaign'
  graph: Graph
  layout: GraphLayout
}

/** Lay a chain, story or campaign graph out in `W` × `H` pixels of pane (more when its labels need more); `print` = the report's type sizes. */
export function drawGraph(graph: Graph, mode: 'chain' | 'campaign', W: number, H: number, t: GraphTokens, print = false): Drawing {
  const g = mode === 'campaign' ? foldCampaign(graph) : graph
  const opts = { width: W, height: H, fonts: fontsFor(t, print), sizeOf, print }
  return { mode, graph: g, layout: mode === 'campaign' ? layoutCampaign(g, opts) : layoutLanes(g, opts) }
}

/** a point that is not graph data: a corner, a lane name, a column title, the end of a lane separator */
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
        fontSize: LANE_PILL.size,
        fontWeight: 600,
        fontFamily: t.sans,
        backgroundColor: t.surface2,
        borderColor: t.line,
        borderWidth: LANE_PILL.border,
        borderRadius: 10,
        padding: [3, LANE_PILL.padX],
        distance: 0,
      }
    : { show: false },
  tooltip: { show: false },
  emphasis: { disabled: true },
  blur: { itemStyle: { opacity: 0 }, label: { opacity: 1 } },
  silent: true,
})

/**
 * The ECharts option for a drawing, one layout pixel to one screen pixel: the series' view box is the
 * layout's own box, pinned by two corner points, so ECharts neither stretches nor squeezes it.
 * `print` = static picture for the report, with the lane names drawn on it (the page draws its own).
 */
export function graphOption(d: Drawing, t: GraphTokens, selectedStep: number | null, print = false, selectedNode: string | null = null): Record<string, unknown> {
  const { graph, layout, mode } = d
  const camp = mode === 'campaign'
  const f = fontsFor(t, print)
  const colorOf = (n: GNode): string => {
    if (n.kind === 'routine') return t.fg3
    if (n.severity) return t.sev[n.severity] ?? t.fg2
    if (n.kind === 'user' || n.kind === 'chain') return t.accent
    if (camp && (n.degree ?? 0) < 2) return t.fg3
    if (n.lane === 'attacker') return t.sev.high
    if (n.lane === 'infra') return t.sev.low
    if (n.lane === 'artifact') return n.linked ? t.accent : t.fg2
    return n.linked ? t.accent : t.fg3
  }
  // a step folded into a group is shown selected through its group
  const selectedId = selectedStep != null ? (graph.nodes.find((n) => n.stepIdx === selectedStep || n.stepIdxs?.includes(selectedStep))?.id ?? null) : selectedNode
  const data = graph.nodes.map((n) => {
    const p = layout.nodes.get(n.id)!
    const selected = n.id === selectedId
    const color = colorOf(n)
    const routine = n.kind === 'routine'
    const faded = camp && n.kind !== 'chain' && (n.degree ?? 0) < 2
    const align = p.position === 'left' ? 'right' : p.position === 'right' ? 'left' : 'center'
    const text = [...p.label.title.map((l) => `{a|${l}}`), ...p.label.sub.map((l) => `{s|${l}}`)].join('\n')
    return {
      id: n.id,
      name: n.label,
      value: n.sub ?? '',
      x: p.x,
      y: p.y,
      fixed: true,
      symbol: symbolOf(n),
      symbolSize: p.size,
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
        position: p.position,
        distance: p.distance,
        align,
        // a function, not a template string: the evidence may hold "{b}" or "{c}"
        formatter: () => text,
        backgroundColor: t.surface,
        borderRadius: 4,
        padding: [f.padY, f.padX],
        rich: {
          a: {
            color: faded ? t.fg2 : t.fg1,
            fontSize: f.title,
            fontWeight: n.kind === 'seed' || n.kind === 'chain' || n.kind === 'user' || selected ? 600 : 500,
            fontFamily: t.sans,
            lineHeight: f.titleLine,
            align,
          },
          s: { color: t.fg3, fontSize: f.sub, fontFamily: t.mono, lineHeight: f.subLine, align },
        },
      },
      node: n,
    }
  })
  const byId = new Map(graph.nodes.map((n) => [n.id, n]))
  const links = graph.edges.map((e) => {
    const other = byId.get(e.target)
    const shared = camp && (other?.degree ?? 0) >= 2
    const lineStyle =
      e.kind === 'artifact'
        ? { color: t.accent, width: 2, curveness: 0.2, type: 'solid', opacity: 0.9 }
        : e.kind === 'sequence' || e.kind === 'recipient'
          ? { color: t.fg2, width: 1.6, curveness: e.kind === 'sequence' ? 0.12 : 0, opacity: 0.6 }
          : camp
            ? { color: shared && other ? colorOf(other) : t.line2, width: shared ? 1.8 : 1, type: shared ? 'solid' : 'dashed', curveness: 0.08, opacity: shared ? 0.6 : 0.9 }
            : { color: t.line2, width: 1, type: 'dashed', curveness: 0.1, opacity: 0.7 }
    return {
      source: e.source,
      target: e.target,
      value: e.label ?? '',
      lineStyle,
      symbol: e.kind === 'sequence' || e.kind === 'recipient' || e.kind === 'artifact' ? ['none', 'arrow'] : ['none', 'none'],
      symbolSize: 8,
      // no text on the edges: turned along the curves and stacked where several leave one node, it covered the labels.
      // What a tie is (link, attachment, replied, forwards to) is in its tooltip, and the node at its other end says it too.
      label: { show: false },
      edge: e,
    }
  })
  // lane separators, lane names (report only) and column titles are points of the graph, so they sit where the layout put them
  const { width: W, height: H } = layout
  const guideNodes = [
    anchor(t, 'corner:0', 0, 0),
    anchor(t, 'corner:1', W, H),
    ...layout.titles.map((c) => anchor(t, c.id, c.x, c.y, c.text, 'inside')),
    ...layout.lanes.flatMap((b, i) => [
      ...(print ? [anchor(t, `lane:${b.lane}`, LANE_PILL.left, b.y, b.name)] : []),
      ...(i ? [anchor(t, `lane:${b.lane}:l`, 0, b.top), anchor(t, `lane:${b.lane}:r`, W, b.top)] : []),
    ]),
  ]
  const guideLinks = layout.lanes.slice(1).map((b) => ({
    source: `lane:${b.lane}:l`,
    target: `lane:${b.lane}:r`,
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
      formatter: (p: { dataType: string; data: { node?: GNode; edge?: { source: string; target: string; label?: string } } }) => {
        // ECharts writes this as HTML, and labels, edge values and details come from the evidence
        if (p.dataType === 'edge') {
          const e = p.data.edge
          if (!e) return ''
          const ends = `${escapeHtml(byId.get(e.source)?.label ?? e.source)} → ${escapeHtml(byId.get(e.target)?.label ?? e.target)}`
          return e.label ? `<b>${escapeHtml(e.label)}</b><br/>${ends}` : ends
        }
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
        // the view box is the layout's box (see the corner anchors): no scaling
        left: 0,
        top: 0,
        width: W,
        height: H,
        roam: false,
        draggable: !print && camp,
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
  const drawing = drawGraph(graph, arg.mode === 'campaign' ? 'campaign' : 'chain', arg.mode === 'campaign' ? 1200 : 1700, 0, PRINT_TOKENS, true)
  const { width: W, height: H } = drawing.layout
  const host = document.createElement('div')
  host.style.cssText = `position:fixed;left:-30000px;top:0;width:${W}px;height:${H}px;pointer-events:none;`
  document.body.appendChild(host)
  const chart = echarts.init(host, undefined, { renderer: 'canvas', devicePixelRatio: 2, width: W, height: H })
  try {
    chart.setOption(graphOption(drawing, PRINT_TOKENS, null, true), true)
    return chart.getDataURL({ type: 'png', pixelRatio: 2, backgroundColor: '#ffffff' })
  } catch {
    return null
  } finally {
    chart.dispose()
    host.remove()
  }
}
