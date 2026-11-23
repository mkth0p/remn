import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import * as echarts from 'echarts/core'
import type { Chain } from '../data/chains'
import { buildCampaignGraph, buildChainGraph, type GNode, type Graph } from '../data/chainGraph'
import type { EntityRef } from '../state/store'
import { drawGraph, graphOption, tokens } from './graphDrawing'

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

/**
 * ECharts renderer for the chain, campaign and story graphs (see data/chainGraph.ts for the models and
 * graphLayout.ts for where things go). The graph is drawn at its real size in a pane that scrolls; a
 * chain's lane names stay pinned to the left edge while its timeline scrolls under them.
 */
export function ChainGraph({ mode, chain, chains, graph: given, selectedStep, onStep, onEntity, onChain, onRecords, onEntityNode, selectedNode }: Props) {
  const viewRef = useRef<HTMLDivElement>(null)
  const scrollRef = useRef<HTMLDivElement>(null)
  const ref = useRef<HTMLDivElement>(null)
  const chartRef = useRef<echarts.ECharts | null>(null)
  const [pane, setPane] = useState<{ w: number; h: number } | null>(null)
  const graph: (Graph & { insights?: { text: string }[] }) | null = useMemo(
    () => (given !== undefined ? given : mode === 'chain' ? (chain ? buildChainGraph(chain) : null) : buildCampaignGraph(chains)),
    [given, mode, chain, chains],
  )
  const lanes = mode === 'chain'

  // the pane's size sets the column width and how much the lanes may grow; the graph never gets smaller than its labels need
  useLayoutEffect(() => {
    const el = scrollRef.current
    if (!el) return
    const read = () => setPane((p) => (p && p.w === el.clientWidth && p.h === el.clientHeight ? p : { w: el.clientWidth, h: el.clientHeight }))
    read()
    const obs = new ResizeObserver(read)
    obs.observe(el)
    return () => obs.disconnect()
  }, [])
  // labels are measured in the app's fonts: lay out again once they are in
  useEffect(() => {
    let alive = true
    document.fonts?.ready.then(() => alive && setPane((p) => (p ? { ...p } : p)))
    return () => {
      alive = false
    }
  }, [])
  const drawing = useMemo(() => (graph && pane && pane.w > 0 ? drawGraph(graph, mode, Math.max(480, pane.w), Math.max(320, pane.h), tokens()) : null), [graph, mode, pane])

  useEffect(() => {
    if (!ref.current || !drawing) return
    if (!chartRef.current) chartRef.current = echarts.init(ref.current, undefined, { renderer: 'canvas' })
    const c = chartRef.current
    c.resize()
    const option = graphOption(drawing, tokens(), selectedStep, false, selectedNode ?? null)
    // the tooltip stays inside the part of the graph the pane shows
    ;(option.tooltip as Record<string, unknown>).position = (pt: number[], _p: unknown, _d: unknown, _r: unknown, size: { contentSize: number[] }) => {
      const el = scrollRef.current
      const [w, h] = size.contentSize
      const [x0, y0] = el ? [el.scrollLeft, el.scrollTop] : [0, 0]
      const [x1, y1] = el ? [x0 + el.clientWidth, y0 + el.clientHeight] : [drawing.layout.width, drawing.layout.height]
      const x = pt[0] + 14 + w > x1 - 4 ? pt[0] - 14 - w : pt[0] + 14
      const y = pt[1] + 14 + h > y1 - 4 ? pt[1] - 14 - h : pt[1] + 14
      return [Math.max(x0 + 4, Math.min(x, x1 - w - 4)), Math.max(y0 + 4, Math.min(y, y1 - h - 4))]
    }
    c.setOption(option, true)
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
    return () => {
      c.off('click', onClick as never)
    }
  }, [drawing, selectedStep, selectedNode, onStep, onEntity, onChain, onRecords, onEntityNode])
  useEffect(
    () => () => {
      chartRef.current?.dispose()
      chartRef.current = null
    },
    [],
  )

  // another chain opens at its start
  useEffect(() => {
    scrollRef.current?.scrollTo({ left: 0, top: 0 })
  }, [graph])
  // a step picked in the side pane or with j / k is scrolled into view
  useEffect(() => {
    const el = scrollRef.current
    if (!el || !drawing || (selectedStep == null && !selectedNode)) return
    const n = drawing.graph.nodes.find((x) => (selectedStep != null ? x.stepIdx === selectedStep || x.stepIdxs?.includes(selectedStep) : x.id === selectedNode))
    const p = n && drawing.layout.nodes.get(n.id)
    if (!p) return
    // the node with its label, and a little room around them
    const pad = 12
    const half = Math.max(p.size, p.label.width) / 2 + pad
    const y0 = (p.position === 'top' ? p.y - p.size / 2 - p.distance - p.label.height : p.y - p.size / 2) - pad
    const y1 = (p.position === 'bottom' ? p.y + p.size / 2 + p.distance + p.label.height : p.y + p.size / 2) + pad
    const left = p.x - half < el.scrollLeft || p.x + half > el.scrollLeft + el.clientWidth ? p.x - el.clientWidth / 2 : el.scrollLeft
    const top = y0 < el.scrollTop ? y0 : y1 > el.scrollTop + el.clientHeight ? Math.min(y0, y1 - el.clientHeight) : el.scrollTop
    if (left !== el.scrollLeft || top !== el.scrollTop) el.scrollTo({ left, top, behavior: 'smooth' })
  }, [drawing, selectedStep, selectedNode])

  // the edges of a graph wider than its pane: a shade on the side that has more
  useEffect(() => {
    const el = scrollRef.current
    const view = viewRef.current
    if (!el || !view) return
    const edges = () => {
      el.classList.toggle('scrolled', el.scrollLeft > 0)
      view.classList.toggle('more-right', el.scrollLeft + el.clientWidth < el.scrollWidth - 2)
    }
    edges()
    el.addEventListener('scroll', edges, { passive: true })
    return () => el.removeEventListener('scroll', edges)
  }, [drawing])

  // a chain wider than the pane is dragged sideways like a map with the mouse (touch scrolls it natively), and the wheel moves
  // it along; a campaign's nodes are dragged themselves
  useEffect(() => {
    const el = scrollRef.current
    if (!el || !lanes) return
    let from: { x: number; y: number; left: number; top: number } | null = null
    let moved = false
    const down = (e: PointerEvent) => {
      if (e.pointerType !== 'mouse' || e.button !== 0 || (el.scrollWidth <= el.clientWidth && el.scrollHeight <= el.clientHeight)) return
      from = { x: e.clientX, y: e.clientY, left: el.scrollLeft, top: el.scrollTop }
      moved = false
    }
    const move = (e: PointerEvent) => {
      if (!from) return
      const dx = e.clientX - from.x
      const dy = e.clientY - from.y
      if (!moved && Math.abs(dx) + Math.abs(dy) < 5) return
      moved = true
      el.classList.add('panning')
      el.scrollLeft = from.left - dx
      el.scrollTop = from.top - dy
    }
    const up = () => {
      from = null
      el.classList.remove('panning')
    }
    // the click that ends a drag is not a click on the node under the pointer
    const click = (e: MouseEvent) => {
      if (!moved) return
      moved = false
      e.stopPropagation()
    }
    // a timeline that only scrolls sideways: a mouse wheel scrolls it sideways (a trackpad's sideways swipe does already)
    const wheel = (e: WheelEvent) => {
      if (e.ctrlKey || Math.abs(e.deltaX) >= Math.abs(e.deltaY) || el.scrollHeight > el.clientHeight + 1 || el.scrollWidth <= el.clientWidth + 1) return
      el.scrollLeft += e.deltaY
      e.preventDefault()
    }
    el.addEventListener('pointerdown', down)
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
    window.addEventListener('pointercancel', up)
    el.addEventListener('click', click, true)
    el.addEventListener('wheel', wheel, { passive: false })
    return () => {
      el.removeEventListener('pointerdown', down)
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', up)
      window.removeEventListener('pointercancel', up)
      el.removeEventListener('click', click, true)
      el.removeEventListener('wheel', wheel)
    }
  }, [lanes])

  const size = drawing ? { width: drawing.layout.width, height: drawing.layout.height } : undefined
  return (
    <div className="chain-graph-wrap">
      <div ref={viewRef} className="chain-graph-view">
        <div ref={scrollRef} className={'chain-graph-scroll' + (lanes ? ' lanes' : '')}>
          <div className="chain-graph-stage" style={size}>
            {lanes && drawing && (
              <div className="chain-graph-lanes" aria-hidden="true">
                {drawing.layout.lanes.map((b) => (
                  <span key={b.lane} className="chain-graph-lane" style={{ top: b.y }}>
                    {b.name}
                  </span>
                ))}
              </div>
            )}
            <div ref={ref} className="chain-graph" style={size} />
          </div>
        </div>
      </div>
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
          hint="drag to pan, hover a line to see the tie, click a node"
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
          source files · drag to pan, click a record or an entity
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
