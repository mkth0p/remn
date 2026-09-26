import { LANE_LABEL, LANES, type GNode, type Graph, type Lane } from '../data/chainGraph'

/**
 * Pixel layouts for the chain, story and campaign graphs.
 *
 * A graph is drawn at its real size: one pixel of layout is one pixel on screen, so the shapes keep
 * their proportions and every label keeps the room it was given. A chain gets columns of one width
 * in time order and one band per lane. Each label is wrapped to its column (two lines of title, three
 * in the report picture, two of detail, then an ellipsis), and each band is as tall as its tallest node
 * and label, so no label reaches into the next lane. The entities of a lane (senders and domains above,
 * machines and IPs below) are packed side by side so no two labels touch, on a second or third row
 * when one row would push them too far from their steps, and inside the pane when the columns fit it.
 * A graph wider or taller than its pane scrolls: nothing is squeezed to fit.
 */

/** width of `text` drawn in the CSS `font` */
export type Measure = (text: string, font: string) => number

export interface LabelFonts {
  sans: string
  mono: string
  /** title size and line height */
  title: number
  titleLine: number
  /** detail line size and line height */
  sub: number
  subLine: number
  padX: number
  padY: number
}

export interface NodeLabel {
  title: string[]
  sub: string[]
  /** outer size of the label box, padding included */
  width: number
  height: number
}

export interface PlacedNode {
  x: number
  y: number
  size: number
  label: NodeLabel
  position: 'top' | 'bottom' | 'left' | 'right'
  /** gap between the symbol and its label box, as ECharts reads it */
  distance: number
}

export interface LaneBand {
  lane: Lane
  name: string
  top: number
  bottom: number
  /** centre line of the lane's first row of nodes, where the lane name sits */
  y: number
}

export interface GraphLayout {
  width: number
  height: number
  nodes: Map<string, PlacedNode>
  /** chain and story graphs: one band per lane, top to bottom */
  lanes: LaneBand[]
  /** campaign graph: the column titles */
  titles: { id: string; text: string; x: number; y: number }[]
}

export interface LayoutOptions {
  /** room the pane offers; the layout grows past it rather than squeeze */
  width: number
  height: number
  fonts: LabelFonts
  sizeOf: (n: GNode) => number
  measure?: Measure
  /** the report picture: it has to fit a page, so it takes narrower columns with a third line of title, and no more width than it uses */
  print?: boolean
}

export const fontOf = (size: number, family: string, weight = 400) => `${weight} ${size}px ${family}`

let ctx: CanvasRenderingContext2D | null | undefined

/** Text width on the canvas the graph draws on; an estimate where there is none (tests, jsdom). */
export const measureText: Measure = (text, font) => {
  if (ctx === undefined) {
    ctx = null
    // jsdom has canvas elements without a context and says so on the console: only ask a real browser
    if (typeof document !== 'undefined' && typeof navigator !== 'undefined' && !/jsdom/i.test(navigator.userAgent)) {
      try {
        ctx = document.createElement('canvas').getContext('2d')
      } catch {
        ctx = null
      }
    }
  }
  if (!ctx) return estimateWidth(text, font)
  ctx.font = font
  return ctx.measureText(text).width
}

/** a generous estimate of a text's width: monospace is 0.6 em a character, proportional type is read per character class */
export function estimateWidth(text: string, font: string): number {
  const size = Number(/([\d.]+)px/.exec(font)?.[1] ?? 12)
  if (/mono/i.test(font)) return Array.from(text).length * size * 0.6
  let em = 0
  for (const ch of text) em += /[\sil.,:;'|!()[\]]/.test(ch) ? 0.3 : /[mwMW@%]/.test(ch) ? 0.88 : /[A-Z0-9#&]/.test(ch) ? 0.66 : 0.56
  return em * size
}

/** a line may end after these */
const BREAK_AFTER = ' \\/@,:;|'
/** and, inside a word longer than a line, after these */
const SOFT_BREAK_AFTER = '-._=&?'
/** "+10 min → +22 min · 46 rows": a line breaks at the dot first, and drops it */
const PART = ' · '

/**
 * `text` in at most `maxLines` lines no wider than `maxWidth`. Lines break between the parts of a
 * "·" list, then after a space, a path separator or punctuation, inside a word only when the word is
 * wider than a line, and the last line ends with an ellipsis when the text does not fit.
 */
export function wrapText(text: string, maxWidth: number, maxLines: number, font: string, measure: Measure = measureText): string[] {
  const s = text.replace(/\s+/g, ' ').trim()
  if (!s || maxLines < 1) return []
  const width = (x: string) => measure(x, font)
  const lines: string[] = []
  let start = 0
  while (start < s.length) {
    const rest = s.slice(start)
    if (width(rest) <= maxWidth) {
      lines.push(rest)
      break
    }
    if (lines.length === maxLines - 1) {
      lines.push(ellipsize(rest, maxWidth, font, measure))
      break
    }
    const fit = fitEnd(s, start, maxWidth, width)
    const part = s.lastIndexOf(PART, fit - 1)
    if (part > start) {
      lines.push(s.slice(start, part))
      start = part + PART.length
      continue
    }
    const end = breakAt(s, start, fit)
    lines.push(s.slice(start, end).trimEnd())
    start = end
    while (s[start] === ' ') start++
  }
  return lines
}

/** the end of the longest slice of `s` from `start` that fits, at least one character */
function fitEnd(s: string, start: number, maxWidth: number, width: (x: string) => number): number {
  let lo = start + 1
  let hi = s.length
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2)
    if (width(s.slice(start, mid).trimEnd()) <= maxWidth) lo = mid
    else hi = mid - 1
  }
  return lo
}

/** where a line that could run to `end` breaks: after the last space or separator, else after a hyphen or a dot past the line's first third, else at `end` */
function breakAt(s: string, start: number, end: number): number {
  if (end >= s.length) return end
  for (let i = end; i > start; i--) if (s[i] === ' ' || BREAK_AFTER.includes(s[i - 1])) return i
  const floor = start + Math.floor((end - start) / 3)
  for (let i = end; i > floor; i--) if (SOFT_BREAK_AFTER.includes(s[i - 1]) || s[i] === '(') return i
  return end
}

/** the longest start of `text` that fits with an ellipsis */
export function ellipsize(text: string, maxWidth: number, font: string, measure: Measure = measureText): string {
  if (measure(text, font) <= maxWidth) return text
  let lo = 0
  let hi = text.length
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2)
    if (measure(text.slice(0, mid).trimEnd() + '…', font) <= maxWidth) lo = mid
    else hi = mid - 1
  }
  return text.slice(0, lo).trimEnd() + '…'
}

/** "C:\Users\bob\Downloads\invoice.pdf.exe" -> "C:\…\invoice.pdf.exe": in a label that runs out of room the folders go before the file name */
export function shortenPaths(text: string): string {
  return text.replace(/([A-Za-z]:\\|\\\\[^\\\s]+\\)((?:[^\\\s]+\\){2,})([^\\\s]+)/g, '$1…\\$3').replace(/(^|\s)\/((?:[^/\s]+\/){2,})([^/\s]+)/g, '$1/…/$3')
}

/** ECharts rich text ends a styled run at "}": the label shows a lookalike, the tooltip the evidence as it is */
const richSafe = (s: string) => s.replace(/}/g, '\uff5d')

/** A node's label wrapped to `textWidth`: the title on up to `lines.title` lines, the detail under it on up to `lines.sub`. */
export function nodeLabel(title: string, sub: string | undefined, textWidth: number, f: LabelFonts, lines: { title: number; sub: number }, measure: Measure = measureText): NodeLabel {
  // measured bold: a selected node's title is drawn at 600 and must still fit
  const tf = fontOf(f.title, f.sans, 600)
  const sf = fontOf(f.sub, f.mono)
  const fit = (text: string, font: string, n: number) => {
    const clean = richSafe(text)
    const out = wrapText(clean, textWidth, n, font, measure)
    if (out[out.length - 1]?.endsWith('…')) {
      const short = shortenPaths(clean)
      if (short !== clean) return wrapText(short, textWidth, n, font, measure)
    }
    return out
  }
  const t = fit(title, tf, lines.title)
  const s = sub ? fit(sub, sf, lines.sub) : []
  const w = Math.max(0, ...t.map((l) => measure(l, tf)), ...s.map((l) => measure(l, sf)))
  return { title: t, sub: s, width: Math.ceil(w) + 2 * f.padX, height: t.length * f.titleLine + s.length * f.subLine + 2 * f.padY }
}

/** the lane names: a pill on the left of each band (drawn by the page, or on the picture for the report) */
export const LANE_PILL = { left: 10, size: 10, padX: 8, border: 1 }
/** room between two labels side by side */
const GAP = 12
/** between a node and its label */
const LABEL_GAP = 5
/** inside a band, above and below its rows */
const BAND_PAD = 12
/** between two rows of one band */
const ROW_GAP = 10
/** most rows a crowded lane takes */
const MAX_ROWS = 3
/** most height a band gains when the pane is taller than the graph */
const MAX_EXTRA = 40
/** past the last column */
const RIGHT = 24
/** node kinds that sit on a time column; the others (senders, domains, machines, IPs, files) sit where their neighbours are */
const COLUMN_KINDS = new Set<GNode['kind']>(['seed', 'step', 'routine', 'user', 'chain'])

interface Item {
  id: string
  /** where the node wants its centre */
  d: number
  /** room it takes: its label or its symbol, whichever is wider */
  w: number
  x: number
  row: number
}

/**
 * One row of items in order, none overlapping: runs that would collide are pushed apart around the mean of where they want to be,
 * kept between `minX` and `maxX` (the left edge wins when a row is too crowded for both).
 */
function packRow(row: Item[], minX: number, maxX: number): void {
  type Run = { items: Item[]; start: number; width: number }
  const runs: Run[] = []
  const place = (start: number, width: number) => Math.max(minX, Math.min(maxX - width, start))
  const ideal = (items: Item[], width: number) => {
    let off = 0
    let sum = 0
    for (const it of items) {
      sum += it.d - it.w / 2 - off
      off += it.w + GAP
    }
    return place(sum / items.length, width)
  }
  for (const it of row) {
    let run: Run = { items: [it], start: place(it.d - it.w / 2, it.w), width: it.w }
    while (runs.length) {
      const prev = runs[runs.length - 1]
      if (prev.start + prev.width + GAP <= run.start + 1e-6) break
      runs.pop()
      const items = [...prev.items, ...run.items]
      const width = prev.width + GAP + run.width
      run = { items, start: ideal(items, width), width }
    }
    runs.push(run)
  }
  for (const run of runs) {
    let x = run.start
    for (const it of run.items) {
      it.x = x + it.w / 2
      x += it.w + GAP
    }
  }
}

/** Items of one lane on as few rows as keep each within `tolerance` of where it wants to be (at most MAX_ROWS). */
function packLane(items: Item[], minX: number, maxX: number, tolerance: number): void {
  const sorted = [...items].sort((a, b) => a.d - b.d)
  let best: { worst: number; at: [number, number][] } | null = null
  for (let rows = 1; rows <= MAX_ROWS; rows++) {
    const ends = new Array<number>(rows).fill(-Infinity)
    for (const it of sorted) {
      // the first row where it fits as it is, else the row that pushes it least
      let pick = 0
      let shift = Infinity
      for (let r = 0; r < rows; r++) {
        const s = Math.max(0, ends[r] + GAP + it.w / 2 - it.d)
        if (s < shift - 0.5) {
          pick = r
          shift = s
        }
      }
      it.row = pick
      ends[pick] = it.d + shift + it.w / 2
    }
    for (let r = 0; r < rows; r++)
      packRow(
        sorted.filter((it) => it.row === r),
        minX,
        maxX,
      )
    const worst = Math.max(0, ...sorted.map((it) => Math.abs(it.x - it.d)))
    if (!best || worst < best.worst - 0.5) best = { worst, at: sorted.map((it) => [it.x, it.row]) }
    if (worst <= tolerance) break
  }
  sorted.forEach((it, i) => {
    ;[it.x, it.row] = best!.at[i]
  })
}

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v))

/** Chain and story graphs: lanes top to bottom, time left to right, every node and label in its own room. */
export function layoutLanes(graph: Graph, o: LayoutOptions): GraphLayout {
  const measure = o.measure ?? measureText
  const f = o.fonts
  const lanes = LANES.filter((l) => graph.nodes.some((n) => n.lane === l))
  const pillFont = fontOf(LANE_PILL.size, f.sans, 600)
  const pillW = Math.max(0, ...lanes.map((l) => measure(LANE_LABEL[l], pillFont))) + 2 * (LANE_PILL.padX + LANE_PILL.border)
  const gutter = Math.ceil(LANE_PILL.left + pillW + GAP)
  const columns = Math.max(1, graph.columns, Math.ceil(Math.max(0, ...graph.nodes.map((n) => n.x))) + 1)
  const [minCol, maxCol, titleLines] = o.print ? [100, 230, 3] : [144, 210, 2]
  const colW = Math.floor(clamp((o.width - gutter - RIGHT) / columns, minCol, maxCol))
  const colX = (x: number) => gutter + x * colW + colW / 2
  const entityText = Math.max(colW - GAP - 2 * f.padX, o.print ? 200 : 170)
  // nothing passes this unless a row is too crowded: the pane (or the page) when the columns fit it; past them, the graph
  // scrolls anyway and the last column may take half a column more on screen
  const gridRight = gutter + columns * colW
  const maxX = gridRight <= o.width - RIGHT ? o.width - RIGHT : gridRight + (o.print ? 0 : colW / 2)
  // a node on a time column takes its column, and more when the columns beside it in its lane are empty:
  // half the way to its nearest neighbour on either side, so two neighbours never claim the same room
  const room = new Map<string, number>()
  for (const lane of lanes) {
    const row = graph.nodes.filter((n) => n.lane === lane && COLUMN_KINDS.has(n.kind)).sort((a, b) => a.x - b.x)
    row.forEach((n, i) => {
      const x = colX(n.x)
      const left = i ? x - colX(row[i - 1].x) : 2 * (x - gutter)
      const right = i < row.length - 1 ? colX(row[i + 1].x) - x : 2 * (maxX - x)
      room.set(n.id, clamp(Math.min(left, right, 2 * colW, 300), colW, Infinity) - GAP)
    })
  }

  const labels = new Map<string, NodeLabel>()
  const sizes = new Map<string, number>()
  const byLane = new Map<Lane, Item[]>()
  for (const n of graph.nodes) {
    const slot = room.get(n.id)
    const label = slot ? nodeLabel(n.label, n.sub, slot - 2 * f.padX, f, { title: titleLines, sub: 2 }, measure) : nodeLabel(n.label, n.sub, entityText, f, { title: 2, sub: 1 }, measure)
    const size = o.sizeOf(n)
    labels.set(n.id, label)
    sizes.set(n.id, size)
    const list = byLane.get(n.lane) ?? []
    list.push({ id: n.id, d: colX(n.x), w: Math.max(label.width, size), x: 0, row: 0 })
    byLane.set(n.lane, list)
  }

  // across: each lane packed on its own rows
  for (const items of byLane.values()) packLane(items, gutter + 2, maxX, colW * 0.75)

  // down: each band as tall as its rows, labels above the nodes in the top lane (its edges all go down), below elsewhere
  type Row = { node: number; label: number; items: Item[] }
  const bands = lanes.map((lane) => {
    const items = byLane.get(lane) ?? []
    const rows: Row[] = []
    for (const it of items) {
      const r = (rows[it.row] ??= { node: 0, label: 0, items: [] })
      r.items.push(it)
      r.node = Math.max(r.node, sizes.get(it.id)!)
      r.label = Math.max(r.label, labels.get(it.id)!.height)
    }
    const used = rows.filter(Boolean)
    const height = 2 * BAND_PAD + used.reduce((h, r) => h + r.node + LABEL_GAP + r.label, 0) + ROW_GAP * (used.length - 1)
    return { lane, rows: used, height }
  })
  const natural = bands.reduce((h, b) => h + b.height, 0)
  // a pane taller than the graph: the bands share the room, a little each
  const extra = bands.length ? clamp((o.height - natural) / bands.length, 0, MAX_EXTRA) : 0

  const nodes = new Map<string, PlacedNode>()
  const laneBands: LaneBand[] = []
  let top = 0
  for (const b of bands) {
    const bottom = top + b.height + extra
    const above = b.lane === 'attacker'
    let y = above ? bottom - BAND_PAD - extra / 2 : top + BAND_PAD + extra / 2
    let firstRow = 0
    b.rows.forEach((r, i) => {
      const centre = above ? y - r.node / 2 : y + r.node / 2
      if (i === 0) firstRow = centre
      for (const it of r.items) {
        const size = sizes.get(it.id)!
        nodes.set(it.id, { x: it.x, y: centre, size, label: labels.get(it.id)!, position: above ? 'top' : 'bottom', distance: (r.node - size) / 2 + LABEL_GAP })
      }
      const step = r.node + LABEL_GAP + r.label + ROW_GAP
      y += above ? -step : step
    })
    laneBands.push({ lane: b.lane, name: LANE_LABEL[b.lane], top, bottom, y: firstRow })
    top = bottom
  }

  const right = Math.max(gridRight, ...Array.from(byLane.values()).flatMap((items) => items.map((it) => it.x + it.w / 2)))
  return {
    width: Math.ceil(o.print ? right + RIGHT : Math.max(o.width, right + RIGHT)),
    height: Math.ceil(Math.max(o.height, top)),
    nodes,
    lanes: laneBands,
    titles: [],
  }
}

/** the campaign's three columns: attacker entities, the chains (people), machines and IPs */
export const CAMPAIGN_COLUMNS: { lane: Lane; title: string }[] = [
  { lane: 'attacker', title: 'attacker side' },
  { lane: 'identity', title: 'people' },
  { lane: 'infra', title: 'machines & IPs' },
]

/** Campaign graph: attacker entities left, the chains in the middle, machines and IPs right, each column ordered to keep edges short. */
export function layoutCampaign(graph: Graph, o: LayoutOptions): GraphLayout {
  const measure = o.measure ?? measureText
  const f = o.fonts
  const labels = new Map<string, NodeLabel>()
  for (const n of graph.nodes) labels.set(n.id, nodeLabel(n.label, n.sub, n.kind === 'chain' ? (o.print ? 300 : 260) : o.print ? 230 : 200, f, { title: 2, sub: 1 }, measure))
  const chains = graph.nodes.filter((n) => n.kind === 'chain').sort((a, b) => (b.score ?? 0) - (a.score ?? 0))
  const rank = new Map(chains.map((c, i) => [c.id, i]))
  const bary = (n: GNode) => {
    const r = graph.edges.filter((e) => e.target === n.id || e.source === n.id).map((e) => rank.get(e.source === n.id ? e.target : e.source) ?? 0)
    return r.length ? r.reduce((a, b) => a + b, 0) / r.length : 0
  }
  const column = (lane: Lane) =>
    graph.nodes
      .filter((n) => n.lane === lane)
      .map((n) => ({ n, b: bary(n) }))
      .sort((a, b) => a.b - b.b || (b.n.degree ?? 0) - (a.n.degree ?? 0) || a.n.label.localeCompare(b.n.label))
      .map((x) => x.n)
  const left = column('attacker')
  const right = column('infra')
  const widest = (ns: GNode[]) => Math.max(0, ...ns.map((n) => labels.get(n.id)!.width))
  const tallest = (ns: GNode[]) => Math.max(0, ...ns.map((n) => labels.get(n.id)!.height))
  const biggest = (ns: GNode[]) => Math.max(0, ...ns.map((n) => o.sizeOf(n)))
  const margin = 16
  const edgeRoom = 90
  const chainRow = Math.max(84, biggest(chains) + LABEL_GAP + tallest(chains) + 16)
  const sideRow = Math.max(46, tallest([...left, ...right]) + 10, biggest([...left, ...right]) + 10)
  const leftW = margin + widest(left) + LABEL_GAP + biggest(left)
  const rightW = margin + widest(right) + LABEL_GAP + biggest(right)
  const width = Math.ceil(Math.max(o.width, leftW + rightW + widest(chains) + 2 * edgeRoom))
  const xLeft = Math.max(width * 0.2, leftW - biggest(left) / 2)
  const xRight = Math.min(width * 0.8, width - rightW + biggest(right) / 2)
  const titleRoom = 48
  const content = Math.max(chains.length * chainRow, left.length * sideRow, right.length * sideRow)
  const height = Math.ceil(Math.max(o.height, titleRoom + content + 16))
  const nodes = new Map<string, PlacedNode>()
  let firstTop = height
  const place = (ns: GNode[], x: number, row: number, position: PlacedNode['position']) => {
    const top = titleRoom + Math.max(0, (height - 16 - titleRoom - ns.length * row) / 2)
    if (ns.length) firstTop = Math.min(firstTop, top)
    ns.forEach((n, i) => nodes.set(n.id, { x, y: top + i * row + row / 2, size: o.sizeOf(n), label: labels.get(n.id)!, position, distance: LABEL_GAP }))
  }
  place(chains, (xLeft + xRight) / 2, chainRow, 'bottom')
  place(left, xLeft, sideRow, 'left')
  place(right, xRight, sideRow, 'right')
  const titleY = Math.max(14, firstTop - 22)
  const xOf: Record<string, number> = { attacker: xLeft, identity: (xLeft + xRight) / 2, infra: xRight }
  const titles = CAMPAIGN_COLUMNS.filter((c) => graph.nodes.some((n) => n.lane === c.lane)).map((c) => ({ id: `col:${c.lane}`, text: c.title, x: xOf[c.lane], y: titleY }))
  return { width, height, nodes, lanes: [], titles }
}
