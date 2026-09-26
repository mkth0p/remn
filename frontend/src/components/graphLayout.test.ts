import { describe, expect, it } from 'vitest'
import type { Chain, ChainStep } from '../data/chains'
import { buildCampaignGraph, buildChainGraph, type Graph } from '../data/chainGraph'
import { drawGraph, graphOption, PRINT_TOKENS, type GraphTokens } from './ChainGraph'
import { estimateWidth, shortenPaths, wrapText, type GraphLayout, type PlacedNode } from './graphLayout'

const M = 60_000
const T0 = Date.UTC(2026, 8, 2, 9, 10)
const SCREEN: GraphTokens = { ...PRINT_TOKENS, sans: "'Inter Variable', Inter, sans-serif", mono: "'JetBrains Mono Variable', monospace" }

const step = (p: Partial<ChainStep> & { title: string; min: number }): ChainStep => ({
  kind: 'event',
  source: 'events',
  id: null,
  count: 1,
  weight: 6,
  artifacts: [],
  findings: [{ ruleId: 'r', title: 'a finding', severity: 'high' }],
  ts: T0 + p.min * M,
  tsEnd: T0 + p.min * M,
  offsetMin: p.min,
  origin: 'host',
  computer: 'WS-002.northstar.example',
  ...p,
})

/** a chain shaped like the linked lab's attachment case: long host titles, a mailbox run, a forwarding rule, routine logons from many IPs */
function labChain(): Chain {
  const link = ['mail URL domain delivery-review.example']
  const file = ['mail attachment shipping_ns-002.pdf.exe']
  const steps: ChainStep[] = [
    step({ title: 'sign-in from FR via Browser to Office 365 Exchange Online', min: 1, origin: 'm365', computer: null, ipAddress: '198.51.100.10' }),
    step({ title: 'DNS query delivery-review.example', min: 2, artifacts: link, findings: [] }),
    step({ title: 'file created C:\\Users\\benoit.durand\\Downloads\\Shipping_NS-002.pdf.exe', min: 3, artifacts: file }),
    step({ title: 'network connection msedge.exe -> delivery-review.example:443', min: 4, artifacts: link, findings: [] }),
    step({
      title: 'reply to the sender: RE: [S02] Urgent invoice NS-02',
      min: 5,
      kind: 'mail',
      source: 'mails',
      origin: undefined,
      computer: null,
      artifacts: ['victim engaged with the sender', 'same thread'],
    }),
    step({ title: 'logon (RemoteInteractive) on WS-002.northstar.example from 203.0.113.67', min: 6, ipAddress: '203.0.113.67' }),
    step({ title: 'process powershell.exe spawned by outlook.exe: powershell.exe -NoProfile -Command Write-Output', min: 7, artifacts: [...link, ...file] }),
    step({ title: "PowerShell script block: Write-Output 'SYNTHETIC S02: Shipping_NS-002.pdf.exe https://delivery-review.example/stage'", min: 8, artifacts: [...link, ...file] }),
    step({ title: 'failed sign-in (50126) from NL via Other clients to Office 365 Exchange Online ×7', min: 10, origin: 'm365', computer: null, ipAddress: '203.0.113.67', count: 7 }),
    step({ title: 'persistence (4698): A scheduled task was created \\Northstar\\Updater-S02', min: 14 }),
    ...Array.from({ length: 30 }, (_, i) => step({ title: 'mailbox items accessed (Sync)', min: 17 + i * 0.2, origin: 'm365', computer: null, ipAddress: '203.0.113.67' })),
    step({ title: "inbox rule created 'Invoice routing': forward to finance@delivery-review.example, deletes", min: 26, origin: 'm365', computer: null, artifacts: ['forwarding rule'] }),
    step({ title: 'mailbox forwarding to smtp:finance@delivery-review.example', min: 35, origin: 'm365', computer: null, artifacts: ['mailbox forwarding'] }),
    step({ title: 'OAuth consent granted (Northstar Document Helper S02) scope Mail.Read Mail.ReadWrite offline_access', min: 47, origin: 'm365', computer: null }),
    ...['10.20.5.71', '10.20.1.11', '10.20.5.191', '10.20.1.131', '10.20.5.72', '10.20.1.12'].map((ip, i) =>
      step({
        title: `logon (Network) on WS-00${2 + (i % 2)}.northstar.example from ${ip}`,
        min: 60 + i * 300,
        weight: 1,
        findings: [],
        ipAddress: ip,
        computer: `WS-00${2 + (i % 2)}.northstar.example`,
      }),
    ),
  ]
  return {
    id: 'c-benoit',
    identity: 'benoit.durand',
    identityLabel: 'benoit.durand@northstar.example',
    seed: {
      id: 1,
      ts: T0,
      subject: '[S02] Urgent invoice NS-02',
      fromAddr: 'documents@delivery-review.example',
      risk: 90,
      flags: [],
      findings: [],
      urlDomains: ['delivery-review.example'],
      attachments: ['shipping_ns-002.pdf.exe'],
    },
    steps,
    start: T0,
    end: T0 + 3000 * M,
    score: 97,
    severity: 'critical',
    artifactLinks: 8,
    entities: { user: 'benoit.durand@northstar.example', ips: [], hosts: [], attackerAddresses: [], domains: [] },
    summary: 's',
  }
}

type Box = { x: number; y: number; w: number; h: number; what: string }
const symbolBox = (id: string, p: PlacedNode): Box => ({ x: p.x - p.size / 2, y: p.y - p.size / 2, w: p.size, h: p.size, what: `symbol ${id}` })
function labelBox(id: string, p: PlacedNode): Box {
  const { width: w, height: h } = p.label
  const what = `label ${id}`
  if (p.position === 'bottom') return { x: p.x - w / 2, y: p.y + p.size / 2 + p.distance, w, h, what }
  if (p.position === 'top') return { x: p.x - w / 2, y: p.y - p.size / 2 - p.distance - h, w, h, what }
  if (p.position === 'left') return { x: p.x - p.size / 2 - p.distance - w, y: p.y - h / 2, w, h, what }
  return { x: p.x + p.size / 2 + p.distance, y: p.y - h / 2, w, h, what }
}
const overlap = (a: Box, b: Box) => a.x < b.x + b.w - 0.5 && b.x < a.x + a.w - 0.5 && a.y < b.y + b.h - 0.5 && b.y < a.y + a.h - 0.5

/** every pair of symbols and labels that touch, and everything that leaves the drawing */
function collisions(layout: GraphLayout): string[] {
  const boxes = Array.from(layout.nodes.entries()).flatMap(([id, p]) => [symbolBox(id, p), labelBox(id, p)])
  const out: string[] = []
  for (let i = 0; i < boxes.length; i++) {
    const a = boxes[i]
    if (a.x < 0 || a.y < 0 || a.x + a.w > layout.width || a.y + a.h > layout.height) out.push(`${a.what} leaves the drawing`)
    for (let j = i + 1; j < boxes.length; j++) {
      const b = boxes[j]
      // a node's own label sits against its symbol
      if (a.what.split(' ')[1] === b.what.split(' ')[1]) continue
      if (overlap(a, b)) out.push(`${a.what} × ${b.what}`)
    }
  }
  return out
}

describe('the chain graph layout', () => {
  const graph = buildChainGraph(labChain())

  it.each([
    [480, 320],
    [830, 560],
    [1076, 670],
    [1600, 900],
    [2600, 1100],
  ])('draws a long chain in a %i × %i pane with no symbol or label over another, none outside the drawing', (w, h) => {
    const { layout } = drawGraph(graph, 'chain', w, h, SCREEN)
    expect(collisions(layout)).toEqual([])
    expect(layout.width).toBeGreaterThanOrEqual(w)
    expect(layout.height).toBeGreaterThanOrEqual(h)
  })

  it('keeps every node and its label inside its own lane', () => {
    const { layout } = drawGraph(graph, 'chain', 900, 400, SCREEN)
    expect(layout.lanes.map((b) => b.lane)).toEqual(['attacker', 'mail', 'identity', 'cloud', 'host', 'infra'])
    for (const n of graph.nodes) {
      const p = layout.nodes.get(n.id)!
      const band = layout.lanes.find((b) => b.lane === n.lane)!
      for (const box of [symbolBox(n.id, p), labelBox(n.id, p)]) {
        expect(box.y, `${box.what} starts above its lane`).toBeGreaterThanOrEqual(band.top)
        expect(box.y + box.h, `${box.what} ends below its lane`).toBeLessThanOrEqual(band.bottom)
      }
    }
    // the bands follow each other without a gap or an overlap
    layout.lanes.slice(1).forEach((b, i) => expect(b.top).toBe(layout.lanes[i].bottom))
  })

  it('never squeezes: a narrow pane gets a wider drawing, with the steps in time order one column apart', () => {
    const { layout } = drawGraph(graph, 'chain', 600, 400, SCREEN)
    expect(layout.width).toBeGreaterThan(1500)
    const steps = graph.nodes.filter((n) => n.kind === 'step' || n.kind === 'routine').sort((a, b) => a.x - b.x)
    const xs = steps.map((n) => layout.nodes.get(n.id)!.x)
    xs.slice(1).forEach((x, i) => expect(x - xs[i]).toBeGreaterThanOrEqual(144))
    // the seed column and every step's column share one width
    expect(new Set(xs.slice(1).map((x, i) => Math.round(x - xs[i]))).size).toBe(1)
  })

  it('keeps a chain whose columns fit the pane inside it, entities and the last labels included', () => {
    const { layout } = drawGraph(graph, 'chain', 2600, 1100, SCREEN)
    expect(layout.width).toBe(2600)
  })

  it('wraps labels to their room and shortens a path to its file name before cutting it', () => {
    const { layout } = drawGraph(graph, 'chain', 1076, 670, SCREEN)
    const labelOf = (re: RegExp) => layout.nodes.get(graph.nodes.find((n) => re.test(n.label))!.id)!.label
    const file = labelOf(/^file created/)
    expect(file.title.join(' ')).toContain('C:\\…\\')
    expect(file.title.length).toBeLessThanOrEqual(2)
    // a step with empty columns beside it in its lane takes their room and prints whole
    expect(labelOf(/^sign-in from FR/).title.join(' ')).toBe('sign-in from FR via Browser to Office 365 Exchange Online')
    for (const p of layout.nodes.values()) expect(p.label.title.length + p.label.sub.length).toBeLessThanOrEqual(4)
  })

  it('lays the report picture out to fit its width, just as clear', () => {
    const { layout } = drawGraph(graph, 'chain', 1700, 0, PRINT_TOKENS, true)
    expect(collisions(layout)).toEqual([])
    // it fits the width the report gives it, as a page must
    expect(layout.width).toBeLessThanOrEqual(1700)
  })

  it('maps one layout pixel to one screen pixel and names no edge on the graph itself', () => {
    const d = drawGraph(graph, 'chain', 1076, 670, SCREEN)
    const option = graphOption(d, SCREEN, 3)
    const series = (option.series as Record<string, unknown>[])[0]
    // the view box is the drawing's box, and two corner points pin the data's box to it: ECharts neither stretches nor squeezes
    expect(series).toMatchObject({ left: 0, top: 0, width: d.layout.width, height: d.layout.height, roam: false })
    const data = series.data as { id: string; x: number; y: number }[]
    expect(data.find((p) => p.id === 'corner:0')).toMatchObject({ x: 0, y: 0 })
    expect(data.find((p) => p.id === 'corner:1')).toMatchObject({ x: d.layout.width, y: d.layout.height })
    for (const p of data) {
      expect(p.x).toBeGreaterThanOrEqual(0)
      expect(p.x).toBeLessThanOrEqual(d.layout.width)
      expect(p.y).toBeGreaterThanOrEqual(0)
      expect(p.y).toBeLessThanOrEqual(d.layout.height)
    }
    const links = series.links as { label: { show: boolean }; edge?: { label?: string } }[]
    expect(links.filter((l) => l.edge?.label).length).toBeGreaterThan(3)
    expect(links.every((l) => !l.label.show)).toBe(true)
    // the lane names are the page's, pinned while the timeline scrolls; the report picture draws its own
    expect(data.some((p) => p.id === 'lane:host')).toBe(false)
    const printed = (graphOption(d, SCREEN, null, true).series as { data: { id: string }[] }[])[0].data
    expect(printed.some((p) => p.id === 'lane:host')).toBe(true)
  })

  it('outlines the group a selected step was folded into', () => {
    const d = drawGraph(graph, 'chain', 1076, 670, SCREEN)
    const group = graph.nodes.find((n) => (n.stepIdxs?.length ?? 0) > 5)!
    const data = (graphOption(d, SCREEN, group.stepIdxs![3]).series as { data: { id: string; itemStyle: { borderWidth: number } }[] }[])[0].data
    expect(data.find((p) => p.id === group.id)!.itemStyle.borderWidth).toBe(3)
  })
})

describe('the campaign graph layout', () => {
  it('keeps twenty chains readable: one row each, the drawing grows instead', () => {
    const chains = Array.from({ length: 20 }, (_, i) => {
      const c = labChain()
      return {
        ...c,
        id: `c${i}`,
        identityLabel: `employee${String(i).padStart(3, '0')}@northstar.example`,
        score: 99 - i,
        entities: {
          user: `employee${i}`,
          ips: ['198.51.100.10', `203.0.113.${i}`, `10.20.${i}.7`],
          hosts: [`WS-${i}.northstar.example`, ...(i % 3 ? [] : ['FS-001.northstar.example'])],
          attackerAddresses: [`billing${i % 4}@supplier-verify.example`],
          domains: [`consent-review-${i % 5}.example`, 'delivery-review.example'],
        },
      }
    })
    const g: Graph = buildCampaignGraph(chains)
    const d = drawGraph(g, 'campaign', 1076, 560, SCREEN)
    expect(collisions(d.layout)).toEqual([])
    expect(d.layout.height).toBeGreaterThan(560)
  })
})

describe('wrapText', () => {
  const font = '600 11px Inter'
  const measure = estimateWidth

  it('breaks at spaces, keeps every line within the width and ends a cut text with an ellipsis', () => {
    const text = 'process powershell.exe spawned by outlook.exe: powershell.exe -NoProfile -Command Write-Output'
    const lines = wrapText(text, 110, 2, font, measure)
    expect(lines).toHaveLength(2)
    for (const l of lines) expect(measure(l, font)).toBeLessThanOrEqual(110)
    expect(lines[0]).toBe('process')
    expect(lines[1].endsWith('…')).toBe(true)
    expect(wrapText('DNS query', 110, 2, font, measure)).toEqual(['DNS query'])
  })

  it('breaks a "·" list between its parts and drops the dot', () => {
    expect(wrapText('+47 min → +4.2 h · 4 rows', 100, 2, '9.5px monospace', measure)).toEqual(['+47 min → +4.2 h', '4 rows'])
  })

  it('breaks a word longer than a line after a separator or a hyphen', () => {
    expect(wrapText('documents@delivery-review.example', 140, 2, font, measure)).toEqual(['documents@', 'delivery-review.example'])
    expect(wrapText('delivery-review-portal.example', 80, 2, font, measure)[0]).toBe('delivery-')
  })

  it('shortens paths to their file name', () => {
    expect(shortenPaths('file created C:\\Users\\bob\\Downloads\\invoice.pdf.exe')).toBe('file created C:\\…\\invoice.pdf.exe')
    expect(shortenPaths('ran /usr/local/lib/tool/run.sh and /tmp/x')).toBe('ran /…/run.sh and /tmp/x')
    expect(shortenPaths('open https://example.com/a/b/c')).toBe('open https://example.com/a/b/c')
  })
})
