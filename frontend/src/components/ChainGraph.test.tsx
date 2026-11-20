// @vitest-environment jsdom
import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Chain, ChainStep } from '../data/chains'
import type { Graph } from '../data/chainGraph'

/**
 * The graph pane around the chart: ECharts draws on a canvas jsdom does not have, so a stand-in
 * chart keeps the option it is given and the click handler it is handed, as ECharts would.
 */
interface FakeChart {
  option: Record<string, unknown> | null
  click: ((p: unknown) => void) | null
  disposed: boolean
}
const charts = vi.hoisted(() => [] as FakeChart[])
vi.mock('echarts/core', () => ({
  use: () => {},
  init: () => {
    const c: FakeChart = { option: null, click: null, disposed: false }
    charts.push(c)
    return {
      resize: () => {},
      setOption: (o: Record<string, unknown>) => void (c.option = o),
      on: (_ev: string, h: (p: unknown) => void) => void (c.click = h),
      off: () => void (c.click = null),
      dispose: () => void (c.disposed = true),
    }
  },
}))
vi.mock('echarts/charts', () => ({ GraphChart: {} }))
vi.mock('echarts/components', () => ({ LegendComponent: {}, TooltipComponent: {} }))
vi.mock('echarts/renderers', () => ({ CanvasRenderer: {} }))

const { ChainGraph } = await import('./ChainGraph')

const M = 60_000
const step = (p: Partial<ChainStep> & { title: string; ts: number }): ChainStep => ({
  kind: 'event',
  source: 'events',
  id: null,
  count: 1,
  weight: 5,
  artifacts: [],
  findings: [{ ruleId: 'r', title: 'a finding', severity: 'high' }],
  offsetMin: (p.ts - 1000) / M,
  tsEnd: p.ts,
  origin: 'host',
  computer: 'WS-1.corp.example',
  ...p,
})
// an invented chain: a lure, a sign-in and a process on the recipient's machine
const chain = (id: string, user: string, ip: string): Chain => ({
  id,
  identity: user,
  identityLabel: `${user}@corp.example`,
  start: 1000,
  end: 1000 + 30 * M,
  score: 80,
  severity: 'high',
  artifactLinks: 1,
  summary: 's',
  seed: { id: 7, ts: 1000, subject: 'Invoice <b>{b}</b>', fromAddr: 'billing@lure.example', risk: 85, flags: [], findings: [], urlDomains: ['lure.example'], attachments: [] },
  entities: { user: `${user}@corp.example`, ips: [ip], hosts: ['WS-1.corp.example'], attackerAddresses: ['billing@lure.example'], domains: ['lure.example'] },
  steps: [
    step({ title: 'sign-in from NL', ts: 1000 + 2 * M, origin: 'm365', ipAddress: ip }),
    step({ title: 'powershell downloads from lure.example', ts: 1000 + 9 * M, artifacts: ['mail URL domain lure.example'] }),
  ],
})

type Node = { id: string; name: string; label?: { formatter?: () => string }; node?: { kind: string; stepIdx?: number; chainId?: string } }
const chart = () => charts[charts.length - 1]
const nodes = () => ((chart().option!.series as { data: Node[] }[])[0].data ?? []).filter((n) => n.node)
const click = (n: Node) => chart().click!({ dataType: 'node', data: n })
const handlers = () => ({ onStep: vi.fn(), onEntity: vi.fn(), onChain: vi.fn(), onRecords: vi.fn(), onEntityNode: vi.fn() })

beforeEach(() => {
  charts.length = 0
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      disconnect() {}
    },
  )
  // jsdom lays nothing out: the pane is given a size, as a browser would
  vi.spyOn(HTMLElement.prototype, 'clientWidth', 'get').mockReturnValue(900)
  vi.spyOn(HTMLElement.prototype, 'clientHeight', 'get').mockReturnValue(500)
  Element.prototype.scrollTo = () => {}
})
afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('the chain graph', () => {
  it('draws a chain on its lanes, with the key to its shapes', () => {
    const h = handlers()
    const { container } = render(<ChainGraph mode="chain" chain={chain('c1', 'alice', '203.0.113.9')} chains={[]} selectedStep={null} {...h} />)
    expect(nodes().length).toBeGreaterThan(2)
    expect([...container.querySelectorAll('.chain-graph-lane')].map((l) => l.textContent)).toContain('mailbox')
    expect(screen.getByText('seed mail')).toBeTruthy()
    expect(screen.getByText(/drag to pan, hover a line to see the tie/)).toBeTruthy()
  })

  it('opens the step, the chain or the entity a click lands on', () => {
    const h = handlers()
    render(<ChainGraph mode="chain" chain={chain('c1', 'alice', '203.0.113.9')} chains={[]} selectedStep={null} {...h} />)
    const stepNode = nodes().find((n) => n.node?.kind === 'step')!
    click(stepNode)
    expect(h.onStep).toHaveBeenCalledWith(stepNode.node!.stepIdx)
    chart().click!({ dataType: 'edge', data: {} })
    expect(h.onStep).toHaveBeenCalledTimes(1)
  })

  it('writes the evidence into labels and tooltips as text, never as a template or as HTML', () => {
    render(<ChainGraph mode="chain" chain={chain('c1', 'alice', '203.0.113.9')} chains={[]} selectedStep={null} {...handlers()} />)
    const seed = nodes().find((n) => n.node?.kind === 'seed')!
    // a brace of the evidence cannot close the label's style block or name an ECharts field
    const label = seed.label!.formatter!()
    expect(label).toContain('Invoice <b>{b')
    expect(label).not.toContain('{b}')
    const tip = (chart().option!.tooltip as { formatter: (p: unknown) => string }).formatter({ dataType: 'node', data: seed })
    expect(tip).toContain('&lt;b&gt;')
    expect(tip).not.toContain('<b>{b}</b>')
  })

  it('opens a chain from a campaign, and says when no entity is shared between chains', () => {
    const h = handlers()
    render(<ChainGraph mode="campaign" chain={null} chains={[chain('c1', 'alice', '203.0.113.9'), chain('c2', 'bob', '198.51.100.4')]} selectedStep={null} {...h} />)
    const person = nodes().find((n) => n.node?.kind === 'chain' && n.node.chainId === 'c2')!
    click(person)
    expect(h.onChain).toHaveBeenCalledWith('c2')
    expect(screen.getByText('person, coloured by the chain')).toBeTruthy()
  })

  it('draws a story graph it is given, and hands back the records and entities clicked', () => {
    const h = handlers()
    const graph: Graph = {
      columns: 2,
      nodes: [
        { id: 'r1', label: '4688 powershell.exe', lane: 'host', kind: 'seed', x: 0, weight: 3, linked: true, recordIds: ['ev:1', 'ev:2'] },
        { id: 'f1', label: 'payload.ps1', lane: 'artifact', kind: 'file', x: 1, weight: 1, linked: true, entityId: 'file:payload.ps1' },
      ],
      edges: [{ source: 'r1', target: 'f1', kind: 'artifact', label: 'wrote' }],
    }
    render(<ChainGraph mode="chain" chain={null} chains={[]} graph={graph} selectedStep={null} selectedNode="f1" {...h} />)
    click(nodes().find((n) => n.id === 'r1')!)
    expect(h.onRecords).toHaveBeenCalledWith(['ev:1', 'ev:2'])
    click(nodes().find((n) => n.id === 'f1')!)
    expect(h.onEntityNode).toHaveBeenCalledWith('file:payload.ps1')
    expect(screen.getByText(/diamond = record that started the story/)).toBeTruthy()
  })

  it('lets the chart go when the pane closes', () => {
    const { unmount } = render(<ChainGraph mode="chain" chain={chain('c1', 'alice', '203.0.113.9')} chains={[]} selectedStep={null} {...handlers()} />)
    unmount()
    expect(chart().disposed).toBe(true)
  })
})
