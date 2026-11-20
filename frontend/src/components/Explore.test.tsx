// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import type { RelationshipEdge, RelationshipNode, RelationshipRef, RelationshipResult } from '../data/relationships'
import type { RelationshipReview } from '../data/relationshipReviews'
import { ExploreControls, ExploreList, Explorer, LinkList } from './Explore'
import type { RelationshipGraph } from './useRelationshipGraph'

afterEach(cleanup)

const T0 = Date.UTC(2026, 6, 2, 22, 0)
// invented records of two evidence items: a logon, a script run and written, a connection seen in a snapshot
const ref = (id: number, evidenceId: number, title: string, minutes: number, patch: Partial<RelationshipRef> = {}): RelationshipRef => ({
  id,
  evidenceId,
  source: 'events',
  sourceFile: evidenceId === 1 ? 'Security.evtx' : 'Sysmon.evtx',
  sourceSha256: null,
  sourceIndex: id - 1,
  recordKind: 'event',
  ts: T0 + minutes * 60_000,
  observedAt: null,
  title,
  ...patch,
})
const node = (id: string, kind: string, label: string, scope = ''): RelationshipNode => ({ id, kind, value: label.toLowerCase(), scope, label })
const NODES = [
  node('host:ws-017', 'host', 'WS-017'),
  node('account:corp\\m.durand', 'account', 'CORP\\m.durand', 'corp'),
  node('process:powershell', 'process', 'powershell.exe', 'WS-017'),
  node('file:payload', 'file', 'C:\\Users\\Public\\payload.ps1', 'WS-017'),
  node('ip:203.0.113.9', 'ip', '203.0.113.9'),
  node('record:1', 'record', 'event 1'),
]
const edge = (source: string, target: string, relation: string, refs: RelationshipRef[], patch: Partial<RelationshipEdge> = {}): RelationshipEdge => ({
  source,
  target,
  relation,
  reason: `the record names both: ${relation}`,
  confidence: 'high',
  refs,
  count: refs.length,
  ...patch,
})
const EDGES = [
  edge('account:corp\\m.durand', 'host:ws-017', 'logged on to', [ref(1, 1, '4624 logon of m.durand', 0), ref(2, 2, 'logon session on WS-017', 1)]),
  edge('host:ws-017', 'process:powershell', 'ran', [ref(3, 2, 'process created: powershell.exe', 5)]),
  edge('process:powershell', 'file:payload', 'wrote', [ref(4, 2, 'file created: payload.ps1', 6, { context: { TargetFilename: 'C:\\Users\\Public\\payload.ps1' } })], {
    count: 9,
    supportTruncated: true,
  }),
  edge('host:ws-017', 'ip:203.0.113.9', 'connected to', [ref(5, 2, 'connection in the netstat snapshot', 0, { recordKind: 'observation', ts: null, observedAt: T0 + 60 * 60_000 })], {
    confidence: 'medium',
  }),
]
const RESULT: RelationshipResult = { nodes: NODES, edges: EDGES, stats: { events: 5, mails: 0, truncated: false, rowCap: 20_000, referenceCap: 50 } }

/** The graph hook as a page holds it, with the actions it was asked for recorded. */
function graph(patch: Partial<RelationshipGraph> = {}): RelationshipGraph {
  const result = 'result' in patch ? (patch.result ?? null) : RESULT
  return {
    result,
    nodes: new Map((result?.nodes ?? []).map((n) => [n.id, n])),
    busy: false,
    error: '',
    progress: '',
    evidence: [{ id: 1, caseId: 1, name: 'Security.evtx', size: 1, kind: 'evtx', integrity: 'verified', addedAt: 1, status: 'done', count: 2 }],
    evidenceId: '',
    setEvidenceId: vi.fn(),
    aliasesText: '{}',
    setAliasesText: vi.fn(),
    aliases: {},
    reviews: {},
    build: vi.fn(async () => {}),
    stop: vi.fn(),
    save: vi.fn(async () => {}),
    ...patch,
  }
}
const openLink = (relation: string) => {
  const details = screen.getByText(relation, { selector: 'summary strong' }).closest('details') as HTMLDetailsElement
  details.open = true
  fireEvent(details, new Event('toggle'))
  return details
}

describe('the relationship build controls', () => {
  it('builds for the evidence picked, and rebuilds a graph already there', () => {
    const g = graph({ result: null })
    const { rerender } = render(<ExploreControls g={g} />)
    fireEvent.change(screen.getByRole('combobox', { name: 'Evidence scope' }), { target: { value: '1' } })
    expect(g.setEvidenceId).toHaveBeenCalledWith('1')
    fireEvent.click(screen.getByRole('button', { name: 'Build relationships' }))
    expect(g.build).toHaveBeenCalled()
    rerender(<ExploreControls g={graph()} />)
    expect(screen.getByRole('button', { name: 'Rebuild relationships' })).toBeTruthy()
  })

  it('says how far a scan got, and that a partial graph is no proof of absence', () => {
    const g = graph({
      busy: true,
      progress: 'Scanned 4,000 of 9,000 events.',
      result: { ...RESULT, cursor: { events: 4000, mails: 0 }, stats: { ...RESULT.stats, truncated: true } },
      error: 'Aliases must be a JSON object',
    })
    render(<ExploreControls g={g} />)
    expect(screen.getByRole('alert').textContent).toBe('Aliases must be a JSON object')
    const notes = screen.getAllByRole('status').map((s) => s.textContent)
    expect(notes[0]).toContain('Scanned 4,000 of 9,000 events.')
    expect(notes.some((n) => n?.startsWith('This scan is incomplete.'))).toBe(true)
    expect(notes.some((n) => n?.includes('Absence of a link here is not evidence of absence.'))).toBe(true)
    fireEvent.click(screen.getByRole('button', { name: 'Stop after this page' }))
    expect(g.stop).toHaveBeenCalled()
  })
})

describe('the entity list', () => {
  it('asks for a build first', () => {
    render(<ExploreList g={graph({ result: null })} selected="" onSelect={() => {}} />)
    expect(screen.getByText(/Build relationships first\./)).toBeTruthy()
  })

  it('lists the entities by their links, never a record, and opens on the first seen in two sources', async () => {
    const onSelect = vi.fn()
    render(<ExploreList g={graph()} selected="" onSelect={onSelect} />)
    // the account is named by both evidence items, so it is where the page starts
    await waitFor(() => expect(onSelect).toHaveBeenCalledWith('account:corp\\m.durand'))
    const listed = screen.getAllByRole('button', { name: / · / }).map((b) => b.textContent)
    expect(listed[0]).toMatch(/^host · WS-017/)
    expect(listed.some((t) => t?.startsWith('record'))).toBe(false)
    expect(screen.getByText('5 matches · showing up to 200')).toBeTruthy()
  })

  it('narrows the list by a search and by a type', () => {
    render(<ExploreList g={graph()} selected="host:ws-017" onSelect={() => {}} />)
    fireEvent.change(screen.getByRole('textbox', { name: 'Search entities' }), { target: { value: 'ws-017' } })
    // the scope is searched too: the process and the file ran on WS-017
    expect(screen.getByText('3 matches · showing up to 200')).toBeTruthy()
    fireEvent.change(screen.getByRole('combobox', { name: 'Entity type' }), { target: { value: 'file' } })
    expect(screen.getByText('1 matches · showing up to 200')).toBeTruthy()
    expect(screen.getByRole('button', { name: /file · C:\\Users\\Public\\payload\.ps1/ })).toBeTruthy()
  })
})

describe('the selected entity', () => {
  it('draws its neighbours, each one a way to explore it by mouse or keyboard', () => {
    const onSelect = vi.fn()
    render(<Explorer g={graph()} selected="host:ws-017" onSelect={onSelect} onOpen={() => {}} />)
    const diagram = screen.getByRole('img', { name: 'Connections around the selected entity' })
    expect(within(diagram).getAllByRole('button')).toHaveLength(3)
    fireEvent.click(within(diagram).getByRole('button', { name: 'Explore powershell.exe' }))
    fireEvent.keyDown(within(diagram).getByRole('button', { name: 'Explore 203.0.113.9' }), { key: 'Enter' })
    expect(onSelect.mock.calls).toEqual([['process:powershell'], ['ip:203.0.113.9']])
  })

  it('lists the records within two links in time order, a snapshot by when it was collected', () => {
    const onOpen = vi.fn()
    render(<Explorer g={graph()} selected="host:ws-017" onSelect={() => {}} onOpen={onOpen} />)
    const timeline = screen.getByText(/^Related evidence timeline/).closest('details') as HTMLElement
    expect(screen.getByText('Related evidence timeline · 5 records')).toBeTruthy()
    const opens = within(timeline)
      .getAllByRole('button')
      .map((b) => b.textContent)
    expect(opens).toEqual(['Open events #1', 'Open events #2', 'Open events #3', 'Open events #4', 'Open events #5'])
    expect(timeline.textContent).toContain('Collected')
    fireEvent.click(within(timeline).getByRole('button', { name: 'Open events #3' }))
    expect(onOpen).toHaveBeenCalledWith(EDGES[1].refs[0])
  })

  it('says to build first when there is no graph', () => {
    render(<Explorer g={graph({ result: null })} selected="" onSelect={() => {}} onOpen={() => {}} />)
    expect(screen.getByText('Build relationships to browse the entities.')).toBeTruthy()
  })
})

describe('the links', () => {
  it('give their reason, rule and supporting records once opened, and say how many are not shown', () => {
    render(<LinkList edges={[EDGES[2]]} g={graph()} onExplore={() => {}} onOpen={() => {}} keyPrefix="p" />)
    const link = openLink('wrote')
    expect(link.textContent).toContain('the record names both: wrote')
    expect(link.textContent).toContain('Rule: explicit source fields')
    expect(link.textContent).toContain('(capped sample; total may include duplicate imports)')
    expect(link.textContent).toContain('Showing 1 of 9 supporting observations.')
    expect(link.textContent).toContain('"TargetFilename"')
  })

  it('save the analyst review of a link, and say when saving failed', async () => {
    const saved: RelationshipReview[] = []
    const g = graph({
      save: vi.fn(async (r: RelationshipReview) => {
        saved.push(r)
        if (saved.length > 1) throw new Error('quota')
      }),
    })
    render(<LinkList edges={[EDGES[0]]} g={g} onExplore={() => {}} onOpen={() => {}} keyPrefix="p" />)
    const link = openLink('logged on to')
    fireEvent.change(within(link).getByRole('combobox', { name: 'Relationship decision' }), { target: { value: 'accepted' } })
    fireEvent.click(within(link).getByRole('checkbox', { name: 'Include accepted link in report' }))
    fireEvent.change(within(link).getByRole('textbox', { name: 'Relationship notes' }), { target: { value: 'the VPN logon of the night shift' } })
    expect(within(link).getByRole('status').textContent).toBe('Unsaved')
    fireEvent.click(within(link).getByRole('button', { name: 'Save relationship review' }))
    await waitFor(() => expect(within(link).getByRole('status').textContent).toBe('Saved'))
    expect(saved[0]).toMatchObject({
      status: 'accepted',
      includeInReport: true,
      notes: 'the VPN logon of the night shift',
      sourceLabel: 'CORP\\m.durand',
      targetLabel: 'WS-017',
      references: EDGES[0].refs,
    })
    fireEvent.click(within(link).getByRole('button', { name: 'Save relationship review' }))
    await waitFor(() => expect(within(link).getByRole('status').textContent).toBe('Save failed'))
  })

  it('explore either end of a link, open a record, and say how many links a long list leaves out', () => {
    const onExplore = vi.fn()
    const onOpen = vi.fn()
    render(<LinkList edges={EDGES} g={graph()} onExplore={onExplore} onOpen={onOpen} keyPrefix="p" limit={2} />)
    expect(screen.getByText('Showing 2 of 4 links.')).toBeTruthy()
    const link = openLink('ran')
    fireEvent.click(within(link).getByRole('button', { name: 'Explore source' }))
    fireEvent.click(within(link).getByRole('button', { name: 'Explore target' }))
    expect(onExplore.mock.calls).toEqual([['host:ws-017'], ['process:powershell']])
    fireEvent.click(within(link).getByRole('button', { name: 'Open events #3' }))
    expect(onOpen).toHaveBeenCalledWith(EDGES[1].refs[0])
    expect(link.textContent).toContain('evidence #2 · Sysmon.evtx · record 3')
  })
})
