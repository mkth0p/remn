// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { storyAnchor, type Identity, type Story, type StoryResult, type StoryStep } from '../data/stories'
import { applyStoryDecisions, mergeInto, setCall, setStepCall, splitAt, takeOut, type StoryDecision, type StoryDecisions, type StoryView } from '../data/storyDecisions'

// the timeline files are written by the browser: the test keeps what was asked for
const downloads = vi.hoisted(() => [] as string[])
vi.mock('../data/storyExport', async (original) => ({
  ...(await original<typeof import('../data/storyExport')>()),
  downloadTimeline: (kind: string) => downloads.push(kind),
}))

const { DecisionsPanel, OrphanDecisions, StepCallTag, StepDecisionPanel, StoryCallBar, StoryCallTag, StoryTools } = await import('./StoryDecisions')

afterEach(() => {
  cleanup()
  downloads.length = 0
})

const T0 = Date.UTC(2026, 4, 12, 7, 0)
const MIN = 60_000

// invented stories: an intrusion on one account, a host story, and an account of another organisation
const step = (id: number, minutes: number, extra: Partial<StoryStep> = {}): StoryStep => ({
  id: `event:${id}`,
  refs: [`event:${id}`],
  source: 'events',
  ts: T0 + minutes * MIN,
  tsEnd: T0 + minutes * MIN,
  count: 1,
  title: `record ${id}`,
  host: 'ws-021',
  ip: null,
  origin: 'host',
  phase: null,
  phaseBasis: '',
  findings: [],
  severity: null,
  tie: { kind: 'flag', basis: 'the record names them', confidence: 'strong' },
  notes: [],
  accounts: ['id:lena'],
  session: null,
  process: null,
  hops: [],
  routine: false,
  ...extra,
})
const lena: Identity = {
  id: 'id:lena',
  label: 'lena.ortiz@harbour.example',
  kind: 'person',
  org: 'harbour.example',
  forms: [{ kind: 'addr', value: 'lena.ortiz@harbour.example', seen: 5, ref: null, confidence: 'strong' }],
  joins: [],
  possibly: [],
  namesakes: [],
  conflicts: [],
  notes: [],
}
const omar: Identity = { ...lena, id: 'id:omar', label: 'omar@quay.example', org: 'quay.example', forms: [{ kind: 'addr', value: 'omar@quay.example', seen: 2, ref: null, confidence: 'strong' }] }

function story(id: string, subject: Story['subject'], steps: StoryStep[]): Story {
  return {
    id,
    kind: subject.kind,
    subject,
    title: subject.label,
    headline: 'headline',
    summary: 'summary',
    start: steps[0].ts,
    end: steps[steps.length - 1].tsEnd,
    severity: 'high',
    score: 70,
    confidence: 'medium',
    phases: [],
    steps,
    records: steps.length,
    hosts: ['ws-021'],
    accounts: [],
    ips: [],
    attackerAddresses: [],
    chains: [],
    findings: [...new Set(steps.flatMap((s) => s.findings.map((f) => f.key!)))].sort(),
    campaigns: [],
    gaps: [],
    lineage: { sessions: [], hops: [], processes: [] },
  }
}
const RES: StoryResult = {
  version: 1,
  stories: [
    story('s-lena', { kind: 'person', id: 'id:lena', label: 'lena.ortiz@harbour.example', org: 'harbour.example' }, [
      step(1, 0, { findings: [{ ruleId: 'vpn', title: 'VPN logon from abroad', severity: 'high', key: 'vpn|1' }] }),
      step(2, 10, { findings: [{ ruleId: 'clear', title: 'Audit log cleared', severity: 'critical', key: 'clear|2' }] }),
      step(3, 20, { refs: ['event:3', 'event:4'], count: 2 }),
    ]),
    story('s-host', { kind: 'host', id: 'ws-030', label: 'ws-030', org: null }, [step(10, 5, { host: 'ws-030' }), step(11, 15, { host: 'ws-030' })]),
    story('s-omar', { kind: 'person', id: 'id:omar', label: 'omar@quay.example', org: 'quay.example' }, [step(20, 30, { accounts: ['id:omar'] })]),
  ],
  campaigns: [],
  chains: { chains: [], stats: {} } as never,
  identities: [lena, omar],
  hosts: [],
  unstoried: [],
  stats: {},
}
const engine = (id: string) => RES.stories.find((s) => s.id === id)!
/** A decision as the page takes it: on the engine story, with its anchor now. */
const on = (id: string, change: (d: StoryDecision) => void, all: StoryDecisions = {}): StoryDecisions => {
  const d: StoryDecision = { ...(all[id] ?? {}), anchor: storyAnchor(engine(id), RES.identities), updatedAt: T0 }
  change(d)
  return { ...all, [id]: d }
}
const views = (decisions: StoryDecisions = {}) => applyStoryDecisions(RES, decisions).views
const viewOf = (vs: StoryView[], id: string) => vs.find((v) => v.story.id === id)!
const NO_LABELS = new Map<string, string>()

describe('the decision on a story', () => {
  it('asks for a reason before it confirms or dismisses a story, and saves the one given', async () => {
    const onDecide = vi.fn(async () => {})
    render(<StoryCallBar view={viewOf(views(), 's-lena')} onDecide={onDecide} />)
    const save = screen.getByRole('button', { name: 'Save decision' }) as HTMLButtonElement
    expect(save.disabled).toBe(true)
    fireEvent.click(screen.getByRole('button', { name: 'confirmed incident' }))
    expect(save.disabled).toBe(true)
    expect(save.title).toContain('needs a reason')
    fireEvent.change(screen.getByRole('textbox', { name: 'Reason for the story decision' }), { target: { value: 'the VPN logon is from the stolen laptop' } })
    fireEvent.click(save)
    expect(onDecide).toHaveBeenCalledWith('confirmed', 'the VPN logon is from the stolen laptop')
  })

  it('says a dismissal takes the stories merged into it along, and shows the decision saved', () => {
    const merged = on('s-host', (d) => mergeInto(d, storyAnchor(engine('s-lena'), RES.identities), 'the same intrusion'))
    const { unmount } = render(<StoryCallBar view={viewOf(views(merged), 's-lena')} onDecide={async () => {}} />)
    fireEvent.click(screen.getByRole('button', { name: 'benign' }))
    expect(screen.getByRole('note').textContent).toBe('The story merged into this one is dismissed with it.')
    unmount()
    const decided = on('s-lena', (d) => setCall(d, 'story', 'confirmed', 'seen on the firewall too'))
    render(<StoryCallBar view={viewOf(views(decided), 's-lena')} onDecide={async () => {}} />)
    expect(screen.getByRole('status').textContent).toMatch(/^decided confirmed incident · /)
  })
})

describe('the story tools', () => {
  it('exports the timeline in the format asked for', () => {
    const vs = views()
    render(<StoryTools view={viewOf(vs, 's-lena')} views={vs} labels={NO_LABELS} onMerge={async () => {}} />)
    fireEvent.click(screen.getByRole('button', { name: 'export the timeline as CSV' }))
    fireEvent.click(screen.getByRole('button', { name: 'export the timeline as Markdown' }))
    expect(downloads).toEqual(['csv', 'md'])
  })

  it('asks in the page before it merges stories of two organisations', async () => {
    const onMerge = vi.fn(async () => {})
    const vs = views()
    render(<StoryTools view={viewOf(vs, 's-lena')} views={vs} labels={NO_LABELS} onMerge={onMerge} />)
    fireEvent.click(screen.getByRole('button', { name: 'merge into another story' }))
    const region = screen.getByRole('region', { name: 'Merge the story' })
    // a story is never offered as a target of its own merge
    const offered = within(region)
      .getAllByRole('option')
      .map((o) => o.textContent ?? '')
    expect(offered.filter((o) => o.includes('ws-030') || o.includes('omar@quay.example'))).toHaveLength(2)
    expect(offered.some((o) => o.includes('lena.ortiz'))).toBe(false)
    fireEvent.change(within(region).getByRole('combobox', { name: 'Story to merge into' }), { target: { value: 's-omar' } })
    fireEvent.change(within(region).getByRole('textbox', { name: 'Reason for the merge' }), { target: { value: 'one phishing run' } })
    fireEvent.click(within(region).getByRole('button', { name: 'Merge' }))
    const ask = screen.getByRole('alertdialog', { name: 'Merge across organisations' })
    expect(ask.textContent).toContain('harbour.example')
    expect(ask.textContent).toContain('quay.example')
    expect(onMerge).not.toHaveBeenCalled()
    fireEvent.click(within(ask).getByRole('button', { name: 'merge across organisations' }))
    await vi.waitFor(() => expect(onMerge).toHaveBeenCalledWith(viewOf(vs, 's-omar'), 'one phishing run', ['harbour.example', 'quay.example']))
  })

  it('says why a story cannot be merged into a dismissed one, and keeps a split story where it is', () => {
    const dismissedHost = on('s-host', (d) => setCall(d, 'story', 'benign', 'a backup job'))
    const vs = views(dismissedHost)
    const { unmount } = render(<StoryTools view={viewOf(vs, 's-lena')} views={vs} labels={NO_LABELS} onMerge={async () => {}} />)
    fireEvent.click(screen.getByRole('button', { name: 'merge into another story' }))
    fireEvent.change(screen.getByRole('combobox', { name: 'Story to merge into' }), { target: { value: 's-host' } })
    expect(screen.getByRole('alert').textContent).toContain('nothing is merged into a dismissed story')
    unmount()
    const split = views(on('s-lena', (d) => splitAt(d, engine('s-lena').steps[1], 'two separate logons')))
    render(<StoryTools view={viewOf(split, 's-lena')} views={split} labels={NO_LABELS} onMerge={async () => {}} />)
    const merge = screen.getByRole('button', { name: 'merge into another story' }) as HTMLButtonElement
    expect(merge.disabled).toBe(true)
    expect(merge.title).toBe('A story split in two is not merged: undo the split first.')
  })
})

describe('the decision on a step', () => {
  const panel = (view: StoryView, s: StoryStep) => {
    const h = { onCall: vi.fn(async () => {}), onOut: vi.fn(async () => {}), onSplit: vi.fn(async () => {}) }
    render(<StepDecisionPanel view={view} step={s} {...h} />)
    return h
  }

  it('disputes a step, and marks its finding false positive only when asked', async () => {
    const h = panel(viewOf(views(), 's-lena'), engine('s-lena').steps[1])
    fireEvent.click(screen.getByRole('button', { name: 'dispute' }))
    fireEvent.change(screen.getByRole('textbox', { name: 'Reason for the step decision' }), { target: { value: 'a scheduled rotation' } })
    expect(screen.getByText(/also mark its finding false positive \(Audit log cleared\)/)).toBeTruthy()
    fireEvent.click(screen.getByRole('checkbox', { name: 'also mark the finding false positive' }))
    fireEvent.click(screen.getByRole('button', { name: 'Dispute step' }))
    await vi.waitFor(() => expect(h.onCall).toHaveBeenCalledWith('disputed', 'a scheduled rotation', true))
  })

  it('takes records out of the story only with a reason', async () => {
    const h = panel(viewOf(views(), 's-lena'), engine('s-lena').steps[2])
    fireEvent.click(screen.getByRole('button', { name: 'not part of this story' }))
    const out = screen.getByRole('button', { name: 'Take its 2 records out' }) as HTMLButtonElement
    expect(out.disabled).toBe(true)
    fireEvent.change(screen.getByRole('textbox', { name: 'Reason for the step decision' }), { target: { value: 'another user on the same host' } })
    fireEvent.click(out)
    await vi.waitFor(() => expect(h.onOut).toHaveBeenCalledWith('another user on the same host'))
  })

  it('splits at a later step, never at the first, and says how many steps go with it', async () => {
    const view = viewOf(views(), 's-lena')
    panel(view, engine('s-lena').steps[0])
    expect((screen.getByRole('button', { name: 'split the story here' }) as HTMLButtonElement).title).toBe('Nothing comes before the first step.')
    cleanup()
    const h = panel(view, engine('s-lena').steps[1])
    fireEvent.click(screen.getByRole('button', { name: 'split the story here' }))
    expect(screen.getByText('This step and the 1 after it become a story of their own, with its own decision.')).toBeTruthy()
    fireEvent.change(screen.getByRole('textbox', { name: 'Reason for the step decision' }), { target: { value: 'a second intrusion' } })
    fireEvent.click(screen.getByRole('button', { name: 'Split here' }))
    await vi.waitFor(() => expect(h.onSplit).toHaveBeenCalledWith('a second intrusion'))
  })

  it('shows the call already taken on a step and takes it back', async () => {
    const decided = on('s-lena', (d) => setStepCall(d, engine('s-lena').steps[0], 'confirmed', 'the user confirmed the trip'))
    const h = panel(viewOf(views(decided), 's-lena'), engine('s-lena').steps[0])
    expect(screen.getByText(/the step and its tie: the user confirmed the trip/)).toBeTruthy()
    expect((screen.getByRole('button', { name: 'confirm' }) as HTMLButtonElement).disabled).toBe(true)
    fireEvent.click(screen.getByRole('button', { name: 'take back' }))
    await vi.waitFor(() => expect(h.onCall).toHaveBeenCalledWith(null, '', false))
  })
})

describe('the list of decisions', () => {
  it('lists each decision on the story with its reason and a way back from it', () => {
    const s = engine('s-lena').steps
    let decisions = on('s-lena', (d) => {
      setCall(d, 'story', 'confirmed', 'seen on the firewall too')
      setStepCall(d, s[0], 'disputed', 'a known trip')
      takeOut(d, s[2], 'another user')
      splitAt(d, s[1], 'two separate logons')
    })
    decisions = on('s-host', (d) => mergeInto(d, storyAnchor(engine('s-lena'), RES.identities), 'the same intrusion'), decisions)
    const view = viewOf(views(decisions), 's-lena')
    const h = { onOpenStep: vi.fn(), onUndoCall: vi.fn(), onUndoStep: vi.fn(), onDropLost: vi.fn(), onPutBack: vi.fn(), onUnsplit: vi.fn(), onUnmerge: vi.fn() }
    render(<DecisionsPanel view={view} {...h} />)
    const panel = screen.getByRole('region', { name: 'Decisions on the story' })
    expect(panel.textContent).toContain('seen on the firewall too')
    fireEvent.click(screen.getByRole('button', { name: 'set back to open' }))
    expect(h.onUndoCall).toHaveBeenCalled()
    fireEvent.click(screen.getByText('record 1'))
    expect(h.onOpenStep).toHaveBeenCalledWith('event:1')
    fireEvent.click(screen.getByRole('button', { name: 'take back' }))
    expect(h.onUndoStep).toHaveBeenCalledWith(s[0])
    expect(panel.textContent).toContain('2 record(s)')
    fireEvent.click(screen.getByRole('button', { name: 'put back' }))
    expect(h.onPutBack).toHaveBeenCalledWith(view.out[0])
    fireEvent.click(screen.getByRole('button', { name: 'undo the merge' }))
    expect(h.onUnmerge).toHaveBeenCalledWith({ key: 's-host', story: engine('s-host') })
    fireEvent.click(screen.getByRole('button', { name: 'undo the split' }))
    expect(h.onUnsplit).toHaveBeenCalled()
  })

  it('says a story with no decision is open', () => {
    const noop = () => {}
    render(<DecisionsPanel view={viewOf(views(), 's-host')} onOpenStep={noop} onUndoCall={noop} onUndoStep={noop} onDropLost={noop} onPutBack={noop} onUnsplit={noop} onUnmerge={noop} />)
    expect(screen.getByText(/^Open: no decision yet/)).toBeTruthy()
    expect(screen.getByText('No step confirmed or disputed.')).toBeTruthy()
    expect(screen.getByText('None: every record the build ties to the story is in it.')).toBeTruthy()
  })
})

describe('decisions whose story is gone', () => {
  const orphan = {
    key: 'gone',
    entry: {
      anchor: { kind: 'host' as const, subject: ['host:ws-099'], findings: [], title: 'ws-099', start: T0 },
      updatedAt: T0,
      call: { verdict: 'benign' as const, reason: 'patching', decidedAt: T0 },
    },
  }

  it('asks in the page before deleting them, and attaches them only to a whole story', () => {
    const onDelete = vi.fn()
    const onAttach = vi.fn()
    render(<OrphanDecisions orphans={[orphan]} story={null} onAttach={onAttach} onDelete={onDelete} />)
    expect(screen.getByText('benign: patching')).toBeTruthy()
    expect((screen.getByRole('button', { name: 'attach to the open story' }) as HTMLButtonElement).disabled).toBe(true)
    fireEvent.click(screen.getByRole('button', { name: 'delete' }))
    const ask = screen.getByRole('alertdialog', { name: 'Delete the decisions' })
    fireEvent.click(within(ask).getByRole('button', { name: 'keep' }))
    expect(onDelete).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: 'delete' }))
    fireEvent.click(screen.getByRole('button', { name: 'delete for good' }))
    expect(onDelete).toHaveBeenCalledWith('gone')
    cleanup()
    render(<OrphanDecisions orphans={[orphan]} story={viewOf(views(), 's-host')} onAttach={onAttach} onDelete={onDelete} />)
    fireEvent.click(screen.getByRole('button', { name: 'attach to the open story' }))
    expect(onAttach).toHaveBeenCalledWith('gone')
  })
})

describe('the marks of a decision', () => {
  it('mark a decided story, a merged one, and a step the analyst called', () => {
    const decisions = on(
      's-host',
      (d) => mergeInto(d, storyAnchor(engine('s-lena'), RES.identities), 'the same intrusion'),
      on('s-lena', (d) => setCall(d, 'story', 'false_positive', 'a red-team exercise')),
    )
    const view = viewOf(views(decisions), 's-lena')
    const { container } = render(
      <>
        <StoryCallTag view={view} />
        <StepCallTag call={{ verdict: 'disputed', reason: 'a known trip', decidedAt: T0, rows: [], title: 'record 1', ts: T0 }} />
      </>,
    )
    expect(screen.getByTitle('a red-team exercise').textContent).toBe('false positive')
    expect(screen.getByText('+1 merged')).toBeTruthy()
    expect(container.textContent).toContain('disputed by the analyst')
  })
})
