import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { RemnDB, setDb, type Finding } from '../db/schema'
import { decideFindings } from './findingReviews'
import { storyAnchor, type Identity, type Story, type StoryResult, type StoryStep } from './stories'
import {
  applyStoryDecisions,
  attachStoryDecision,
  decideStory,
  loadStoryDecisions,
  mergeCheck,
  mergeInto,
  putBack,
  setCall,
  setStepCall,
  splitAt,
  splitId,
  STORY_DECISIONS_KEY,
  storiesForReport,
  takeOut,
  type StoryDecision,
  type StoryDecisions,
} from './storyDecisions'

const T0 = Date.UTC(2026, 8, 4, 8, 0)
const MIN = 60_000

const step = (id: number, minutes: number, extra: Partial<StoryStep> = {}): StoryStep => ({
  id: `event:${id}`,
  refs: [`event:${id}`],
  source: 'events',
  ts: T0 + minutes * MIN,
  tsEnd: T0 + minutes * MIN,
  count: 1,
  title: `record ${id}`,
  host: 'ws-004',
  ip: null,
  origin: 'host',
  phase: null,
  phaseBasis: '',
  findings: [],
  severity: null,
  tie: { kind: 'flag', basis: 'the record names them', confidence: 'strong' },
  notes: [],
  accounts: ['id:daniel'],
  session: null,
  process: null,
  hops: [],
  routine: false,
  ...extra,
})
const flag = (key: string, title: string, severity: 'critical' | 'high' | 'medium') => [{ ruleId: key.split('|')[0], title, severity, key }]

const daniel: Identity = {
  id: 'id:daniel',
  label: 'daniel.roy@northstar.example',
  kind: 'person',
  org: 'northstar.example',
  forms: [
    { kind: 'addr', value: 'daniel.roy@northstar.example', seen: 9, ref: null, confidence: 'strong' },
    { kind: 'netbios', value: 'northstar\\daniel.roy', seen: 9, ref: null, confidence: 'medium' },
  ],
  joins: [],
  possibly: [],
  namesakes: [],
  conflicts: [],
  notes: [],
}
const carla: Identity = {
  ...daniel,
  id: 'id:carla',
  label: 'carla@othercorp.example',
  org: 'othercorp.example',
  forms: [{ kind: 'addr', value: 'carla@othercorp.example', seen: 3, ref: null, confidence: 'strong' }],
}

function story(id: string, subject: Story['subject'], steps: StoryStep[], extra: Partial<Story> = {}): Story {
  return {
    id,
    kind: subject.kind,
    subject,
    title: subject.label,
    headline: 'the engine headline',
    summary: 'the engine summary',
    start: steps[0].ts,
    end: steps[steps.length - 1].tsEnd,
    severity: 'critical',
    score: 80,
    confidence: 'medium',
    phases: [],
    steps,
    records: steps.reduce((n, s) => n + s.refs.length, 0),
    hosts: ['ws-004'],
    accounts: [],
    ips: [],
    attackerAddresses: ['203.0.113.69'],
    chains: [],
    findings: [...new Set(steps.flatMap((s) => s.findings.map((f) => f.key!)))].sort(),
    campaigns: [],
    gaps: [],
    lineage: { sessions: [], hops: [], processes: [] },
    ...extra,
  }
}

/** Daniel's intrusion, a host story on WS-009, and Carla in another organisation. */
function build(ids = { a: 'story-a', b: 'story-b', c: 'story-c' }, regroup = false): StoryResult {
  const a = story(ids.a, { kind: 'person', id: 'id:daniel', label: regroup ? 'northstar\\daniel.roy' : 'daniel.roy@northstar.example', org: 'northstar.example' }, [
    // a rebuild can pull an earlier record into the first step, which then takes that record's id
    step(regroup ? 0 : 1, 0, { refs: regroup ? ['event:0', 'event:1'] : ['event:1'], count: regroup ? 2 : 1, phase: 'initial-access', findings: flag('rdp|1', 'RDP logon from outside', 'high') }),
    step(2, 16, { phase: 'defense-impairment', findings: flag('clear|2', 'Audit log cleared', 'critical'), tie: { kind: 'flag', basis: 'the record names them', confidence: 'medium' } }),
    step(3, 20, { refs: ['event:3', 'event:4', 'event:5'], count: 3, phase: 'credential-access', routine: true, tie: { kind: 'address', basis: 'the same source', confidence: 'medium' } }),
    step(6, 40, { phase: 'persistence', findings: flag('svc|6', 'Service installed', 'medium'), tie: { kind: 'session', basis: 'the same logon session', confidence: 'strong' } }),
  ])
  const b = story(ids.b, { kind: 'host', id: 'ws-009', label: 'ws-009', org: null }, [
    step(20, 10, { host: 'ws-009', phase: 'execution', findings: flag('exec|20', 'Encoded PowerShell', 'high') }),
    step(21, 30, { host: 'ws-009', phase: 'discovery', findings: flag('disc|21', 'Domain discovery', 'medium') }),
  ])
  const c = story(ids.c, { kind: 'person', id: 'id:carla', label: 'carla@othercorp.example', org: 'othercorp.example' }, [
    step(30, 50, { phase: 'initial-access', accounts: ['id:carla'], findings: flag('rdp|30', 'RDP logon from outside', 'high') }),
  ])
  return { version: 1, stories: [a, b, c], campaigns: [], chains: { chains: [], stats: {} } as never, identities: [daniel, carla], hosts: [], unstoried: [], stats: {} }
}

/** A decision as the page takes it: on the engine story, with its anchor now. */
function on(res: StoryResult, id: string, change: (d: StoryDecision) => void, all: StoryDecisions = {}, key = id): StoryDecisions {
  const s = res.stories.find((x) => x.id === id)!
  const d: StoryDecision = { ...(all[key] ?? {}), anchor: storyAnchor(s, res.identities), updatedAt: Date.now() }
  change(d)
  return { ...all, [key]: d }
}
const stepOf = (res: StoryResult, id: string, stepId: string) => res.stories.find((s) => s.id === id)!.steps.find((s) => s.id === stepId)!

describe('decisions on a step', () => {
  it('leave a disputed step out of the phases, severity and headline the page shows, and make a confirmed flag a strong tie', () => {
    const res = build()
    const decisions = on(res, 'story-a', (d) => setStepCall(d, stepOf(res, 'story-a', 'event:2'), 'disputed', 'a scheduled log rotation'))
    const [a] = applyStoryDecisions(res, decisions).views
    // the step stays in the story, struck out on the page, but marks nothing
    expect(a.story.steps.map((s) => s.id)).toEqual(['event:1', 'event:2', 'event:3', 'event:6'])
    expect(a.steps.get('event:2')).toMatchObject({ verdict: 'disputed', reason: 'a scheduled log rotation' })
    expect(a.story.phases.map((p) => p.phase)).toEqual(['initial-access', 'credential-access', 'persistence'])
    expect(a.story.severity).toBe('high')
    expect(a.story.headline).toBe('RDP logon from outside → Service installed')
    expect(a.story.findings).toEqual(['rdp|1', 'svc|6'])
    // its one medium flag disputed, every flag left is strong
    expect(a.story.confidence).toBe('strong')

    const confirmed = on(res, 'story-a', (d) => setStepCall(d, stepOf(res, 'story-a', 'event:2'), 'confirmed'))
    const [b] = applyStoryDecisions(res, confirmed).views
    // confirming changes nothing the engine stated but the tie's confidence
    expect(b.story.severity).toBe('critical')
    expect(b.story.phases).toBe(res.stories[0].phases)
    expect(b.story.confidence).toBe('strong')
    // a second call on the same step replaces the first
    const again = on(res, 'story-a', (d) => setStepCall(d, stepOf(res, 'story-a', 'event:2'), 'disputed'), confirmed)
    expect(again['story-a'].steps).toHaveLength(1)
    expect(applyStoryDecisions(res, again).views[0].steps.get('event:2')?.verdict).toBe('disputed')
  })
})

describe('the severity a decision restates', () => {
  it('follows the engine: three techniques in three phases from rules that can be believed raise a story to high, not any three phases', () => {
    const steps = [
      step(1, 0, { phase: 'discovery', findings: flag('whoami|1', 'whoami', 'medium') }),
      step(2, 5, { phase: 'lateral-movement', findings: flag('psexec|2', 'PsExec', 'medium') }),
      step(3, 9, { phase: 'persistence', findings: flag('task|3', 'Scheduled task', 'medium') }),
      step(4, 12, { phase: 'execution', findings: flag('lead|4', 'A lead rule', 'medium') }),
    ]
    const firm = [
      { key: 'T1033', phase: 'discovery', step: 'event:1' },
      { key: 'T1569.002', phase: 'lateral-movement', step: 'event:2' },
      { key: 'T1053.005', phase: 'persistence', step: 'event:3' },
    ]
    const res = { ...build(), stories: [story('story-x', { kind: 'person', id: 'id:daniel', label: 'daniel.roy@northstar.example', org: 'northstar.example' }, steps, { severity: 'high', firm })] }
    // disputing the lead's step leaves the three believed techniques: still high
    const lead = on(res, 'story-x', (d) => setStepCall(d, stepOf(res, 'story-x', 'event:4'), 'disputed'))
    expect(applyStoryDecisions(res, lead).views[0].story.severity).toBe('high')
    // disputing one of them leaves three phases of medium findings, one of them the lead's: medium
    const task = on(res, 'story-x', (d) => setStepCall(d, stepOf(res, 'story-x', 'event:3'), 'disputed'))
    const [x] = applyStoryDecisions(res, task).views
    expect(x.story.phases).toHaveLength(3)
    expect(x.story.severity).toBe('medium')
  })
})

describe('after a rebuild', () => {
  it('finds each decision again by what its story is about and by its records, whatever the ids and the label became', () => {
    const first = build()
    let all: StoryDecisions = {}
    all = on(first, 'story-a', (d) => setCall(d, 'story', 'confirmed', 'pbeesly’s account used from outside'), all)
    all = on(first, 'story-a', (d) => setStepCall(d, stepOf(first, 'story-a', 'event:1'), 'confirmed', 'the RDP logon is the way in'), all)
    all = on(first, 'story-a', (d) => setStepCall(d, stepOf(first, 'story-a', 'event:2'), 'disputed', 'log rotation'), all)
    all = on(first, 'story-a', (d) => takeOut(d, stepOf(first, 'story-a', 'event:3'), 'another user mistyping'), all)
    all = on(first, 'story-a', (d) => splitAt(d, stepOf(first, 'story-a', 'event:6'), 'the service is a second intrusion'), all)
    all = on(first, 'story-b', (d) => mergeInto(d, storyAnchor(first.stories[0], first.identities), 'the same session on WS-009'), all)
    // a decision on a story no build holds
    all['story-gone'] = {
      anchor: { kind: 'person', subject: ['addr:nobody@northstar.example'], findings: [], title: 'nobody@northstar.example', start: T0 },
      updatedAt: 1,
      call: { verdict: 'benign', reason: 'x', decidedAt: 1 },
    }

    // new evidence: every id changes, daniel's story is now labelled by his NetBIOS form and its first step starts a record earlier
    const second = build({ a: 'story-a2', b: 'story-b2', c: 'story-c2' }, true)
    const decided = applyStoryDecisions(second, all)
    const [first1, part2, c] = decided.views
    expect(decided.views.map((v) => v.story.id)).toEqual(['story-a2', splitId('story-a2'), 'story-c2'])
    // the host story merged into daniel's reads as part of it; its id leads there
    expect(decided.byId.get('story-b2')).toBe(first1)
    expect(first1.merged.map((m) => [m.story.id, m.merge.reason])).toEqual([['story-b2', 'the same session on WS-009']])
    // the records taken out stay out, the split still cuts at the service, the steps keep their calls
    expect(first1.story.steps.map((s) => s.id)).toEqual(['event:0', 'event:20', 'event:2', 'event:21'])
    expect(part2.story.steps.map((s) => s.id)).toEqual(['event:6'])
    expect(first1.steps.get('event:0')?.verdict).toBe('confirmed')
    expect(first1.steps.get('event:2')?.verdict).toBe('disputed')
    expect(first1.out[0]).toMatchObject({ found: 3, out: { reason: 'another user mistyping' } })
    expect(first1.call).toMatchObject({ verdict: 'confirmed' })
    expect(part2).toMatchObject({ part: 'split', key: 'story-a' })
    // each part is stated from its own steps: the disputed log clear marks nothing
    expect(first1.story.phases.map((p) => p.phase)).toEqual(['initial-access', 'execution', 'discovery'])
    expect(first1.story.severity).toBe('high')
    expect(first1.story.hosts).toEqual(['ws-004', 'ws-009'])
    expect(part2.story.severity).toBe('medium')
    expect(c.story).toBe(second.stories[2])
    expect(decided.orphans.map((o) => o.key)).toEqual(['story-gone'])
  })

  it('reads a merge whose story is gone as the story on its own, and keeps the split undone when its step is gone', () => {
    const first = build()
    let all = on(first, 'story-b', (d) => mergeInto(d, { kind: 'person', subject: ['addr:nobody@northstar.example'], findings: [], title: 'nobody', start: T0 }, 'x'))
    all = on(first, 'story-a', (d) => splitAt(d, { ...stepOf(first, 'story-a', 'event:6'), refs: ['event:99'] }, 'a record no build holds'), all)
    const decided = applyStoryDecisions(first, all)
    const b = decided.byId.get('story-b')!
    expect(b.story.id).toBe('story-b')
    expect(b.mergeLost?.reason).toBe('x')
    expect(decided.byId.get('story-a')?.split).toMatchObject({ applied: false })
    expect(decided.byId.has(splitId('story-a'))).toBe(false)
  })
})

describe('merging', () => {
  it('refuses a story decided benign or false positive, asks about another organisation, and leaves split stories alone', () => {
    const res = build()
    const benign = on(res, 'story-a', (d) => setCall(d, 'story', 'benign', 'a penetration test'))
    const [a, b] = applyStoryDecisions(res, benign).views
    expect(mergeCheck(b, a)).toMatchObject({ ok: false })
    expect(mergeCheck(b, a).why).toContain('decided benign')
    expect(mergeCheck(a, b)).toEqual({ ok: true })
    expect(mergeCheck(a, a).ok).toBe(false)
    const [open, , carla] = applyStoryDecisions(res, {}).views
    expect(mergeCheck(carla, open)).toEqual({ ok: true, orgs: ['othercorp.example', 'northstar.example'] })
    const split = on(res, 'story-a', (d) => splitAt(d, stepOf(res, 'story-a', 'event:3'), 'two incidents'))
    const views = applyStoryDecisions(res, split).views
    expect(mergeCheck(views[0], views[2]).why).toContain('undo the split first')
    expect(mergeCheck(views[2], views[1]).why).toContain('second part')
  })
})

describe('kept in the case', () => {
  let db: RemnDB
  beforeEach(() => {
    db = new RemnDB(`story-decisions-${Math.random()}`)
    setDb(db)
  })
  afterEach(async () => {
    await db.delete()
  })

  it('writes each decision under its story with the story’s anchor, removes one left empty, and attaches one whose story is gone', async () => {
    const res = build()
    const a = { story: res.stories[0], key: null }
    await decideStory(1, a, res.identities, (d) => setCall(d, 'story', 'reviewed', 'looked at it'))
    await decideStory(1, { ...a, key: 'story-a' }, res.identities, (d) => takeOut(d, res.stories[0].steps[2], 'noise'))
    let saved = await loadStoryDecisions(1)
    expect(Object.keys(saved)).toEqual(['story-a'])
    expect(saved['story-a'].anchor).toMatchObject({ kind: 'person', subject: ['addr:daniel.roy@northstar.example', 'netbios:northstar\\daniel.roy'], findings: ['clear|2', 'rdp|1', 'svc|6'] })
    expect(saved['story-a'].out?.[0].rows).toEqual([
      { source: 'events', id: 3 },
      { source: 'events', id: 4 },
      { source: 'events', id: 5 },
    ])
    saved = await decideStory(1, { ...a, key: 'story-a' }, res.identities, (d) => {
      setCall(d, 'story', 'open', '')
      putBack(d, d.out![0])
    })
    expect(saved).toEqual({})
    // a decision on a story no build holds goes onto the open story, after what that story holds
    await db.kv.put({
      key: STORY_DECISIONS_KEY(1),
      value: { gone: { anchor: { ...storyAnchor(res.stories[0], res.identities), subject: ['addr:x@y'] }, updatedAt: 1, call: { verdict: 'confirmed', reason: 'r', decidedAt: 1 } } },
    })
    saved = await attachStoryDecision(1, 'gone', { story: res.stories[1], key: null }, res.identities)
    expect(saved.gone.anchor.subject).toEqual(['host:ws-009'])
    expect(applyStoryDecisions(res, saved).byId.get('story-b')?.call?.verdict).toBe('confirmed')
  })

  it('marks a disputed step’s findings false positive only through the findings review, which a rule rerun keeps', async () => {
    await db.findings.bulkAdd([
      {
        caseId: 1,
        ruleId: 'clear',
        key: 'clear|2',
        title: 'Audit log cleared',
        severity: 'critical',
        source: 'events',
        ts: T0,
        entities: {},
        count: 1,
        refs: [2],
        attack: [],
        status: 'new',
        createdAt: 1,
        notes: 'seen',
      },
      { caseId: 2, ruleId: 'clear', key: 'clear|2', title: 'another case', severity: 'critical', source: 'events', ts: T0, entities: {}, count: 1, refs: [2], attack: [], status: 'new', createdAt: 1 },
    ] as Finding[])
    expect(await decideFindings(1, ['clear|2'], 'false_positive', 'False positive: log rotation.')).toBe(1)
    const [mine, other] = await db.findings.orderBy('id').toArray()
    expect(mine).toMatchObject({ status: 'false_positive', decidedBy: 'analyst', notes: 'seen\n\nFalse positive: log rotation.', notesBy: 'analyst' })
    expect(other.status).toBe('new')
    expect(((await db.kv.get('finding-reviews-1'))?.value as Record<string, Finding>)['clear|2']).toMatchObject({ status: 'false_positive' })
  })
})

describe('in the report', () => {
  const f = (key: string, status: Finding['status'] = 'new') => ({ id: key.length, key, status, ruleId: key.split('|')[0], severity: 'high', attack: [], title: key }) as unknown as Finding

  it('leaves out a dismissed story, prints a decided one with reviewed items only, and hands every decided story to the verdict', () => {
    const res = build()
    let all = on(res, 'story-a', (d) => setCall(d, 'story', 'confirmed', 'the intrusion'))
    all = on(res, 'story-a', (d) => setStepCall(d, stepOf(res, 'story-a', 'event:2'), 'disputed', 'rotation'), all)
    all = on(res, 'story-b', (d) => setCall(d, 'story', 'false_positive', 'the admin’s own script'), all)
    const findings = [f('rdp|1'), f('clear|2'), f('svc|6', 'false_positive')]
    const all3 = storiesForReport(res, {}, all, findings, 'medium')
    expect(all3.stories.map((s) => s.story.id)).toEqual(['story-a', 'story-c'])
    expect(all3).toMatchObject({ dismissed: 1, left: 0 })
    expect(all3.stories[0].decisions).toMatchObject({ call: { verdict: 'confirmed' }, disputed: [{ id: 'event:2', title: 'record 2', reason: 'rotation' }] })
    const [confirmed, dismissedStory] = all3.decided
    // the disputed step's finding and a finding marked false positive do not stand for the story
    expect(confirmed).toMatchObject({ verdict: 'confirmed', severity: 'high', printed: true, reason: 'the intrusion' })
    expect(confirmed.findings.map((x) => x.key)).toEqual(['rdp|1'])
    expect(dismissedStory).toMatchObject({ verdict: 'false_positive', printed: false })
    // reviewed items only: the decided story prints without a note, the undecided one does not
    const reviewed = storiesForReport(res, {}, all, findings, 'medium', true)
    expect(reviewed.stories.map((s) => s.story.id)).toEqual(['story-a'])
    expect(reviewed.left).toBe(1)
    // a confirmed story under the floor is still decided, and not printed
    expect(storiesForReport(res, {}, all, findings, 'critical').decided[0]).toMatchObject({ verdict: 'confirmed', printed: false })
  })

  it('keeps a note on the first part of a split story and prints a merged story’s note with the one it went into', () => {
    const res = build()
    let all = on(res, 'story-a', (d) => splitAt(d, stepOf(res, 'story-a', 'event:6'), 'second intrusion'))
    all = on(res, 'story-b', (d) => mergeInto(d, storyAnchor(res.stories[0], res.identities), 'same session'), all)
    const notes = {
      'story-a': { text: 'Daniel came in over RDP.', updatedAt: 1, anchor: storyAnchor(res.stories[0], res.identities) },
      'story-b': { text: 'WS-009 ran the encoded command.', updatedAt: 1, anchor: storyAnchor(res.stories[1], res.identities) },
    }
    const out = storiesForReport(res, notes, all, [], 'info')
    const [first, second] = out.stories.filter((s) => s.story.id.startsWith('story-a'))
    expect(first.note).toBe('Daniel came in over RDP.\n\nOn the story of ws-009, merged into this one: WS-009 ran the encoded command.')
    expect(first.key).toBe('story-a')
    expect(first.decisions).toMatchObject({ part: 'first', merged: [{ title: 'ws-009', reason: 'same session' }] })
    expect(second.note).toBeUndefined()
    expect(second.decisions).toMatchObject({ part: 'second', split: { reason: 'second intrusion' } })
  })
})
