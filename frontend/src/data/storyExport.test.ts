import { describe, expect, it } from 'vitest'
import type { Story, StoryStep } from './stories'
import { applyStoryDecisions, type StoryDecisions } from './storyDecisions'
import { mdText, TIMELINE_COLUMNS, timelineCsv, timelineJson, timelineMarkdown, timelineRows } from './storyExport'

const T0 = Date.UTC(2026, 8, 4, 8, 26)
const step = (id: number, minutes: number, extra: Partial<StoryStep>): StoryStep => ({
  id: `event:${id}`,
  refs: [`event:${id}`],
  source: 'events',
  ts: T0 + minutes * 60_000,
  tsEnd: T0 + minutes * 60_000,
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

function view(decisions: StoryDecisions = {}) {
  const story: Story = {
    id: 'story-1',
    kind: 'person',
    subject: { kind: 'person', id: 'id:daniel', label: 'daniel.roy@northstar.example', org: 'northstar.example' },
    title: 'daniel.roy@northstar.example',
    headline: 'RDP logon from outside',
    summary: '',
    start: T0,
    end: T0 + 20 * 60_000,
    severity: 'high',
    score: 60,
    confidence: 'strong',
    phases: [{ phase: 'initial-access', label: 'Initial access', first: T0, last: T0, steps: 1, records: 1, findings: 1, severity: 'high' }],
    steps: [
      step(1, 0, { phase: 'initial-access', findings: [{ ruleId: 'rdp', title: 'RDP logon from outside', severity: 'high', key: 'rdp|1' }] }),
      // what a record wrote, hostile to a spreadsheet and to Markdown
      step(2, 20, {
        refs: ['event:2', 'event:3'],
        count: 2,
        title: '=HYPERLINK("http://evil.example/x","open") | [click](http://evil.example) <img src=x>',
        host: '@ws-009',
        accounts: ['id:daniel', 'id:other'],
        tie: { kind: 'session', basis: '+ the same logon session', confidence: 'medium' },
      }),
    ],
    records: 3,
    hosts: ['ws-004'],
    accounts: ['id:daniel'],
    ips: [],
    attackerAddresses: [],
    chains: [],
    findings: ['rdp|1'],
    campaigns: [],
    gaps: [],
    lineage: { sessions: [], hops: [], processes: [] },
  }
  const res = { version: 1, stories: [story], campaigns: [], chains: { chains: [], stats: {} } as never, identities: [], hosts: [], unstoried: [], stats: {} }
  return applyStoryDecisions(res, decisions).views[0]
}
const labels = new Map([['id:daniel', 'daniel.roy@northstar.example']])

describe("a story's timeline", () => {
  it('has one row per step: UTC time, host, account, phase, title, tie, confidence, findings, records and the analyst’s call', () => {
    const [first, second] = timelineRows(view(), labels)
    expect(first).toEqual({
      timeUtc: '2026-09-04T08:26:00.000Z',
      host: 'ws-004',
      account: 'daniel.roy@northstar.example',
      phase: 'Initial access',
      title: 'record 1',
      tie: 'flagged: the record names them',
      confidence: 'strong',
      findings: 'RDP logon from outside (high)',
      refs: 'event:1',
      analyst: '',
    })
    expect(second).toMatchObject({ account: 'daniel.roy@northstar.example, id:other', refs: 'event:2 event:3', tie: 'same session: + the same logon session' })
  })

  it('neutralises in CSV what a spreadsheet would run as a formula', () => {
    const csv = timelineCsv(view(), labels)
    const [head, , hostile] = csv.split('\r\n')
    expect(head).toBe(TIMELINE_COLUMNS.join(','))
    // the title opens with =, the host with @: both are read as text
    expect(hostile).toContain(`"'=HYPERLINK(""http://evil.example/x"",""open"") | [click](http://evil.example) <img src=x>"`)
    expect(hostile).toContain(",'@ws-009,")
    expect(hostile).not.toMatch(/,=|,@|,\+/)
  })

  it('carries the analyst’s decisions in JSON and Markdown, a disputed step struck out, with nothing a record wrote turned into a link or markup', () => {
    const now = view()
    const decisions: StoryDecisions = {
      'story-1': {
        anchor: { kind: 'person', subject: ['label:daniel.roy@northstar.example'], findings: ['rdp|1'], title: 'daniel.roy@northstar.example', start: T0 },
        updatedAt: 1,
        call: { verdict: 'confirmed', reason: 'the way in | *really*', decidedAt: T0 },
        steps: [{ verdict: 'disputed', reason: 'another user', decidedAt: T0, rows: [{ source: 'events', id: 2 }], title: now.story.steps[1].title, ts: now.story.steps[1].ts }],
      },
    }
    const decided = view(decisions)
    const json = timelineJson(decided, labels, T0)
    expect(json.decision).toEqual({ verdict: 'confirmed', reason: 'the way in | *really*', decidedAt: '2026-09-04T08:26:00.000Z' })
    expect(json.steps[1]).toMatchObject({ order: 2, analyst: { verdict: 'disputed', reason: 'another user' }, refs: ['event:2', 'event:3'], tie: { kind: 'session', confidence: 'medium' } })
    expect(json.story).toMatchObject({ severity: 'high', phases: ['Initial access'] })
    const md = timelineMarkdown(decided, labels)
    expect(md).toContain("- Analyst's decision: confirmed incident: the way in \\| \\*really\\*")
    expect(md).toContain('- 1 step(s) disputed by the analyst are struck out')
    const row = md.split('\n').find((l) => l.includes('HYPERLINK'))!
    // one table row: the record's pipes are escaped, its link, image and HTML are text, its address defanged
    expect(row.split(/(?<!\\)\|/)).toHaveLength(11)
    expect(row).toContain('~~=HYPERLINK("hxxp://evil.example/x","open") \\| \\[click\\](hxxp://evil.example) \\<img src=x\\>~~')
    expect(row).toContain('| disputed: another user |')
    expect(mdText('a\n  b _c_ `d` www.evil.example')).toBe('a b \\_c\\_ \\`d\\` www[.]evil.example')
  })
})
