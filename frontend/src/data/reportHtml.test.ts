import { describe, expect, it } from 'vitest'
import type { Case, Finding } from '../db/schema'
import type { Chain } from './chains'
import { buildIncidents } from '../rules/incidents'
import { DEFAULT_REPORT } from './review'
import { bottomLine, buildReportHtml, computeConfidence, computeVerdict, foldSteps, groupByRule, MAX_MOMENTS, MAX_STEP_ROWS, moments, threatProfile, type ReportData } from './reportHtml'
import { setLocalTime } from '../util/format'
import type { ChainStep } from './chains'

let seq = 1
const f = (p: Partial<Finding> & { ruleId: string; severity: Finding['severity'] }): Finding => ({
  id: seq++,
  caseId: 1,
  key: `${p.ruleId}|${seq}`,
  title: p.ruleId,
  source: 'mails',
  ts: 10,
  entities: {},
  count: 1,
  refs: [seq],
  attack: [],
  status: 'new',
  createdAt: 0,
  ...p,
})
const kase: Case = {
  id: 1,
  name: 'Case <b>one</b> & co',
  analyst: 'A. Nalyst',
  createdAt: 0,
  updatedAt: 0,
  storage: 'browser',
  settings: {
    internalDomains: ['corp.test'],
    vipNames: [],
    brands: [],
    internalIps: [],
    adminAccounts: [],
    serviceAccounts: [],
    businessHours: { start: 8, end: 19, tz: 'Europe/Paris' },
    weekendDays: [6, 0],
    networkAllowed: false,
  } as unknown as Case['settings'],
}
const chain: Chain = {
  id: 'alice',
  identity: 'alice',
  identityLabel: 'alice@corp.test',
  start: 0,
  end: 3_600_000,
  score: 80,
  severity: 'high',
  artifactLinks: 1,
  summary: 'the automatic summary',
  scoreBreakdown: { seed: 30, links: 20, steps: 15, findings: 10, sources: 5, cap: null, linkSteps: 1 },
  seed: { id: 7, ts: 0, subject: 'Urgent <invoice>', fromAddr: 'x@evil.test', risk: 90, flags: [], findings: [], urlDomains: [], attachments: [] },
  steps: [
    {
      kind: 'event',
      source: 'events',
      id: 11,
      ts: 60_000,
      tsEnd: 60_000,
      count: 1,
      title: 'logon from 203.0.113.9',
      weight: 3,
      artifacts: ['mail URL domain'],
      findings: [],
      offsetMin: 1,
      origin: 'm365',
    },
  ],
  entities: { user: 'alice', ips: ['203.0.113.9'], hosts: [], attackerAddresses: ['x@evil.test'], domains: [] },
}

function data(over: Partial<ReportData> = {}): ReportData {
  const findings = [
    f({ ruleId: 'chain', key: 'chain|alice|7', severity: 'high', refs: [7] }),
    f({ ruleId: 'mail-credential-phishing', severity: 'critical', refs: [7], title: 'Credential phishing <form>' }),
    f({ ruleId: 'other', severity: 'medium', refs: [8], entities: { subject: 'Other mail' }, status: 'reviewed', notes: 'looked at it', notesBy: 'ai', decidedBy: 'ai', aiReason: 'because' }),
  ]
  const grouped = buildIncidents(findings, { chains: [chain] })
  return {
    kase,
    generatedAt: 1_700_000_000_000,
    settings: DEFAULT_REPORT,
    summary: '**Summary** text',
    evidence: [{ id: 1, caseId: 1, name: 'box.mbox', size: 1024, kind: 'mail', format: 'mbox', sha256Client: 'abc', integrity: 'verified', addedAt: 0, count: 10 } as never],
    chains: [chain],
    reviews: { alice: { verdict: 'confirmed', narrative: 'What happened, in order.', narrativeBy: 'ai', by: 'ai', aiReason: 'tied to the mail' } },
    membersOf: new Map(grouped.filter((i) => i.kind === 'chain').map((i) => [i.chain!.id, i.findings.filter((x) => x.ruleId !== 'chain')])),
    graphs: { alice: 'data:image/png;base64,iVBORw0KGgo=' },
    campaignInsights: [],
    incidents: grouped.filter((i) => i.kind !== 'chain'),
    findings,
    iocs: [],
    timeline: [],
    tasks: [],
    notes: [],
    undecided: 0,
    fontData: 'AAAA',
    ...over,
  }
}

it('prints only accepted selected relationships and escapes source labels and notes', () => {
  const accepted = {
    key: 'x',
    status: 'accepted' as const,
    includeInReport: true,
    notes: 'Reviewed <script>unsafe</script>',
    sourceLabel: '<img onerror=alert(1)>',
    targetLabel: 'PC',
    relation: 'observed',
    reason: 'same record',
    confidence: 'high',
    references: [
      { id: 1, evidenceId: 1, source: 'events' as const, sourceFile: 'processes.csv', sourceSha256: 'abc', sourceIndex: 0, recordKind: 'observation', ts: null, observedAt: 1, title: 'process' },
    ],
    aliases: {},
    updatedAt: 1,
  }
  const html = buildReportHtml(data({ relationships: [accepted, { ...accepted, key: 'rejected', status: 'rejected', sourceLabel: 'REJECTED_SENTINEL' }] }))
  expect(html).toContain('Reviewed evidence relationships')
  expect(html).toContain('processes.csv')
  expect(html).toContain('Collected:')
  expect(html).not.toContain('<img onerror=')
  expect(html).not.toContain('<script>unsafe')
  expect(html).not.toContain('REJECTED_SENTINEL')
})

describe('report html', () => {
  it('carries the REMN cover, numbered sections and the chain and incident cards, with every case string escaped', () => {
    const html = buildReportHtml(data())
    expect(html).toContain('class="wordmark">REMN<')
    expect(html).toContain('Case &lt;b&gt;one&lt;/b&gt; &amp; co')
    expect(html).not.toContain('<b>one</b>')
    expect(html).toContain('Urgent &lt;invoice&gt;')
    expect(html).toContain('Credential phishing &lt;form&gt;')
    expect(html).toContain('<span class="num">01</span><h2>Executive summary</h2>')
    expect(html).toContain('<h2>Attack chains</h2>')
    expect(html).toContain('class="pill verdict-confirmed">confirmed<')
    expect(html).toContain('What happened, in order.')
    expect(html).toContain('narrative drafted by the model')
    expect(html).toContain('note drafted by the model')
    expect(html).toContain('src="data:image/png;base64,iVBORw0KGgo="')
    expect(html).toContain("@font-face{font-family:'Gulax'")
    expect(html).toContain('every item decided')
    expect(html).not.toContain('undefined')
    // the cover opens on the verdict and the threat profile
    expect(html).toContain('class="seal compromise"')
    expect(html).toContain('Compromise confirmed')
    expect(html).toContain('<h2>What happened</h2>')
    expect(html).toContain('<h2>Findings by rule</h2>')
    expect(html).toContain('<h2>Method and limits</h2>')
  })

  it('reads a verdict from the decisions, never from the findings alone', () => {
    const d = data()
    expect(computeVerdict(d).kind).toBe('compromise')
    const undecided = data({ reviews: {}, incidents: d.incidents.map((i) => ({ ...i, status: 'new' as const })), undecided: 2 })
    expect(computeVerdict(undecided)).toMatchObject({ kind: 'pending', confirmed: 0 })
    const reviewedOnly = data({ reviews: { [chain.id]: { verdict: 'unsure' } } })
    expect(computeVerdict(reviewedOnly).kind).toBe('unconfirmed')
    const pua = f({
      ruleId: 'collection-defender-pua',
      severity: 'medium',
      source: 'events',
      refs: [5],
      title: 'Defender recorded a potentially unwanted application',
      status: 'escalated',
      entities: { threatName: 'PUA:Win32/Sample' },
    })
    const inc = buildIncidents([pua], {})
    const unwanted = data({ chains: [], reviews: {}, incidents: inc, findings: [pua] })
    expect(computeVerdict(unwanted)).toMatchObject({ kind: 'unwanted', label: 'Unwanted software' })
    expect(buildReportHtml(unwanted)).toContain('class="seal unwanted"')
    // the runs of the same unwanted program, confirmed alongside its detection, stay one verdict; a confirmed high finding does not
    const run = f({
      ruleId: 'collection-execution-user-path',
      severity: 'medium',
      source: 'events',
      refs: [6],
      title: 'Executable ran from a user profile location',
      status: 'escalated',
      attack: ['T1204.002'],
      entities: { computer: 'WS-1', image: 'c:/users/bob/appdata/local/shift/shift.exe' },
    })
    const withRuns = data({ chains: [], reviews: {}, incidents: buildIncidents([pua, run], {}), findings: [pua, run] })
    expect(computeVerdict(withRuns).kind).toBe('unwanted')
    const beacon = f({
      ruleId: 'win-sysmon-network-lolbin',
      severity: 'high',
      source: 'events',
      refs: [7],
      title: 'Network connection by a script host',
      status: 'escalated',
      entities: { computer: 'WS-1' },
    })
    const withBeacon = data({ chains: [], reviews: {}, incidents: buildIncidents([pua, beacon], {}), findings: [pua, beacon] })
    expect(computeVerdict(withBeacon).kind).toBe('compromise')
    // a confirmed medium item that is not user execution (persistence, evasion, lateral movement) is a second threat, not the same one
    const task = f({
      ruleId: 'win-scheduled-task-suspicious-content',
      severity: 'medium',
      source: 'events',
      refs: [8],
      title: 'Scheduled task with suspicious command',
      status: 'escalated',
      attack: ['T1053.005'],
      entities: { computer: 'WS-1' },
    })
    const withTask = data({ chains: [], reviews: {}, incidents: buildIncidents([pua, task], {}), findings: [pua, task] })
    expect(computeVerdict(withTask).kind).toBe('suspicious')
    // a confirmed item without an event time (a collected artefact) still appears in what happened, after the timed ones
    const html = buildReportHtml(
      data({
        chains: [],
        reviews: {},
        incidents: buildIncidents(
          [
            { ...pua, ts: null },
            { ...run, ts: 5, entities: { computer: 'WS-2' } },
          ],
          {},
        ),
        findings: [
          { ...pua, ts: null },
          { ...run, ts: 5, entities: { computer: 'WS-2' } },
        ],
      }),
    )
    expect(html).toContain('<h2>What happened</h2>')
    expect(html.indexOf('no event time')).toBeGreaterThan(html.indexOf('<ol class="moments">'))
    // the timed item (an incident titled after its host) comes first, the collected one last
    expect(html.indexOf('<b>WS-2</b>')).toBeGreaterThan(html.indexOf('<ol class="moments">'))
    expect(html.indexOf('no event time')).toBeGreaterThan(html.indexOf('<b>WS-2</b>'))
  })

  it('draws the threat profile from the ATT&CK techniques and rule tags of the printed findings', () => {
    const d = data()
    const profile = threatProfile(d)
    const by = Object.fromEntries(profile.map((b) => [b.def.id, b]))
    expect(by['initial-access'].state).toBe('confirmed')
    expect(by['impact'].state).toBe('none')
    const html = buildReportHtml(d)
    expect(html).toContain('class="hex confirmed"')
    expect(html).toContain('class="hex none"')
  })

  it('counts ATT&CK v19 technique ids toward the defense-evasion badge', () => {
    // v19 moved Impair Defenses and event-log clearing to T1685-T1690: the SigmaHQ rules carry
    // those ids, and a finding tagged only T1685 lit no badge
    const d = data()
    const tamper = f({ ruleId: 'sigma-defender-tamper', severity: 'high', source: 'events', refs: [99], attack: ['T1685'] })
    const de = threatProfile({ ...d, findings: [...d.findings, tamper] }).find((b) => b.def.id === 'defense-evasion')!
    expect(de.state).toBe('observed')
    expect(de.techniques).toEqual(['T1685'])
  })

  it('groups findings by rule with counts, spans and the values matched, and quotes the bottom line', () => {
    const rows = [1, 2, 3].map((i) =>
      f({ ruleId: 'win-new-firewall-rule', severity: 'medium', source: 'events', refs: [i], ts: i * 60_000, entities: { computer: 'WS-1', applicationPath: `c:\\app${i}.exe` } }),
    )
    const g = groupByRule(rows, { computer: 'WS-1' })
    expect(g).toHaveLength(1)
    expect(g[0]).toMatchObject({ findings: 3, rows: 3, first: 60_000, last: 180_000 })
    expect(g[0].values).toEqual(['c:\\app1.exe', 'c:\\app2.exe', 'c:\\app3.exe'])
    expect(bottomLine('**Bottom line** The host ran an installer.\n\n**What happened**\n- 08:30 tasks created')).toBe('The host ran an installer.')
    expect(bottomLine('Plain first paragraph.\n\nSecond.')).toBe('Plain first paragraph.')
  })

  it('folds runs of the same step into one row with a count and a span, and caps the rows it prints', () => {
    const s = (i: number, title: string, ties: string[] = []): ChainStep => ({
      kind: 'event',
      source: 'events',
      id: i,
      ts: i * 60_000,
      tsEnd: i * 60_000,
      count: 1,
      title,
      weight: 2,
      artifacts: ties,
      findings: [],
      offsetMin: i,
      origin: 'm365',
      ipAddress: '203.0.113.9',
    })
    const steps = [
      s(1, 'mailbox items accessed'),
      s(2, 'mailbox items accessed'),
      s(3, 'mailbox items accessed'),
      s(4, 'file downloaded', ['tie']),
      s(5, 'mailbox items accessed'),
      s(6, 'mailbox items accessed', ['tie']),
    ]
    const folded = foldSteps(steps)
    expect(folded.map((f) => [f.step.title, f.n])).toEqual([
      ['mailbox items accessed', 3],
      ['file downloaded', 1],
      ['mailbox items accessed', 1],
      ['mailbox items accessed', 1],
    ])
    expect(folded[0].offsetMin).toBe(1)
    expect(folded[0].offsetEnd).toBe(3)
    const runs = buildReportHtml(data({ chains: [{ ...chain, steps }] }))
    expect(runs).toContain('<span class="chip">×3</span>')
    expect(runs).toContain('<thead>')
    expect(runs).not.toContain('position:fixed')
    const long = { ...chain, steps: Array.from({ length: MAX_STEP_ROWS + 25 }, (_, i) => s(i + 1, `step ${i + 1}`)) }
    expect(buildReportHtml(data({ chains: [long] }))).toContain('25 more step row(s) not printed')
  })

  it('drops pictures and fonts that are not what the app produced, and follows the section switches', () => {
    const html = buildReportHtml(data({ graphs: { alice: 'javascript:alert(1)' }, fontData: 'not base64!', settings: { ...DEFAULT_REPORT, includeEvidence: false, includeIocs: false }, undecided: 3 }))
    expect(html).not.toContain('javascript:alert')
    expect(html).not.toContain('@font-face')
    expect(html).not.toContain('<h2>Evidence and chain of custody</h2>')
    expect(html).not.toContain('<h2>Indicators of compromise</h2>')
    expect(html).toContain('<b>3</b> items without a decision')
  })
})

describe('what the report claims about the case', () => {
  it('keeps a confirmed item in the verdict when the print settings leave it out', () => {
    const reviewedOnly = data({ reviews: { [chain.id]: { verdict: 'unsure' } } })
    expect(computeVerdict(reviewedOnly).kind).toBe('unconfirmed')
    const hidden = f({ ruleId: 'local-admin-added', severity: 'low', refs: [21], status: 'escalated' })
    const v = computeVerdict({ ...reviewedOnly, unprintedConfirmed: [{ severity: 'low', findings: [hidden] }] })
    expect(v.confirmed).toBe(1)
    expect(v.kind).not.toBe('unconfirmed')
    expect(v.detail).toContain('not printed')
  })

  it('does not call an analysis complete when a file was not read in full or the rules are behind', () => {
    expect(computeConfidence(data({ iocsChecked: 1, rules: { lastRun: 1, evidenceAfter: 0, errors: 0 } })).level).toBe('high')
    const stopped = data({
      iocsChecked: 1,
      evidence: [{ id: 1, caseId: 1, name: 'dc.evtx', size: 1, kind: 'evtx', status: 'error', error: 'parse stopped at the limit', integrity: 'verified', addedAt: 0, count: 10 } as never],
    })
    const c = computeConfidence(stopped)
    expect(c.level).not.toBe('high')
    expect(c.reasons.join(' ')).toContain('not read completely')
    expect(buildReportHtml(stopped)).toContain('incomplete: parse stopped')
    expect(computeConfidence(data({ iocsChecked: 1, rules: { lastRun: null, evidenceAfter: 0, errors: 0 } })).reasons).toContain('the rules have not run on this case')
  })

  it('says first under Where it stops what the evidence cannot show, escaped', () => {
    const html = buildReportHtml(
      data({
        gaps: [
          { kind: 'record-holes', severity: 'high', text: 'Security on DC01 (<b>x</b>.evtx): 3 records missing from its numbering.', evidenceId: 1 },
          { kind: 'mail-throttled', severity: 'high', text: 'MailItemsAccessed for a@example.test was throttled.' },
        ],
      }),
    )
    const limits = html.slice(html.indexOf('<h4>Where it stops</h4>'))
    expect(limits).toContain('<li>Security on DC01 (&lt;b&gt;x&lt;/b&gt;.evtx): 3 records missing from its numbering.</li>')
    expect(limits.indexOf('records missing')).toBeLessThan(limits.indexOf('Times are UTC'))
    expect(limits).toContain('MailItemsAccessed for a@example.test was throttled.')
  })

  it('says indicators were checked only when a lookup ran', () => {
    const on = data({ kase: { ...kase, settings: { ...kase.settings, networkAllowed: true } } })
    expect(buildReportHtml(on)).toContain('No indicator was checked against a reputation service')
    expect(buildReportHtml({ ...on, iocsChecked: 3, iocsTotal: 10 })).toContain('3 of 10 indicators were checked')
  })

  it('says how many moments it leaves out of What happened, and counts them all', () => {
    const many = Array.from({ length: MAX_MOMENTS + 6 }, (_, i) => f({ ruleId: `r${i}`, severity: 'high', refs: [100 + i], status: 'escalated', ts: i * 60_000 }))
    const incs = buildIncidents(many, {})
    const d = data({ chains: [], reviews: {}, incidents: incs, findings: many })
    const m = moments(d)
    expect(m.items).toHaveLength(MAX_MOMENTS)
    expect(m.total).toBe(incs.length)
    expect(buildReportHtml(d)).toContain(`The first ${MAX_MOMENTS} of ${incs.length} are listed`)
  })

  it('prints UTC whatever the display setting', () => {
    setLocalTime(true)
    try {
      expect(buildReportHtml(data())).toContain('1970-01-01 00:01:00Z')
    } finally {
      setLocalTime(false)
    }
  })
})

it('prints an undated timeline entry without inventing a time for it', () => {
  const html = buildReportHtml(data({ timeline: [{ caseId: 1, kind: 'timeline', text: 'Run key: updater.exe', ts: 1_788_000_000_000, untimed: true, createdAt: 0, updatedAt: 0 }] }))
  expect(html).toContain('no event time')
  expect(html).not.toContain('2026-08-29')
})

it('says draft on the cover and lists what is open, and prints the waivers of a final report', () => {
  const draft = buildReportHtml(data({ issue: { status: 'draft', open: [{ label: 'Every item has a decision', detail: '3 item(s) without a decision' }], waived: [] } }))
  expect(draft).toContain('draft · not issued')
  expect(draft).toContain('class="cover draft"')
  expect(draft).toContain('This is a draft. Open before it can be final: every item has a decision (3 item(s) without a decision)')
  const final = buildReportHtml(
    data({ issue: { status: 'final', finalAt: Date.UTC(2026, 8, 23, 10, 0, 0), open: [], waived: [{ label: 'Every item has a decision', reason: 'low noise left for later' }] } }),
  )
  expect(final).toContain('final · issued 2026-09-23 10:00:00Z')
  expect(final).not.toContain('cover draft')
  expect(final).toContain('The analyst&#39;s reason: low noise left for later')
})
