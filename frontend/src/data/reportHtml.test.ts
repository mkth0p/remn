import { describe, expect, it } from 'vitest'
import type { Case, Finding } from '../db/schema'
import type { Chain } from './chains'
import { buildIncidents } from '../rules/incidents'
import { DEFAULT_REPORT } from './review'
import { bottomLine, buildReportHtml, computeConfidence, computeVerdict, foldSteps, groupByRule, MAX_MOMENTS, MAX_STEP_ROWS, moments, threatProfile, type ReportData } from './reportHtml'
import type { DecidedStory } from './storyDecisions'
import { setLocalTime } from '../util/format'
import { readMeasure } from './ruleMeasures'
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

  it('marks the findings of a rule never seen to detect what it looks for, and says so in its method', () => {
    const measures = {
      'mail-credential-phishing': readMeasure({ own: true, of: 2, hits: 2, fires: 2 }, 'bundled'),
      other: readMeasure({ of: 3, fires: 1, clean: { findings: 4, events: 4, machines: 1, scope: 10_000, of: 7 } }, 'bundled'),
    }
    const html = buildReportHtml(data({ measures, measuredOn: 'Measured on 2026-09-24 on <recordings>.' }))
    expect(html).toContain('<code>other</code> · <b class="lead">lead</b>')
    expect(html).not.toContain('<code>mail-credential-phishing</code> · <b class="lead">')
    expect(html).toContain('of those rules, 1 fires on recorded attacks of what it looks for and 1 was never seen to (their findings are marked lead). Measured on 2026-09-24 on &lt;recordings&gt;.')
    const limits = html.slice(html.indexOf('<h4>Where it stops</h4>'))
    expect(limits).toContain('<li>1 printed finding comes from a rule never seen to detect what it looks for on recorded attacks (marked lead)')
    // without measures, nothing is said about them
    const plain = buildReportHtml(data())
    expect(plain).not.toContain('class="lead"')
    expect(plain).not.toContain('never seen to')
  })

  it('says under each rule whether its rows bear it out, where they are, and lists what does not hold', () => {
    const d = data()
    const byRule = (r: string) => d.findings.find((x) => x.ruleId === r)!.id!
    const rec = { file: 'box.mbox', record: 'message 8', key: 'k' }
    const claims = {
      findings: {
        [byRule('mail-credential-phishing')]: { status: 'verified' as const, cited: 1, checked: 1, reasons: [], records: [rec] },
        [byRule('other')]: { status: 'contradicted' as const, cited: 1, checked: 1, reasons: ['box.mbox message 9 no longer matches the rule'], records: [] },
      },
      texts: [
        { key: 'summary', what: 'the executive summary', check: { status: 'unsupported' as const, named: ['198.51.100.9'], reasons: ['it names 198.51.100.9, which no row of the evidence holds'] } },
      ],
    }
    const html = buildReportHtml({ ...d, claims })
    expect(html).toContain('<span class="sub claim verified" title="">rows checked · box.mbox message 8</span>')
    expect(html).toContain('<span class="sub claim contradicted" title="box.mbox message 9 no longer matches the rule">rows disagree</span>')
    expect(html).toContain('<div class="cap claim unsupported">Checked against its rows: it names 198.51.100.9, which no row of the evidence holds.</div>')
    expect(html).toContain(
      'each printed finding was read back against the rows it cites (the first 50 of each): 1 verified, 0 unsupported, 1 contradicted; 1 text (chain narratives, incident and story notes, the summary) checked for the addresses, accounts and hashes it names, 0 holding',
    )
    const limits = html.slice(html.indexOf('<h4>Where it stops</h4>'))
    expect(limits).toContain('<li>The finding &quot;other&quot; (other) is contradicted by its rows: box.mbox message 9 no longer matches the rule.</li>')
    expect(limits).toContain('<li>The executive summary is unsupported: it names 198.51.100.9, which no row of the evidence holds.</li>')
  })

  it("prints each story along its phases with what marks them, the analyst's note and its check, and where it stops", () => {
    const step = (id: string, phase: string, title: string, findings: { title: string; severity: Finding['severity'] }[] = []) => ({
      id,
      refs: [id],
      source: 'events',
      ts: 60_000,
      tsEnd: 60_000,
      count: 1,
      title,
      host: 'WS-004',
      ip: null,
      origin: 'host',
      phase,
      phaseBasis: '',
      findings: findings.map((x) => ({ ruleId: x.title, key: null, ...x })),
      severity: findings[0]?.severity ?? null,
      tie: { kind: 'flag', basis: '', confidence: 'strong' },
      notes: [],
      accounts: [],
      session: null,
      process: null,
      hops: [],
      routine: false,
    })
    const phase = (p: string, label: string, severity: Finding['severity'] | null) => ({ phase: p, label, first: 60_000, last: 120_000, steps: 1, records: 1, findings: severity ? 1 : 0, severity })
    const story = {
      id: 'story-1',
      kind: 'person',
      subject: { kind: 'person', id: 'id:1', label: 'daniel.roy@corp.test', org: 'corp.test' },
      title: 'daniel.roy@corp.test: RDP <logon> from outside',
      headline: 'RDP logon from outside',
      summary: 'the automatic summary of the story',
      start: 60_000,
      end: 120_000,
      severity: 'critical',
      score: 90,
      confidence: 'strong',
      phases: [phase('initial-access', 'Initial access', 'high'), phase('defense-impairment', 'Defense impairment', 'critical'), phase('persistence', 'Persistence', null)],
      steps: [
        step('event:1', 'initial-access', 'RDP logon', [{ title: 'RDP logon from outside', severity: 'high' }]),
        step('event:2', 'defense-impairment', 'log cleared', [{ title: 'Audit log cleared', severity: 'critical' }]),
        step('event:3', 'persistence', 'task created <x>'),
      ],
      records: 3,
      hosts: ['WS-004'],
      accounts: [],
      ips: ['203.0.113.69'],
      attackerAddresses: ['203.0.113.69'],
      chains: [],
      findings: [],
      campaigns: [],
      gaps: ['WS-004 has no Sysmon process records: what ran is only 4688 without command lines.'],
      lineage: { sessions: [], hops: [], processes: [] },
    } as never
    const key = 'person|x|1970-01-01'
    const claims = {
      findings: {},
      texts: [{ key: `story:${key}`, what: 'the note', check: { status: 'unsupported' as const, named: ['10.9.9.9'], reasons: ['it names 10.9.9.9, which no row of the story holds'] } }],
    }
    const html = buildReportHtml(data({ stories: [{ story, key, note: 'He came in over **RDP** from 10.9.9.9.' }], storiesLeft: 2, claims }))
    const section = html.slice(html.indexOf('<h2>Stories</h2>'), html.indexOf('<h2>Attack chains</h2>'))
    expect(section).toContain('daniel.roy@corp.test: RDP &lt;logon&gt; from outside')
    expect(section).toContain('strong ties')
    // the phases in the story's order, each with its worst finding or, without one, its first step
    expect(section.indexOf('Initial access')).toBeLessThan(section.indexOf('Defense impairment'))
    expect(section).toContain('Audit log cleared')
    expect(section).toContain('task created &lt;x&gt;')
    expect(section).toContain('<strong>RDP</strong>')
    expect(section).not.toContain('the automatic summary of the story')
    expect(section).toContain('Checked against its rows: it names 10.9.9.9, which no row of the story holds.')
    expect(section).toContain('Where it stops: WS-004 has no Sysmon process records')
    expect(section).toContain('2 more stories are not printed')
    // a report without stories has no Stories section
    expect(buildReportHtml(data())).not.toContain('<h2>Stories</h2>')
  })

  it('says where a cut build stops, a story no record shows starting, stories out of date and notes whose story is gone', () => {
    const phase = (p: string, label: string) => ({ phase: p, label, first: 60_000, last: 120_000, steps: 1, records: 1, findings: 1, severity: 'high' })
    const story = {
      id: 'story-2',
      kind: 'host',
      subject: { kind: 'host', id: 'fs-001', label: 'FS-001', org: null },
      title: 'FS-001',
      headline: 'Service installed',
      summary: 'A service was installed.',
      start: 60_000,
      end: 120_000,
      severity: 'high',
      score: 60,
      confidence: 'strong',
      phases: [phase('execution', 'Execution'), phase('persistence', 'Persistence')],
      steps: [],
      records: 2,
      hosts: ['FS-001'],
      accounts: [],
      ips: [],
      attackerAddresses: [],
      chains: [],
      findings: [],
      campaigns: [],
      gaps: [],
      lineage: { sessions: [], hops: [], processes: [] },
    } as never
    const stats = { events: 50_000, truncated: ['context', 'refs'], cut: { context: 12, 'context-hosts': 12, refs: 3 } }
    const html = buildReportHtml(
      data({
        stories: [{ story, key: 'story-2' }],
        storyStats: stats,
        storiesStale: ['the findings changed since they were built (a rule run, a false positive or a severity set by hand)'],
        storyNotesOrphaned: 2,
      }),
    )
    const section = html.slice(html.indexOf('<h2>Stories</h2>'), html.indexOf('<h2>', html.indexOf('<h2>Stories</h2>') + 1))
    expect(section).toContain('Out of date: the findings changed since they were built')
    expect(section).toContain('Incomplete: The records around the flags passed 50,000')
    expect(section).toContain('and left out 12 on the flagged hosts.')
    expect(section).toContain('3 finding(s) cite more than 2,000 records')
    expect(section).toContain('An absent step or story is not a negative result.')
    expect(section).toContain('2 analyst notes are on a story this build no longer holds')
    // the story's own gap: no record shows how it started
    expect(section).toContain('Where it stops: No record of the story shows how it started')
    const limits = html.slice(html.indexOf('<h4>Where it stops</h4>'))
    expect(limits).toContain('<li>Stories out of date: the findings changed since they were built')
    expect(limits).toContain('<li>Stories incomplete: 3 finding(s) cite more than 2,000 records')
    // a current, complete build says none of it
    const clean = buildReportHtml(data({ stories: [{ story, key: 'story-2' }], storyStats: { events: 10, truncated: [] }, storiesStale: [] }))
    expect(clean).not.toContain('Out of date:')
    expect(clean).not.toContain('Stories incomplete')
  })

  it("prints an incident's stories together under one heading that says why they read as one", () => {
    const story = (id: string, title: string, start: number, extra: Record<string, unknown> = {}) =>
      ({
        id,
        kind: 'person',
        subject: { kind: 'person', id: `id:${id}`, label: title, org: null },
        title,
        headline: title,
        summary: '',
        start,
        end: start + 60_000,
        severity: 'high',
        score: 50,
        confidence: 'strong',
        phases: [],
        steps: [],
        records: 1,
        hosts: [],
        accounts: [],
        ips: [],
        attackerAddresses: [],
        chains: [],
        findings: [],
        campaigns: [],
        gaps: [],
        lineage: { sessions: [], hops: [], processes: [] },
        incident: null,
        ...extra,
      }) as never
    const link = (other: string, confidence: string, basis: string) => ({ story: other, kind: 'credentials', basis, confidence, refs: [] })
    const a = story('a', 'carla.morel', 60_000, { incident: 'incident-1', links: [link('c', 'strong', "carla.morel used svc-backup's account <x>")] })
    const b = story('b', 'WS-010', 30_000)
    const c = story('c', 'svc-backup', 120_000, { incident: 'incident-1', links: [link('a', 'strong', "carla.morel used svc-backup's account <x>"), link('b', 'weak', 'on the host then')] })
    const incident = {
      id: 'incident-1',
      label: 'carla.morel and svc-backup',
      stories: ['a', 'c', 'd'],
      start: 60_000,
      end: 180_000,
      severity: 'critical',
      score: 90,
      people: [],
      hosts: ['FS-001'],
      cut: 2,
      cutStories: [],
    }
    const html = buildReportHtml(
      data({
        stories: [
          { story: a, key: 'a' },
          { story: b, key: 'b' },
          { story: c, key: 'c' },
        ],
        storyIncidents: [incident as never],
      }),
    )
    const section = html.slice(html.indexOf('<h2>Stories</h2>'), html.indexOf('<h2>', html.indexOf('<h2>Stories</h2>') + 1))
    expect(section).toContain('One intrusion: carla.morel and svc-backup')
    // its stories under it, in time order, before the story it does not hold
    expect(section.indexOf('One intrusion')).toBeLessThan(section.indexOf('<h3>carla.morel</h3>'))
    expect(section.indexOf('<h3>carla.morel</h3>')).toBeLessThan(section.indexOf('<h3>svc-backup</h3>'))
    expect(section.indexOf('<h3>svc-backup</h3>')).toBeLessThan(section.indexOf('<h3>WS-010</h3>'))
    // why, once per pair and escaped; a weak link joins nothing
    expect(section).toContain('Why they read as one: carla.morel used svc-backup&#39;s account &lt;x&gt; (strong).')
    expect(section).not.toContain('on the host then')
    expect(section).toContain('1 more of its stories is not printed')
    expect(section).toContain('2 more linked stories are left out of it')
    // without the build's incidents the stories print one by one, as before
    expect(
      buildReportHtml(
        data({
          stories: [
            { story: a, key: 'a' },
            { story: c, key: 'c' },
          ],
        }),
      ),
    ).not.toContain('One intrusion')
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

describe('stories the analyst decided', () => {
  const decidedStory = (over: Partial<DecidedStory> = {}): DecidedStory => ({
    title: 'daniel.roy@corp.test',
    verdict: 'confirmed',
    reason: 'the RDP logon from outside is the way in',
    severity: 'high',
    start: 60_000,
    end: 120_000,
    hosts: ['WS-004'],
    findings: [],
    printed: true,
    ...over,
  })
  // a case with nothing decided but its stories
  const bare = (over: Partial<ReportData> = {}) => data({ chains: [], reviews: {}, incidents: [], findings: [], membersOf: new Map(), ...over })

  it('count in the verdict as incidents with the same decision would, printed or not', () => {
    expect(computeVerdict(bare()).kind).toBe('clean')
    expect(computeVerdict(bare({ decidedStories: [decidedStory()] }))).toMatchObject({ kind: 'compromise', label: 'Compromise confirmed', confirmed: 1, severity: 'high' })
    expect(computeVerdict(bare({ decidedStories: [decidedStory({ severity: 'medium' })] })).kind).toBe('suspicious')
    // left out of the report by its settings, still confirmed, and the cover says it is not printed
    const hidden = computeVerdict(bare({ decidedStories: [decidedStory({ printed: false })] }))
    expect(hidden).toMatchObject({ kind: 'compromise', confirmed: 1 })
    expect(hidden.detail).toContain('1 of them is not printed')
    // a confirmed story whose findings are only unwanted software reads as that
    const pua = f({ ruleId: 'collection-defender-pua', severity: 'medium', title: 'Defender recorded a potentially unwanted application' })
    expect(computeVerdict(bare({ decidedStories: [decidedStory({ severity: 'medium', findings: [pua] })] })).kind).toBe('unwanted')
    // reviewed reads as reviewed; benign and false positive as false positives, with the case's own
    expect(computeVerdict(bare({ decidedStories: [decidedStory({ verdict: 'reviewed' })] }))).toMatchObject({ kind: 'unconfirmed', reviewed: 1 })
    expect(computeVerdict(bare({ falsePositives: 2, decidedStories: [decidedStory({ verdict: 'benign' }), decidedStory({ verdict: 'false_positive' })] }))).toMatchObject({
      kind: 'clean',
      falsePositives: 4,
    })
    // a confirmed story's findings fill its tactics on the cover, and it is one of the moments of What happened
    const rdp = f({ ruleId: 'win-rdp-logon-external', severity: 'high', attack: ['T1133'], source: 'events' })
    const d = bare({ findings: [rdp], decidedStories: [decidedStory({ findings: [rdp] })] })
    expect(threatProfile(d).find((b) => b.def.id === 'initial-access')?.state).toBe('confirmed')
    const m = moments(d)
    expect(m.items).toMatchObject([{ title: 'Story of daniel.roy@corp.test', decision: 'confirmed', kind: 'story', note: 'the RDP logon from outside is the way in' }])
  })

  it("print each decision on the story's card, leave a disputed step out of what marks its phase, and say how many stories were dismissed", () => {
    const step = (id: string, title: string, finding?: string) => ({
      id,
      refs: [id],
      source: 'events',
      ts: 60_000,
      tsEnd: 60_000,
      count: 1,
      title,
      host: 'WS-004',
      ip: null,
      origin: 'host',
      phase: 'initial-access',
      phaseBasis: '',
      findings: finding ? [{ ruleId: finding, title: finding, severity: 'high', key: finding }] : [],
      severity: finding ? 'high' : null,
      tie: { kind: 'flag', basis: '', confidence: 'strong' },
      notes: [],
      accounts: [],
      session: null,
      process: null,
      hops: [],
      routine: false,
    })
    const story = {
      id: 'story-1',
      kind: 'person',
      subject: { kind: 'person', id: 'id:1', label: 'daniel.roy@corp.test', org: 'corp.test' },
      title: 'daniel.roy@corp.test',
      headline: 'RDP logon from outside',
      summary: '',
      start: 60_000,
      end: 120_000,
      severity: 'high',
      score: 70,
      confidence: 'strong',
      phases: [{ phase: 'initial-access', label: 'Initial access', first: 60_000, last: 60_000, steps: 1, records: 1, findings: 1, severity: 'high' }],
      steps: [step('event:1', 'vpn logon', 'VPN logon from a new country'), step('event:2', 'rdp <logon>', 'RDP logon from outside')],
      records: 2,
      hosts: ['WS-004'],
      accounts: [],
      ips: [],
      attackerAddresses: [],
      chains: [],
      findings: ['RDP logon from outside'],
      campaigns: [],
      gaps: [],
      lineage: { sessions: [], hops: [], processes: [] },
    } as never
    const decisions = {
      call: { verdict: 'confirmed' as const, reason: 'came in over <RDP>', decidedAt: 1 },
      part: 'first' as const,
      split: { title: 'service installed', ts: 180_000, reason: 'a second intrusion' },
      merged: [{ title: 'ws-009', reason: 'the same session', orgs: ['corp.test', 'other.test'] }],
      out: [{ title: 'failed logons', count: 3, reason: 'another user mistyping' }],
      disputed: [{ id: 'event:1', title: 'vpn logon', ts: 60_000, reason: 'the travelling CFO' }],
      confirmedSteps: 1,
    }
    const html = buildReportHtml(data({ stories: [{ story, key: 'story-1', decisions }], storiesDismissed: 2, storiesLeft: 1, settings: { ...DEFAULT_REPORT, onlyReviewed: true } }))
    const section = html.slice(html.indexOf('<h2>Stories</h2>'), html.indexOf('<h2>Attack chains</h2>'))
    expect(section).toContain('daniel.roy@corp.test (first part)</h3><span class="pill verdict-confirmed">confirmed incident</span>')
    expect(section).toContain('The analyst decided it confirmed incident: came in over &lt;RDP&gt;')
    expect(section).toContain('Merged into it by the analyst: the story of ws-009 (another organisation, corp.test and other.test): the same session')
    expect(section).toContain('Split by the analyst at “service installed”')
    expect(section).toContain('Taken out by the analyst: “failed logons” (3 records): another user mistyping')
    expect(section).toContain('Disputed by the analyst and left out of its phases and severity: “vpn logon” (1970-01-01 00:01:00Z): the travelling CFO')
    expect(section).toContain('1 step confirmed by the analyst.')
    // the disputed step's finding no longer marks the phase
    const phases = section.slice(section.indexOf('<table>'), section.indexOf('</table>'))
    expect(phases).toContain('RDP logon from outside')
    expect(phases).not.toContain('VPN logon from a new country')
    expect(section).toContain('1 more story is not printed: below the severity floor, without a note or a decision (reviewed items only)')
    expect(section).toContain('2 stories decided benign or false positive by the analyst are not printed.')
    expect(html).toContain('2 stories decided benign or false positive are not printed')
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
