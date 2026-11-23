import { describe, expect, it } from 'vitest'
import type { Case, CaseNote, Evidence, Finding, QuestionAnswer } from '../db/schema'
import { buildIncidents } from '../rules/incidents'
import type { Chain } from './chains'
import { chainCoverageWarnings } from './chains'
import type { ReportClaims } from './claims'
import type { GapSay, GapStatement } from './evidenceGaps'
import { questionsForReport } from './questions/answers'
import { evidenceProfile } from './questions/coverage'
import { DEFAULT_REPORT, EMPTY_CLIENT } from './review'
import { reportDocumentXml } from './reportDocx'
import { buildReportHtml, type ReportData } from './reportHtml'
import { EN, reportText, type ReportLanguage } from './reportText'
import { measuredOn, readMeasure } from './ruleMeasures'
import { storiesStaleness, type StoryResult } from './stories'
import { spinedStory } from '../test/spineStory'

// every name, host, address and text here is invented for the test

let seq = 1
const finding = (p: Partial<Finding> & { ruleId: string }): Finding => ({
  id: seq++,
  caseId: 1,
  key: `${p.ruleId}|${seq}`,
  title: p.ruleId,
  source: 'events',
  severity: 'high',
  ts: Date.UTC(2026, 3, 2, 9),
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
  name: 'Quillfeather',
  analyst: 'Zorvath',
  createdAt: 0,
  updatedAt: 0,
  storage: 'browser',
  settings: { internalDomains: ['corp.test'], vipNames: [], businessHours: { start: 8, end: 19, tz: 'UTC' } } as unknown as Case['settings'],
}

const chain: Chain = {
  id: 'kestrin',
  identity: 'kestrin',
  identityLabel: 'kestrin@corp.test',
  start: Date.UTC(2026, 3, 2, 8),
  end: Date.UTC(2026, 3, 2, 9),
  score: 80,
  severity: 'high',
  artifactLinks: 1,
  summary: 'Zyx chain summary',
  scoreBreakdown: { seed: 30, links: 20, steps: 15, findings: 10, sources: 5, cap: 70, linkSteps: 1 },
  seed: { id: 7, ts: Date.UTC(2026, 3, 2, 8), subject: 'Zyx invoice', fromAddr: 'qv@evil.test', risk: 90, flags: [], findings: [], urlDomains: [], attachments: [] },
  steps: [
    {
      kind: 'event',
      source: 'events',
      id: 11,
      ts: Date.UTC(2026, 3, 2, 8, 5),
      tsEnd: Date.UTC(2026, 3, 2, 8, 5),
      count: 1,
      title: 'Zyx step title',
      weight: 3,
      artifacts: ['Zyx artifact'],
      findings: [],
      offsetMin: 5,
      origin: 'm365',
    },
  ],
  entities: { user: 'kestrin', ips: ['203.0.113.9'], hosts: ['WS-017'], attackerAddresses: ['qv@evil.test'], domains: ['evil.test'] },
}

const findings: Finding[] = [
  finding({ ruleId: 'chain', key: 'chain|kestrin|7', refs: [7], source: 'mails' }),
  finding({ ruleId: 'zyx-mail-rule', source: 'mails', refs: [7], title: 'Zyx mail rule', severity: 'critical', entities: { fromAddr: 'qv@evil.test', subject: 'Zyx invoice' } }),
  finding({
    ruleId: 'zyx-host-rule',
    title: 'Zyx host rule',
    status: 'escalated',
    attack: ['T1059.001'],
    entities: { computer: 'WS-017', targetUser: 'CORP\\qorbin', destinationIp: '203.0.113.50' },
    notes: 'Zyx analyst note',
    notesBy: 'ai',
    decidedBy: 'ai',
    aiReason: 'Zyx model reason',
  }),
  finding({ ruleId: 'zyx-other-rule', title: 'Zyx other rule', severity: 'medium', status: 'reviewed', entities: { computer: 'WS-017' } }),
  finding({ ruleId: 'zyx-lone-rule', title: 'Zyx lone rule', severity: 'low', entities: {} }),
  finding({ ruleId: 'engine:hayabusa:zyx', title: 'Zyx engine rule', severity: 'medium', status: 'false_positive', entities: { computer: 'WS-055', ipAddress: '198.51.100.88' } }),
]

const at = (n: number) => ({ kind: 'record' as const, n, channel: 'Security', computer: 'WS-017' })
const ref = (n: number) => ({ file: 'Zyx.evtx', record: `record ${n}`, at: at(n), key: `k${n}` })

/** one statement of each kind the evidence can lack */
const SAYS: GapSay[] = [
  { kind: 'record-holes', where: { file: 'Zyx.evtx', channel: 'Security', computer: 'WS-017' }, floor: true, missing: 3, gaps: 2, first: 4, last: 90, largest: [5, 7] },
  { kind: 'record-holes', where: { file: 'Zyx.evtx', channels: 2, computers: 3 }, floor: false, missing: 1, gaps: 1, first: 4, last: 8, largest: [5, 5] },
  { kind: 'checksum-data', file: 'Zyx.evtx', bad: 2, chunks: 9 },
  { kind: 'checksum-header', file: 'Zyx.evtx', headers: 1, fileHeader: true },
  { kind: 'clock-logs', computer: 'WS-017', logs: 2, from: Date.UTC(2026, 3, 2, 9), to: Date.UTC(2026, 3, 2, 8) },
  { kind: 'clock-set', computer: 'WS-017', from: Date.UTC(2026, 3, 2, 9), to: Date.UTC(2026, 3, 2, 8) },
  { kind: 'time-backwards', where: { file: 'Zyx.evtx' }, steps: 4, largest: 7_200_000, record: 77, unread: 2 },
  {
    kind: 'missing-between-files',
    channel: 'Security',
    computer: 'WS-017',
    from: 101,
    to: 179,
    before: 'Zyx-a.evtx',
    beforeLast: 100,
    after: 'Zyx-b.evtx',
    afterFirst: 180,
  },
  { kind: 'log-starts-late', computer: 'WS-017', start: Date.UTC(2026, 3, 2), logs: [['Security', Date.UTC(2026, 3, 3)]], count: 1 },
  { kind: 'export-cap', file: 'Zyx-ual.csv', records: 50_000, source: 'ual' },
  { kind: 'export-cap', file: 'Zyx-trace.csv', records: 1000, source: 'message-trace' },
  { kind: 'export-cap', file: 'Zyx-audit.csv', records: 777, source: 'entra-audit' },
  { kind: 'xml-export', file: 'Zyx.xml', records: 12 },
  { kind: 'parse-limit', file: 'Zyx.evtx', kept: 1_000_000 },
  { kind: 'read-in-part', file: 'Zyx.evtx', note: 'Zyx parser note' },
  { kind: 'mail-throttled', user: 'kestrin@corp.test', from: Date.UTC(2026, 3, 2) },
  { kind: 'signins-start-late', first: Date.UTC(2026, 3, 3), start: Date.UTC(2026, 3, 2) },
]
const gaps: GapStatement[] = SAYS.map((say) => ({ kind: say.kind === 'clock-set' ? 'clock-set-back' : 'record-holes', severity: 'high', text: EN.gap(say), say }) as GapStatement)

function claims(): ReportClaims {
  const ids = findings.map((f) => f.id!)
  const check = (why: ReportClaims['findings'][number]['why'], status: 'contradicted' | 'unsupported' = 'contradicted') => ({
    status,
    cited: 3,
    checked: 3,
    reasons: why.map(EN.claim.reason),
    why,
    records: [ref(9)],
  })
  return {
    findings: {
      [ids[1]]: check([{ kind: 'no-match', records: [ref(9), { file: 'Zyx.mbox', record: 'message 2', at: { kind: 'message', n: 2 }, key: 'm' }], more: 2 }]),
      [ids[2]]: check([
        { kind: 'rows-missing', missing: 1, checked: 3 },
        { kind: 'value-absent', field: 'ipAddress', values: ['198.51.100.9'] },
        { kind: 'time', ts: Date.UTC(2026, 3, 2), first: Date.UTC(2026, 3, 3) },
      ]),
      [ids[3]]: check([{ kind: 'no-rows' }], 'unsupported'),
      [ids[4]]: {
        ...check([{ kind: 'no-match', records: [{ file: 'Zyx.json', record: 'x', at: { kind: 'cloud', what: 'sign-in', id: 'abc' }, key: 'c' }], more: 0 }]),
        records: [{ file: 'Zyx.json', record: 'x', at: { kind: 'cloud', what: 'sign-in', id: 'abc' }, key: 'c' }],
      },
    },
    texts: [
      { key: 'summary', about: { kind: 'summary' }, what: 'x' },
      { key: 'chain:kestrin', about: { kind: 'chain', title: 'kestrin' }, what: 'x' },
      { key: `incident:${ids[2]}`, about: { kind: 'incident', title: 'Zyx host rule' }, what: 'x' },
      { key: 'story:person|x|2026-09-04', about: { kind: 'story', title: 'Zyx story' }, what: 'x' },
    ].map((x, i) => ({
      ...x,
      about: x.about as ReportClaims['texts'][number]['about'],
      what: EN.claim.about(x.about as ReportClaims['texts'][number]['about']),
      check: {
        status: 'unsupported' as const,
        named: ['198.51.100.9'],
        why: [i % 2 ? { kind: 'text-absent' as const, values: ['198.51.100.9'], more: 2, rows: 3 } : { kind: 'text-absent-case' as const, values: ['198.51.100.9'], more: 0 }],
        reasons: [],
      },
    })),
  }
}

const answers = new Map<string, QuestionAnswer>([
  [
    'Q1074',
    {
      caseId: 1,
      questionId: 'Q1074',
      status: 'answered',
      text: 'Zyx answer text',
      citations: [{ source: 'events', rowId: 80, label: 'Zyx citation label', ts: 0, addedAt: 0 }],
      createdAt: 0,
      updatedAt: 0,
    },
  ],
])

const note = (kind: CaseNote['kind'], text: string, extra: Partial<CaseNote> = {}): CaseNote => ({ caseId: 1, kind, text, ts: Date.UTC(2026, 3, 2, 8), createdAt: 0, updatedAt: 0, ...extra })
const evidence = (p: Partial<Evidence>): Evidence => ({ caseId: 1, name: 'Zyx.evtx', size: 10, kind: 'evtx', integrity: 'verified', addedAt: 0, status: 'done', count: 5, ...p }) as Evidence

/** The same case, its parts that REMN writes put in the words of the given language as the Report page does. */
function report(language: ReportLanguage): ReportData {
  const t = reportText(language)
  const incidents = buildIncidents(findings, { chains: [chain] })
  const story = spinedStory()
  return {
    kase,
    generatedAt: Date.UTC(2026, 3, 10),
    settings: {
      ...DEFAULT_REPORT,
      language,
      includeFp: true,
      includeEvidence: true,
      includeIocs: true,
      includeGraphs: true,
      client: {
        ...EMPTY_CLIENT,
        client: 'Zyx Holdings',
        engagementRef: 'ZYX-1',
        engagementStart: '2026-04-01',
        engagementEnd: '2026-04-09',
        requestedBy: 'Zyx Requester',
        distribution: 'Zyx Distribution',
        versions: [{ version: '1', date: '2026-04-09', author: 'Zorvath', note: 'Zyx version note' }],
        objectives: 'Zyx objectives',
        periodFrom: '2026-03-30',
        periodTo: '2026-04-03',
        systemsIn: 'WS-017',
        systemsOut: 'WS-099',
        accountsIn: 'qorbin',
        accountsOut: 'kestrin',
        initialAccess: 'Zyx initial access',
        rootCause: 'Zyx root cause',
        analyticConfidence: 'moderate',
        confidenceBasis: 'Zyx confidence basis',
        impact: 'Zyx impact',
        containment: [{ date: '2026-04-03', action: 'Zyx containment', by: 'Zorvath' }],
        recShort: 'Zyx short',
        recMedium: 'Zyx medium',
        recLong: 'Zyx long',
        tlp: 'amber',
        confidentiality: 'Zyx confidentiality',
      },
    },
    summary: 'Zyx summary text',
    summaryBy: 'ai',
    summaryAt: Date.UTC(2026, 3, 1),
    falsePositives: 1,
    evidence: [
      evidence({ id: 1, stats: { firstTs: Date.UTC(2026, 2, 30), lastTs: Date.UTC(2026, 3, 3) } }),
      evidence({ id: 2, name: 'Zyx-broken.evtx', status: 'error', error: 'Zyx parser error' }),
      evidence({
        id: 3,
        name: 'Zyx.zip',
        kind: 'package',
        stats: {
          errors: 2,
          unsupported: 1,
          skipped: 3,
          inventoryComplete: false,
          reconciliation: [{ status: 'missing' }],
          eventRange: { firstTs: Date.UTC(2026, 2, 28), lastTs: Date.UTC(2026, 3, 2) },
        },
      }),
    ],
    chains: [chain],
    reviews: { kestrin: { verdict: 'confirmed', narrative: 'Zyx narrative', narrativeBy: 'ai', by: 'ai', aiReason: 'Zyx triage reason' } },
    coverageWarnings: chainCoverageWarnings({ eventsTruncated: 1, authEventsTruncated: 1, seedsTruncated: 1, repliesTruncated: 1, chainsTruncated: 1 }, t),
    membersOf: new Map(incidents.filter((i) => i.kind === 'chain').map((i) => [i.chain!.id, i.findings.filter((x) => x.ruleId !== 'chain')])),
    graphs: { kestrin: 'data:image/png;base64,iVBORw0KGgo=', campaign: 'data:image/png;base64,iVBORw0KGgo=' },
    campaignInsights: [t.chain.appears(t.chain.node.sender ?? 'sender', 'qv@evil.test', 2)],
    incidents: incidents.filter((i) => i.kind !== 'chain'),
    findings,
    iocs: [{ caseId: 1, kind: 'domain', value: 'evil.test', sources: ['events'], firstSeen: null, lastSeen: null, count: 1, verdict: 'malicious' }],
    timeline: [note('timeline', 'Zyx timeline entry')],
    tasks: [note('task', 'Zyx task', { done: false })],
    notes: [note('note', 'Zyx case note')],
    undecided: 2,
    unprintedConfirmed: [{ severity: 'low', findings: [findings[4]] }],
    issue: { status: 'draft', open: [], waived: [] },
    rules: { lastRun: Date.UTC(2026, 3, 2), evidenceAfter: 1, errors: 2 },
    iocsTotal: 3,
    iocsChecked: 0,
    ai: {
      runs: 2,
      toolCalls: 5,
      proposals: 5,
      accepted: 3,
      rejected: 1,
      undone: 1,
      notices: 1,
      models: ['zyx-model'],
      transports: ['browser', 'mcp'],
      first: Date.UTC(2026, 3, 2),
      last: Date.UTC(2026, 3, 3),
      byProposalKind: Object.fromEntries(['decision', 'note', 'row_mark', 'rule', 'summary'].map((k) => [k, { proposed: 1, accepted: 1, rejected: 0 }])),
      check: { entries: 9, intact: false, brokenAt: 4, head: 'ab'.repeat(32) },
    },
    gaps,
    measures: {
      'zyx-host-rule': readMeasure({ of: 3, fires: 1, clean: { findings: 4, events: 4, machines: 1, scope: 10_000, of: 7 } }, 'bundled'),
      'zyx-other-rule': readMeasure({ of: 3, fires: 0 }, 'bundled'),
    },
    measuredOn: measuredOn(
      {
        version: 1,
        measured: '2026-03-01',
        sources: {
          sigma: { repo: 'r', sha: 's', recordings: 10 },
          attackSamples: { repo: 'r', sha: 's', recordings: 11 },
          attackData: { repo: 'r', sha: 's', recordings: 12 },
          attackDataWindows: { repo: 'r', sha: 's', recordings: 13 },
          evtxToMitre: { repo: 'r', sha: 's', recordings: 14 },
          baseline: { repo: 'r', tag: 'v1', machines: 3, events: 1000 },
        },
      },
      t,
    ),
    claims: claims(),
    stories: [
      {
        story,
        key: 'person|x|2026-09-04',
        note: 'Zyx story note',
        decisions: { call: { verdict: 'confirmed', reason: 'Zyx decision reason', decidedAt: 1 }, merged: [], out: [], disputed: [], confirmedSteps: 2 },
      },
      // a story with no way in, which the report says of it
      { story: { ...story, phases: story.phases.filter((p) => p.phase !== 'initial-access') }, key: 'person|y|2026-09-04', note: '' },
    ],
    storiesLeft: 2,
    storyStats: {
      truncated: [
        'flagged',
        'refs',
        'identities',
        'addresses',
        'hosts',
        'context',
        'flaggedMails',
        'seeds',
        'undated',
        'windows',
        'replies',
        'dns',
        'dhcp',
        'dc',
        'name-keys',
        'host-keys',
        'address-keys',
        'trimmed',
        'size',
        'accounts',
      ],
      cut: { flagged: 1, refs: 2, seeds: 3, undated: 4, windows: 5, trimmed: 6, size: 7, flaggedMails: 8 },
      identityScope: 'rows',
      storiesTruncated: true,
    } as StoryResult['stats'],
    storiesStale: [
      ...storiesStaleness({ inputs: { findings: 'a', evidence: 'a', settings: 'a' } } as StoryResult, { findings: 'b', evidence: 'b', settings: 'b' }, t),
      ...storiesStaleness({} as StoryResult, { findings: 'b', evidence: 'b', settings: 'b' }, t),
    ],
    storyNotesOrphaned: 1,
    storiesDismissed: 1,
    storyDecisionsOrphaned: 1,
    questions: questionsForReport(['S1001', 'S0001'], answers, evidenceProfile([{ value: 'Security', count: 10 }], [], 0), t),
    scope: { hosts: ['WS-017'], hostsCapped: true, accounts: ['qorbin'], accountsCapped: true },
    ruleAuthors: { 'zyx-host-rule': 'Zyx Author' },
  }
}

/** The text of the HTML report as a reader sees it, one piece per run of text between tags, with the titles and alternative texts. */
function htmlPieces(html: string): string[] {
  const body = html.replace(/<style[\s\S]*?<\/style>/g, '').replace(/<script[\s\S]*?<\/script>/g, '')
  const attrs = [...body.matchAll(/\s(?:title|alt|aria-label)="([^"]*)"/g)].map((m) => m[1])
  return [...body.split(/<[^>]*>/), ...attrs]
    .map(decode)
    .map((s) => s.trim())
    .filter(Boolean)
}
/** The text of the Word report, one piece per run. */
function docxPieces(xml: string): string[] {
  return [...xml.matchAll(/<w:t(?: [^>]*)?>([^<]*)<\/w:t>/g)].map((m) => decode(m[1]).trim()).filter(Boolean)
}
const decode = (s: string) =>
  s
    .replace(/&#x([0-9a-f]+);/gi, (_, x: string) => String.fromCodePoint(parseInt(x, 16)))
    .replace(/&#(\d+);/g, (_, x: string) => String.fromCodePoint(Number(x)))
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&')

/**
 * The strings of the case itself: what the analyst, the evidence, the rules, the model and the
 * server's analysis wrote. The English the interface keeps beside the values a report reads in its
 * own language is left out, so a report that printed it would be caught.
 */
function caseStrings(d: ReportData): string[] {
  const out = new Set<string>()
  const skip = new Set(['reasons', 'subtitle', 'what', 'record', 'text'])
  const walk = (v: unknown, key: string, parent: unknown) => {
    if (typeof v === 'string') {
      // a gap's English text, a claim's reasons, an incident's English subtitle: the interface's words
      if (skip.has(key) && parent && typeof parent === 'object' && ('say' in parent || 'why' in parent || 'about' in parent || 'at' in parent || 'check' in parent)) return
      for (const piece of v.split(/\n+|\*\*|^[-#>]+\s/m)) if (piece.trim().length > 1) out.add(piece.trim())
      // an indicator is printed defanged
      if (v.includes('.')) out.add(v.replace(/\./g, '[.]'))
      return
    }
    // the names of the fields a finding's entities come from are the evidence's names
    if (key === 'entities' && v && typeof v === 'object') for (const k of Object.keys(v)) out.add(k)
    if (v instanceof Map) for (const [k, x] of v) walk(x, String(k), v)
    else if (Array.isArray(v)) for (const x of v) walk(x, key, parent)
    else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) walk(x, k, v)
  }
  // DFIQ's scenarios and questions are quoted as DFIQ publishes them; REMN's own are its words, and so is what the evidence covers
  const dfiq = (id: string, name: string) => (/^[SFQ]0/.test(id) ? '' : name)
  const questions = d.questions?.scenarios.map((sc) => ({
    name: dfiq(sc.id, sc.name),
    facets: sc.facets.map((fa) => ({ name: dfiq(fa.id, fa.name), questions: fa.questions.map((q) => ({ name: dfiq(q.id, q.name), answer: q.text, citations: q.citations })) })),
  }))
  walk({ ...d, questions, measuredOn: undefined, coverageWarnings: undefined, campaignInsights: undefined, storiesStale: undefined, measures: undefined }, '', null)
  return [...out].sort((a, b) => b.length - a.length)
}

/** Names REMN cites as they are: products, data sets, commands, logs and licences. */
const NAMES = [
  'Detection Rule License',
  'SigmaHQ',
  'EVTX-ATTACK-SAMPLES',
  'EVTX-to-MITRE-Attack',
  'Splunk attack_data',
  'attack_data',
  'Get-MessageTraceV2',
  'Get-MessageTrace',
  'Search-UnifiedAuditLog',
  'MailItemsAccessed',
  'wevtutil epl',
  'dfiq.org',
  'Ollama',
  'System',
  'baseline',
  // the pages of the interface, which stays in English, are named as the reader will find them
  'page Stories',
]

/** Words written the same in both languages, which a French report may share with an English one. */
const SAME = new Set(
  (
    'absent archive artefact cause cite conclusion export exfiltration html impact info initial investigation issues long machine machines min ' +
    'part phase phases place point questions script service services six structure ticket verdict ex pe co ef im c2 ia ai de pu id ' +
    'date dates technique techniques licence kerberos ntlm microsoft windows org application exchange onedrive sharepoint mft usn lnk srum ' +
    'ip ips ioc iocs url urls utc sha md5 dns dhcp evtx csv json xml zip mbox remn sigma hayabusa dfiq mitre att ck tlp mcp entra ' +
    'message messages note notes type total page pages client incident incidents format session sessions mission source sources score phishing ' +
    // the TLP labels are written as FIRST defines them, in every language
    'version action actions tlp clear green amber strict red'
  ).split(' '),
)

/** The pieces a French report shares with the English one that the case did not write, and the English words of REMN left in its French pieces. */
function english(fr: string[], en: string[], data: string[]): { shared: string[]; words: string[] } {
  const strip = (s: string) => {
    let x = s
    // a value of the case is taken out where it stands as a whole, not out of the middle of a word
    for (const d of data) if (x.includes(d)) x = x.replace(new RegExp(`(?<![\\p{L}\\p{N}])${d.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\p{L}\\p{N}])`, 'gu'), ' ')
    for (const n of NAMES) x = x.split(n).join(' ')
    return x
  }
  const words = (s: string) =>
    (
      strip(s)
        .toLowerCase()
        .match(/[a-zà-öø-ÿ][a-zà-öø-ÿ'’-]*[a-zà-öø-ÿ]/g) ?? []
    ).filter((w) => !SAME.has(w))
  const enSet = new Set(en)
  const shared = [...new Set(fr.filter((p) => enSet.has(p) && words(p).length))]
  const frWords = new Set(fr.flatMap(words))
  const enWords = new Set(en.flatMap(words))
  // the words REMN writes in English that also stand in the French report
  const left = [...enWords].filter((w) => frWords.has(w))
  return { shared, words: left.sort() }
}

describe('the report in French', () => {
  const en = report('en')
  const fr = report('fr')
  const data = [...new Set([...caseStrings(en), ...caseStrings(fr)])].sort((a, b) => b.length - a.length)

  it('writes no English of its own in the HTML report: only what the case, the analyst, the model and the evidence wrote stays as written', () => {
    expect(english(htmlPieces(buildReportHtml(fr)), htmlPieces(buildReportHtml(en)), data)).toEqual({ shared: [], words: [] })
  })

  it('writes no English of its own in the Word report either', () => {
    expect(english(docxPieces(reportDocumentXml(fr)), docxPieces(reportDocumentXml(en)), data)).toEqual({ shared: [], words: [] })
  })

  it('says in French what the evidence lacks, why a claim does not hold and what each incident is', () => {
    const t = reportText('fr')
    const html = htmlPieces(buildReportHtml(fr)).join('\n')
    const doc = docxPieces(reportDocumentXml(fr)).join('\n')
    for (const say of SAYS) expect(html).toContain(t.gap(say))
    expect(html).toContain('ne correspondent plus à la règle')
    expect(html).toContain(t.claim.about({ kind: 'chain', title: 'kestrin' }))
    for (const i of fr.incidents) {
      expect(html).toContain(t.incident.subtitle(i.about))
      expect(doc).toContain(t.incident.subtitle(i.about))
    }
    expect(html).toContain(t.storyCut.noWayIn)
    expect(html).toContain(t.ai.kind.row_mark)
    // the interface keeps its English from the same values
    expect(fr.incidents.map((i) => i.subtitle)).toEqual(fr.incidents.map((i) => EN.incident.subtitle(i.about)))
    expect(gaps.map((g) => g.text)).toEqual(SAYS.map((say) => EN.gap(say)))
  })

  it("says what it quotes in English: the analysis's step titles, DFIQ's questions and the model's words", () => {
    const html = htmlPieces(buildReportHtml(fr)).join('\n')
    expect(html).toContain("sont écrits en anglais par l'analyse des chaînes")
    expect(html).toContain('Les questions de DFIQ sont citées en anglais')
    expect(html).toContain("cité tel qu'il l'a écrit, sans traduction")
    // REMN's own questions are in French, DFIQ's as DFIQ publishes them
    const names = (d: ReportData) => d.questions!.scenarios.flatMap((s) => [s, ...s.facets, ...s.facets.flatMap((f) => f.questions)].map((x): [string, string] => [x.id, x.name]))
    const frNames = new Map(names(fr))
    for (const [id, name] of names(en))
      if (/^[SFQ]0/.test(id)) expect(frNames.get(id)).not.toBe(name)
      else expect(frNames.get(id)).toBe(name)
  })
})
