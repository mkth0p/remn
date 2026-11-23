import { describe, expect, it } from 'vitest'
import type { Case, Finding, QuestionAnswer } from '../db/schema'
import { buildIncidents } from '../rules/incidents'
import { DEFAULT_REPORT } from './review'
import { buildReportDocx, reportDocumentXml } from './reportDocx'
import { computeConfidence, limitLines, producedLines, computeVerdict, type ReportData } from './reportHtml'
import { questionsForReport } from './questions/answers'
import { evidenceProfile } from './questions/coverage'
import { readMeasure } from './ruleMeasures'
import { spinedStory } from '../test/spineStory'

const finding = (p: Partial<Finding>): Finding => ({
  id: 1,
  caseId: 1,
  key: 'k',
  ruleId: 'ps-enc',
  title: 'Encoded PowerShell <script>',
  source: 'events',
  severity: 'high',
  ts: Date.UTC(2026, 0, 2),
  entities: { computer: 'WS1', commandLine: 'powershell -enc AAAA\u0001' },
  count: 3,
  refs: [1, 2, 3],
  attack: ['T1059.001'],
  status: 'escalated',
  createdAt: 0,
  ...p,
})
const kase = {
  id: 1,
  name: 'Case & <co>',
  analyst: 'A. Nalyst',
  createdAt: 0,
  updatedAt: 0,
  settings: { internalDomains: [], vipNames: [], businessHours: { start: 8, end: 19, tz: 'UTC' } },
} as unknown as Case
const data = (): ReportData => {
  const findings = [finding({})]
  return {
    kase,
    generatedAt: Date.UTC(2026, 8, 25),
    settings: { ...DEFAULT_REPORT, includeEvidence: true, includeIocs: true },
    summary: '**Bottom line:** the host ran an encoded PowerShell command.\n\n- first point',
    evidence: [],
    chains: [],
    reviews: {},
    membersOf: new Map(),
    graphs: {},
    campaignInsights: [],
    incidents: buildIncidents(findings),
    findings,
    iocs: [{ caseId: 1, kind: 'domain', value: 'evil.example', sources: ['events'], firstSeen: null, lastSeen: null, count: 1, verdict: 'malicious' }],
    timeline: [],
    tasks: [],
    notes: [],
    undecided: 0,
    issue: { status: 'draft', open: [], waived: [] },
  }
}

/** The names and contents of a stored ZIP's entries, read from its central directory. */
function unzip(bytes: Uint8Array): Map<string, string> {
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const end = bytes.length - 22
  expect(v.getUint32(end, true)).toBe(0x06054b50)
  const count = v.getUint16(end + 10, true)
  let at = v.getUint32(end + 16, true)
  const out = new Map<string, string>()
  const dec = new TextDecoder()
  for (let i = 0; i < count; i++) {
    expect(v.getUint32(at, true)).toBe(0x02014b50)
    const size = v.getUint32(at + 20, true)
    const nameLen = v.getUint16(at + 28, true)
    const local = v.getUint32(at + 42, true)
    const name = dec.decode(bytes.subarray(at + 46, at + 46 + nameLen))
    const dataAt = local + 30 + v.getUint16(local + 26, true) + v.getUint16(local + 28, true)
    out.set(name, dec.decode(bytes.subarray(dataAt, dataAt + size)))
    at += 46 + nameLen
  }
  return out
}

describe('Word report', () => {
  it('is an Office package with the document, its styles, its header and its footer', () => {
    const parts = unzip(buildReportDocx(data()))
    expect([...parts.keys()]).toEqual([
      '[Content_Types].xml',
      '_rels/.rels',
      'docProps/core.xml',
      'docProps/app.xml',
      'word/_rels/document.xml.rels',
      'word/document.xml',
      'word/styles.xml',
      'word/header1.xml',
      'word/footer1.xml',
    ])
    expect(parts.get('docProps/core.xml')).toContain('REMN report · Case &amp; &lt;co&gt;')
    expect(parts.get('word/footer1.xml')).toContain('draft')
  })

  it('escapes case text, drops characters XML cannot hold, and carries the report sections', () => {
    const xml = reportDocumentXml(data())
    expect(xml).not.toContain('<script>')
    expect(xml).not.toContain('\u0001')
    expect(xml).toContain('Encoded PowerShell &lt;script&gt;')
    expect(xml).toContain('DRAFT, not issued')
    expect(xml).toContain('Compromise confirmed')
    expect(xml).toContain('evil[.]example')
    for (const s of ['Executive summary', 'What happened', 'Incidents', 'Indicators of compromise', 'Findings by rule', 'Where it stops']) expect(xml).toContain(`>${s}<`)
    // a well-formed document: every paragraph and table closes
    expect(xml.match(/<w:p>|<w:p /g)?.length).toBe(xml.match(/<\/w:p>/g)?.length)
    expect(xml.match(/<w:tbl>/g)?.length).toBe(xml.match(/<\/w:tbl>/g)?.length)
  })
})

/** Text as the Word document holds it, escaped for XML. */
const xml = (t: string) => t.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

describe('Word report against the HTML report', () => {
  const answers = new Map<string, QuestionAnswer>([
    [
      'Q1074',
      {
        caseId: 1,
        questionId: 'Q1074',
        status: 'answered',
        text: 'The Security log was cleared.',
        citations: [{ source: 'events', rowId: 80, label: 'Security.evtx record 4,200', ts: 0, addedAt: 0 }],
        createdAt: 0,
        updatedAt: 0,
      },
    ],
  ])
  const full = (): ReportData => {
    const d = data()
    const id = d.findings[0].id!
    return {
      ...d,
      questions: questionsForReport(['S1001'], answers, evidenceProfile([{ value: 'Security', count: 10 }], [], 0))!,
      ai: {
        runs: 2,
        toolCalls: 5,
        proposals: 1,
        accepted: 1,
        rejected: 0,
        undone: 0,
        notices: 1,
        models: ['local-model'],
        transports: ['browser'],
        first: 1,
        last: 2,
        byProposalKind: { decision: { proposed: 1, accepted: 1, rejected: 0 } },
        check: { entries: 9, intact: true, head: 'ab'.repeat(32) },
      },
      stories: [
        {
          story: spinedStory(),
          key: 'person|x|2026-09-04',
          note: 'Came in by mail.',
          decisions: { call: { verdict: 'confirmed', reason: 'the reset mail', decidedAt: 1 }, merged: [], out: [], disputed: [], confirmedSteps: 2 },
        },
      ],
      storiesDismissed: 1,
      measures: { 'ps-enc': readMeasure({ of: 3, fires: 1, clean: { findings: 4, events: 4, machines: 1, scope: 10_000, of: 7 } }, 'bundled') },
      claims: {
        findings: {
          [id]: {
            status: 'contradicted',
            cited: 3,
            checked: 3,
            reasons: ['Security.evtx record 9 no longer matches the rule'],
            why: [{ kind: 'no-match', records: [{ file: 'Security.evtx', record: 'record 9', at: { kind: 'record', n: 9 }, key: 'k' }], more: 0 }],
            records: [{ file: 'Security.evtx', record: 'record 9', at: { kind: 'record', n: 9 }, key: 'k' }],
          },
        },
        texts: [
          {
            key: 'summary',
            what: 'the executive summary',
            about: { kind: 'summary' },
            check: {
              status: 'unsupported',
              named: ['198.51.100.9'],
              reasons: ['it names 198.51.100.9, which no row of the evidence holds'],
              why: [{ kind: 'text-absent-case', values: ['198.51.100.9'], more: 0 }],
            },
          },
        ],
      },
      relationships: [
        {
          key: 'r',
          status: 'accepted',
          includeInReport: true,
          notes: 'reviewed',
          sourceLabel: 'WS1',
          targetLabel: 'DC1',
          relation: 'logged on to',
          reason: 'same record',
          confidence: 'high',
          references: [
            {
              id: 1,
              evidenceId: 1,
              source: 'events',
              sourceFile: 'processes.csv',
              sourceSha256: 'cd'.repeat(32),
              sourceIndex: 0,
              recordKind: 'observation',
              ts: null,
              observedAt: 1,
              title: 'process',
            },
          ],
          aliases: {},
          updatedAt: 1,
        },
      ],
      gaps: [
        {
          kind: 'record-holes',
          severity: 'high',
          text: 'Security on DC01 (dc.evtx): 3 records missing from its numbering, in 1 gap between record 4 and 8 (the largest: 5–7). Records deleted from the log, or in a part that could not be read.',
          say: { kind: 'record-holes', where: { file: 'dc.evtx', channel: 'Security', computer: 'DC01' }, floor: false, missing: 3, gaps: 1, first: 4, last: 8, largest: [5, 7] },
          evidenceId: 1,
        },
      ],
    }
  }

  it('carries every line of how it was produced and where it stops that the HTML prints', () => {
    const d = full()
    const doc = reportDocumentXml(d)
    for (const l of producedLines(d, computeVerdict(d))) expect(doc).toContain(xml(l))
    for (const l of limitLines(d, computeConfidence(d))) expect(doc).toContain(xml(l))
    expect(doc).toContain('3 records missing from its numbering')
    expect(doc).toContain('investigative question')
  })

  it('carries the questions, the model’s part, the story detail, the claim notes, the lead marks and the relationship references', () => {
    const doc = reportDocumentXml(full())
    expect(doc).toContain('>Questions<')
    expect(doc).toContain('The Security log was cleared.')
    expect(doc).toContain('Security.evtx record 4,200')
    expect(doc).toContain('>How AI was used<')
    expect(doc).toContain('2 runs · 5 tool calls')
    expect(doc).toContain('ledger: 9 entries, chain intact')
    // the story: its spine, its phases, the analyst's decisions, how many were dismissed
    expect(doc).toContain('Spine: 6 of 8 steps')
    expect(doc).toContain('[way in]')
    expect(doc).toContain('The analyst decided it confirmed incident: the reset mail')
    expect(doc).toContain('2 steps confirmed by the analyst.')
    expect(doc).toContain('1 story decided benign or false positive by the analyst is not printed.')
    // the rule line: a lead, rows that disagree and where they are
    expect(doc).toContain('LEAD')
    expect(doc).toContain('rows disagree · Security.evtx record 9 and 2 more: Security.evtx record 9 no longer matches the rule')
    expect(doc).toContain('Checked against its rows: it names 198.51.100.9')
    // the records a relationship rests on
    expect(doc).toContain('processes.csv')
    expect(doc).toContain('Collected: 1970-01-01 00:00:00Z')
    expect(doc).toContain('cd'.repeat(32))
  })

  it('says what a story is without contradicting how the verdict counts a confirmed story', () => {
    const doc = reportDocumentXml(full())
    expect(doc).not.toContain('not a decision')
    expect(doc).toContain('a confirmed story counts in the verdict as a confirmed incident does')
  })
})
