import { describe, expect, it } from 'vitest'
import type { Case, Finding } from '../db/schema'
import { buildIncidents } from '../rules/incidents'
import { DEFAULT_REPORT } from './review'
import { buildReportDocx, reportDocumentXml } from './reportDocx'
import type { ReportData } from './reportHtml'

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
  it('is an Office package with the document, its styles and its footer', () => {
    const parts = unzip(buildReportDocx(data()))
    expect([...parts.keys()]).toEqual([
      '[Content_Types].xml',
      '_rels/.rels',
      'docProps/core.xml',
      'docProps/app.xml',
      'word/_rels/document.xml.rels',
      'word/document.xml',
      'word/styles.xml',
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
