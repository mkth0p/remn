import { describe, expect, it } from 'vitest'
import type { Case, Finding } from '../db/schema'
import type { Chain } from './chains'
import { buildIncidents } from '../rules/incidents'
import { DEFAULT_REPORT } from './review'
import { buildReportHtml, foldSteps, MAX_STEP_ROWS, type ReportData } from './reportHtml'
import type { ChainStep } from './chains'

let seq = 1
const f = (p: Partial<Finding> & { ruleId: string; severity: Finding['severity'] }): Finding => ({ id: seq++, caseId: 1, key: `${p.ruleId}|${seq}`, title: p.ruleId, source: 'mails', ts: 10, entities: {}, count: 1, refs: [seq], attack: [], status: 'new', createdAt: 0, ...p })
const kase: Case = { id: 1, name: 'Case <b>one</b> & co', analyst: 'A. Nalyst', createdAt: 0, updatedAt: 0, storage: 'browser', settings: { internalDomains: ['corp.test'], vipNames: [], brands: [], internalIps: [], adminAccounts: [], serviceAccounts: [], businessHours: { start: 8, end: 19, tz: 'Europe/Paris' }, weekendDays: [6, 0], networkAllowed: false } as unknown as Case['settings'] }
const chain: Chain = {
  id: 'alice', identity: 'alice', identityLabel: 'alice@corp.test', start: 0, end: 3_600_000, score: 80, severity: 'high', artifactLinks: 1, summary: 'the automatic summary',
  scoreBreakdown: { seed: 30, links: 20, steps: 15, findings: 10, sources: 5, cap: null, linkSteps: 1 },
  seed: { id: 7, ts: 0, subject: 'Urgent <invoice>', fromAddr: 'x@evil.test', risk: 90, flags: [], findings: [], urlDomains: [], attachments: [] },
  steps: [{ kind: 'event', source: 'events', id: 11, ts: 60_000, tsEnd: 60_000, count: 1, title: 'logon from 203.0.113.9', weight: 3, artifacts: ['mail URL domain'], findings: [], offsetMin: 1, origin: 'm365' }],
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
    kase, generatedAt: 1_700_000_000_000, settings: DEFAULT_REPORT, summary: '**Summary** text', evidence: [{ id: 1, caseId: 1, name: 'box.mbox', size: 1024, kind: 'mail', format: 'mbox', sha256Client: 'abc', integrity: 'verified', addedAt: 0, count: 10 } as never],
    chains: [chain], reviews: { alice: { verdict: 'confirmed', narrative: 'What happened, in order.', narrativeBy: 'ai', by: 'ai', aiReason: 'tied to the mail' } },
    membersOf: new Map(grouped.filter((i) => i.kind === 'chain').map((i) => [i.chain!.id, i.findings.filter((x) => x.ruleId !== 'chain')])),
    graphs: { alice: 'data:image/png;base64,iVBORw0KGgo=' }, campaignInsights: [],
    incidents: grouped.filter((i) => i.kind !== 'chain'), findings, iocs: [], timeline: [], tasks: [], notes: [], undecided: 0, fontData: 'AAAA',
    ...over,
  }
}

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
  })

  it('folds runs of the same step into one row with a count and a span, and caps the rows it prints', () => {
    const s = (i: number, title: string, ties: string[] = []): ChainStep => ({ kind: 'event', source: 'events', id: i, ts: i * 60_000, tsEnd: i * 60_000, count: 1, title, weight: 2, artifacts: ties, findings: [], offsetMin: i, origin: 'm365', ipAddress: '203.0.113.9' })
    const steps = [s(1, 'mailbox items accessed'), s(2, 'mailbox items accessed'), s(3, 'mailbox items accessed'), s(4, 'file downloaded', ['tie']), s(5, 'mailbox items accessed'), s(6, 'mailbox items accessed', ['tie'])]
    const folded = foldSteps(steps)
    expect(folded.map((f) => [f.step.title, f.n])).toEqual([['mailbox items accessed', 3], ['file downloaded', 1], ['mailbox items accessed', 1], ['mailbox items accessed', 1]])
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
