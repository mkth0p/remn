import { describe, expect, it } from 'vitest'
import { defaultSettings, type Case, type Evidence, type Finding } from '../db/schema'
import { buildIncidents } from '../rules/incidents'
import { clientReport, DEFAULT_REPORT, EMPTY_BRANDING, EMPTY_CLIENT, reportBranding, type ClientReport, type ReportBranding } from './review'
import {
  buildReportHtml,
  ruleAuthors,
  evidenceScope,
  SCOPE_READ,
  impactInventory,
  indicatorAppendix,
  limitLines,
  computeConfidence,
  spineStartingPoint,
  techniqueTable,
  type ReportData,
} from './reportHtml'
import { reportDocumentXml, buildReportDocx } from './reportDocx'
import type { ReportLanguage } from './reportText'
import { validateRule, type Rule } from '../rules/engine'
import type { DecidedStory } from './storyDecisions'
import { spinedStory } from '../test/spineStory'

// every name, host and address here is invented for the test
let seq = 1
const f = (p: Partial<Finding> & { ruleId: string }): Finding => ({
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
  name: 'Client case',
  analyst: 'A. Nalyst',
  createdAt: 0,
  updatedAt: 0,
  storage: 'browser',
  settings: { ...defaultSettings(), internalDomains: ['corp.test'] },
}
const evidence = (p: Partial<Evidence>): Evidence => ({ caseId: 1, name: 'Security.evtx', size: 10, kind: 'evtx', integrity: 'verified', addedAt: 0, status: 'done', count: 5, ...p }) as Evidence

const confirmedFinding = f({
  ruleId: 'win-encoded-powershell',
  title: 'Encoded PowerShell',
  status: 'escalated',
  attack: ['T1059.001'],
  entities: { computer: 'WS-017', targetUser: 'CORP\\jdoe', hashes: 'SHA256=' + 'ab'.repeat(32) + ',MD5=' + 'cd'.repeat(16), destinationIp: '203.0.113.50' },
})
const unconfirmed = f({
  ruleId: 'win-rdp-logon',
  title: 'RDP logon',
  status: 'reviewed',
  attack: ['T1021.001'],
  entities: { computer: 'WS-099', targetUser: 'CORP\\other', ipAddress: '198.51.100.77' },
})
const dismissed = f({ ruleId: 'win-fp', title: 'Noise', status: 'false_positive', attack: ['T1087'], entities: { computer: 'WS-055', ipAddress: '198.51.100.88' } })
const story: DecidedStory = {
  title: 'mlee@corp.test',
  verdict: 'confirmed',
  reason: 'phished',
  severity: 'critical',
  start: Date.UTC(2026, 3, 1, 8),
  end: Date.UTC(2026, 3, 1, 9),
  hosts: ['WS-021'],
  subject: { kind: 'person', label: 'mlee@corp.test' },
  attackerAddresses: ['192.0.2.10', '10.1.2.3'],
  findings: [
    f({
      ruleId: 'm365-new-inbox-rule',
      title: 'Inbox rule created',
      status: 'new',
      attack: ['T1564.008'],
      entities: { user: 'mlee@corp.test', fromDomain: 'bad-login.example', urlDomain: 'mail.corp.test' },
    }),
  ],
  printed: true,
}

function data(client: Partial<ClientReport> = {}, over: Partial<ReportData> = {}): ReportData {
  const findings = [confirmedFinding, unconfirmed, dismissed]
  return {
    kase,
    generatedAt: Date.UTC(2026, 3, 10),
    settings: { ...DEFAULT_REPORT, includeFp: true, client: { ...EMPTY_CLIENT, ...client } },
    summary: '',
    evidence: [
      evidence({ stats: { firstTs: Date.UTC(2026, 2, 30), lastTs: Date.UTC(2026, 3, 3) } }),
      evidence({ name: 'pkg.zip', kind: 'package', stats: { eventRange: { firstTs: Date.UTC(2026, 2, 28), lastTs: Date.UTC(2026, 3, 2) } } }),
    ],
    chains: [],
    reviews: {},
    membersOf: new Map(),
    graphs: {},
    campaignInsights: [],
    incidents: buildIncidents(findings),
    findings,
    iocs: [],
    timeline: [],
    tasks: [],
    notes: [],
    undecided: 0,
    decidedStories: [story],
    scope: { hosts: ['WS-017', 'WS-021', 'DC-01'], hostsCapped: false, accounts: ['jdoe', 'mlee'], accountsCapped: true },
    ...over,
  }
}
const section = (html: string, id: string) => {
  const at = html.indexOf(`<section class="s" id="${id}">`)
  return at < 0 ? '' : html.slice(at, html.indexOf('</section>', at))
}

describe('the client report', () => {
  it('prints the engagement, the conclusion, containment and recommendations the analyst wrote, and leaves out what is empty', () => {
    const html = buildReportHtml(
      data({
        client: 'Example <Holdings>',
        engagementRef: 'ENG-2026-014',
        engagementStart: '2026-04-03',
        engagementEnd: '2026-04-09',
        requestedBy: 'the security officer',
        distribution: 'CISO\n\nLegal counsel',
        versions: [{ version: '0.1', date: '2026-04-08', author: 'A. Nalyst', note: 'first draft' }],
        initialAccess: 'A phishing mail led to a **credential** entry.',
        rootCause: 'No second factor on the mail service.',
        containment: [
          { date: '2026-04-05', action: 'Reset the password of jdoe', by: 'client IT' },
          { date: '2026-04-04', action: 'Isolated WS-017', by: '' },
        ],
        recShort: '- Enforce a second factor',
        recLong: '- Review mail filtering',
      }),
    )
    const engagement = section(html, 'engagement')
    expect(engagement).toContain('Example &lt;Holdings&gt;')
    expect(engagement).toContain('2026-04-03 to 2026-04-09')
    expect(engagement).toContain('CISO<br>Legal counsel')
    expect(engagement).toContain('first draft')
    expect(html).toContain('Prepared for Example &lt;Holdings&gt; · engagement ENG-2026-014')
    // the engagement comes first, then the scope and the conclusion before what happened
    expect(html.indexOf('id="engagement"')).toBeLessThan(html.indexOf('id="scope"'))
    expect(html.indexOf('id="conclusion"')).toBeLessThan(html.indexOf('id="happened"'))
    expect(section(html, 'conclusion')).toContain('<strong>credential</strong>')
    expect(section(html, 'conclusion')).toContain('No second factor on the mail service.')
    // containment in date order
    const containment = section(html, 'containment')
    expect(containment.indexOf('Isolated WS-017')).toBeLessThan(containment.indexOf('Reset the password'))
    const recs = section(html, 'recommendations')
    expect(recs).toContain('Short term')
    expect(recs).toContain('Long term')
    expect(recs).not.toContain('Medium term')

    const bare = buildReportHtml(data())
    for (const id of ['engagement', 'conclusion', 'containment', 'recommendations']) expect(bare).not.toContain(`id="${id}"`)
    expect(bare).not.toContain('Prepared for')
  })

  it('takes the scope from the evidence when the analyst wrote none, and says so', () => {
    const scope = section(buildReportHtml(data()), 'scope')
    expect(scope).toContain('2026-03-28 00:00:00Z to 2026-04-03 00:00:00Z')
    expect(scope).toContain('from the evidence: the first and last record it holds')
    expect(scope).toContain('WS-017<br>WS-021<br>DC-01')
    expect(scope).toContain('from the evidence: the hosts its records come from')
    expect(scope).toContain('the 2 most frequent; it names more')
    // nothing is out of scope unless the analyst says so
    expect(scope).not.toContain('out of scope')
    const own = section(
      buildReportHtml(data({ periodFrom: '2026-03-01', periodTo: '2026-04-01', systemsIn: 'WS-017', systemsOut: 'the OT network', objectives: 'Find how the mailbox was reached.' })),
      'scope',
    )
    expect(own).toContain('2026-03-01 to 2026-04-01')
    expect(own).not.toContain('from the evidence: the hosts')
    expect(own).toContain('the OT network')
    expect(own).toContain('Find how the mailbox was reached.')
  })

  it('lists the accounts and hosts the confirmed items name, and nothing from what was not confirmed', () => {
    const impact = impactInventory(data())
    expect(impact.accounts.map((a) => a.name)).toEqual(['mlee@corp.test', 'CORP\\jdoe'])
    expect(impact.hosts.map((a) => a.name)).toEqual(['WS-021', 'WS-017'])
    expect(impact.accounts[0].from).toEqual(['story mlee@corp.test'])
    const all = JSON.stringify(impact)
    expect(all).not.toContain('WS-099')
    expect(all).not.toContain('other')
    const html = section(buildReportHtml(data({ impact: 'The mailbox was read for **two days**.' })), 'impact')
    expect(html).toContain('<strong>two days</strong>')
    expect(html).toContain('incident CORP\\jdoe')
  })

  it('lists the outside addresses, domains and hashes the confirmed items name without a reputation lookup, each with where it comes from', () => {
    const { rows } = indicatorAppendix(data())
    const values = rows.map((r) => `${r.kind}:${r.value}`)
    expect(values).toContain('ip:203.0.113.50')
    expect(values).toContain('ip:192.0.2.10')
    expect(values).toContain('domain:bad-login.example')
    expect(values).toContain(`hash:${'ab'.repeat(32)}`)
    expect(values).toContain(`hash:${'cd'.repeat(16)}`)
    // the victim's side is not an indicator, and neither is what nobody confirmed
    expect(values).not.toContain('ip:10.1.2.3')
    expect(values).not.toContain('domain:mail.corp.test')
    expect(values).not.toContain('email:mlee@corp.test')
    expect(values).not.toContain('ip:198.51.100.77')
    expect(rows.find((r) => r.value === '192.0.2.10')!.from).toEqual(['story mlee@corp.test'])
    expect(rows.find((r) => r.value === '203.0.113.50')!.from).toEqual(['confirmed finding Encoded PowerShell (win-encoded-powershell)'])
    const html = section(buildReportHtml(data()), 'iocs')
    expect(html).toContain('203[.]0[.]113[.]50')
    expect(html).toContain('not looked up')
    // a flagged indicator keeps its verdict and says it came from the lookup
    const flagged = indicatorAppendix(
      data({}, { iocs: [{ caseId: 1, kind: 'domain', value: 'evil.example', sources: ['mails'], firstSeen: null, lastSeen: null, count: 1, verdict: 'malicious' }] }),
    ).rows.find((r) => r.value === 'evil.example')!
    expect(flagged).toMatchObject({ verdict: 'malicious', from: ['reputation lookup (seen in mails)'] })
  })

  it('tables the ATT&CK techniques of the printed and confirmed findings, false positives left out', () => {
    const rows = techniqueTable(data())
    // in the tactics' order; a technique the profile does not map comes last
    expect(rows.map((r) => r.id)).toEqual(['T1059.001', 'T1021.001', 'T1564.008'])
    expect(rows[0]).toMatchObject({ tactics: ['Execution'], confirmed: true, rules: ['Encoded PowerShell'] })
    expect(rows.find((r) => r.id === 'T1021.001')).toMatchObject({ tactics: ['Lateral movement'], confirmed: false })
    expect(rows.find((r) => r.id === 'T1564.008')!.tactics).toEqual([])
    expect(section(buildReportHtml(data()), 'techniques')).toContain('not mapped to a tactic')
  })

  it('marks the cover, the foot and every Word page with the TLP level and the confidentiality line', () => {
    const marked = data({ tlp: 'amber+strict', confidentiality: 'Confidential: prepared for the client only' })
    const html = buildReportHtml(marked)
    expect(html.match(/<span class="tlp amber">TLP:AMBER\+STRICT<\/span>/g)).toHaveLength(2)
    expect(html).toContain('Confidential: prepared for the client only')
    const header = new TextDecoder().decode(buildReportDocx(marked))
    expect(header).toContain('TLP:AMBER+STRICT · Confidential: prepared for the client only')
    expect(buildReportHtml(data())).not.toContain('class="marking"')
  })

  it('calls the measure of how complete the review is completeness, and prints a confidence in the conclusion only as the analyst gave it', () => {
    const html = buildReportHtml(data())
    expect(html).toContain('<b>completeness ')
    expect(html).not.toMatch(/<b>confidence (high|medium|low)<\/b>/)
    expect(html).toContain('how complete the review is, not how sure its conclusion is')
    expect(html).not.toContain('analyst&#39;s confidence')
    const own = buildReportHtml(data({ analyticConfidence: 'moderate', confidenceBasis: 'the proxy logs were not collected' }))
    expect(own).toContain('<b>analyst&#39;s confidence moderate</b>the proxy logs were not collected')
    expect(reportDocumentXml(data())).toContain('Completeness ')
  })

  it('offers the spine as a starting point but never prints it as the conclusion until the analyst rewrote it', () => {
    const draft = spineStartingPoint([
      { story: spinedStory(), key: 'k', decisions: { call: { verdict: 'confirmed', reason: '', decidedAt: 1 }, merged: [], out: [], disputed: [], confirmedSteps: 0 } },
    ])
    expect(draft).toContain('the way in reads as Mail from it-desk@northstar-sso.example')
    const untouched = data({ initialAccess: draft, initialAccessDraft: draft })
    const html = buildReportHtml(untouched)
    expect(html).not.toContain('id="conclusion"')
    expect(limitLines(untouched, computeConfidence(untouched))).toContain(
      "The initial access offered from a story's spine has not been rewritten by the analyst; the report does not print it as a conclusion.",
    )
    const rewritten = buildReportHtml(data({ initialAccess: `${draft} The user entered a password on the page.`, initialAccessDraft: draft }))
    expect(section(rewritten, 'conclusion')).toContain('The user entered a password on the page.')
  })

  it('says under where it stops when something was confirmed and no conclusion was stated', () => {
    const d = data()
    expect(limitLines(d, computeConfidence(d))).toContain('The analyst has stated neither the initial access nor the root cause.')
    const stated = data({ rootCause: 'An exposed RDP service.' })
    expect(limitLines(stated, computeConfidence(stated))).not.toContain('The analyst has stated neither the initial access nor the root cause.')
  })

  it('carries the client sections into the Word report', () => {
    const xml = reportDocumentXml(data({ client: 'Example Holdings', recMedium: '- Segment the network', containment: [{ date: '2026-04-04', action: 'Isolated WS-017', by: '' }] }))
    for (const s of ['Engagement', 'Scope', 'Impact', 'Containment', 'Recommendations', 'Indicators of compromise', 'ATT&amp;CK techniques']) expect(xml).toContain(`>${s}<`)
    expect(xml).toContain('Segment the network')
    expect(xml).toContain('203[.]0[.]113[.]50')
  })

  it('reads the scope from the evidence without machine, service or built-in accounts, and says when it read only the most frequent', () => {
    const s = evidenceScope(
      [{ value: 'WS-017', count: 9 }],
      [
        [
          { value: 'CORP\\jdoe', count: 3 },
          { value: 'SYSTEM', count: 50 },
          { value: 'WS-017$', count: 40 },
        ],
        [
          { value: 'corp\\JDOE', count: 1 },
          { value: 'mlee@corp.test', count: 7 },
        ],
      ],
    )
    expect(s).toEqual({ hosts: ['WS-017'], hostsCapped: false, accounts: ['mlee@corp.test', 'CORP\\jdoe'], accountsCapped: false })
    const many = Array.from({ length: SCOPE_READ }, (_, i) => ({ value: `user${i}`, count: 1 }))
    expect(evidenceScope([], [many, []]).accountsCapped).toBe(true)
  })

  it('reads the client part of stored settings whatever a bundle holds', () => {
    expect(clientReport(undefined)).toEqual(EMPTY_CLIENT)
    const odd = clientReport({ client: 42, tlp: 'purple', analyticConfidence: 'certain', versions: [{ version: '1', date: 3 }, null], containment: 'none', recShort: 'x' })
    expect(odd).toMatchObject({ client: '', tlp: '', analyticConfidence: '', recShort: 'x', containment: [] })
    expect(odd.versions).toEqual([{ version: '1', date: '', author: '', note: '' }])
  })
})

// an invented 4 by 2 pixel PNG
const PNG_4X2 = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAQAAAACCAIAAADwyuo0AAAAEElEQVR4nGP4z8AARwzIHABvqgf5gNwAKAAAAABJRU5ErkJggg=='
const styled = (language: ReportLanguage, branding: Partial<ReportBranding> = {}, client: Partial<ClientReport> = {}): ReportData => {
  const d = data(client)
  return { ...d, settings: { ...d.settings, language, branding: { ...EMPTY_BRANDING, ...branding } } }
}
/** the text of the parts of a stored Word file, run together: enough to find a name or a value in it */
const docxText = (d: ReportData) => new TextDecoder().decode(buildReportDocx(d))

describe('the report in French and under a firm', () => {
  it('writes the HTML and the Word report in French when the analyst chose it, with French dates and numbers', () => {
    const fr = styled('fr', {}, { engagementStart: '2026-03-01', engagementEnd: '2026-03-09', client: 'Example Holdings' })
    const html = buildReportHtml(fr)
    expect(html).toContain('<html lang="fr">')
    for (const title of ['Mission', 'Périmètre', 'Déroulé des faits', 'Indicateurs de compromission', 'Méthode et limites']) expect(html).toContain(`<h2>${title}</h2>`)
    expect(html).toContain('Compromission confirmée')
    expect(html).toContain('Établi pour Example Holdings')
    expect(html).toContain('du 01/03/2026 au 09/03/2026')
    expect(html).toContain('produit le 10/04/2026 00:00:00 UTC')
    // nothing of the English labels is left in the words the report writes itself
    for (const en of ['<h2>Scope</h2>', '<h2>What happened</h2>', 'Where it stops', 'bottom line', 'How this was produced', 'Prepared for', 'not looked up']) expect(html).not.toContain(en)
    const doc = reportDocumentXml(fr)
    expect(doc).toContain('Déroulé des faits')
    expect(doc).toContain('Comment ce rapport a été produit')
    expect(doc).not.toContain('What happened')
    expect(docxText(fr)).toContain('<w:lang w:val="fr-FR"/>')
  })

  it('stays in English, with the look it had, when no language and no firm are set', () => {
    const html = buildReportHtml(data())
    expect(html).toContain('<html lang="en">')
    expect(html).toContain('<span class="wordmark">REMN</span><span class="tag">forensic analysis report</span>')
    expect(html).toContain('<title>REMN report · Client case</title>')
    expect(html).not.toContain('class="logo"')
    const docx = docxText(data())
    expect(docx).toContain('<w:lang w:val="en-GB"/>')
    expect(docx).not.toContain('word/media/')
    expect(docx).toContain('REMN · Client case · Compromise confirmed')
  })

  it("puts the firm's name, logo and cover line where REMN's stand, in the HTML and in the Word report", () => {
    const branded = styled('en', { firmName: 'Example Response', coverLine: 'Incident response report', logo: PNG_4X2 })
    const html = buildReportHtml(branded)
    expect(html).toContain(`<img class="logo" src="${PNG_4X2}" alt="Example Response"><span class="firm">Example Response</span><span class="tag">Incident response report</span>`)
    expect(html).not.toContain('<span class="wordmark">REMN</span>')
    expect(html).toContain('<title>Example Response · Client case</title>')
    expect(html).toContain('<span class="wm firm">Example Response</span>')
    const docx = docxText(branded)
    expect(docx).toContain('word/media/logo.png')
    expect(docx).toContain('<Default Extension="png" ContentType="image/png"/>')
    expect(docx).toContain('Target="media/logo.png"')
    expect(reportDocumentXml(branded)).toContain('<a:blip r:embed="rIdLogo"/>')
    expect(reportDocumentXml(branded)).toContain('Incident response report')
    expect(docx).toContain('Example Response · Client case · Compromise confirmed')
    // a logo that is not an image is left out of both
    const odd = styled('en', { logo: 'data:image/png;base64,AAAA' })
    expect(buildReportHtml(odd)).not.toContain('class="logo"')
    expect(docxText(odd)).not.toContain('word/media/')
  })

  it('numbers the printed pages and runs a header with the brand, the case and the marking, in the report language', () => {
    const html = buildReportHtml(styled('en', { firmName: 'Example Response' }, { tlp: 'red' }))
    expect(html).toContain('@top-left{content:"Example Response · Client case"')
    expect(html).toContain('@top-right{content:"TLP:RED"')
    expect(html).toContain('@bottom-right{content:"page " counter(page) " of " counter(pages)')
    expect(html).toContain('@page:first{@top-left{content:none}')
    expect(buildReportHtml(styled('fr'))).toContain('content:"page " counter(page) " sur " counter(pages)')
    expect(buildReportHtml(styled('fr'))).toContain('.cover.draft::after{content:"PROJET"}')
    // the case name cannot close the style element it is written into
    const hostile = buildReportHtml({ ...data(), kase: { ...kase, name: 'x"</style><script>alert(1)</script>' } })
    expect(hostile).not.toContain('</style><script>')
    expect(hostile).toContain('content:"REMN · x\\"\\3c /style\\3e ')
  })

  it('reads the language and the branding of stored settings whatever a bundle holds', () => {
    expect(reportBranding(undefined)).toEqual(EMPTY_BRANDING)
    expect(reportBranding({ firmName: 3, coverLine: 'x', logo: 'data:image/png;base64,AAAA' })).toEqual({ firmName: '', coverLine: 'x', logo: '' })
    expect(reportBranding({ logo: PNG_4X2 }).logo).toBe(PNG_4X2)
  })
})

describe('the authors of the rules', () => {
  // rules as the engine reads them from a pack: an invented one with a Sigma header and its author, one of REMN's own without
  const asRule = (r: unknown): Rule => {
    const v = validateRule(r)
    if (!v.ok) throw new Error(v.error)
    return v.rule
  }
  const where = { eventId: 4104 }
  const sigmaRule = asRule({ id: 'win-encoded-powershell', title: 'Encoded PowerShell', severity: 'high', source: 'events', where, sigma: { id: 'x', author: 'A. Rule-Writer, B. Other' } })
  const ownRule = asRule({ id: 'win-rdp-logon', title: 'RDP logon', severity: 'medium', source: 'events', where })

  it('reads the author a Sigma rule names, and nothing for a rule that names none', () => {
    expect(ruleAuthors([sigmaRule, ownRule, asRule({ id: 'odd', title: 'odd', severity: 'low', source: 'events', where, sigma: { author: 7 } })])).toEqual({
      'win-encoded-powershell': 'A. Rule-Writer, B. Other',
    })
  })

  it('names the author beside the findings of the rule, in the HTML and in the Word report, as the Detection Rule License asks', () => {
    const d = data({}, { ruleAuthors: ruleAuthors([sigmaRule, ownRule]) })
    const findings = section(buildReportHtml(d), 'findings')
    expect(findings).toContain('<code>win-encoded-powershell</code> · by A. Rule-Writer, B. Other')
    expect(findings).not.toContain('<code>win-rdp-logon</code> · by')
    expect(findings).toContain('Detection Rule License')
    expect(section(buildReportHtml(d), 'incidents')).toContain('by A. Rule-Writer, B. Other')
    const doc = reportDocumentXml(d)
    expect(doc).toContain('win-encoded-powershell · by A. Rule-Writer, B. Other')
    expect(doc).toContain('Detection Rule License')
    expect(buildReportHtml({ ...d, settings: { ...d.settings, language: 'fr' } })).toContain('<code>win-encoded-powershell</code> · auteur : A. Rule-Writer, B. Other')
    // a report whose rules name no author says nothing of the licence
    expect(section(buildReportHtml(data()), 'findings')).not.toContain('Detection Rule License')
  })
})
