import type { Severity } from '../db/schema'
import { chainSeverity, effectiveSeverity } from './review'
import { packageCoverageIssues } from './packageCoverage'
import { bottomLine, computeConfidence, computeVerdict, evidenceIssue, groupByRule, moments, type ReportData } from './reportHtml'
import { defang, fmtBytes, fmtNum as n, fmtUtc as fmtTs } from '../util/format'
import { zipStore } from '../util/zip'

/**
 * The report as a Word document, for a client or a team that edits the report before it goes out.
 * It carries what the HTML report says, section by section, from the same ReportData and the same
 * verdict, confidence and grouping, as plain headings, paragraphs and tables a reader can restyle:
 * no graphs (those stay in the HTML report) and no layout Word would have to guess at.
 */

export const DOCX_MIME = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'

const STATUS_WORD: Record<string, string> = { new: 'not reviewed', reviewed: 'reviewed', escalated: 'confirmed', false_positive: 'false positive' }
/** the report's severity colours, as Word writes them */
const SEV_HEX: Record<string, string> = { critical: 'A8231F', high: 'D1403F', medium: 'D9822B', low: '2F6FDB', info: '8A95A3' }

// ---------------------------------------------------------------------------
// WordprocessingML
// ---------------------------------------------------------------------------

/** Escaped for XML, without the control characters XML 1.0 cannot hold (a log line can carry them). */
const x = (s: unknown) =>
  String(s ?? '')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f￾￿]/g, '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')

interface RunOpts {
  bold?: boolean
  italic?: boolean
  mono?: boolean
  color?: string
  size?: number
}
/** A run of text; line breaks inside it become Word breaks. */
function run(text: string, o: RunOpts = {}): string {
  // in the order the schema sets for run properties: Word refuses a file that breaks it
  const props = [
    o.mono ? '<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas" w:cs="Consolas"/>' : '',
    o.bold ? '<w:b/>' : '',
    o.italic ? '<w:i/>' : '',
    o.color ? `<w:color w:val="${o.color}"/>` : '',
    o.size ? `<w:sz w:val="${o.size}"/>` : '',
  ].join('')
  const parts = text.split(/\r?\n/)
  return `<w:r>${props ? `<w:rPr>${props}</w:rPr>` : ''}${parts.map((p, i) => `${i ? '<w:br/>' : ''}<w:t xml:space="preserve">${x(p)}</w:t>`).join('')}</w:r>`
}
type Inline = string | ({ text: string } & RunOpts)
const runs = (xs: Inline[]) => xs.map((r) => (typeof r === 'string' ? run(r) : run(r.text, r))).join('')
function para(content: Inline | Inline[], style?: string): string {
  return `<w:p>${style ? `<w:pPr><w:pStyle w:val="${style}"/></w:pPr>` : ''}${runs(Array.isArray(content) ? content : [content])}</w:p>`
}
const heading = (text: string, level: 1 | 2 | 3) => para(text, `Heading${level}`)
/** A list item: the glyph, then a tab to the hanging indent. */
const bullet = (content: Inline | Inline[], glyph = '•') =>
  `<w:p><w:pPr><w:pStyle w:val="ListBullet"/></w:pPr>${run(glyph)}<w:r><w:tab/></w:r>${runs(Array.isArray(content) ? content : [content])}</w:p>`
const caption = (text: string) => para(text, 'Caption')
const sevRun = (s: string): Inline => ({ text: s.toUpperCase(), bold: true, color: SEV_HEX[s] ?? SEV_HEX.info })

/** A table with a header row that repeats on each page; cells are plain text. */
function table(head: string[], rows: string[][]): string {
  const cell = (text: string, header = false) =>
    `<w:tc><w:tcPr>${header ? '<w:shd w:val="clear" w:color="auto" w:fill="EEF1F4"/>' : ''}</w:tcPr><w:p><w:pPr><w:pStyle w:val="TableText"/></w:pPr>${run(text, { bold: header })}</w:p></w:tc>`
  return `<w:tbl><w:tblPr><w:tblStyle w:val="RemnTable"/><w:tblW w:w="5000" w:type="pct"/></w:tblPr><w:tr><w:trPr><w:tblHeader/></w:trPr>${head.map((h) => cell(h, true)).join('')}</w:tr>${rows
    .map((r) => `<w:tr><w:trPr><w:cantSplit/></w:trPr>${r.map((c) => cell(c)).join('')}</w:tr>`)
    .join('')}</w:tbl>${para('')}`
}

/** Markdown as Word paragraphs: headings, bullets and prose; emphasis and links are kept as text. */
function markdown(text: string): string {
  const inline = (s: string) =>
    s
      .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '$1 ($2)')
      .replace(/(\*\*|__)(.+?)\1/g, '$2')
      .replace(/(^|[^*])\*(?!\s)([^*]+)\*/g, '$1$2')
      .replace(/`([^`]+)`/g, '$1')
  const out: string[] = []
  let prose: string[] = []
  const flush = () => {
    if (prose.length) out.push(para(inline(prose.join(' '))))
    prose = []
  }
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line) {
      flush()
      continue
    }
    const h = /^#{1,6}\s+(.*)$/.exec(line)
    const li = /^(?:[-*+]|\d+[.)])\s+(.*)$/.exec(line)
    if (h) {
      flush()
      out.push(para({ text: inline(h[1]), bold: true }))
    } else if (li) {
      flush()
      out.push(bullet(inline(li[1])))
    } else prose.push(line)
  }
  flush()
  return out.join('')
}

const span = (from: number | null | undefined, to: number | null | undefined) => (from && to && to !== from ? `${fmtTs(from)} to ${fmtTs(to)}` : fmtTs(from) || 'no event time')

// ---------------------------------------------------------------------------
// the document
// ---------------------------------------------------------------------------

/** The body of word/document.xml: the same sections as the HTML report, in the same order. */
export function reportDocumentXml(d: ReportData): string {
  const { kase, settings } = d
  const verdict = computeVerdict(d)
  const confidence = computeConfidence(d)
  const generated = new Date(d.generatedAt ?? Date.now()).toISOString().replace('T', ' ').slice(0, 19) + 'Z'
  const rowsTotal = d.evidence.reduce((t, e) => t + (e.count ?? 0), 0)
  const verified = d.evidence.filter((e) => e.integrity === 'verified').length
  const bySev: Record<string, number> = {}
  for (const f of d.findings) bySev[effectiveSeverity(f)] = (bySev[effectiveSeverity(f)] ?? 0) + 1
  const line = bottomLine(d.summary)
  const body: string[] = []

  // cover
  body.push(para('REMN forensic analysis report', 'Subtitle'))
  body.push(para(kase.name, 'Title'))
  body.push(
    para([
      `Generated ${generated} · ${kase.analyst ? `analyst ${kase.analyst}` : 'analyst not set'}`,
      ...(d.issue
        ? [
            ' · ',
            {
              text: d.issue.status === 'final' && d.issue.finalAt ? `final, issued ${new Date(d.issue.finalAt).toISOString().replace('T', ' ').slice(0, 19)}Z` : 'DRAFT, not issued',
              bold: true,
              color: d.issue.status === 'final' ? '1B7F66' : 'D9822B',
            },
          ]
        : []),
    ]),
  )
  body.push(
    caption(`All times UTC · findings from ${settings.minSeverity} severity up${settings.onlyReviewed ? ', reviewed items only' : ''}${settings.includeFp ? ', false positives included' : ''}`),
  )
  body.push(para([{ text: verdict.label, bold: true, size: 32, color: verdict.severity ? SEV_HEX[verdict.severity] : '1B7F66' }]))
  if (line) body.push(markdown(line))
  body.push(para(verdict.detail))
  body.push(para([{ text: `Confidence ${confidence.level}: `, bold: true }, confidence.reasons.slice(0, 3).join(' · ')]))
  body.push(
    table(
      ['evidence files', 'rows analysed', 'findings', 'incidents · chains', 'confirmed', 'flagged indicators'],
      [[n(d.evidence.length), n(rowsTotal), n(d.findings.length), n(d.incidents.length + d.chains.length), n(verdict.confirmed), n(d.iocs.length)]],
    ),
  )
  body.push(
    caption(
      `By severity: ${(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((s) => `${s} ${bySev[s] ?? 0}`).join(' · ')}. Decisions: ${verdict.confirmed} confirmed, ${verdict.reviewed} reviewed or unsure, ${verdict.falsePositives} false positive${verdict.falsePositives === 1 ? '' : 's'}${d.undecided ? `, ${d.undecided} without a decision` : ', every item decided'}. ${n(verified)}/${n(d.evidence.length)} evidence files verified by digest.`,
    ),
  )

  if (d.summary) {
    body.push(heading('Executive summary', 1))
    body.push(markdown(d.summary))
    if (d.summaryBy === 'ai') body.push(caption("Drafted by the analyst model from the reviewed items; the decisions it rests on are the analyst's."))
    if (d.summaryAt && d.findings.some((f) => f.createdAt > d.summaryAt!))
      body.push(caption('Written before the findings last changed: the numbers and ids in it may describe an earlier state of the case.'))
  }

  const happened = moments(d)
  body.push(heading('What happened', 1))
  if (happened.items.length) {
    body.push(
      para(
        `${happened.items.some((m) => m.decision === 'confirmed') ? 'The confirmed items in the order they happened.' : 'Nothing was confirmed; the reviewed items in the order they happened.'} Dates are event times, UTC.${happened.total > happened.items.length ? ` The first ${happened.items.length} of ${happened.total} are listed.` : ''}`,
      ),
    )
    body.push(
      table(
        ['when (UTC)', 'severity', 'what', 'decision', 'note'],
        happened.items.map((m) => [
          m.ts === Number.MAX_SAFE_INTEGER ? 'no event time' : span(m.ts, m.end),
          m.severity,
          `${m.title}${m.entities.length ? `\n${m.entities.join(' · ')}` : ''}`,
          m.decision,
          m.note,
        ]),
      ),
    )
  } else body.push(para(happened.decided ? 'No dated item to place.' : 'No item has been decided yet: run the review before printing.'))

  if (d.stories?.length) {
    body.push(heading('Stories', 1))
    body.push(para("A story is what happened to one person, or on one host, in one incident. A story is how the case reads, not a decision: the decisions are the chains' and the incidents'."))
    for (const { story: s, note } of d.stories) {
      body.push(heading(s.title, 2))
      body.push(para([sevRun(s.severity), ` · ${span(s.start, s.end)} · ${n(s.records)} record${s.records === 1 ? '' : 's'}`]))
      if (s.headline) body.push(para(s.headline))
      if (note) body.push(markdown(note))
      for (const g of s.gaps.slice(0, 4)) body.push(caption(`Where the evidence stops: ${g}`))
    }
    if (d.storiesLeft) body.push(caption(`${n(d.storiesLeft)} more ${d.storiesLeft === 1 ? 'story is' : 'stories are'} not printed.`))
  }

  if (d.chains.length) {
    body.push(heading('Attack chains', 1))
    body.push(para("A chain is a suspicious mail and what the recipient's accounts and machines did after it. Findings whose rows are steps of a chain are decided with it."))
    for (const c of d.chains) {
      const r = d.reviews[c.id]
      body.push(heading(`${c.identityLabel}: ${c.seed.subject || 'chain'}`, 2))
      body.push(para([sevRun(chainSeverity(c, r)), ` · ${r?.verdict ? `verdict ${r.verdict}` : 'no verdict'} · ${span(c.start, c.end)} · ${n(c.steps.length)} step${c.steps.length === 1 ? '' : 's'}`]))
      if (r?.narrative) {
        body.push(markdown(r.narrative))
        if (r.narrativeBy === 'ai') body.push(caption('Narrative drafted by the analyst model.'))
      } else if (c.summary) body.push(para(c.summary))
      const members = d.membersOf.get(c.id) ?? []
      if (members.length) body.push(ruleTable(members))
    }
    if (settings.includeGraphs) body.push(caption('The chain graphs are in the HTML report.'))
  }

  body.push(heading('Incidents', 1))
  if (d.incidents.length) {
    body.push(para("Findings on the same mail, or about the same user, host or IP within six hours, are one incident. Each table groups the incident's findings by rule."))
    for (const i of d.incidents) {
      body.push(heading(i.title, 2))
      body.push(para([sevRun(i.severity), ` · ${STATUS_WORD[i.status] ?? i.status} · ${i.subtitle} · ${span(i.ts, i.tsEnd)} · ${n(i.refs.length)} row(s)`]))
      const ents = Object.entries(i.entities).slice(0, 6)
      if (ents.length) body.push(caption(ents.map(([k, v]) => `${k}=${String(v)}`).join(' · ')))
      if (i.lead.notes) {
        body.push(markdown(i.lead.notes))
        if (i.lead.notesBy === 'ai') body.push(caption('Note drafted by the model during triage.'))
      }
      if (i.lead.decidedBy === 'ai' && i.lead.aiReason) body.push(caption(`Triage note (model): ${i.lead.aiReason}`))
      body.push(ruleTable(i.findings, i.entities))
    }
  } else body.push(para('No incident outside the attack chains passes the severity floor.'))

  if (settings.includeEvidence) {
    body.push(heading('Evidence and chain of custody', 1))
    if (d.evidence.length)
      body.push(
        table(
          ['file', 'kind', 'size', 'rows', 'SHA-256', 'integrity', 'read', 'added (UTC)'],
          d.evidence.map((e) => {
            const issue = e.kind === 'package' ? packageCoverageIssues(e).join('; ') : evidenceIssue(e)
            return [e.name, e.format || e.kind, fmtBytes(e.size), n(e.count), e.sha256Client ?? '', e.integrity, issue ? `incomplete: ${issue}` : 'complete', fmtTs(e.addedAt)]
          }),
        ),
      )
    else body.push(para('No evidence file.'))
  }

  const relationships = (d.relationships ?? []).filter((r) => r.status === 'accepted' && r.includeInReport)
  if (relationships.length) {
    body.push(heading('Reviewed evidence relationships', 1))
    body.push(para('Analyst-selected connections. Shared entities do not establish causation.'))
    for (const r of relationships) {
      body.push(heading(`${r.sourceLabel} → ${r.relation} → ${r.targetLabel}`, 3))
      body.push(para(`${r.reason} (${r.confidence})`))
      if (r.notes) body.push(markdown(r.notes))
    }
  }

  if (settings.includeIocs) {
    body.push(heading('Indicators of compromise', 1))
    if (d.iocs.length) {
      body.push(para('Indicators flagged by the reputation providers; values are defanged.'))
      body.push(
        table(
          ['kind', 'indicator', 'verdict', 'tags', 'seen'],
          d.iocs.map((i) => [i.kind, defang(i.value), i.verdict ?? '', (i.tags ?? []).join(', '), `${i.count} (${i.sources.join(', ')})`]),
        ),
      )
    } else body.push(para('No indicator flagged: reputation checks were not run, or nothing was found malicious.'))
  }

  if (settings.includeTimeline && d.timeline.length) {
    body.push(heading('Case timeline', 1))
    body.push(
      table(
        ['when (UTC)', 'entry', 'from'],
        d.timeline.map((t) => [t.untimed ? 'no event time' : fmtTs(t.ts), t.text, t.link ? `${t.link.source} ${t.link.label ?? t.link.id}` : '']),
      ),
    )
  }
  if (settings.includeTasks && d.tasks.length) {
    body.push(heading('Tasks', 1))
    for (const t of d.tasks) body.push(bullet([`${t.text} `, { text: `· ${fmtTs(t.updatedAt)}`, color: '8A95A3' }], t.done ? '☑' : '☐'))
  }
  if (settings.includeNotes && d.notes.length) {
    body.push(heading('Analyst notes', 1))
    for (const note of d.notes) {
      body.push(caption(fmtTs(note.createdAt)))
      body.push(markdown(note.text))
    }
  }

  body.push(heading('Findings by rule', 1))
  if (d.findings.length) {
    body.push(para('Every printed finding, one line per rule: how many findings and rows, when, and the values matched.'))
    body.push(ruleTable(d.findings))
  } else body.push(para('No finding passes the severity floor.'))

  body.push(heading('Where it stops', 1))
  const issue = d.issue
  const limits = [
    ...(issue?.status === 'draft'
      ? [`This is a draft. Open before it can be final: ${issue.open.map((c) => `${c.label.toLowerCase()} (${c.detail})`).join('; ') || 'the analyst has not issued it'}.`]
      : []),
    ...(issue?.waived ?? []).map((w) => `Issued with an open check: ${w.label.toLowerCase()}. The analyst's reason: ${w.reason}`),
    ...(d.gaps ?? []).map((g) => g.text),
    'Times are UTC. Rules and timelines describe what the evidence records; the absence of a finding is not evidence of absence.',
    'Collection snapshots record when an artefact was collected, not when it was created or run.',
    ...(d.coverageWarnings ?? []).map((w) => `Chain analysis incomplete: ${w}`),
    d.iocsChecked
      ? `${d.iocsChecked} of ${d.iocsTotal ?? d.iocsChecked} indicators were checked against reputation services.`
      : 'No indicator was checked against a reputation service; indicators are not enriched.',
    ...(d.rules && d.rules.lastRun == null ? ['The detection rules had not run on this case when the report was made.'] : []),
    ...(d.rules?.evidenceAfter ? [`${d.rules.evidenceAfter} evidence file(s) were added after the last rule run; their findings may be missing.`] : []),
    ...confidence.reasons.filter((r) => !/^every item decided/.test(r)).map((r) => `Confidence: ${r}.`),
  ]
  for (const l of limits) body.push(bullet(l))

  body.push(heading('Case settings', 1))
  body.push(
    caption(
      `internal domains: ${kase.settings.internalDomains.join(', ') || '—'} · VIPs: ${kase.settings.vipNames.join(', ') || '—'} · business hours ${kase.settings.businessHours.start}h–${kase.settings.businessHours.end}h (${kase.settings.businessHours.tz}) · report floor ${settings.minSeverity}${settings.onlyReviewed ? ' · reviewed items only' : ''}${settings.includeFp ? ' · false positives included' : ''}`,
    ),
  )

  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>${body.join('')}<w:sectPr><w:footerReference w:type="default" r:id="rIdFooter"/><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="567" w:footer="567" w:gutter="0"/></w:sectPr></w:body></w:document>`

  function ruleTable(findings: ReportData['findings'], said: Record<string, string> = {}): string {
    return table(
      ['severity', 'rule', 'findings · rows', 'when (UTC)', 'status', 'ATT&CK', 'what matched'],
      groupByRule(findings, said).map((g) => [
        g.severity,
        `${g.title}\n${g.ruleId}`,
        `${n(g.findings)} · ${n(g.rows)}`,
        span(g.first, g.last),
        Object.entries(g.statuses)
          .map(([s, c]) => `${STATUS_WORD[s] ?? s}${c > 1 ? ` ×${c}` : ''}`)
          .join(', '),
        g.attack.slice(0, 4).join(' '),
        g.values.length
          ? `${g.values
              .slice(0, 6)
              .map((v) => (v.length > 90 ? v.slice(0, 89) + '…' : v))
              .join('\n')}${g.values.length > 6 ? `\n+${g.values.length - 6} more` : ''}`
          : '–',
      ]),
    )
  }
}

const STYLES = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Calibri" w:cs="Calibri"/><w:color w:val="0F1720"/><w:sz w:val="20"/><w:szCs w:val="20"/><w:lang w:val="en-GB"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="100" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:spacing w:after="120"/></w:pPr><w:rPr><w:b/><w:sz w:val="48"/><w:szCs w:val="48"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:rPr><w:caps/><w:color w:val="1B7F66"/><w:spacing w:val="20"/><w:sz w:val="18"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:keepNext/><w:pBdr><w:bottom w:val="single" w:sz="4" w:space="2" w:color="CFD5DC"/></w:pBdr><w:spacing w:before="360" w:after="120"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:b/><w:sz w:val="30"/><w:szCs w:val="30"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:keepNext/><w:spacing w:before="240" w:after="80"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:b/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:qFormat/><w:pPr><w:keepNext/><w:spacing w:before="160" w:after="60"/><w:outlineLvl w:val="2"/></w:pPr><w:rPr><w:b/><w:sz w:val="21"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Caption"><w:name w:val="caption"/><w:basedOn w:val="Normal"/><w:qFormat/><w:rPr><w:color w:val="4F5B69"/><w:sz w:val="17"/><w:szCs w:val="17"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="ListBullet"><w:name w:val="List Bullet"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="60"/><w:ind w:left="360" w:hanging="220"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="TableText"><w:name w:val="Table Text"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="0" w:line="240" w:lineRule="auto"/></w:pPr><w:rPr><w:sz w:val="17"/><w:szCs w:val="17"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Footer"><w:name w:val="footer"/><w:basedOn w:val="Normal"/><w:rPr><w:color w:val="8A95A3"/><w:sz w:val="16"/></w:rPr></w:style>
<w:style w:type="table" w:default="1" w:styleId="TableNormal"><w:name w:val="Normal Table"/><w:tblPr><w:tblInd w:w="0" w:type="dxa"/><w:tblCellMar><w:top w:w="0" w:type="dxa"/><w:left w:w="108" w:type="dxa"/><w:bottom w:w="0" w:type="dxa"/><w:right w:w="108" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>
<w:style w:type="table" w:styleId="RemnTable"><w:name w:val="REMN Table"/><w:basedOn w:val="TableNormal"/><w:tblPr><w:tblBorders><w:top w:val="single" w:sz="4" w:space="0" w:color="CFD5DC"/><w:left w:val="single" w:sz="4" w:space="0" w:color="CFD5DC"/><w:bottom w:val="single" w:sz="4" w:space="0" w:color="CFD5DC"/><w:right w:val="single" w:sz="4" w:space="0" w:color="CFD5DC"/><w:insideH w:val="single" w:sz="4" w:space="0" w:color="E3E6EA"/><w:insideV w:val="single" w:sz="4" w:space="0" w:color="E3E6EA"/></w:tblBorders><w:tblCellMar><w:top w:w="40" w:type="dxa"/><w:left w:w="80" w:type="dxa"/><w:bottom w:w="40" w:type="dxa"/><w:right w:w="80" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>
</w:styles>`

/** The report as the bytes of a .docx file. */
export function buildReportDocx(d: ReportData): Uint8Array {
  const at = new Date(d.generatedAt ?? Date.now())
  const created = at.toISOString().replace(/\.\d{3}Z$/, 'Z')
  const verdict = computeVerdict(d)
  const footer = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:pPr><w:pStyle w:val="Footer"/></w:pPr>${run(`REMN · ${d.kase.name} · ${verdict.label}${d.issue?.status === 'draft' ? ' · draft' : ''} · page `)}<w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>1</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p></w:ftr>`
  return zipStore(
    [
      {
        name: '[Content_Types].xml',
        data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>`,
      },
      {
        name: '_rels/.rels',
        data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>`,
      },
      {
        name: 'docProps/core.xml',
        data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>${x(`REMN report · ${d.kase.name}`)}</dc:title>${d.kase.analyst ? `<dc:creator>${x(d.kase.analyst)}</dc:creator>` : ''}<dcterms:created xsi:type="dcterms:W3CDTF">${created}</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">${created}</dcterms:modified></cp:coreProperties>`,
      },
      {
        name: 'docProps/app.xml',
        data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>REMN</Application></Properties>`,
      },
      {
        name: 'word/_rels/document.xml.rels',
        data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rIdFooter" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/></Relationships>`,
      },
      { name: 'word/document.xml', data: reportDocumentXml(d) },
      { name: 'word/styles.xml', data: STYLES },
      { name: 'word/footer1.xml', data: footer },
    ],
    at,
  )
}
