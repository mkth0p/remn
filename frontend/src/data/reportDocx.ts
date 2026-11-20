import type { Severity } from '../db/schema'
import { chainSeverity, effectiveSeverity, stepVisible } from './review'
import { packageCoverageIssues } from './packageCoverage'
import {
  AI_TABLE_HEAD,
  aiTexts,
  assetRow,
  conclusionParts,
  CONTAINMENT_HEAD,
  containmentRows,
  engagementFacts,
  IMPACT_HEAD,
  impactInventory,
  indicatorAppendix,
  INDICATOR_HEAD,
  indicatorRow,
  INDICATORS_INTRO,
  markingLine,
  MAX_INDICATORS,
  recommendationTerms,
  scopeRows,
  TECHNIQUE_HEAD,
  techniqueRow,
  techniqueTable,
  TECHNIQUES_INTRO,
  VERSION_HEAD,
  bottomLine,
  claimLine,
  computeConfidence,
  computeVerdict,
  evidenceIssue,
  foldSteps,
  groupByRule,
  incidentBases,
  limitLines,
  MAX_STEP_ROWS,
  measureWords,
  moments,
  producedLines,
  questionsIntro,
  REFERENCE_HEAD,
  referenceRows,
  STORIES_INTRO,
  storiesCaveatTexts,
  storyDecisionTexts,
  storyPart,
  storyPhaseRows,
  storySpineRows,
  storyWhere,
  textCheck,
  threatProfile,
  type ReportData,
} from './reportHtml'
import { groupByIncident, storyOwnGaps } from './stories'
import { STORY_VERDICT_LABEL } from './storyDecisions'
import { ANSWER_LABEL } from './questions/answers'
import { fmtBytes, fmtNum as n, fmtUtc as fmtTs } from '../util/format'
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

/** A two-column table of labels and values, without a header row. */
function facts(rows: [string, string][]): string {
  const cell = (text: string, label: boolean) =>
    `<w:tc><w:tcPr>${label ? '<w:tcW w:w="1500" w:type="pct"/>' : ''}</w:tcPr><w:p><w:pPr><w:pStyle w:val="TableText"/></w:pPr>${run(text, { bold: label })}</w:p></w:tc>`
  return `<w:tbl><w:tblPr><w:tblStyle w:val="RemnTable"/><w:tblW w:w="5000" w:type="pct"/></w:tblPr>${rows.map(([k, v]) => `<w:tr><w:trPr><w:cantSplit/></w:trPr>${cell(k, true)}${cell(v, false)}</w:tr>`).join('')}</w:tbl>${para('')}`
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
  /** a text's check against its rows, under the text, when it does not hold or names nothing to check */
  const checkOf = (key: string) => {
    const c = textCheck(key, d.claims)
    if (c) body.push(caption(c.text))
  }

  // cover
  const client = settings.client
  const conclusion = conclusionParts(client)
  body.push(para('REMN forensic analysis report', 'Subtitle'))
  body.push(para(kase.name, 'Title'))
  const preparedFor = [client.client.trim() ? `Prepared for ${client.client.trim()}` : '', client.engagementRef.trim() ? `engagement ${client.engagementRef.trim()}` : ''].filter(Boolean).join(' · ')
  if (preparedFor) body.push(para({ text: preparedFor, size: 24 }))
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
  body.push(para([{ text: `Completeness ${confidence.level}: `, bold: true }, confidence.reasons.slice(0, 3).join(' · ')]))
  body.push(caption('How complete the review is, not how sure its conclusion is.'))
  if (conclusion.confidence) {
    body.push(para([{ text: `Analyst's confidence ${conclusion.confidence}${conclusion.basis ? ': ' : ''}`, bold: true }, conclusion.basis]))
    body.push(caption("The analyst's own assessment of the conclusion."))
  }
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
  const profile = threatProfile(d)
  const tactics = (state: 'confirmed' | 'observed') =>
    profile
      .filter((b) => b.state === state)
      .map((b) => `${b.def.label} (${n(b.findings)}${b.techniques.length ? `: ${b.techniques.join(', ')}` : ''})`)
      .join('; ')
  if (profile.some((b) => b.state !== 'none'))
    body.push(
      caption(`Threat profile: ${[tactics('confirmed') ? `confirmed: ${tactics('confirmed')}` : '', tactics('observed') ? `observed: ${tactics('observed')}` : ''].filter(Boolean).join('. ')}.`),
    )

  const engagement = engagementFacts(client)
  if (engagement.facts.length || engagement.distribution.length || engagement.versions.length) {
    body.push(heading('Engagement', 1))
    if (engagement.facts.length) body.push(facts(engagement.facts))
    if (engagement.distribution.length) {
      body.push(heading('Distribution', 3))
      for (const x of engagement.distribution) body.push(bullet(x))
    }
    if (engagement.versions.length) {
      body.push(heading('Version history', 3))
      body.push(table(VERSION_HEAD, engagement.versions))
    }
  }

  if (d.summary) {
    body.push(heading('Executive summary', 1))
    body.push(markdown(d.summary))
    if (d.summaryBy === 'ai') body.push(caption("Drafted by the analyst model from the reviewed items; the decisions it rests on are the analyst's."))
    checkOf('summary')
    if (d.summaryAt && d.findings.some((f) => f.createdAt > d.summaryAt!))
      body.push(caption('Written before the findings last changed: the numbers and ids in it may describe an earlier state of the case.'))
  }

  body.push(heading('Scope', 1))
  if (client.objectives.trim()) body.push(markdown(client.objectives))
  body.push(facts(scopeRows(d).map((r) => [r.label, `${r.items.join('\n')}${r.note ? `\n(${r.note})` : ''}`])))

  if (conclusion.initialAccess || conclusion.rootCause) {
    body.push(heading('Conclusion', 1))
    if (conclusion.initialAccess) {
      body.push(heading('Initial access', 3))
      body.push(markdown(conclusion.initialAccess))
    }
    if (conclusion.rootCause) {
      body.push(heading('Root cause', 3))
      body.push(markdown(conclusion.rootCause))
    }
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

  const impact = impactInventory(d)
  if (impact.accounts.length || impact.hosts.length || client.impact.trim()) {
    body.push(heading('Impact', 1))
    body.push(
      para(
        'The accounts and hosts the confirmed items name, printed or not: the people a confirmed chain or story is about, the hosts it ran on, and the accounts and hosts of the findings confirmed with them. Machine, service and built-in accounts are left out.',
      ),
    )
    if (client.impact.trim()) {
      body.push(markdown(client.impact))
      body.push(caption("The analyst's account of the impact."))
    }
    if (impact.accounts.length) body.push(table(['account', ...IMPACT_HEAD.slice(1)], impact.accounts.map(assetRow)))
    if (impact.hosts.length) body.push(table(['host', ...IMPACT_HEAD.slice(1)], impact.hosts.map(assetRow)))
    if (!impact.accounts.length && !impact.hosts.length) body.push(para('No confirmed item names an account or a host.'))
  }
  const actions = containmentRows(client)
  if (actions.length) {
    body.push(heading('Containment', 1))
    body.push(para('The containment and eradication actions taken, as the analyst recorded them.'))
    body.push(table(CONTAINMENT_HEAD, actions))
  }
  const terms = recommendationTerms(client)
  if (terms.length) {
    body.push(heading('Recommendations', 1))
    for (const [t, text] of terms) {
      body.push(heading(t, 3))
      body.push(markdown(text))
    }
  }

  if (d.questions) {
    const q = d.questions
    body.push(heading('Questions', 1))
    body.push(para(questionsIntro(q)))
    for (const sc of q.scenarios) {
      body.push(heading(`${sc.name} (${sc.id}, ${sc.origin === 'dfiq' ? 'DFIQ' : 'REMN'})`, 2))
      for (const f of sc.facets) {
        body.push(heading(f.name, 3))
        for (const qu of f.questions) {
          body.push(para([{ text: `${qu.id} `, mono: true }, { text: qu.name, bold: true }, ` · ${ANSWER_LABEL[qu.status] ?? qu.status}`]))
          if (qu.text.trim()) body.push(markdown(qu.text))
          else if (qu.status === 'open') body.push(caption('unanswered'))
          for (const c of qu.citations) body.push(bullet(`${c.source === 'findings' ? 'finding ' : ''}${c.label}${c.ts ? ` · ${fmtTs(c.ts)}` : ''}`))
          if (!qu.citations.length && qu.status === 'answered') body.push(caption('no record cited'))
          if (qu.coverage && (qu.status !== 'answered' || qu.covered === false)) body.push(caption(`Evidence: ${qu.coverage}`))
        }
      }
    }
  }

  if (d.stories?.length) {
    body.push(heading('Stories', 1))
    body.push(para(STORIES_INTRO))
    for (const c of storiesCaveatTexts(d)) body.push(caption(c.text))
    for (const { incident: i, items } of groupByIncident(d.stories, (r) => r.story, d.storyIncidents)) {
      if (i) {
        body.push(heading(`One intrusion: ${i.label}`, 2))
        body.push(
          para([
            sevRun(i.severity),
            ` · ${span(i.start, i.end)} · ${n(i.stories.length)} stories${i.hosts.length ? ` · hosts ${i.hosts.slice(0, 6).join(', ')}${i.hosts.length > 6 ? ` +${i.hosts.length - 6}` : ''}` : ''}`,
          ]),
        )
        const bases = incidentBases(items)
        if (bases.length) body.push(caption(`Why they read as one: ${bases.slice(0, 4).join('; ')}${bases.length > 4 ? ` and ${bases.length - 4} more` : ''}.`))
        const unprinted = i.stories.length - items.length
        if (unprinted > 0) body.push(caption(`${n(unprinted)} more of its stories ${unprinted === 1 ? 'is' : 'are'} not printed: below the severity floor, without a note, or past the first twenty.`))
        if (i.cut) body.push(caption(`${n(i.cut)} more linked ${i.cut === 1 ? 'story is' : 'stories are'} left out of it: an incident holds twenty stories at most.`))
      }
      for (const { story: s, key, note, decisions: dec } of items) {
        const w = storyWhere(s)
        body.push(heading(`${s.title}${storyPart(dec)}`, i ? 3 : 2))
        body.push(
          para([
            sevRun(s.severity),
            ...(dec?.call ? [' · ', { text: STORY_VERDICT_LABEL[dec.call.verdict], bold: true }] : []),
            ` · ${s.confidence} confidence · ${w.who} · ${span(s.start, s.end)} · ${n(s.records)} record(s) in ${n(s.steps.length)} step(s)${w.hosts ? ` · hosts ${w.hosts}${w.hostsMore ? ` +${w.hostsMore}` : ''}` : ''}${w.from ? ` · from ${w.from}` : ''}`,
          ]),
        )
        if (note) {
          body.push(markdown(note))
          body.push(caption("The analyst's reading of the story."))
          checkOf(`story:${key}`)
        } else if (s.summary || s.headline) body.push(para(s.summary || s.headline))
        const spine = storySpineRows(s)
        if (spine) {
          body.push(para({ text: `Spine: ${n(spine.rows.length)} of ${n(spine.of)} steps`, bold: true }))
          body.push(
            table(
              ['when (UTC)', 'phase', 'step', 'why it is in the story'],
              spine.rows.map((r) => [
                span(r.ts, r.tsEnd),
                `${r.severity ? `${r.severity} · ` : ''}${r.phase}`,
                `${r.title}${r.host ? ` on ${r.host}` : ''}${r.wayIn ? ' [way in]' : ''}${r.anchor ? ' [anchor]' : ''}${r.finding ? `\n${r.finding}${r.more ? ` +${n(r.more)}` : ''}` : ''}`,
                r.why,
              ]),
            ),
          )
          if (spine.basis) body.push(caption(spine.basis))
          body.push(para({ text: 'Phases', bold: true }))
        }
        body.push(
          table(
            ['phase', 'when (UTC)', 'steps', 'what marks it'],
            storyPhaseRows(s, dec).map((p) => [`${p.severity ? `${p.severity} · ` : ''}${p.label}`, span(p.first, p.last), n(p.steps), p.marks]),
          ),
        )
        for (const l of storyDecisionTexts(dec)) body.push(caption(l))
        const gaps = storyOwnGaps(s)
        if (gaps.length) body.push(caption(`Where it stops: ${gaps.join(' ')}`))
      }
    }
    if (d.storiesLeft)
      body.push(
        caption(
          `${n(d.storiesLeft)} more ${d.storiesLeft === 1 ? 'story is' : 'stories are'} not printed: below the severity floor${settings.onlyReviewed ? ', without a note or a decision (reviewed items only)' : ''} or past the first twenty.`,
        ),
      )
    if (d.storiesDismissed)
      body.push(
        caption(`${n(d.storiesDismissed)} ${d.storiesDismissed === 1 ? 'story' : 'stories'} decided benign or false positive by the analyst ${d.storiesDismissed === 1 ? 'is' : 'are'} not printed.`),
      )
  }

  if (d.chains.length) {
    body.push(heading('Attack chains', 1))
    body.push(
      para(
        "A chain is a suspicious mail and what the recipient's accounts and machines did after it, scored on the seed, the ties to the mail, the steps, the findings and the sources involved. Findings whose rows are steps of a chain are decided with it.",
      ),
    )
    if (settings.includeGraphs && d.chains.length > 1)
      body.push(caption(`Shared between chains: ${d.campaignInsights.length ? d.campaignInsights.join(' · ') : 'no sender, domain, IP or host is shared between the chains'}.`))
    for (const c of d.chains) {
      const r = d.reviews[c.id]
      body.push(heading(`${c.identityLabel}: ${c.seed.subject || 'chain'}`, 2))
      body.push(
        para([
          sevRun(chainSeverity(c, r)),
          ` · ${r?.verdict ? `verdict ${r.verdict}` : 'no verdict'} · ${span(c.start, c.end)} · ${n(c.steps.length)} step${c.steps.length === 1 ? '' : 's'} · score ${c.score}`,
        ]),
      )
      body.push(
        caption(
          `Seed ${c.seed.source === 'events' ? 'event' : 'mail'} “${c.seed.subject}” from ${c.seed.fromAddr ?? ''} at ${fmtTs(c.seed.ts)} (risk ${c.seed.risk}) · ${c.artifactLinks} artifact tie(s)${c.entities.attackerAddresses.length ? ` · attacker ${c.entities.attackerAddresses.join(', ')}` : ''}${c.entities.ips.length ? ` · IPs ${c.entities.ips.join(', ')}` : ''}${c.entities.hosts.length ? ` · hosts ${c.entities.hosts.join(', ')}` : ''}`,
        ),
      )
      if (r?.narrative) {
        body.push(markdown(r.narrative))
        if (r.narrativeBy === 'ai') body.push(caption('Narrative drafted by the analyst model.'))
        checkOf(`chain:${c.id}`)
      } else if (c.summary) body.push(para(c.summary))
      const visible = c.steps.filter((st) => stepVisible(st, settings.chainDetail))
      const folded = foldSteps(visible)
      const printed = folded.slice(0, MAX_STEP_ROWS)
      const left = folded.length - printed.length
      const hidden = c.steps.length - visible.length
      const offset = (m: number) => `${m >= 0 ? '+' : ''}${Math.round(m)}`
      body.push(
        table(
          ['time (UTC)', 'offset', 'source', 'step', 'ties to the mail / findings'],
          printed.map((f) => {
            const st = f.step
            return [
              f.n > 1 && f.tsEnd !== f.ts ? `${fmtTs(f.ts)}\nto ${fmtTs(f.tsEnd)}` : fmtTs(f.ts),
              f.n > 1 && f.offsetEnd !== f.offsetMin ? `${offset(f.offsetMin)} → ${offset(f.offsetEnd)} min` : `${offset(f.offsetMin)} min`,
              st.kind === 'mail' ? 'mailbox' : st.origin === 'm365' ? 'Microsoft 365' : 'host',
              `${st.title}${f.n > 1 ? ` ×${f.n}` : st.count > 1 ? ` ×${st.count}` : ''}${st.computer || st.ipAddress ? `\n${[st.computer, st.ipAddress].filter(Boolean).join(' · ')}` : ''}`,
              [...st.artifacts, ...st.findings.map((x) => x.title)].join('; '),
            ]
          }),
        ),
      )
      if (left || hidden)
        body.push(
          caption(
            `${left ? `${left} more step row(s) not printed (open the chain in REMN for the full list)` : ''}${left && hidden ? ' · ' : ''}${hidden ? `${hidden} routine step(s) not printed at the “${settings.chainDetail}” detail level` : ''}.`,
          ),
        )
      const members = d.membersOf.get(c.id) ?? []
      if (members.length) {
        body.push(caption(`${members.length} finding(s) linked to this chain, decided with it.`))
        body.push(ruleTable(members))
      }
      if (r?.by === 'ai' && r.aiReason) body.push(caption(`Triage note (model): ${r.aiReason}`))
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
      checkOf(`incident:${i.lead.id ?? i.title}`)
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
    const packages = d.evidence.filter((e) => e.kind === 'package')
    if (packages.length) {
      body.push(heading('Investigation package coverage', 3))
      body.push(
        table(
          ['package', 'coverage'],
          packages.map((e) => [e.name, packageCoverageIssues(e).join('; ') || 'No reported import issues']),
        ),
      )
    }
  }

  const relationships = (d.relationships ?? []).filter((r) => r.status === 'accepted' && r.includeInReport)
  if (relationships.length) {
    body.push(heading('Reviewed evidence relationships', 1))
    body.push(para('Analyst-selected connections. Observation and collection times remain distinct; shared entities do not establish causation.'))
    for (const r of relationships) {
      body.push(heading(`${r.sourceLabel} → ${r.relation} → ${r.targetLabel}`, 3))
      body.push(para(`${r.reason} (${r.confidence})`))
      if (r.notes) body.push(markdown(r.notes))
      if (Object.keys(r.aliases ?? {}).length) body.push(para(`Explicit aliases: ${JSON.stringify(r.aliases)}`))
      if (r.references.length) body.push(table(REFERENCE_HEAD, referenceRows(r)))
    }
  }

  if (settings.includeIocs) {
    const ind = indicatorAppendix(d)
    body.push(heading('Indicators of compromise', 1))
    if (ind.rows.length) {
      body.push(para(INDICATORS_INTRO))
      body.push(table(INDICATOR_HEAD, ind.rows.map(indicatorRow)))
      if (ind.left) body.push(caption(`${n(ind.left)} more indicator${ind.left === 1 ? ' is' : 's are'} not listed: the appendix holds ${n(MAX_INDICATORS)}.`))
    } else body.push(para('No confirmed item names an outside address, domain, sender, URL or hash, and no reputation service flagged one.'))
  }
  const techniques = techniqueTable(d)
  if (techniques.length) {
    body.push(heading('ATT&CK techniques', 1))
    body.push(para(TECHNIQUES_INTRO))
    body.push(table(TECHNIQUE_HEAD, techniques.map(techniqueRow)))
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
    body.push(para('Every printed finding, one line per rule: how many findings and rows, when, and the values matched. The incidents above carry the same findings in context.'))
    body.push(ruleTable(d.findings))
  } else body.push(para('No finding passes the severity floor.'))

  if (d.ai && d.ai.runs) {
    const a = aiTexts(d.ai)
    body.push(heading('How AI was used', 1))
    body.push(para(a.intro))
    body.push(caption(a.facts))
    body.push(a.rows.length ? table(AI_TABLE_HEAD, a.rows) : para(a.none))
    body.push(caption(a.decisions))
    body.push(caption(a.ledger))
  }

  body.push(heading('Method and limits', 1))
  body.push(heading('How this was produced', 2))
  for (const l of producedLines(d, verdict)) body.push(bullet(l))
  body.push(heading('Where it stops', 2))
  for (const l of limitLines(d, confidence)) body.push(bullet(l))

  body.push(heading('Case settings', 1))
  body.push(
    caption(
      `internal domains: ${kase.settings.internalDomains.join(', ') || '—'} · VIPs: ${kase.settings.vipNames.join(', ') || '—'} · business hours ${kase.settings.businessHours.start}h–${kase.settings.businessHours.end}h (${kase.settings.businessHours.tz}) · reputation lookups ${d.iocsChecked ? `run on ${n(d.iocsChecked)} indicator${d.iocsChecked === 1 ? '' : 's'}` : 'not run'} · report floor ${settings.minSeverity}${settings.onlyReviewed ? ' · reviewed items only' : ''}${settings.includeFp ? ' · false positives included' : ''} · chain steps: ${settings.chainDetail}`,
    ),
  )

  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>${body.join('')}<w:sectPr><w:headerReference w:type="default" r:id="rIdHeader"/><w:footerReference w:type="default" r:id="rIdFooter"/><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="567" w:footer="567" w:gutter="0"/></w:sectPr></w:body></w:document>`

  /** One line per rule: its severity, title and id with what its measure says, whether its rows bear it out, when, and what it matched. */
  function ruleTable(findings: ReportData['findings'], said: Record<string, string> = {}): string {
    return table(
      ['severity', 'rule', 'findings · rows', 'when (UTC)', 'status', 'ATT&CK', 'what matched'],
      groupByRule(findings, said).map((g) => {
        const measure = measureWords(d.measures?.[g.ruleId])
        const claim = claimLine(g.ids, d.claims)
        return [
          g.severity !== g.ruleSeverity ? `${g.severity}\nrule: ${g.ruleSeverity}` : g.severity,
          `${g.title}\n${g.ruleId}${measure ? ` · ${measure.lead ? measure.text.toUpperCase() : measure.text}` : ''}${g.escalations.length ? ` · ${g.escalations.slice(0, 2).join(' · ')}` : ''}${
            claim
              ? `\n${claim.word}${claim.where ? ` · ${claim.where}${claim.more ? ` and ${n(claim.more)} more` : ''}` : ''}${claim.status !== 'verified' && claim.reasons.length ? `: ${claim.reasons.join(' ')}` : ''}`
              : ''
          }`,
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
        ]
      }),
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
<w:style w:type="paragraph" w:styleId="Header"><w:name w:val="header"/><w:basedOn w:val="Normal"/><w:rPr><w:color w:val="4F5B69"/><w:sz w:val="16"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Footer"><w:name w:val="footer"/><w:basedOn w:val="Normal"/><w:rPr><w:color w:val="8A95A3"/><w:sz w:val="16"/></w:rPr></w:style>
<w:style w:type="table" w:default="1" w:styleId="TableNormal"><w:name w:val="Normal Table"/><w:tblPr><w:tblInd w:w="0" w:type="dxa"/><w:tblCellMar><w:top w:w="0" w:type="dxa"/><w:left w:w="108" w:type="dxa"/><w:bottom w:w="0" w:type="dxa"/><w:right w:w="108" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>
<w:style w:type="table" w:styleId="RemnTable"><w:name w:val="REMN Table"/><w:basedOn w:val="TableNormal"/><w:tblPr><w:tblBorders><w:top w:val="single" w:sz="4" w:space="0" w:color="CFD5DC"/><w:left w:val="single" w:sz="4" w:space="0" w:color="CFD5DC"/><w:bottom w:val="single" w:sz="4" w:space="0" w:color="CFD5DC"/><w:right w:val="single" w:sz="4" w:space="0" w:color="CFD5DC"/><w:insideH w:val="single" w:sz="4" w:space="0" w:color="E3E6EA"/><w:insideV w:val="single" w:sz="4" w:space="0" w:color="E3E6EA"/></w:tblBorders><w:tblCellMar><w:top w:w="40" w:type="dxa"/><w:left w:w="80" w:type="dxa"/><w:bottom w:w="40" w:type="dxa"/><w:right w:w="80" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>
</w:styles>`

/** The report as the bytes of a .docx file. */
export function buildReportDocx(d: ReportData): Uint8Array {
  const at = new Date(d.generatedAt ?? Date.now())
  const created = at.toISOString().replace(/\.\d{3}Z$/, 'Z')
  const verdict = computeVerdict(d)
  // the handling marking at the top of every page, when the analyst set one
  const header = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:pPr><w:pStyle w:val="Header"/><w:jc w:val="center"/></w:pPr>${run(markingLine(d.settings.client), { bold: true })}</w:p></w:hdr>`
  const footer = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:pPr><w:pStyle w:val="Footer"/></w:pPr>${run(`REMN · ${d.kase.name} · ${verdict.label}${d.issue?.status === 'draft' ? ' · draft' : ''} · page `)}<w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>1</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p></w:ftr>`
  return zipStore(
    [
      {
        name: '[Content_Types].xml',
        data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/><Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>`,
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
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rIdHeader" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/><Relationship Id="rIdFooter" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/></Relationships>`,
      },
      { name: 'word/document.xml', data: reportDocumentXml(d) },
      { name: 'word/styles.xml', data: STYLES },
      { name: 'word/header1.xml', data: header },
      { name: 'word/footer1.xml', data: footer },
    ],
    at,
  )
}
