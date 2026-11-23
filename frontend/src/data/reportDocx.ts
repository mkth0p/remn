import type { Severity } from '../db/schema'
import { chainSeverity, effectiveSeverity, stepVisible } from './review'
import { packageCoverageIssues } from './packageCoverage'
import {
  aiTexts,
  assetRow,
  conclusionParts,
  containmentRows,
  engagementFacts,
  impactInventory,
  indicatorAppendix,
  indicatorRow,
  markingLine,
  MAX_INDICATORS,
  recommendationTerms,
  scopeRows,
  techniqueRow,
  techniqueTable,
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
  referenceRows,
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
import { logoImage, reportText, type LogoImage, type ReportText } from './reportText'
import { zipStore } from '../util/zip'

/**
 * The report as a Word document, for a client or a team that edits the report before it goes out.
 * It carries what the HTML report says, section by section, from the same ReportData and the same
 * verdict, confidence and grouping, as plain headings, paragraphs and tables a reader can restyle:
 * no graphs (those stay in the HTML report) and no layout Word would have to guess at.
 */

export const DOCX_MIME = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'

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

const span = (t: ReportText, from: number | null | undefined, to: number | null | undefined) => (from && to && to !== from ? `${t.ts(from)} ${t.to} ${t.ts(to)}` : t.ts(from) || t.noEventTime)

/** the largest the logo stands on the cover, in EMU (a centimetre is 360,000): 4.5 by 1.6 cm */
const LOGO_BOX = { cx: 1_620_000, cy: 576_000 }

/** The logo as an inline picture, scaled to fit the box and keep its proportions. */
function logoDrawing(logo: LogoImage, name: string): string {
  const scale = Math.min(LOGO_BOX.cx / logo.width, LOGO_BOX.cy / logo.height)
  const cx = Math.max(1, Math.round(logo.width * scale))
  const cy = Math.max(1, Math.round(logo.height * scale))
  return `<w:p><w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="${cx}" cy="${cy}"/><wp:docPr id="1" name="${x(name)}"/><a:graphic><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic><pic:nvPicPr><pic:cNvPr id="1" name="logo.${logo.ext}"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:embed="rIdLogo"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="${cx}" cy="${cy}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>`
}

// ---------------------------------------------------------------------------
// the document
// ---------------------------------------------------------------------------

/** The body of word/document.xml: the same sections as the HTML report, in the same order, in the report's language. */
export function reportDocumentXml(d: ReportData): string {
  const { kase, settings } = d
  const t = reportText(settings.language)
  const n = t.num
  const verdict = computeVerdict(d, t)
  const confidence = computeConfidence(d, t)
  const generated = t.ts(d.generatedAt ?? Date.now())
  const rowsTotal = d.evidence.reduce((x, e) => x + (e.count ?? 0), 0)
  const verified = d.evidence.filter((e) => e.integrity === 'verified').length
  const bySev: Record<string, number> = {}
  for (const f of d.findings) bySev[effectiveSeverity(f)] = (bySev[effectiveSeverity(f)] ?? 0) + 1
  const line = bottomLine(d.summary)
  const sev = (s: string) => t.sev[s] ?? s
  const sevRun = (s: string): Inline => ({ text: sev(s).toUpperCase(), bold: true, color: SEV_HEX[s] ?? SEV_HEX.info })
  const body: string[] = []
  /** a text's check against its rows, under the text, when it does not hold or names nothing to check */
  const checkOf = (key: string) => {
    const c = textCheck(key, d.claims, t)
    if (c) body.push(caption(c.text))
  }

  // cover: the firm's logo and name when the analyst set them, else REMN's line
  const client = settings.client
  const conclusion = conclusionParts(client, t)
  const firm = settings.branding.firmName.trim()
  const logo = logoImage(settings.branding.logo)
  if (logo) body.push(logoDrawing(logo, firm || 'logo'))
  if (firm) body.push(para({ text: firm, bold: true, size: 28 }))
  body.push(para(settings.branding.coverLine.trim() || t.cover.subtitle, 'Subtitle'))
  body.push(para(kase.name, 'Title'))
  const preparedFor = [client.client.trim() ? t.cover.preparedFor(client.client.trim()) : '', client.engagementRef.trim() ? t.cover.engagement(client.engagementRef.trim()) : '']
    .filter(Boolean)
    .join(' · ')
  if (preparedFor) body.push(para({ text: preparedFor, size: 24 }))
  body.push(
    para([
      t.docx.generated(generated, kase.analyst ? t.cover.analyst(kase.analyst) : t.cover.noAnalyst),
      ...(d.issue
        ? [
            ' · ',
            {
              text: d.issue.status === 'final' && d.issue.finalAt ? t.docx.final(t.ts(d.issue.finalAt)) : t.docx.draft,
              bold: true,
              color: d.issue.status === 'final' ? '1B7F66' : 'D9822B',
            },
          ]
        : []),
    ]),
  )
  body.push(caption(t.cover.meta(settings.minSeverity, settings.onlyReviewed, settings.includeFp)))
  body.push(para([{ text: verdict.label, bold: true, size: 32, color: verdict.severity ? SEV_HEX[verdict.severity] : '1B7F66' }]))
  if (line) body.push(markdown(line))
  body.push(para(verdict.detail))
  body.push(para([{ text: t.docx.completeness(t.level[confidence.level] ?? confidence.level), bold: true }, confidence.reasons.slice(0, 3).join(' · ')]))
  body.push(caption(t.docx.completenessSub))
  if (conclusion.confidence) {
    body.push(para([{ text: t.docx.analystConfidence(conclusion.confidence, !!conclusion.basis), bold: true }, conclusion.basis]))
    body.push(caption(t.docx.analystConfidenceSub))
  }
  body.push(table(t.cover.kpi, [[n(d.evidence.length), n(rowsTotal), n(d.findings.length), n(d.incidents.length + d.chains.length), n(verdict.confirmed), n(d.iocs.length)]]))
  body.push(
    caption(
      t.docx.bySeverity(
        (['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((s) => `${sev(s)} ${bySev[s] ?? 0}`).join(' · '),
        verdict.confirmed,
        verdict.reviewed,
        verdict.falsePositives,
        d.undecided,
        `${n(verified)}/${n(d.evidence.length)}`,
      ),
    ),
  )
  const profile = threatProfile(d)
  const tactics = (state: 'confirmed' | 'observed') =>
    profile
      .filter((b) => b.state === state)
      .map((b) => `${t.tactic[b.def.id] ?? b.def.label} (${n(b.findings)}${b.techniques.length ? `: ${b.techniques.join(', ')}` : ''})`)
      .join('; ')
  if (profile.some((b) => b.state !== 'none')) body.push(caption(t.docx.profile(tactics('confirmed'), tactics('observed'))))

  const engagement = engagementFacts(client, t)
  if (engagement.facts.length || engagement.distribution.length || engagement.versions.length) {
    body.push(heading(t.section.engagement, 1))
    if (engagement.facts.length) body.push(facts(engagement.facts))
    if (engagement.distribution.length) {
      body.push(heading(t.client.distribution, 3))
      for (const v of engagement.distribution) body.push(bullet(v))
    }
    if (engagement.versions.length) {
      body.push(heading(t.client.versions, 3))
      body.push(table(t.client.versionHead, engagement.versions))
    }
  }

  if (d.summary) {
    body.push(heading(t.section.summary, 1))
    body.push(markdown(d.summary))
    if (d.summaryBy === 'ai') body.push(caption(t.summary.byAiDocx))
    checkOf('summary')
    if (d.summaryAt && d.findings.some((f) => f.createdAt > d.summaryAt!)) body.push(caption(t.summary.staleDocx))
  }

  body.push(heading(t.section.scope, 1))
  if (client.objectives.trim()) body.push(markdown(client.objectives))
  body.push(facts(scopeRows(d, t).map((r) => [r.label, `${r.items.join('\n')}${r.note ? `\n(${r.note})` : ''}`])))

  if (conclusion.initialAccess || conclusion.rootCause) {
    body.push(heading(t.section.conclusion, 1))
    if (conclusion.initialAccess) {
      body.push(heading(t.client.initialAccess, 3))
      body.push(markdown(conclusion.initialAccess))
    }
    if (conclusion.rootCause) {
      body.push(heading(t.client.rootCause, 3))
      body.push(markdown(conclusion.rootCause))
    }
  }

  const happened = moments(d, t)
  body.push(heading(t.section.happened, 1))
  if (happened.items.length) {
    body.push(
      para(
        `${happened.items.some((m) => m.confirmed) ? t.happened.confirmed : t.happened.reviewed} ${t.happened.times}${happened.total > happened.items.length ? ` ${t.happened.firstDocx(happened.items.length, happened.total)}` : ''}`,
      ),
    )
    body.push(
      table(
        t.happened.head,
        happened.items.map((m) => [
          m.ts === Number.MAX_SAFE_INTEGER ? t.noEventTime : span(t, m.ts, m.end),
          sev(m.severity),
          `${m.title}${m.entities.length ? `\n${m.entities.join(' · ')}` : ''}`,
          m.decision,
          m.note,
        ]),
      ),
    )
  } else body.push(para(happened.decided ? t.happened.noDated : t.happened.noDecision))

  const impact = impactInventory(d, t)
  if (impact.accounts.length || impact.hosts.length || client.impact.trim()) {
    body.push(heading(t.section.impact, 1))
    body.push(para(t.client.impactIntro))
    if (client.impact.trim()) {
      body.push(markdown(client.impact))
      body.push(caption(t.client.impactNoteDocx))
    }
    const asset = (a: (typeof impact.accounts)[number]) => assetRow(a, t)
    if (impact.accounts.length) body.push(table([t.client.account, ...t.client.impactHead.slice(1)], impact.accounts.map(asset)))
    if (impact.hosts.length) body.push(table([t.client.host, ...t.client.impactHead.slice(1)], impact.hosts.map(asset)))
    if (!impact.accounts.length && !impact.hosts.length) body.push(para(t.client.impactNone))
  }
  const actions = containmentRows(client, t)
  if (actions.length) {
    body.push(heading(t.section.containment, 1))
    body.push(para(t.client.containmentIntro))
    body.push(table(t.client.containmentHead, actions))
  }
  const terms = recommendationTerms(client, t)
  if (terms.length) {
    body.push(heading(t.section.recommendations, 1))
    for (const [term, text] of terms) {
      body.push(heading(term, 3))
      body.push(markdown(text))
    }
  }

  if (d.questions) {
    const q = d.questions
    body.push(heading(t.section.questions, 1))
    body.push(para(questionsIntro(q, t)))
    for (const sc of q.scenarios) {
      body.push(heading(`${sc.name} (${sc.id}, ${sc.origin === 'dfiq' ? 'DFIQ' : 'REMN'})`, 2))
      for (const f of sc.facets) {
        body.push(heading(f.name, 3))
        for (const qu of f.questions) {
          body.push(para([{ text: `${qu.id} `, mono: true }, { text: qu.name, bold: true }, ` · ${t.answer[qu.status] ?? qu.status}`]))
          if (qu.text.trim()) body.push(markdown(qu.text))
          else if (qu.status === 'open') body.push(caption(t.question.unanswered))
          for (const c of qu.citations) body.push(bullet(`${c.source === 'findings' ? `${t.question.finding} ` : ''}${c.label}${c.ts ? ` · ${t.ts(c.ts)}` : ''}`))
          if (!qu.citations.length && qu.status === 'answered') body.push(caption(t.question.noCitation))
          if (qu.coverage && (qu.status !== 'answered' || qu.covered === false)) body.push(caption(t.question.evidence(qu.coverage)))
        }
      }
    }
  }

  if (d.stories?.length) {
    body.push(heading(t.section.stories, 1))
    body.push(para(t.story.intro))
    for (const c of storiesCaveatTexts(d, t)) body.push(caption(c.text))
    for (const { incident: i, items } of groupByIncident(d.stories, (r) => r.story, d.storyIncidents)) {
      if (i) {
        body.push(heading(t.story.intrusion(i.label), 2))
        body.push(
          para([
            sevRun(i.severity),
            ` · ${span(t, i.start, i.end)} · ${t.story.count(i.stories.length)}${i.hosts.length ? ` · ${t.story.hosts} ${i.hosts.slice(0, 6).join(', ')}${i.hosts.length > 6 ? ` +${i.hosts.length - 6}` : ''}` : ''}`,
          ]),
        )
        const bases = incidentBases(items, t)
        if (bases.length) body.push(caption(`${t.story.whyOne(`${bases.slice(0, 4).join('; ')}${bases.length > 4 ? ` ${t.andMore(bases.length - 4)}` : ''}`)}.`))
        const unprinted = i.stories.length - items.length
        if (unprinted > 0) body.push(caption(t.story.unprinted(unprinted)))
        if (i.cut) body.push(caption(t.story.cut(i.cut)))
      }
      for (const { story: s, key, note, decisions: dec } of items) {
        const w = storyWhere(s, t)
        body.push(heading(`${s.title}${storyPart(dec, t)}`, i ? 3 : 2))
        body.push(
          para([
            sevRun(s.severity),
            ...(dec?.call ? [' · ', { text: t.storyVerdict[dec.call.verdict] ?? dec.call.verdict, bold: true }] : []),
            ` · ${t.story.confidence(t.level[s.confidence] ?? s.confidence)} · ${w.who} · ${span(t, s.start, s.end)} · ${t.story.records(s.records, s.steps.length)}${w.hosts ? ` · ${t.story.hosts} ${w.hosts}${w.hostsMore ? ` +${w.hostsMore}` : ''}` : ''}${w.from ? ` · ${t.story.from} ${w.from}` : ''}`,
          ]),
        )
        if (note) {
          body.push(markdown(note))
          body.push(caption(t.story.noteDocx))
          checkOf(`story:${key}`)
        } else if (s.summary || s.headline) body.push(para(s.summary || s.headline))
        const spine = storySpineRows(s, t)
        if (spine) {
          body.push(para({ text: t.story.spine(spine.rows.length, spine.of), bold: true }))
          body.push(
            table(
              t.story.spineHead,
              spine.rows.map((r) => [
                span(t, r.ts, r.tsEnd),
                `${r.severity ? `${sev(r.severity)} · ` : ''}${r.phase}`,
                `${r.title}${r.host ? ` ${t.story.on} ${r.host}` : ''}${r.wayIn ? ` [${t.story.wayIn}]` : ''}${r.anchor ? ` [${t.story.anchor}]` : ''}${r.finding ? `\n${r.finding}${r.more ? ` +${n(r.more)}` : ''}` : ''}`,
                r.why,
              ]),
            ),
          )
          if (spine.basis) body.push(caption(spine.basis))
          body.push(para({ text: t.story.phases, bold: true }))
        }
        body.push(
          table(
            t.story.phaseHead,
            storyPhaseRows(s, dec, t).map((p) => [`${p.severity ? `${sev(p.severity)} · ` : ''}${p.label}`, span(t, p.first, p.last), n(p.steps), p.marks]),
          ),
        )
        for (const l of storyDecisionTexts(dec, t)) body.push(caption(l))
        const gaps = storyOwnGaps(s, t)
        if (gaps.length) body.push(caption(`${t.story.stops} ${gaps.join(' ')}`))
      }
    }
    if (d.storiesLeft) body.push(caption(t.story.left(d.storiesLeft, settings.onlyReviewed)))
    if (d.storiesDismissed) body.push(caption(t.story.dismissed(d.storiesDismissed)))
  }

  if (d.chains.length) {
    body.push(heading(t.section.chains, 1))
    body.push(para(t.chain.introDocx))
    if (settings.includeGraphs && d.chains.length > 1) body.push(caption(`${t.chain.shared}: ${d.campaignInsights.length ? d.campaignInsights.join(' · ') : t.chain.nothingShared}.`))
    for (const c of d.chains) {
      const r = d.reviews[c.id]
      body.push(heading(`${c.identityLabel}: ${c.seed.subject || t.chain.fallbackTitle}`, 2))
      body.push(
        para([
          sevRun(chainSeverity(c, r)),
          ` · ${r?.verdict ? t.chain.verdict(t.chainVerdict[r.verdict] ?? r.verdict) : t.chain.noVerdict} · ${span(t, c.start, c.end)} · ${t.chain.stepCount(c.steps.length)} · ${t.chain.score(c.score)}`,
        ]),
      )
      body.push(
        caption(
          `${t.chain.seed(c.seed.source === 'events' ? 'event' : 'mail', c.seed.subject, c.seed.fromAddr ?? '', t.ts(c.seed.ts), c.seed.risk)} · ${t.chain.ties(c.artifactLinks)}${c.entities.attackerAddresses.length ? ` · ${t.chain.attacker} ${c.entities.attackerAddresses.join(', ')}` : ''}${c.entities.ips.length ? ` · ${t.chain.ips} ${c.entities.ips.join(', ')}` : ''}${c.entities.hosts.length ? ` · ${t.chain.hosts} ${c.entities.hosts.join(', ')}` : ''}`,
        ),
      )
      if (r?.narrative) {
        body.push(markdown(r.narrative))
        if (r.narrativeBy === 'ai') body.push(caption(t.chain.narrativeByAiDocx))
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
          t.chain.head,
          printed.map((f) => {
            const st = f.step
            return [
              f.n > 1 && f.tsEnd !== f.ts ? `${t.ts(f.ts)}\n${t.to} ${t.ts(f.tsEnd)}` : t.ts(f.ts),
              f.n > 1 && f.offsetEnd !== f.offsetMin ? `${offset(f.offsetMin)} → ${offset(f.offsetEnd)} ${t.chain.minutes}` : `${offset(f.offsetMin)} ${t.chain.minutes}`,
              t.lane[st.kind === 'mail' ? 'mail' : st.origin === 'm365' ? 'm365' : 'host'],
              `${st.title}${f.n > 1 ? ` ×${f.n}` : st.count > 1 ? ` ×${st.count}` : ''}${st.computer || st.ipAddress ? `\n${[st.computer, st.ipAddress].filter(Boolean).join(' · ')}` : ''}`,
              [...st.artifacts, ...st.findings.map((y) => y.title)].join('; '),
            ]
          }),
        ),
      )
      if (left || hidden) body.push(caption(`${left ? t.chain.left(left) : ''}${left && hidden ? ' · ' : ''}${hidden ? t.chain.hidden(hidden, settings.chainDetail) : ''}.`))
      const members = d.membersOf.get(c.id) ?? []
      if (members.length) {
        body.push(caption(`${t.chain.members(members.length)}.`))
        body.push(ruleTable(members))
      }
      if (r?.by === 'ai' && r.aiReason) body.push(caption(t.chain.triage(r.aiReason)))
    }
    if (settings.includeGraphs) body.push(caption(t.chain.graphsInHtml))
  }

  body.push(heading(t.section.incidents, 1))
  if (d.incidents.length) {
    body.push(para(t.incident.introDocx))
    for (const i of d.incidents) {
      body.push(heading(i.title, 2))
      body.push(para([sevRun(i.severity), ` · ${t.status[i.status] ?? i.status} · ${t.incident.subtitle(i.about)} · ${span(t, i.ts, i.tsEnd)} · ${t.incident.rows(i.refs.length)}`]))
      const ents = Object.entries(i.entities).slice(0, 6)
      if (ents.length) body.push(caption(ents.map(([k, v]) => `${k}=${String(v)}`).join(' · ')))
      if (i.lead.notes) {
        body.push(markdown(i.lead.notes))
        if (i.lead.notesBy === 'ai') body.push(caption(t.incident.noteByAiDocx))
      }
      checkOf(`incident:${i.lead.id ?? i.title}`)
      if (i.lead.decidedBy === 'ai' && i.lead.aiReason) body.push(caption(t.chain.triage(i.lead.aiReason)))
      body.push(ruleTable(i.findings, i.entities))
    }
  } else body.push(para(t.incident.none))

  if (settings.includeEvidence) {
    body.push(heading(t.section.evidence, 1))
    if (d.evidence.length)
      body.push(
        table(
          t.evidence.head,
          d.evidence.map((e) => {
            const issue = e.kind === 'package' ? packageCoverageIssues(e, t).join('; ') : evidenceIssue(e, t)
            return [
              e.name,
              e.format || e.kind,
              t.bytes(e.size),
              n(e.count),
              e.sha256Client ?? '',
              t.integrity[e.integrity] ?? e.integrity,
              issue ? t.evidence.incomplete(issue) : t.evidence.complete,
              t.ts(e.addedAt),
            ]
          }),
        ),
      )
    else body.push(para(t.evidence.none))
    const packages = d.evidence.filter((e) => e.kind === 'package')
    if (packages.length) {
      body.push(heading(t.evidence.packages, 3))
      body.push(
        table(
          t.evidence.packageHead,
          packages.map((e) => [e.name, packageCoverageIssues(e, t).join('; ') || t.evidence.noIssues]),
        ),
      )
    }
  }

  const relationships = (d.relationships ?? []).filter((r) => r.status === 'accepted' && r.includeInReport)
  if (relationships.length) {
    body.push(heading(t.section.relationships, 1))
    body.push(para(t.relationship.intro))
    for (const r of relationships) {
      body.push(heading(`${r.sourceLabel} → ${r.relation} → ${r.targetLabel}`, 3))
      body.push(para(`${r.reason} (${r.confidence})`))
      if (r.notes) body.push(markdown(r.notes))
      if (Object.keys(r.aliases ?? {}).length) body.push(para(t.relationship.aliases(JSON.stringify(r.aliases))))
      if (r.references.length) body.push(table(t.relationship.head, referenceRows(r, t)))
    }
  }

  if (settings.includeIocs) {
    const ind = indicatorAppendix(d, t)
    body.push(heading(t.section.iocs, 1))
    if (ind.rows.length) {
      body.push(para(t.indicator.intro))
      body.push(
        table(
          t.indicator.head,
          ind.rows.map((r) => indicatorRow(r, t)),
        ),
      )
      if (ind.left) body.push(caption(t.indicator.left(ind.left, MAX_INDICATORS)))
    } else body.push(para(t.indicator.none))
  }
  const techniques = techniqueTable(d, t)
  if (techniques.length) {
    body.push(heading(t.section.techniques, 1))
    body.push(para(t.technique.intro))
    body.push(
      table(
        t.technique.head,
        techniques.map((r) => techniqueRow(r, t)),
      ),
    )
  }

  if (settings.includeTimeline && d.timeline.length) {
    body.push(heading(t.section.timeline, 1))
    body.push(
      table(
        t.timeline.head,
        d.timeline.map((e) => [e.untimed ? t.noEventTime : t.ts(e.ts), e.text, e.link ? `${e.link.source} ${e.link.label ?? e.link.id}` : '']),
      ),
    )
  }
  if (settings.includeTasks && d.tasks.length) {
    body.push(heading(t.section.tasks, 1))
    for (const e of d.tasks) body.push(bullet([`${e.text} `, { text: `· ${t.ts(e.updatedAt)}`, color: '8A95A3' }], e.done ? '☑' : '☐'))
  }
  if (settings.includeNotes && d.notes.length) {
    body.push(heading(t.section.notes, 1))
    for (const note of d.notes) {
      body.push(caption(t.ts(note.createdAt)))
      body.push(markdown(note.text))
    }
  }

  body.push(heading(t.section.findings, 1))
  if (d.findings.length) {
    body.push(para(t.finding.intro))
    body.push(ruleTable(d.findings))
    if (d.findings.some((f) => d.ruleAuthors?.[f.ruleId])) body.push(caption(t.finding.authors))
  } else body.push(para(t.finding.none))

  if (d.ai && d.ai.runs) {
    const a = aiTexts(d.ai, t)
    body.push(heading(t.section.ai, 1))
    body.push(para(a.intro))
    body.push(caption(a.facts))
    body.push(a.rows.length ? table(t.ai.head, a.rows) : para(a.none))
    body.push(caption(a.decisions))
    body.push(caption(a.ledger))
    body.push(caption(a.ledgerScope))
  }

  body.push(heading(t.section.method, 1))
  body.push(heading(t.produced.title, 2))
  for (const l of producedLines(d, verdict, t)) body.push(bullet(l))
  body.push(heading(t.limit.title, 2))
  for (const l of limitLines(d, confidence, t)) body.push(bullet(l))

  body.push(heading(t.section.settings, 1))
  body.push(
    caption(
      t.settingsLine({
        domains: kase.settings.internalDomains.join(', '),
        vips: kase.settings.vipNames.join(', '),
        start: kase.settings.businessHours.start,
        end: kase.settings.businessHours.end,
        tz: kase.settings.businessHours.tz,
        lookups: d.iocsChecked ?? 0,
        floor: settings.minSeverity,
        onlyReviewed: settings.onlyReviewed,
        fp: settings.includeFp,
        detail: settings.chainDetail,
      }),
    ),
  )

  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><w:body>${body.join('')}<w:sectPr><w:headerReference w:type="default" r:id="rIdHeader"/><w:footerReference w:type="default" r:id="rIdFooter"/><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1134" w:header="567" w:footer="567" w:gutter="0"/></w:sectPr></w:body></w:document>`

  /** One line per rule: its severity, title and id with what its measure says, whether its rows bear it out, when, and what it matched. */
  function ruleTable(findings: ReportData['findings'], said: Record<string, string> = {}): string {
    return table(
      t.finding.ruleHeadDocx,
      groupByRule(findings, said).map((g) => {
        const measure = measureWords(d.measures?.[g.ruleId], t)
        const claim = claimLine(g.ids, d.claims, t)
        return [
          g.severity !== g.ruleSeverity ? `${sev(g.severity)}\n${t.finding.ruleSeverity(g.ruleSeverity)}` : sev(g.severity),
          `${g.title}\n${g.ruleId}${d.ruleAuthors?.[g.ruleId] ? ` · ${t.finding.by(d.ruleAuthors[g.ruleId])}` : ''}${measure ? ` · ${measure.lead ? measure.text.toUpperCase() : measure.text}` : ''}${g.escalations.length ? ` · ${g.escalations.slice(0, 2).join(' · ')}` : ''}${
            claim
              ? `\n${claim.word}${claim.where ? ` · ${claim.where}${claim.more ? ` ${t.andMore(claim.more)}` : ''}` : ''}${claim.status !== 'verified' && claim.reasons.length ? `: ${claim.reasons.join(' ')}` : ''}`
              : ''
          }`,
          `${n(g.findings)} · ${n(g.rows)}`,
          span(t, g.first, g.last),
          Object.entries(g.statuses)
            .map(([s, c]) => `${t.status[s] ?? s}${c > 1 ? ` ×${c}` : ''}`)
            .join(', '),
          g.attack.slice(0, 4).join(' '),
          g.values.length
            ? `${g.values
                .slice(0, 6)
                .map((v) => (v.length > 90 ? v.slice(0, 89) + '…' : v))
                .join('\n')}${g.values.length > 6 ? `\n${t.plusMore(g.values.length - 6)}` : ''}`
            : '–',
        ]
      }),
    )
  }
}

/** The styles of the document; the default run is in the report's language, so Word checks the spelling of the right one. */
const styles = (lang: string) => `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="Calibri" w:cs="Calibri"/><w:color w:val="0F1720"/><w:sz w:val="20"/><w:szCs w:val="20"/><w:lang w:val="${lang}"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="100" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
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
  const t = reportText(d.settings.language)
  const at = new Date(d.generatedAt ?? Date.now())
  const created = at.toISOString().replace(/\.\d{3}Z$/, 'Z')
  const verdict = computeVerdict(d, t)
  const firm = d.settings.branding.firmName.trim()
  const logo = logoImage(d.settings.branding.logo)
  const title = firm ? `${firm} · ${d.kase.name}` : t.cover.title(d.kase.name)
  // the handling marking at the top of every page, when the analyst set one
  const header = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:pPr><w:pStyle w:val="Header"/><w:jc w:val="center"/></w:pPr>${run(markingLine(d.settings.client), { bold: true })}</w:p></w:hdr>`
  const footer = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:pPr><w:pStyle w:val="Footer"/></w:pPr>${run(t.docx.footer(firm || 'REMN', d.kase.name, verdict.label, d.issue?.status === 'draft'))}<w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>1</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p></w:ftr>`
  return zipStore(
    [
      {
        name: '[Content_Types].xml',
        data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>${logo ? `<Default Extension="${logo.ext}" ContentType="${logo.mime}"/>` : ''}<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/><Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>`,
      },
      {
        name: '_rels/.rels',
        data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>`,
      },
      {
        name: 'docProps/core.xml',
        data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>${x(title)}</dc:title>${d.kase.analyst ? `<dc:creator>${x(d.kase.analyst)}</dc:creator>` : ''}<dcterms:created xsi:type="dcterms:W3CDTF">${created}</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">${created}</dcterms:modified></cp:coreProperties>`,
      },
      {
        name: 'docProps/app.xml',
        data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>REMN</Application></Properties>`,
      },
      {
        name: 'word/_rels/document.xml.rels',
        data: `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rIdHeader" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/><Relationship Id="rIdFooter" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/>${logo ? `<Relationship Id="rIdLogo" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/logo.${logo.ext}"/>` : ''}</Relationships>`,
      },
      { name: 'word/document.xml', data: reportDocumentXml(d) },
      { name: 'word/styles.xml', data: styles(t.wordLang) },
      { name: 'word/header1.xml', data: header },
      { name: 'word/footer1.xml', data: footer },
      ...(logo ? [{ name: `word/media/logo.${logo.ext}`, data: logo.bytes }] : []),
    ],
    at,
  )
}
