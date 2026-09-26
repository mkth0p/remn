/**
 * A story's timeline to take away (docs/stories.md "Decisions"): CSV and JSON through the app's
 * export helpers (util/export.ts, whose CSV neutralises a cell a spreadsheet would read as a
 * formula), and Markdown to paste into a report. Each carries the story as the page shows it, the
 * analyst's decisions with it. What the records wrote (titles, names, reasons) is data: in Markdown
 * it is escaped so it cannot become a link, markup or a column of its own.
 */
import { downloadBlob, exportCsv, exportJson, toCsv } from '../util/export'
import { PHASE_LABEL, type StoryStep } from './stories'
import { STORY_VERDICT_LABEL, type StoryView } from './storyDecisions'

const TIE_WORDS: Record<StoryStep['tie']['kind'], string> = {
  flag: 'flagged',
  chain: 'phishing chain',
  session: 'same session',
  hop: 'same way in',
  process: 'process tree',
  address: 'same source',
  identity: 'same person',
}

/** The columns of a story's timeline, in order. */
export const TIMELINE_COLUMNS = ['timeUtc', 'host', 'account', 'phase', 'title', 'tie', 'confidence', 'findings', 'refs', 'analyst'] as const
export type TimelineRow = Record<(typeof TIMELINE_COLUMNS)[number], string>

const iso = (t: number) => new Date(t).toISOString()

/** One row per step of the story as the page shows it, the analyst's call on the step last. */
export function timelineRows(view: StoryView, labels: Map<string, string>): TimelineRow[] {
  return view.story.steps.map((s) => {
    const call = view.steps.get(s.id)
    return {
      timeUtc: iso(s.ts),
      host: s.host ?? '',
      account: s.accounts.map((a) => labels.get(a) ?? a).join(', '),
      phase: s.phase ? (PHASE_LABEL[s.phase] ?? s.phase) : '',
      title: s.title,
      tie: `${TIE_WORDS[s.tie.kind] ?? s.tie.kind}: ${s.tie.basis}`,
      confidence: s.tie.confidence,
      findings: s.findings.map((f) => `${f.title} (${f.severity})`).join('; '),
      refs: s.refs.join(' '),
      analyst: call ? `${call.verdict}${call.reason ? `: ${call.reason}` : ''}` : '',
    }
  })
}

export const timelineCsv = (view: StoryView, labels: Map<string, string>) => toCsv(timelineRows(view, labels), [...TIMELINE_COLUMNS])

/** The story and its steps as data, with the analyst's decisions. */
export function timelineJson(view: StoryView, labels: Map<string, string>, exportedAt = Date.now()) {
  const s = view.story
  const rows = timelineRows(view, labels)
  return {
    format: 'remn-story-timeline',
    exportedAt: iso(exportedAt),
    story: {
      id: s.id,
      kind: s.kind,
      subject: s.subject.label,
      organisation: s.subject.org,
      title: s.title,
      headline: s.headline,
      severity: s.severity,
      score: s.score,
      confidence: s.confidence,
      start: iso(s.start),
      end: iso(s.end),
      phases: s.phases.map((p) => p.label),
      hosts: s.hosts,
      attackerAddresses: s.attackerAddresses,
      part: view.part === 'split' ? 'second part of a split story' : view.split?.applied ? 'first part of a split story' : null,
    },
    decision: view.call ? { verdict: view.call.verdict, reason: view.call.reason, decidedAt: iso(view.call.decidedAt) } : null,
    merged: view.merged.map((m) => ({ story: m.story.title, reason: m.merge.reason, decidedAt: iso(m.merge.decidedAt) })),
    split: view.split?.applied ? { at: view.split.title, ts: iso(view.split.ts), reason: view.split.reason } : null,
    recordsOut: view.out.map((o) => ({ step: o.out.title, records: o.out.rows.length, stillHeld: o.found, reason: o.out.reason })),
    steps: s.steps.map((st, i) => {
      const call = view.steps.get(st.id)
      return {
        time: rows[i].timeUtc,
        timeEnd: iso(st.tsEnd),
        host: st.host,
        ip: st.ip,
        accounts: st.accounts.map((a) => labels.get(a) ?? a),
        phase: rows[i].phase || null,
        title: st.title,
        tie: { kind: st.tie.kind, basis: st.tie.basis, confidence: st.tie.confidence },
        findings: st.findings.map((f) => ({ ruleId: f.ruleId, title: f.title, severity: f.severity, key: f.key })),
        records: st.count,
        refs: st.refs,
        analyst: call ? { verdict: call.verdict, reason: call.reason, decidedAt: iso(call.decidedAt) } : null,
        order: i + 1,
      }
    }),
  }
}

/**
 * Text from the records made plain for Markdown: whitespace folded, markup characters escaped (a
 * link, an image, emphasis, HTML, a table cell's end), and addresses defanged so no link appears.
 */
export function mdText(v: string): string {
  return v
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/[\\`*_[\]<>|~&#!]/g, (c) => `\\${c}`)
    .replace(/\bhttp(s?):\/\//gi, 'hxxp$1://')
    .replace(/\bftp:\/\//gi, 'fxp://')
    .replace(/\bwww\./gi, 'www[.]')
}

const mdTime = (t: number) => iso(t).slice(0, 19).replace('T', ' ')

/** The story's timeline as Markdown to paste into a report: a few lines on the story and its decisions, then a table of its steps. */
export function timelineMarkdown(view: StoryView, labels: Map<string, string>): string {
  const s = view.story
  const lines = [
    `### Story: ${mdText(s.title)}${view.part === 'split' ? ' (second part)' : ''}`,
    '',
    mdText(s.headline),
    '',
    `- Severity: ${s.severity} · score ${s.score} · ${s.steps.length} steps, ${s.records} records · ${mdTime(s.start)} to ${mdTime(s.end)} UTC`,
  ]
  if (s.phases.length) lines.push(`- Phases: ${s.phases.map((p) => mdText(p.label)).join(' → ')}`)
  if (view.call) lines.push(`- Analyst's decision: ${STORY_VERDICT_LABEL[view.call.verdict]}${view.call.reason ? `: ${mdText(view.call.reason)}` : ''}`)
  for (const m of view.merged) lines.push(`- Merged by the analyst: the story of ${mdText(m.story.title)}: ${mdText(m.merge.reason)}`)
  if (view.split?.applied) lines.push(`- Split by the analyst at "${mdText(view.split.title)}" (${mdTime(view.split.ts)} UTC): ${mdText(view.split.reason)}`)
  for (const o of view.out.filter((x) => x.found)) lines.push(`- Taken out by the analyst: ${mdText(o.out.title)} (${o.found} record(s)): ${mdText(o.out.reason)}`)
  const disputed = s.steps.filter((st) => view.steps.get(st.id)?.verdict === 'disputed').length
  if (disputed) lines.push(`- ${disputed} step(s) disputed by the analyst are struck out and left out of the phases and severity.`)
  lines.push('', '| Time (UTC) | Host | Account | Phase | Step | Tie | Findings | Records | Analyst |', '|---|---|---|---|---|---|---|---|---|')
  timelineRows(view, labels).forEach((r, i) => {
    const st = s.steps[i]
    const title = mdText(r.title)
    const refs = st.refs.slice(0, 3).join(' ') + (st.refs.length > 3 ? ` +${st.refs.length - 3}` : '')
    const tie = `${TIE_WORDS[st.tie.kind] ?? st.tie.kind} (${st.tie.confidence})`
    const step = view.steps.get(st.id)?.verdict === 'disputed' ? `~~${title}~~` : title
    lines.push(`| ${mdTime(st.ts)} | ${mdText(r.host)} | ${mdText(r.account)} | ${mdText(r.phase)} | ${step} | ${mdText(tie)} | ${mdText(r.findings)} | ${mdText(refs)} | ${mdText(r.analyst)} |`)
  })
  return lines.join('\n') + '\n'
}

const fileName = (view: StoryView, ext: string) => `story-${view.story.title.replace(/[^a-z0-9_.-]+/gi, '_').slice(0, 60)}${view.part === 'split' ? '-part2' : ''}-timeline.${ext}`

/** Save the story's timeline as a file. */
export function downloadTimeline(kind: 'csv' | 'json' | 'md', view: StoryView, labels: Map<string, string>): void {
  if (kind === 'csv') exportCsv(fileName(view, 'csv'), timelineRows(view, labels), [...TIMELINE_COLUMNS])
  else if (kind === 'json') exportJson(fileName(view, 'json'), timelineJson(view, labels))
  else downloadBlob(fileName(view, 'md'), new Blob([timelineMarkdown(view, labels)], { type: 'text/markdown;charset=utf-8' }))
}
