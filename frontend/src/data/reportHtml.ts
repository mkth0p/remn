import type { Case, CaseNote, Evidence, Finding, Ioc } from '../db/schema'
import type { Chain, ChainStep } from './chains'
import type { ChainReview, ReportSettings } from './review'
import { chainSeverity, effectiveSeverity, stepVisible } from './review'
import type { Incident } from '../rules/incidents'
import { defang, escapeHtml, fmtBytes, fmtNum, fmtTs, renderMarkdown } from '../util/format'

/**
 * The printed report: one self-contained HTML file in REMN's own look (wordmark, accent rule,
 * numbered sections, severity pills, score meters, swimlane pictures), laid out for A4 and the
 * browser's print-to-PDF. Every string from the case goes through escapeHtml; markdown fields go
 * through renderMarkdown; the graph pictures are PNG data URLs this app drew itself.
 */

export interface ReportData {
  kase: Case
  generatedAt: number
  settings: ReportSettings
  summary: string
  evidence: Evidence[]
  chains: Chain[]
  reviews: Record<string, ChainReview>
  /** findings linked to each chain (the chain's own row excluded) */
  membersOf: Map<string, Finding[]>
  /** PNG data URLs by chain id, plus 'campaign' */
  graphs: Record<string, string>
  campaignInsights: string[]
  /** incidents other than chains */
  incidents: Incident[]
  /** every finding the report carries */
  findings: Finding[]
  iocs: Ioc[]
  timeline: CaseNote[]
  tasks: CaseNote[]
  notes: CaseNote[]
  undecided: number
  /** base64 woff2 of the display face for the wordmark, when it could be loaded */
  fontData?: string
}

const ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const
const STATUS_WORD: Record<string, string> = { new: 'not reviewed', reviewed: 'reviewed', escalated: 'confirmed', false_positive: 'false positive' }
const h = escapeHtml

const CSS = `
:root{--accent:#1b7f66;--accent-dim:rgba(27,127,102,.10);--ink:#111820;--ink-2:#5b6876;--ink-3:#8a95a3;--line:#e3e6ea;--line-2:#cfd5dc;--surface:#fff;--surface-2:#f8f9fa;--surface-3:#eef1f4;
--critical:#a8231f;--high:#d1403f;--medium:#d9822b;--low:#2f6fdb;--info:#8a95a3;
--critical-bg:rgba(168,35,31,.10);--high-bg:rgba(209,64,63,.10);--medium-bg:rgba(217,130,43,.12);--low-bg:rgba(47,111,219,.10);--info-bg:rgba(138,149,163,.14);
--sans:'Inter','Segoe UI',system-ui,-apple-system,sans-serif;--mono:'Cascadia Code','JetBrains Mono',Consolas,monospace;--display:'Gulax','Segoe UI',system-ui,sans-serif}
*{box-sizing:border-box}
html{-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{font:12.5px/1.55 var(--sans);color:var(--ink);background:var(--surface);margin:0;padding:34px 40px 60px}
@page{size:A4;margin:16mm 14mm 18mm}
@media print{body{padding:0}.no-print{display:none}.cover-page{break-after:page}}
a{color:var(--accent);text-decoration:none}
code,.mono{font-family:var(--mono);font-size:11px}
.muted{color:var(--ink-2)}.dim{color:var(--ink-3)}
/* cover */
.cover{border-top:5px solid var(--accent);padding-top:18px;margin-bottom:26px}
.brand{display:flex;align-items:baseline;gap:14px}
.wordmark{font-family:var(--display);font-size:30px;letter-spacing:.22em;color:var(--ink);line-height:1}
.tag{font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--ink-3)}
.cover h1{font-size:27px;font-weight:600;letter-spacing:-.01em;margin:22px 0 6px;line-height:1.15}
.cover .meta{font-size:12px;color:var(--ink-2)}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:22px 0 12px}
.kpi{border:1px solid var(--line);border-radius:8px;padding:10px 12px;background:var(--surface-2)}
.kpi .v{font-size:22px;font-weight:600;line-height:1.1;font-family:var(--mono)}
.kpi .l{font-size:10.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--ink-3);margin-top:3px}
.sevbar{display:flex;height:10px;border-radius:5px;overflow:hidden;background:var(--surface-3);margin:8px 0 6px}
.sevbar span{display:block;height:100%}
.legend{display:flex;gap:14px;font-size:11px;color:var(--ink-2);flex-wrap:wrap}
.legend i{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:5px;vertical-align:middle}
.decisions{margin-top:10px;font-size:12px;color:var(--ink-2)}
.decisions b{color:var(--ink)}
/* contents */
.toc{columns:2;column-gap:28px;font-size:12px;margin:0 0 8px;padding:0;list-style:none}
.toc li{margin:0 0 4px;break-inside:avoid}
.toc .n{font-family:var(--mono);color:var(--accent);margin-right:8px}
/* sections */
.s{margin-top:30px;break-inside:auto}
.s-head{display:flex;align-items:baseline;gap:12px;margin-bottom:12px;break-after:avoid;break-inside:avoid}
.s-head .num{font-family:var(--mono);font-size:11px;color:var(--accent);letter-spacing:.08em}
.s-head h2{font-size:17px;font-weight:600;margin:0;letter-spacing:-.01em}
.s-head .rule{flex:1;height:1px;background:var(--line);transform:translateY(-4px)}
.s-head .count{font-family:var(--mono);font-size:11px;color:var(--ink-3)}
.intro{font-size:12px;color:var(--ink-2);margin:0 0 10px}
/* pills */
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:10.5px;font-weight:600;letter-spacing:.02em;white-space:nowrap;line-height:1.6;vertical-align:middle}
.pill.critical{color:var(--critical);background:var(--critical-bg)}.pill.high{color:var(--high);background:var(--high-bg)}.pill.medium{color:var(--medium);background:var(--medium-bg)}.pill.low{color:var(--low);background:var(--low-bg)}.pill.info{color:var(--info);background:var(--info-bg)}
.pill.st-escalated{color:var(--critical);background:var(--critical-bg)}.pill.st-reviewed{color:var(--accent);background:var(--accent-dim)}.pill.st-false_positive{color:var(--ink-3);background:var(--info-bg)}.pill.st-new{color:var(--ink-2);background:var(--surface-3)}
.pill.verdict-confirmed{color:#fff;background:var(--critical)}.pill.verdict-unsure{color:#fff;background:var(--medium)}.pill.verdict-benign{color:#fff;background:var(--accent)}
.chip{display:inline-block;border:1px solid var(--line-2);border-radius:4px;padding:0 5px;font-family:var(--mono);font-size:10px;color:var(--ink-2);margin:0 3px 2px 0}
/* cards */
.card{border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:0 0 14px;break-inside:auto;background:var(--surface)}
.card.chain{border-left:4px solid var(--accent)}
.card.inc{border-left:4px solid var(--line-2);break-inside:avoid}
.card-head,.card-meta,.narr{break-inside:avoid}
.card-head{break-after:avoid}
.card.inc.critical{border-left-color:var(--critical)}.card.inc.high{border-left-color:var(--high)}.card.inc.medium{border-left-color:var(--medium)}.card.inc.low{border-left-color:var(--low)}
.card-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.card-head h3{font-size:14.5px;font-weight:600;margin:0;flex:1;min-width:200px}
.card-meta{font-size:11.5px;color:var(--ink-2);margin:6px 0 8px}
.meter{display:inline-flex;align-items:center;gap:8px;font-family:var(--mono);font-size:11px;color:var(--ink-2)}
.meter .bar{display:flex;width:120px;height:8px;border-radius:4px;overflow:hidden;background:var(--surface-3)}
.meter .bar span{display:block;height:100%}
.narr{border-left:3px solid var(--accent);background:var(--surface-2);padding:8px 12px;margin:8px 0 10px;border-radius:0 6px 6px 0;font-size:12.5px}
.narr p{margin:0 0 6px}.narr p:last-child{margin:0}
.cap{font-size:10.5px;color:var(--ink-3);margin-top:4px}
.note{background:var(--surface-2);padding:8px 12px;border-radius:6px;margin:6px 0 8px;font-size:12.5px}
.note p{margin:0 0 6px}.note p:last-child{margin:0}
figure{margin:8px 0 10px;break-inside:avoid}
figure img{width:100%;max-height:120mm;object-fit:contain;border:1px solid var(--line);border-radius:6px}
figure figcaption{font-size:10.5px;color:var(--ink-3);margin-top:3px}
/* tables */
table{border-collapse:collapse;width:100%;font-size:11.5px;margin:4px 0 8px}
th{font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:var(--ink-3);text-align:left;font-weight:600;padding:5px 8px;border-bottom:1px solid var(--line-2);background:var(--surface-2)}
td{padding:5px 8px;border-bottom:1px solid var(--line);vertical-align:top}
tr{break-inside:avoid}
thead{display:table-header-group}
td .sub{display:block;font-size:10.5px;color:var(--ink-3)}
.lane{display:inline-block;width:8px;height:8px;border-radius:2px;margin-right:6px;vertical-align:middle}
.lane.mail{background:var(--accent)}.lane.m365{background:var(--low)}.lane.host{background:var(--ink-3)}
.nowrap{white-space:nowrap}
/* timeline */
.tl{list-style:none;margin:0;padding:0 0 0 18px;border-left:2px solid var(--line)}
.tl li{position:relative;margin:0 0 10px;padding-left:12px;page-break-inside:avoid}
.tl li::before{content:'';position:absolute;left:-24px;top:5px;width:10px;height:10px;border-radius:50%;background:var(--ink-3);border:2px solid #fff;box-shadow:0 0 0 1px var(--line-2)}
.tl li.critical::before{background:var(--critical)}.tl li.high::before{background:var(--high)}.tl li.medium::before{background:var(--medium)}.tl li.low::before{background:var(--low)}
.tl .t{font-family:var(--mono);font-size:10.5px;color:var(--ink-3)}
.tasks li{list-style:none;margin:0 0 4px;padding:0}
.tasks .box{display:inline-block;width:12px;height:12px;border:1px solid var(--line-2);border-radius:3px;margin-right:8px;vertical-align:-2px;text-align:center;font-size:9px;line-height:11px}
.tasks .done{color:var(--ink-3);text-decoration:line-through}
.notes .n{border-bottom:1px solid var(--line);padding:6px 0 8px;margin:0 0 6px}
.notes .n:last-child{border:0}
.settings{font-family:var(--mono);font-size:11px;color:var(--ink-2);background:var(--surface-2);padding:8px 12px;border-radius:6px}
.foot{margin-top:40px;border-top:1px solid var(--line);padding-top:6px;font-size:10px;color:var(--ink-3);display:flex;justify-content:space-between}
.foot .wm{font-family:var(--display);letter-spacing:.2em;color:var(--ink-2)}
.empty{color:var(--ink-3);font-size:12px}
`

const pill = (sev: string) => `<span class="pill ${ORDER.includes(sev as never) ? sev : 'info'}">${h(sev)}</span>`
const statusPill = (s: string) => `<span class="pill st-${h(s)}">${h(STATUS_WORD[s] ?? s)}</span>`
const verdictPill = (v?: string) => (v ? `<span class="pill verdict-${h(v)}">${h(v)}</span>` : '')
const rows = (xs: string[][]) => xs.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('')
/** a table whose header row repeats on every printed page */
const table = (head: string[], body: string[][]) => `<table><thead><tr>${head.map((x) => `<th>${x}</th>`).join('')}</tr></thead><tbody>${rows(body)}</tbody></table>`

/** The most step rows a chain prints; the rest is summarised in one line. */
export const MAX_STEP_ROWS = 60

export interface FoldedStep {
  step: ChainStep
  /** rows folded into this one (the same step repeating in a run) */
  n: number
  ts: number
  tsEnd: number
  offsetMin: number
  offsetEnd: number
}

/** Consecutive steps that say the same thing (title, source, machine, ties) print as one row with a count and a time span. */
export function foldSteps(steps: ChainStep[]): FoldedStep[] {
  const key = (s: ChainStep) => [s.title, s.kind, s.origin ?? '', s.computer ?? '', s.ipAddress ?? '', [...s.artifacts, ...s.findings.map((f) => f.title)].join(';')].join('')
  const out: FoldedStep[] = []
  for (const s of steps) {
    const last = out[out.length - 1]
    if (last && key(last.step) === key(s)) {
      last.n += 1
      last.tsEnd = Math.max(last.tsEnd, s.tsEnd || s.ts)
      last.offsetEnd = Math.max(last.offsetEnd, s.offsetMin)
    } else out.push({ step: s, n: 1, ts: s.ts, tsEnd: s.tsEnd || s.ts, offsetMin: s.offsetMin, offsetEnd: s.offsetMin })
  }
  return out
}
/** only a PNG data URL this app produced itself is embedded */
const img = (src: string | undefined, alt: string, caption?: string) =>
  src && /^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(src) ? `<figure><img src="${src}" alt="${h(alt)}">${caption ? `<figcaption>${h(caption)}</figcaption>` : ''}</figure>` : ''
const md = (text: string) => renderMarkdown(text)
const n = (x: number) => fmtNum(x)

function meter(c: Chain): string {
  const b = c.scoreBreakdown
  const parts: [string, number][] = b
    ? [
        ['seed', b.seed],
        ['links', b.links],
        ['steps', b.steps],
        ['findings', b.findings],
        ['sources', b.sources],
      ]
    : [['score', c.score]]
  const total = Math.max(
    1,
    parts.reduce((s, [, v]) => s + v, 0),
  )
  const colours = ['#1b7f66', '#2fbf8f', '#2f6fdb', '#d9822b', '#8a95a3']
  const segs = parts.map(([k, v], i) => `<span title="${h(k)} ${v}" style="width:${((v / total) * 100).toFixed(1)}%;background:${colours[i % colours.length]}"></span>`).join('')
  return `<span class="meter" title="${h(parts.map(([k, v]) => `${k} ${v}`).join(' · '))}"><span class="bar">${segs}</span><span>score ${c.score}${b?.cap ? ` (capped ${b.cap})` : ''}</span></span>`
}

function chainCard(c: Chain, d: ReportData): string {
  const r = d.reviews[c.id]
  const visible = c.steps.filter((s) => stepVisible(s, d.settings.chainDetail))
  const hidden = c.steps.length - visible.length
  const folded = foldSteps(visible)
  const printed = folded.slice(0, MAX_STEP_ROWS)
  const left = folded.length - printed.length
  const members = d.membersOf.get(c.id) ?? []
  const offset = (f: FoldedStep) =>
    f.n > 1 && f.offsetEnd !== f.offsetMin
      ? `${f.offsetMin >= 0 ? '+' : ''}${Math.round(f.offsetMin)} → ${f.offsetEnd >= 0 ? '+' : ''}${Math.round(f.offsetEnd)} min`
      : `${f.offsetMin >= 0 ? '+' : ''}${Math.round(f.offsetMin)} min`
  const when = (f: FoldedStep) => (f.n > 1 && f.tsEnd !== f.ts ? `${fmtTs(f.ts)}<span class="sub">to ${fmtTs(f.tsEnd)}</span>` : fmtTs(f.ts))
  const narrative = r?.narrative
    ? `<div class="narr">${md(r.narrative)}</div>${r.narrativeBy === 'ai' ? '<div class="cap">narrative drafted by the model during triage</div>' : ''}`
    : `<div class="narr"><p>${h(c.summary)}</p></div>`
  return `<div class="card chain">
<div class="card-head">${pill(chainSeverity(c, r))}<h3>${h(c.identityLabel)}</h3>${verdictPill(r?.verdict)}${meter(c)}</div>
<div class="card-meta">Seed mail “${h(c.seed.subject)}” from <code>${h(c.seed.fromAddr ?? '')}</code> at ${fmtTs(c.seed.ts)} (risk ${c.seed.risk}) · ${c.steps.length} steps from ${fmtTs(c.start)} to ${fmtTs(c.end)} · ${c.artifactLinks} tie(s) to the mail${c.entities.attackerAddresses.length ? ` · attacker <code>${h(c.entities.attackerAddresses.join(', '))}</code>` : ''}${c.entities.ips.length ? ` · IPs <code>${h(c.entities.ips.join(', '))}</code>` : ''}${c.entities.hosts.length ? ` · hosts <code>${h(c.entities.hosts.join(', '))}</code>` : ''}</div>
${narrative}
${d.settings.includeGraphs ? img(d.graphs[c.id], `graph of the chain for ${c.identityLabel}`, 'Steps by lane and time: diamond = seed mail, box = step (size = weight, colour = worst finding), grey dot = folded routine steps, green edges = ties to the mail.') : ''}
${table(
  ['time (UTC)', 'offset', 'source', 'step', 'ties to the mail / findings'],
  printed.map((f) => {
    const s = f.step
    return [
      `<span class="nowrap">${when(f)}</span>`,
      `<span class="nowrap">${offset(f)}</span>`,
      `<span class="lane ${s.kind === 'mail' ? 'mail' : s.origin === 'm365' ? 'm365' : 'host'}"></span>${h(s.kind === 'mail' ? 'mailbox' : s.origin === 'm365' ? 'Microsoft 365' : 'host')}`,
      h(s.title) +
        (f.n > 1 ? ` <span class="chip">×${f.n}</span>` : s.count > 1 ? ` <span class="chip">×${s.count}</span>` : '') +
        (s.computer || s.ipAddress ? `<span class="sub">${h([s.computer, s.ipAddress].filter(Boolean).join(' · '))}</span>` : ''),
      h([...s.artifacts, ...s.findings.map((x) => x.title)].join('; ')),
    ]
  }),
)}
${left || hidden ? `<div class="cap">${left ? `${left} more step row(s) not printed (open the chain in REMN for the full list)` : ''}${left && hidden ? ' · ' : ''}${hidden ? `${hidden} routine step(s) not printed at the “${h(d.settings.chainDetail)}” detail level` : ''}.</div>` : ''}
${
  members.length
    ? `<div class="cap" style="margin-top:8px">${members.length} finding(s) linked to this chain, decided with it</div>${table(
        ['severity', 'finding', 'rule', 'rows', 'status'],
        members.map((f) => [pill(effectiveSeverity(f)), h(f.title), `<code>${h(f.ruleId)}</code>`, String(f.count), statusPill(f.status)]),
      )}`
    : ''
}
${r?.by === 'ai' && r.aiReason ? `<div class="cap">Triage note (model): ${h(r.aiReason)}</div>` : ''}
</div>`
}

function incidentCard(i: Incident): string {
  return `<div class="card inc ${h(i.severity)}">
<div class="card-head">${pill(i.severity)}<h3>${h(i.title)}</h3>${statusPill(i.status)}</div>
<div class="card-meta">${h(i.subtitle)} · ${fmtTs(i.ts)}${i.tsEnd && i.tsEnd !== i.ts ? ` → ${fmtTs(i.tsEnd)}` : ''} · ${n(i.refs.length)} row(s)${
    Object.keys(i.entities).length
      ? ' · ' +
        Object.entries(i.entities)
          .slice(0, 6)
          .map(([k, v]) => `<span class="chip">${h(k)}=${h(String(v))}</span>`)
          .join('')
      : ''
  }</div>
${i.lead.notes ? `<div class="note">${md(i.lead.notes)}</div>${i.lead.notesBy === 'ai' ? '<div class="cap">note drafted by the model during triage</div>' : ''}` : ''}
${i.lead.decidedBy === 'ai' && i.lead.aiReason ? `<div class="cap">Triage note (model): ${h(i.lead.aiReason)}</div>` : ''}
${table(
  ['severity', 'finding', 'rule', 'rows', 'first (UTC)', 'ATT&amp;CK'],
  i.findings.map((f) => [
    pill(effectiveSeverity(f)) + (f.severityOverride ? `<span class="sub">rule: ${h(f.severity)}</span>` : ''),
    h(f.title) + (f.escalation ? `<span class="sub">${h(f.escalation)}</span>` : ''),
    `<code>${h(f.ruleId)}</code>`,
    String(f.count),
    `<span class="nowrap">${fmtTs(f.ts)}</span>`,
    f.attack.map((t) => `<span class="chip">${h(t)}</span>`).join(''),
  ]),
)}
</div>`
}

export function buildReportHtml(d: ReportData): string {
  const { kase, settings } = d
  const bySev: Record<string, number> = {}
  for (const f of d.findings) bySev[effectiveSeverity(f)] = (bySev[effectiveSeverity(f)] ?? 0) + 1
  const total = Math.max(1, d.findings.length)
  const decisions = {
    confirmed: d.chains.filter((c) => d.reviews[c.id]?.verdict === 'confirmed').length + d.incidents.filter((i) => i.status === 'escalated').length,
    reviewed: d.chains.filter((c) => d.reviews[c.id]?.verdict === 'unsure').length + d.incidents.filter((i) => i.status === 'reviewed').length,
    fp: d.incidents.filter((i) => i.status === 'false_positive').length,
  }
  const sections: { id: string; title: string; count?: number; body: string }[] = []
  if (d.summary) sections.push({ id: 'summary', title: 'Executive summary', body: `<div class="narr">${md(d.summary)}</div>` })
  if (settings.includeEvidence)
    sections.push({
      id: 'evidence',
      title: 'Evidence and chain of custody',
      count: d.evidence.length,
      body: d.evidence.length
        ? table(
            ['file', 'kind', 'size', 'rows', 'SHA-256', 'integrity', 'added (UTC)'],
            d.evidence.map((e) => [
              h(e.name),
              h(e.format || e.kind),
              fmtBytes(e.size),
              n(e.count),
              `<code>${h(e.sha256Client ?? '')}</code>`,
              h(e.integrity),
              `<span class="nowrap">${fmtTs(e.addedAt)}</span>`,
            ]),
          )
        : '<div class="empty">No evidence file.</div>',
    })
  if (d.chains.length) {
    const campaign =
      settings.includeGraphs && d.chains.length > 1 && d.graphs.campaign
        ? `<div class="card"><div class="card-head"><h3>Shared between chains</h3></div>${img(d.graphs.campaign, 'campaign graph', 'Chains and the senders, domains, IPs and hosts they share.')}<div class="cap">${d.campaignInsights.length ? d.campaignInsights.map((x) => h(x)).join(' · ') : 'no sender, domain, IP or host is shared between the chains'}</div></div>`
        : ''
    sections.push({
      id: 'chains',
      title: 'Attack chains',
      count: d.chains.length,
      body: `<p class="intro">A chain is a suspicious mail and what the recipient's accounts and machines did after it, scored on the seed, the ties to the mail, the steps, the findings and the sources involved. Findings whose rows are steps of a chain are decided with it.</p>${campaign}${d.chains.map((c) => chainCard(c, d)).join('\n')}`,
    })
  }
  sections.push({
    id: 'incidents',
    title: 'Incidents',
    count: d.incidents.length,
    body: `<p class="intro">Findings on the same mail, or about the same user, host or IP within six hours, are one incident.</p>${d.incidents.length ? d.incidents.map(incidentCard).join('\n') : '<div class="empty">No incident outside the attack chains passes the severity floor.</div>'}`,
  })
  if (settings.includeIocs)
    sections.push({
      id: 'iocs',
      title: 'Indicators of compromise',
      count: d.iocs.length,
      body: d.iocs.length
        ? `<p class="intro">Indicators flagged by the reputation providers; values are defanged.</p>${table(
            ['kind', 'indicator', 'verdict', 'tags', 'seen'],
            d.iocs.map((i) => [
              h(i.kind),
              `<code>${h(defang(i.value))}</code>`,
              h(i.verdict ?? ''),
              (i.tags ?? []).map((t) => `<span class="chip">${h(t)}</span>`).join(''),
              h(`${i.count} (${i.sources.join(', ')})`),
            ]),
          )}`
        : '<div class="empty">No indicator flagged: reputation checks were not run, or nothing was found malicious.</div>',
    })
  if (settings.includeTimeline && d.timeline.length)
    sections.push({
      id: 'timeline',
      title: 'Case timeline',
      count: d.timeline.length,
      body: `<ul class="tl">${d.timeline.map((t) => `<li class="${h(t.severity ?? 'info')}"><div class="t">${fmtTs(t.ts)}${t.link ? ` · ${h(`${t.link.source} ${t.link.label ?? t.link.id}`)}` : ''}</div><div>${h(t.text)}</div></li>`).join('')}</ul>`,
    })
  if (settings.includeTasks && d.tasks.length)
    sections.push({
      id: 'tasks',
      title: 'Tasks',
      count: d.tasks.length,
      body: `<ul class="tasks">${d.tasks.map((t) => `<li class="${t.done ? 'done' : ''}"><span class="box">${t.done ? '✓' : ''}</span>${h(t.text)} <span class="dim">· ${fmtTs(t.updatedAt)}</span></li>`).join('')}</ul>`,
    })
  if (settings.includeNotes && d.notes.length)
    sections.push({
      id: 'notes',
      title: 'Analyst notes',
      count: d.notes.length,
      body: `<div class="notes">${d.notes.map((x) => `<div class="n"><div class="cap">${fmtTs(x.createdAt)}</div>${md(x.text)}</div>`).join('')}</div>`,
    })
  const timed = [...d.findings].filter((f) => f.ts).sort((a, b) => (a.ts ?? 0) - (b.ts ?? 0))
  sections.push({
    id: 'findings',
    title: 'Findings in time order',
    count: timed.length,
    body: timed.length
      ? table(
          ['time (UTC)', 'severity', 'finding', 'entities'],
          timed.map((f) => [`<span class="nowrap">${fmtTs(f.ts)}</span>`, pill(effectiveSeverity(f)), h(f.title), `<code>${h(Object.values(f.entities).slice(0, 3).join(' · '))}</code>`]),
        )
      : '<div class="empty">No dated finding.</div>',
  })
  sections.push({
    id: 'settings',
    title: 'Case settings',
    body: `<div class="settings">internal domains: ${h(kase.settings.internalDomains.join(', ') || '—')} · VIPs: ${h(kase.settings.vipNames.join(', ') || '—')} · business hours ${kase.settings.businessHours.start}h–${kase.settings.businessHours.end}h (${h(kase.settings.businessHours.tz)}) · external lookups ${kase.settings.networkAllowed ? 'enabled' : 'disabled'} · report floor ${h(settings.minSeverity)}${settings.onlyReviewed ? ' · reviewed items only' : ''}${settings.includeFp ? ' · false positives included' : ''} · chain steps: ${h(settings.chainDetail)}</div>`,
  })

  const num = (i: number) => String(i + 1).padStart(2, '0')
  const font =
    d.fontData && /^[A-Za-z0-9+/=]+$/.test(d.fontData) ? `@font-face{font-family:'Gulax';src:url(data:font/woff2;base64,${d.fontData}) format('woff2');font-weight:400;font-style:normal}` : ''
  const generated = new Date(d.generatedAt).toISOString().replace('T', ' ').slice(0, 19) + 'Z'
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>REMN report · ${h(kase.name)}</title><style>${font}${CSS}</style></head><body>
<div class="cover-page">
<div class="cover">
<div class="brand"><span class="wordmark">REMN</span><span class="tag">forensic analysis report</span></div>
<h1>${h(kase.name)}</h1>
<div class="meta">Generated ${generated}${kase.analyst ? ` · analyst ${h(kase.analyst)}` : ''} · all times UTC · findings from ${h(settings.minSeverity)} severity up${settings.onlyReviewed ? ', reviewed items only' : ''}${settings.includeFp ? ', false positives included' : ''}</div>
<div class="kpis"><div class="kpi"><div class="v">${n(d.chains.length)}</div><div class="l">attack chains</div></div><div class="kpi"><div class="v">${n(d.incidents.length)}</div><div class="l">incidents</div></div><div class="kpi"><div class="v">${n(d.findings.length)}</div><div class="l">findings</div></div><div class="kpi"><div class="v">${n(d.iocs.length)}</div><div class="l">flagged indicators</div></div><div class="kpi"><div class="v">${n(d.evidence.length)}</div><div class="l">evidence files</div></div></div>
<div class="sevbar">${ORDER.map((s) => (bySev[s] ? `<span title="${s} ${bySev[s]}" style="width:${((bySev[s] / total) * 100).toFixed(1)}%;background:var(--${s})"></span>` : '')).join('')}</div>
<div class="legend">${ORDER.map((s) => `<span><i style="background:var(--${s})"></i>${s} ${bySev[s] ?? 0}</span>`).join('')}</div>
<div class="decisions">Decisions: <b>${decisions.confirmed}</b> confirmed · <b>${decisions.reviewed}</b> reviewed or unsure · <b>${decisions.fp}</b> false positive${decisions.fp === 1 ? '' : 's'}${d.undecided ? ` · <b>${d.undecided}</b> item${d.undecided === 1 ? '' : 's'} without a decision` : ' · every item decided'}</div>
</div>
<ul class="toc">${sections.map((s, i) => `<li><span class="n">${num(i)}</span>${h(s.title)}${s.count != null ? ` <span class="dim">(${n(s.count)})</span>` : ''}</li>`).join('')}</ul>
</div>
${sections.map((s, i) => `<section class="s" id="${h(s.id)}"><div class="s-head"><span class="num">${num(i)}</span><h2>${h(s.title)}</h2><span class="rule"></span>${s.count != null ? `<span class="count">${n(s.count)}</span>` : ''}</div>${s.body}</section>`).join('\n')}
<div class="foot"><span class="wm">REMN</span><span>${h(kase.name)} · generated ${generated}</span></div>
</body></html>`
}

let fontPromise: Promise<string | undefined> | null = null
/** The wordmark face as base64, fetched once from the app's own files; undefined when unavailable. */
export function loadReportFont(): Promise<string | undefined> {
  if (!fontPromise) {
    fontPromise = (async () => {
      try {
        const resp = await fetch('/fonts/gulax-regular.woff2')
        if (!resp.ok) return undefined
        const buf = new Uint8Array(await resp.arrayBuffer())
        let bin = ''
        for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode(...buf.subarray(i, i + 0x8000))
        return btoa(bin)
      } catch {
        return undefined
      }
    })()
  }
  return fontPromise
}
