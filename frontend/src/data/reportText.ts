import { fmtBytes, fmtDuration, fmtNum, fmtUtc } from '../util/format'
import type { IncidentAbout } from '../rules/incidents'
import type { ClaimWhy, TextAbout } from './claims'
import type { ExportSource, GapSay, GapWhere } from './evidenceGaps'
import type { RecordPlace } from './recordKeys'

/**
 * The words of the printed report, one dictionary per language, and the firm's logo it carries. The HTML and the Word report take
 * every label, heading and sentence of their own from here, with the numbers, times and sizes
 * written the way the language writes them. The interface stays English; only the report changes.
 *
 * What REMN writes elsewhere and the report prints is written from here too, from values: an
 * incident's line, the limits of the evidence, the reasons a claim does not hold, the cuts of a
 * story or chain build, what an investigation package left out, REMN's own questions and what the
 * evidence covers of them. The interface reads the English. This module imports no other at run
 * time, so those modules can.
 *
 * Printed as they are, whatever the language: what the analyst writes, what a model drafted (and
 * labelled as such), the evidence, rule titles, DFIQ's questions, and the steps, ties and phases of
 * the stories and chains the server builds, which the French report says are in English.
 */

export type ReportLanguage = 'en' | 'fr'
export const REPORT_LANGUAGES: { id: ReportLanguage; label: string }[] = [
  { id: 'en', label: 'English' },
  { id: 'fr', label: 'French' },
]

const pad = (x: number) => String(x).padStart(2, '0')
/** in English the plural takes an s past one; the callers say which word */
const s = (k: number) => (k === 1 ? '' : 's')
/** a list the way English writes it: a, b and c */
const enList = (xs: string[], join: string) => (xs.length <= 2 ? xs.join(` ${join} `) : `${xs.slice(0, -1).join(', ')} ${join} ${xs[xs.length - 1]}`)
/** what a cloud record is, by the prefix of its key (services/parsers/m365.py) */
const EN_CLOUD: Record<string, string> = {
  ual: 'audit record',
  entra: 'sign-in',
  'entra-audit': 'directory audit',
  'entra-risk': 'risk detection',
  'entra-riskyuser': 'risky user',
  'exo-trace': 'message trace',
}
const enRecord = (at: RecordPlace): string => {
  switch (at.kind) {
    case 'message':
      return `message ${fmtNum(at.n)}`
    case 'message-id':
      return `Message-ID ${at.id}`
    case 'cloud':
      return `${EN_CLOUD[at.what] ?? 'record'} ${at.id}`
    case 'record':
      return `record ${fmtNum(at.n)}${at.channel && at.computer ? ` (${at.channel} on ${at.computer})` : ''}`
    default:
      return `row ${typeof at.n === 'number' ? fmtNum(at.n) : at.n}`
  }
}
const enWhere = (w: GapWhere) =>
  w.channel && w.computer
    ? `${w.channel} on ${w.computer} (${w.file})`
    : w.channels != null || w.computers != null
      ? `${w.file} (${fmtNum(w.channels ?? 1)} channel${s(w.channels ?? 1)} from ${fmtNum(w.computers ?? 1)} computer${s(w.computers ?? 1)})`
      : w.file
const EN_CAPS: Record<ExportSource, { records: string; limits: Record<number, string>; missing: string }> = {
  ual: { records: 'Unified Audit Log records', limits: { 5000: 'the most one Search-UnifiedAuditLog call returns', 50000: 'the most a large-set search returns' }, missing: 'Records' },
  'message-trace': {
    records: 'message trace rows',
    limits: { 1000: 'as many as Get-MessageTrace and Get-MessageTraceV2 return unless told otherwise', 5000: 'the most Get-MessageTraceV2 returns' },
    missing: 'Messages',
  },
  'entra-audit': { records: 'directory audit records', limits: { 250000: 'the most the Entra admin centre downloads in one file' }, missing: 'Records' },
}
const enGap = (g: GapSay): string => {
  switch (g.kind) {
    case 'record-holes': {
      const floor = g.floor ? 'at least ' : ''
      const [a, b] = g.largest
      return (
        `${enWhere(g.where)}: ${floor}${fmtNum(g.missing)} record${s(g.missing)} missing from its numbering, in ${floor}${fmtNum(g.gaps)} gap${s(g.gaps)} ` +
        `between record ${fmtNum(g.first)} and ${fmtNum(g.last)} (the largest: ${fmtNum(a)}${b > a ? `–${fmtNum(b)}` : ''}). ` +
        'Records deleted from the log, or in a part that could not be read.'
      )
    }
    case 'checksum-data':
      return `${g.file}: ${fmtNum(g.bad)} of ${fmtNum(g.chunks)} chunk${s(g.chunks)} fail their checksum. Their records were changed after Windows wrote them, or damaged; they were read all the same.`
    case 'checksum-header':
      return `${g.file}: ${[g.headers ? `${fmtNum(g.headers)} chunk header${s(g.headers)}` : '', g.fileHeader ? 'the file header' : ''].filter(Boolean).join(' and ')} fail${g.headers + (g.fileHeader ? 1 : 0) === 1 ? 's' : ''} its checksum: the file's structure was changed after it was written.`
    case 'clock-logs':
      return `On ${g.computer}, ${fmtNum(g.logs)} logs step back together at ${fmtUtc(g.from)}, by up to ${fmtDuration(g.from - g.to)}: its clock was set back, and no log collected records the change. Events stamped between ${fmtUtc(g.to)} and ${fmtUtc(g.from)} may have happened before or after it, so their times do not give their order.`
    case 'clock-set':
      return `The clock of ${g.computer} was set back ${fmtDuration(g.from - g.to)} at ${fmtUtc(g.from)}, to ${fmtUtc(g.to)}: events stamped between those two times may have happened before or after the change, so their times do not give their order.`
    case 'time-backwards':
      return (
        `${enWhere(g.where)}: write times step back ${fmtNum(g.steps)} time${s(g.steps)} between consecutive records with no clock change or log service start in the evidence to explain ${g.steps === 1 ? 'it' : 'them'} ` +
        `(the largest ${fmtDuration(g.largest)}, at record ${fmtNum(g.record)}${g.unread ? `; ${fmtNum(g.unread)} more steps were not examined` : ''}). ` +
        'A record was put in later, or the clock changed where no log collected records it (System and Security record clock changes).'
      )
    case 'missing-between-files':
      return `${g.channel} on ${g.computer}: ${g.from === g.to ? `record ${fmtNum(g.from)} is` : `records ${fmtNum(g.from)}–${fmtNum(g.to)} are`} in none of the files read (${g.before} ends at record ${fmtNum(g.beforeLast)}, ${g.after} starts at ${fmtNum(g.afterFirst)}): an archive or export is missing.`
    case 'log-starts-late':
      return `On ${g.computer}, ${g.count === 1 ? 'one log starts' : `${g.count} logs start`} after the first finding (${fmtUtc(g.start)}): ${g.logs.map(([channel, ts]) => `${channel} at ${fmtUtc(ts)}`).join(', ')}${g.count > g.logs.length ? ` and ${g.count - g.logs.length} more` : ''}. Earlier events there were overwritten or not collected.`
    case 'export-cap': {
      const cap = EN_CAPS[g.source]
      return `${g.file}: exactly ${fmtNum(g.records)} ${cap.records}, ${cap.limits[g.records] ?? ''}. ${cap.missing} after that point in its time window are probably missing.`
    }
    case 'xml-export':
      return (
        `${g.file}: ${fmtNum(g.records)} event record${s(g.records)} exported as XML. An export holds what its query selected and not the log file's own record numbering, ` +
        'so a record deleted from the log before the export cannot be told from one the export left out; the log file itself (wevtutil epl) can be checked for that.'
      )
    case 'parse-limit':
      return `${g.file}: read up to the parse limit and no further (${fmtNum(g.kept)} row${s(g.kept)} kept). Records after that point in the file are not in the case.`
    case 'read-in-part':
      return `${g.file}: read in part (${g.note}). What the file holds after that point is not in the case.`
    case 'mail-throttled':
      return `MailItemsAccessed for ${g.user} was throttled from ${fmtUtc(g.from)}: for the 24 hours after it, the mailbox's item reads were not recorded one by one, so which messages were read then cannot be listed.`
    case 'signins-start-late':
      return `Entra sign-ins start at ${fmtUtc(g.first)}, after the first finding (${fmtUtc(g.start)}): earlier sign-ins are not in the evidence. Entra keeps them 7 days without a P1 or P2 licence, 30 days with one.`
  }
}
const enClaim = (w: ClaimWhy): string => {
  switch (w.kind) {
    case 'no-rows':
      return 'it cites no row'
    case 'rows-missing':
      return `${fmtNum(w.missing)} of the ${fmtNum(w.checked)} row${s(w.checked)} it cites ${w.missing === 1 ? 'is' : 'are'} not in the case: removed, or numbered anew when evidence was added again`
    case 'no-match':
      return `${w.records.map((r) => `${r.file} ${enRecord(r.at)}`).join(' and ')}${w.more ? ` and ${fmtNum(w.more)} more` : ''} no longer ${w.records.length + w.more === 1 ? 'matches' : 'match'} the rule`
    case 'value-absent':
      return `it names ${w.field} ${w.values.join(', ')}, which none of its rows holds`
    case 'time':
      return `its time, ${fmtUtc(w.ts)}, is not its first row's (${fmtUtc(w.first)})`
    case 'text-absent':
      return `it names ${w.values.join(', ')}${w.more ? ` and ${fmtNum(w.more)} more` : ''}, which none of its ${fmtNum(w.rows)} row${s(w.rows)} holds`
    case 'text-absent-case':
      return `it names ${w.values.join(', ')}${w.more ? ` and ${fmtNum(w.more)} more` : ''}, which no row of the evidence holds`
  }
}

const en = {
  /** the language of the HTML document and of the Word document */
  lang: 'en',
  wordLang: 'en-GB',
  num: (x: number | null | undefined) => fmtNum(x),
  /** a time of the evidence or of the report: always UTC */
  ts: (ms: number | null | undefined) => fmtUtc(ms),
  bytes: (b: number | null | undefined) => fmtBytes(b),
  /** a date the analyst entered (yyyy-mm-dd); anything else is printed as written */
  day: (iso: string) => iso,
  to: 'to',
  andMore: (k: number) => `and ${fmtNum(k)} more`,
  plusMore: (k: number) => `+${fmtNum(k)} more`,
  noEventTime: 'no event time',
  /** a span of time, as the limits of the evidence state it */
  dur: (ms: number) => fmtDuration(ms),
  /** a record's place in its file */
  record: enRecord,
  /** a limit of the evidence (data/evidenceGaps.ts) */
  gap: enGap,
  /** why a finding or a text does not hold against its rows, and what the text is (data/claims.ts) */
  claim: {
    reason: enClaim,
    about: (a: TextAbout): string =>
      a.kind === 'chain'
        ? `the narrative of chain "${a.title}"`
        : a.kind === 'incident'
          ? `the notes on "${a.title}"`
          : a.kind === 'story'
            ? `the note on the story "${a.title}"`
            : 'the executive summary',
  },

  sev: { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info' } as Record<string, string>,
  status: { new: 'not reviewed', reviewed: 'reviewed', escalated: 'confirmed', false_positive: 'false positive' } as Record<string, string>,
  chainVerdict: { confirmed: 'confirmed', unsure: 'unsure', benign: 'benign' } as Record<string, string>,
  /** the Stories page's and the Questions page's own words (STORY_VERDICTS, ANSWER_STATUSES) */
  storyVerdict: { open: 'open', reviewed: 'reviewed', confirmed: 'confirmed incident', benign: 'benign', false_positive: 'false positive' } as Record<string, string>,
  answer: { open: 'open', answered: 'answered', cannot: 'cannot answer from this evidence' } as Record<string, string>,
  /** the completeness of the review, and a story's confidence */
  level: { high: 'high', medium: 'medium', low: 'low' } as Record<string, string>,
  /** the analyst's own confidence in the conclusion */
  analytic: { high: 'high', moderate: 'moderate', low: 'low' } as Record<string, string>,
  /** how sure a tie between records is */
  tie: { strong: 'strong', medium: 'medium', weak: 'weak' } as Record<string, string>,
  phase: {
    reconnaissance: 'Reconnaissance',
    'resource-development': 'Resource development',
    'initial-access': 'Initial access',
    execution: 'Execution',
    persistence: 'Persistence',
    'privilege-escalation': 'Privilege escalation',
    stealth: 'Stealth',
    'defense-impairment': 'Defense impairment',
    'credential-access': 'Credential access',
    discovery: 'Discovery',
    'lateral-movement': 'Lateral movement',
    collection: 'Collection',
    'command-and-control': 'Command and control',
    exfiltration: 'Exfiltration',
    impact: 'Impact',
    context: 'context',
  } as Record<string, string>,
  /** the threat profile's badges, by id */
  tactic: {
    'initial-access': 'Initial access',
    execution: 'Execution',
    persistence: 'Persistence',
    privilege: 'Privilege escalation',
    'defense-evasion': 'Defense evasion',
    credential: 'Credential access',
    discovery: 'Discovery',
    lateral: 'Lateral movement',
    collection: 'Collection',
    c2: 'Command and control',
    exfil: 'Exfiltration',
    impact: 'Impact',
    unwanted: 'Unwanted software',
  } as Record<string, string>,
  /** the two letters over each tactic on the cover, from its name in the report's language */
  tacticCode: {
    'initial-access': 'IA',
    execution: 'EX',
    persistence: 'PE',
    privilege: 'PR',
    'defense-evasion': 'DE',
    credential: 'CA',
    discovery: 'DI',
    lateral: 'LM',
    collection: 'CO',
    c2: 'C2',
    exfil: 'EF',
    impact: 'IM',
    unwanted: 'PU',
  } as Record<string, string>,
  transport: {
    browser: 'Ollama on the analyst’s machine',
    openai: 'a local OpenAI-compatible model server',
    server: 'the REMN server’s Ollama',
    claude: 'Claude Code (Anthropic)',
  } as Record<string, string>,
  claimWord: { verified: 'rows checked', unsupported: 'rows missing', contradicted: 'rows disagree' } as Record<string, string>,
  integrity: { pending: 'pending', verified: 'verified', mismatch: 'mismatch' } as Record<string, string>,
  indicatorKind: { ip: 'ip', domain: 'domain', email: 'email', url: 'url', hash: 'hash' } as Record<string, string>,
  lane: { mail: 'mailbox', m365: 'Microsoft 365', host: 'host' },

  section: {
    engagement: 'Engagement',
    summary: 'Executive summary',
    scope: 'Scope',
    conclusion: 'Conclusion',
    happened: 'What happened',
    impact: 'Impact',
    containment: 'Containment',
    recommendations: 'Recommendations',
    questions: 'Questions',
    stories: 'Stories',
    chains: 'Attack chains',
    incidents: 'Incidents',
    evidence: 'Evidence and chain of custody',
    relationships: 'Reviewed evidence relationships',
    iocs: 'Indicators of compromise',
    techniques: 'ATT&CK techniques',
    timeline: 'Case timeline',
    tasks: 'Tasks',
    notes: 'Analyst notes',
    findings: 'Findings by rule',
    ai: 'How AI was used',
    method: 'Method and limits',
    settings: 'Case settings',
  },

  cover: {
    title: (name: string) => `REMN report · ${name}`,
    tag: 'forensic analysis report',
    subtitle: 'REMN forensic analysis report',
    analyst: (name: string) => `analyst ${name}`,
    noAnalyst: 'analyst not set',
    final: (at: string) => `final · issued ${at}`,
    draft: 'draft · not issued',
    draftMark: 'DRAFT',
    preparedFor: (client: string) => `Prepared for ${client}`,
    engagement: (ref: string) => `engagement ${ref}`,
    meta: (floor: string, onlyReviewed: boolean, fp: boolean) =>
      `All times UTC · findings from ${floor} severity up${onlyReviewed ? ', reviewed items only' : ''}${fp ? ', false positives included' : ''}`,
    seal: 'verdict',
    bottomLine: 'bottom line',
    completeness: (level: string) => `completeness ${level}`,
    completenessSub: 'how complete the review is, not how sure its conclusion is',
    analystConfidence: (level: string) => `analyst's confidence ${level}`,
    analystConfidenceSub: "the analyst's own assessment of the conclusion",
    kpi: ['evidence files', 'rows analysed', 'findings', 'incidents · chains', 'confirmed', 'flagged indicators'],
    /** the decisions under the severity bar; b sets a number in bold */
    legend: (c: number, r: number, f: number, u: number, b: (k: number) => string) =>
      `· Decisions: ${b(c)} confirmed · ${b(r)} reviewed or unsure · ${b(f)} false positive${s(f)}${u ? ` · ${b(u)} item${s(u)} without a decision` : ' · every item decided'}`,
    profile: 'threat profile',
    profileCount: (confirmed: number, seen: number, all: number) => `${confirmed ? `${confirmed} confirmed · ` : ''}${seen} of ${all} tactics observed`,
    badgeTitle: (label: string, k: number) => `${label}: ${k} finding${s(k)}`,
    verified: 'evidence files verified by digest',
    undecided: (k: string) => `${k} undecided`,
    reviewComplete: 'review complete',
    engine: 'external detection engine ran',
    aiText: 'model-drafted text, labelled where it appears',
    noAiText: 'no model-drafted text',
    notEnriched: 'indicators not enriched',
    generated: (at: string) => `generated ${at}`,
  },

  verdict: {
    notPrinted: (k: number) => ` ${k} of them ${k === 1 ? 'is' : 'are'} not printed (below the severity floor or left out).`,
    unwanted: 'Unwanted software',
    unwantedDetail: (k: number, sev: string) => `${k} confirmed item${s(k)} describe unwanted or adware-class software at ${sev} severity, no intrusion.`,
    compromise: 'Compromise confirmed',
    compromiseDetail: (k: number, sev: string) => `${k} confirmed item${s(k)}, the worst at ${sev} severity.`,
    suspicious: 'Suspicious activity confirmed',
    suspiciousDetail: (k: number, sev: string) => `${k} confirmed item${s(k)} at ${sev} severity; nothing reached high.`,
    unconfirmed: 'Nothing confirmed',
    unconfirmedDetail: (k: number, undecided: number) => `${k} item${s(k)} reviewed without confirmation${undecided ? `, ${undecided} still undecided` : ''}.`,
    pending: 'Review incomplete',
    pendingDetail: (k: number) => `${k} item${s(k)} without a decision; the verdict waits for them.`,
    clean: 'No confirmed threat',
    cleanEmpty: 'No finding passed the severity floor; there was nothing to decide.',
    cleanDetail: (fps: number) => (fps ? `Every item was reviewed; ${fps} false positive${s(fps)}.` : 'Every item was reviewed and none was confirmed.'),
  },

  completeness: {
    complete: 'every item decided, evidence verified, analysis complete',
    undecided: (k: number) => `${k} item${s(k)} not decided`,
    unverified: (k: number) => `${k} evidence file${s(k)} without a verified digest`,
    packages: (k: number) => `package coverage: ${k} reported issue${s(k)}`,
    incomplete: (k: number) => `${k} evidence file${k === 1 ? ' was' : 's were'} not read completely`,
    chains: (k: number) => `chain analysis incomplete (${k} limit${s(k)} reached)`,
    rulesNotRun: 'the rules have not run on this case',
    evidenceAfter: (k: number) => `${k} evidence file${s(k)} added after the last rule run`,
    rulesFailed: (k: number) => `${k} rule${s(k)} failed in the last run`,
    notEnriched: 'indicators not enriched (no reputation lookup was run)',
  },

  evidenceIssue: {
    stopped: (error: string) => (error ? `parse stopped: ${error}` : 'parse stopped'),
    errors: (k: number) => `${k} parse error${s(k)}`,
    unread: (k: number) => `${k} archive member${s(k)} not read`,
  },

  ai: {
    intro:
      "A language model assisted this investigation: it read the case through read-only tools and proposed; every change it proposed took effect only when the analyst accepted it. Each run, tool call, proposal and decision is recorded in the case's AI ledger, chained by hash.",
    facts: (runs: number, calls: number, span: string, models: string[], where: string[]) =>
      `${fmtNum(runs)} run${s(runs)} · ${fmtNum(calls)} tool call${s(calls)} · ${span}${models.length ? ` · model${s(models.length)}: ${models.join(', ')}` : ''}${where.length ? ` · through ${where.join(', ')}` : ''}`,
    head: ['proposed', 'count', 'accepted', 'rejected'],
    none: 'The model proposed no change to the case.',
    decisions: (accepted: number, rejected: number, undone: number, notices: number) =>
      `${fmtNum(accepted)} accepted, ${fmtNum(rejected)} rejected${undone ? `, ${fmtNum(undone)} undone after acceptance` : ''}${notices ? ` · ${fmtNum(notices)} time${s(notices)} the evidence held text addressed to a model (flagged to the analyst)` : ''}`,
    ledgerIntact: (entries: number) => `ledger: ${fmtNum(entries)} entries, chain intact, head`,
    ledgerBroken: (entries: number, at: number) => `ledger: ${fmtNum(entries)} entries, chain broken at entry ${fmtNum(at)}`,
    ledgerBrokenWhy: ': an entry was changed or removed after it was written',
    ledgerScope:
      "The chain shows an entry changed after it was written, an entry removed from among later ones, and a gap in the numbering. It does not show the newest entries removed, nor the chain written again, from any entry onward, by whoever holds the case: no key protects it, and it is kept in the browser's database and in the exported case. The head is printed whole: a later copy of the case whose ledger still holds an entry with this hash has every entry up to it as it was when this report was made.",
    /** what a proposal was about (ai/inbox.ts ProposalKind) */
    kind: { decision: 'decision', note: 'note', row_mark: 'row mark', rule: 'rule', summary: 'summary' } as Record<string, string>,
  },

  chain: {
    key: ['seed mail', 'step, coloured by its worst finding', 'folded routine steps', 'tie to the mail'],
    campaignKey: ['person, coloured by the chain', 'shared sender or domain', 'shared machine or IP', 'in one chain only'],
    scoreParts: { seed: 'seed', links: 'links', steps: 'steps', findings: 'findings', sources: 'sources', score: 'score' } as Record<string, string>,
    score: (score: number, cap?: number | null) => `score ${score}${cap ? ` (capped ${cap})` : ''}`,
    narrativeByAi: 'narrative drafted by the model during triage',
    narrativeByAiDocx: 'Narrative drafted by the analyst model.',
    seed: (kind: 'event' | 'mail', subject: string, from: string, at: string, risk: number) => `Seed ${kind} “${subject}” from ${from} at ${at} (risk ${risk})`,
    steps: (k: number, from: string, to: string) => `${k} steps from ${from} to ${to}`,
    ties: (k: number) => `${k} artifact tie(s)`,
    attacker: 'attacker',
    ips: 'IPs',
    hosts: 'hosts',
    graphAlt: (label: string) => `graph of the chain for ${label}`,
    graphCaption: 'Steps by lane, time left to right.',
    head: ['time (UTC)', 'offset', 'source', 'step', 'ties to the mail / findings'],
    minutes: 'min',
    left: (k: number) => `${k} more step row(s) not printed (open the chain in REMN for the full list)`,
    hidden: (k: number, detail: string) => `${k} routine step(s) not printed at the “${detail}” detail level`,
    members: (k: number) => `${k} finding(s) linked to this chain, decided with it`,
    triage: (reason: string) => `Triage note (model): ${reason}`,
    fallbackTitle: 'chain',
    verdict: (v: string) => `verdict ${v}`,
    noVerdict: 'no verdict',
    stepCount: (k: number) => `${fmtNum(k)} step${s(k)}`,
    intro:
      "A chain is a suspicious mail and what the recipient's accounts and machines did after it, scored on the seed, the ties to the mail, the steps, the findings and the sources involved. What happened, in order. Findings whose rows are steps of a chain are decided with it.",
    introDocx:
      "A chain is a suspicious mail and what the recipient's accounts and machines did after it, scored on the seed, the ties to the mail, the steps, the findings and the sources involved. Findings whose rows are steps of a chain are decided with it.",
    shared: 'Shared between chains',
    campaignAlt: 'campaign graph',
    campaignCaption: 'People in the middle, the senders and domains that reached them on the left, the machines and IPs they touched on the right.',
    nothingShared: 'no sender, domain, IP or host is shared between the chains',
    graphsInHtml: 'The chain graphs are in the HTML report.',
    /** a sender, domain, address or host the printed chains share (data/chainGraph.ts) */
    appears: (what: string, label: string, chains: number) => `${what} ${label} appears in ${chains} chains`,
    node: { sender: 'sender', 'attacker address': 'attacker address', 'link domain': 'link domain', ip: 'ip', host: 'host' } as Record<string, string>,
  },

  story: {
    decided: (label: string, reason: string) => `The analyst decided it ${label}${reason ? `: ${reason}` : '.'}`,
    merged: (title: string, orgs: string[] | undefined, reason: string) =>
      `Merged into it by the analyst: the story of ${title}${orgs ? ` (another organisation, ${orgs.join(' and ')})` : ''}: ${reason}`,
    split: (second: boolean, title: string, at: string, reason: string) => `${second ? 'The second part of a story the analyst split' : 'Split by the analyst'} at “${title}” (${at}): ${reason}`,
    out: (title: string, k: number, reason: string) => `Taken out by the analyst: “${title}” (${fmtNum(k)} record${s(k)}): ${reason}`,
    disputed: (title: string, at: string, reason: string) => `Disputed by the analyst and left out of its phases and severity: “${title}” (${at})${reason ? `: ${reason}` : ''}`,
    confirmedSteps: (k: number) => `${fmtNum(k)} step${s(k)} confirmed by the analyst.`,
    spine: (k: number, of: number) => `Spine: ${fmtNum(k)} of ${fmtNum(of)} steps`,
    spineHead: ['when (UTC)', 'phase', 'step', 'why it is in the story'],
    on: 'on',
    wayIn: 'way in',
    anchor: 'anchor',
    phases: 'Phases',
    phaseHead: ['phase', 'when (UTC)', 'steps', 'what marks it'],
    host: 'Host',
    person: 'Person',
    secondPart: ' (second part)',
    firstPart: ' (first part)',
    confidence: (level: string) => `${level} confidence`,
    records: (records: number, steps: number) => `${fmtNum(records)} record(s) in ${fmtNum(steps)} step(s)`,
    hosts: 'hosts',
    from: 'from',
    note: "the analyst's reading of the story",
    noteDocx: "The analyst's reading of the story.",
    stops: 'Where it stops:',
    intrusion: (label: string) => `One intrusion: ${label}`,
    count: (k: number) => `${fmtNum(k)} stories`,
    whyOne: (bases: string) => `Why they read as one: ${bases}`,
    unprinted: (k: number) => `${fmtNum(k)} more of its stories ${k === 1 ? 'is' : 'are'} not printed: below the severity floor, without a note, or past the first twenty.`,
    cut: (k: number) => `${fmtNum(k)} more linked ${k === 1 ? 'story is' : 'stories are'} left out of it: an incident holds twenty stories at most.`,
    intro:
      "A story is what happened to one person, or on one host, in one incident: the records around what raised a flag, read along the tactics of ATT&CK in the order they happened, each record tied to the story by its account, its logon session, the way into the host or the process that started it. A story the analyst decided says so: a confirmed story counts in the verdict as a confirmed incident does, a story decided benign or false positive is not printed, and a step the analyst disputed is left out of its story's phases and severity and listed under it. Each says where its evidence stops.",
    stale: (why: string) => `Out of date: ${why}. These stories read the case as it was then: build them again on the Stories page before relying on them.`,
    cutBuild: (why: string) => `Incomplete: ${why} An absent step or story is not a negative result.`,
    orphanedNotes: (k: number) => `${fmtNum(k)} analyst note${k === 1 ? ' is' : 's are'} on a story this build no longer holds: the Stories page lists ${k === 1 ? 'it' : 'them'} to attach again.`,
    orphanedDecisions: (k: number) =>
      `${fmtNum(k)} analyst decision${k === 1 ? ' is' : 's are'} on a story this build no longer holds: the Stories page lists ${k === 1 ? 'it' : 'them'} to attach again, and the report does not count ${k === 1 ? 'it' : 'them'}.`,
    left: (k: number, onlyReviewed: boolean) =>
      `${fmtNum(k)} more ${k === 1 ? 'story is' : 'stories are'} not printed: below the severity floor${onlyReviewed ? ', without a note or a decision (reviewed items only)' : ''} or past the first twenty.`,
    dismissed: (k: number) => `${fmtNum(k)} ${k === 1 ? 'story' : 'stories'} decided benign or false positive by the analyst ${k === 1 ? 'is' : 'are'} not printed.`,
    startFrom: (title: string, ways: string[], first: string) => `From the story of ${title}: ${ways.length ? `the way in reads as ${ways.join('; then ')}` : `its spine begins with ${first}`}.`,
    startWorst: (step: string) => `Its worst step: ${step}.`,
    startAt: (title: string, host: string | null, at: string) => `${title}${host ? ` on ${host}` : ''} at ${at}`,
    title: (title: string) => `Story of ${title}`,
  },

  finding: {
    lead: 'lead',
    noisy: 'also fires on clean machines',
    nothingToCheck: 'It names no address, account or hash: nothing in it was checked against the evidence.',
    checked: (reasons: string) => `Checked against its rows: ${reasons}.`,
    groupHead: ['severity', 'finding', 'findings · rows', 'when (UTC)', 'ATT&CK', 'what matched'],
    ruleHead: ['severity', 'rule', 'findings · rows', 'when (UTC)', 'status', 'what matched'],
    ruleHeadDocx: ['severity', 'rule', 'findings · rows', 'when (UTC)', 'status', 'ATT&CK', 'what matched'],
    ruleSeverity: (sev: string) => `rule: ${sev}`,
    by: (author: string) => `by ${author}`,
    authors: 'The Sigma rules are the work of the authors named beside them, shared by SigmaHQ under the Detection Rule License 1.1.',
    intro: 'Every printed finding, one line per rule: how many findings and rows, when, and the values matched. The incidents above carry the same findings in context.',
    none: 'No finding passes the severity floor.',
  },

  incident: {
    /** the line under an incident's title (rules/incidents.ts) */
    subtitle: (a: IncidentAbout): string => {
      const found = (k: number, rules: number) => `${k} finding${s(k)} from ${rules} rule${s(rules)}`
      switch (a.kind) {
        case 'chain':
          return `score ${a.score} · ${a.steps} step${s(a.steps)} · ${a.linked} linked finding${s(a.linked)}`
        case 'mail':
          return `${a.from ? `from ${a.from} · ` : ''}${found(a.findings, a.rules)}`
        case 'entity':
          return `${a.lead} · ${found(a.findings, a.rules)}${a.seenAs.length ? ` · also seen as ${a.seenAs.join(', ')}` : ''}`
        case 'group':
          return a.entities.map(([k, v]) => `${k}=${v}`).join(' · ') || `${a.rows} row(s)`
        default:
          return found(a.findings, a.rules)
      }
    },
    rows: (k: number) => `${fmtNum(k)} row(s)`,
    noteByAi: 'note drafted by the model during triage',
    noteByAiDocx: 'Note drafted by the model during triage.',
    intro:
      "Findings on the same mail, or about the same user, host or IP within six hours, are one incident. Each table groups the incident's findings by rule: one line per rule with the count, the span and the values it matched.",
    introDocx: "Findings on the same mail, or about the same user, host or IP within six hours, are one incident. Each table groups the incident's findings by rule.",
    none: 'No incident outside the attack chains passes the severity floor.',
  },

  happened: {
    confirmed: 'The confirmed items in the order they happened.',
    reviewed: 'Nothing was confirmed; the reviewed items in the order they happened.',
    times: 'Dates are event times, UTC.',
    first: (k: number, total: number) => `The first ${k} of ${total} are listed; the other ${total - k}, the latest, are printed in full in the incident and chain sections.`,
    firstDocx: (k: number, total: number) => `The first ${k} of ${total} are listed.`,
    noDated: 'No dated item to place.',
    noDecision: 'No item has been decided yet: run the review before printing.',
    collected: 'collected artefact',
    head: ['when (UTC)', 'severity', 'what', 'decision', 'note'],
  },

  summary: {
    byAi: "drafted by the analyst model from the reviewed items; the decisions it rests on are the analyst's",
    byAiDocx: "Drafted by the analyst model from the reviewed items; the decisions it rests on are the analyst's.",
    stale: 'written before the findings last changed: the numbers and ids in it may describe an earlier state of the case',
    staleDocx: 'Written before the findings last changed: the numbers and ids in it may describe an earlier state of the case.',
  },

  produced: {
    title: 'How this was produced',
    evidence: (k: number, kinds: string, rows: number) => `${fmtNum(k)} evidence file${s(k)} (${kinds || 'none'}), ${fmtNum(rows)} rows parsed`,
    rules: (k: number, engine: number) => `${fmtNum(k)} rule${s(k)} produced the printed findings${engine ? `; ${fmtNum(engine)} finding${s(engine)} came from an external detection engine` : ''}`,
    claims: (rows: number, verified: number, unsupported: number, contradicted: number) =>
      `each printed finding was read back against the rows it cites (the first ${fmtNum(rows)} of each): ${fmtNum(verified)} whose rows match the rule, the values and the time, ${fmtNum(unsupported)} unsupported, ${fmtNum(contradicted)} contradicted`,
    texts: (k: number, verified: number, nothing: number, unsupported: number) =>
      `; ${fmtNum(k)} text${s(k)} (chain narratives, incident and story notes, the summary) read for the addresses, accounts and hashes ${k === 1 ? 'it names' : 'they name'}: ${fmtNum(verified)} whose rows hold every value named, ${fmtNum(nothing)} naming none (nothing to check), ${fmtNum(unsupported)} naming a value no row holds`,
    measures: (detects: number, leads: number, on: string) =>
      `of those rules, ${fmtNum(detects)} fire${detects === 1 ? 's' : ''} on recorded attacks of what ${detects === 1 ? 'it looks' : 'they look'} for and ${fmtNum(leads)} ${leads === 1 ? 'was' : 'were'} never seen to (their findings are marked lead)${on ? `. ${on}` : ''}`,
    floor: (sev: string, onlyReviewed: boolean, fp: boolean, dismissed: number) =>
      `findings below ${sev} severity are not printed${onlyReviewed ? '; only reviewed items are printed' : ''}${fp ? '; false positives are printed' : '; false positives are not printed'}${dismissed ? `; ${fmtNum(dismissed)} ${dismissed === 1 ? 'story' : 'stories'} decided benign or false positive ${dismissed === 1 ? 'is' : 'are'} not printed` : ''}`,
    decisions: (c: number, r: number, f: number, u: number) => `${c} confirmed, ${r} reviewed or unsure, ${f} false positive${s(f)}, ${u} undecided`,
    aiTexts: (k: number) =>
      k
        ? `${k} text${s(k)} in this report ${k === 1 ? 'was' : 'were'} drafted by the analyst model and are labelled as such; decisions are the analyst's`
        : 'no text in this report was drafted by a model',
  },

  limit: {
    title: 'Where it stops',
    draft: (open: string) => `This is a draft. Open before it can be final: ${open || 'the analyst has not issued it'}.`,
    waived: (label: string, reason: string) => `Issued with an open check: ${label}. The analyst's reason: ${reason}`,
    questionsOpen: (k: number, uncovered: number) =>
      `${fmtNum(k)} investigative question${k === 1 ? ' is' : 's are'} still open${uncovered ? `; ${fmtNum(uncovered)} of them with no evidence in the case that could answer ${uncovered === 1 ? 'it' : 'them'}` : ''}.`,
    questionsCannot: (k: number) => `${fmtNum(k)} investigative question${s(k)} cannot be answered from this evidence.`,
    findingClaim: (title: string, ruleId: string, contradicted: boolean, reasons: string) =>
      `The finding "${title}" (${ruleId}) is ${contradicted ? 'contradicted by its rows' : 'unsupported'}: ${reasons}.`,
    textClaim: (what: string, reasons: string) => `${what[0].toUpperCase()}${what.slice(1)} is unsupported: ${reasons}.`,
    moreClaims: (k: number) => `${fmtNum(k)} more claims do not hold against their rows; the Report page lists them.`,
    leads: (k: number) =>
      `${fmtNum(k)} printed finding${k === 1 ? ' comes from a rule' : 's come from rules'} never seen to detect what ${k === 1 ? 'it looks' : 'they look'} for on recorded attacks (marked lead): each says where to look, and stands on the rows it cites and the analyst's decision.`,
    times: 'Times are UTC. Rules and timelines describe what the evidence records; the absence of a finding is not evidence of absence.',
    snapshots: 'Collection snapshots record when an artefact was collected, not when it was created or run.',
    chains: (w: string) => `Chain analysis incomplete: ${w}`,
    storiesStale: (why: string) => `Stories out of date: ${why}.`,
    storiesCut: (w: string) => `Stories incomplete: ${w}`,
    packages: (x: string) => `Package coverage: ${x}`,
    iocsChecked: (k: number, total: number) => `${k} of ${total} indicators were checked against reputation services.`,
    iocsNone: 'No indicator was checked against a reputation service; indicators are not enriched.',
    rulesNotRun: 'The detection rules had not run on this case when the report was made.',
    evidenceAfter: (k: number) => `${k} evidence file(s) were added after the last rule run; their findings may be missing.`,
    file: (name: string, issue: string) => `${name}: ${issue}.`,
    completeness: (r: string) => `Completeness: ${r}.`,
    initialAccessDraft: "The initial access offered from a story's spine has not been rewritten by the analyst; the report does not print it as a conclusion.",
    noConclusion: 'The analyst has stated neither the initial access nor the root cause.',
  },

  question: {
    /** REMN's own scenarios, facets and questions by id, where the language writes them otherwise than the catalog */
    catalog: {} as Record<string, string>,
    /** the kinds of evidence by id, where the language writes them otherwise than the catalog */
    evidenceKind: {} as Record<string, string>,
    /** whether the case holds the evidence a question lists (data/questions/coverage.ts) */
    coverage: (held: { label: string; count: number }[], missing: string[]) =>
      held.length
        ? `covered by the ${enList(
            held.map((x) => `${x.label} (${fmtNum(x.count)} ${x.count === 1 ? 'row' : 'rows'})`),
            'and',
          )}`
        : `not covered: no ${enList(missing, 'or')} in this case`,
    finding: 'finding',
    noCitation: 'no record cited',
    unanswered: 'unanswered',
    evidence: (coverage: string) => `Evidence: ${coverage}`,
    intro: (answered: number, cannot: number, open: number, uncovered: number) =>
      `The questions the investigation set out to answer, from the scenarios chosen for the case (DFIQ, dfiq.org, and REMN's own, whose ids start with 0). Each carries the analyst's answer and the records or findings it rests on. ${fmtNum(answered)} answered, ${fmtNum(cannot)} cannot be answered from this evidence, ${fmtNum(open)} still open${uncovered ? `, ${fmtNum(uncovered)} of them with no evidence in the case that could answer ${uncovered === 1 ? 'it' : 'them'}` : ''}.`,
  },

  client: {
    client: 'Client',
    reference: 'Engagement reference',
    dates: 'Engagement dates',
    requestedBy: 'Requested by',
    between: (from: string, to: string) => `${from} to ${to}`,
    from: (from: string) => `from ${from}`,
    until: (to: string) => `until ${to}`,
    distribution: 'Distribution',
    versions: 'Version history',
    versionHead: ['version', 'date', 'author', 'changes'],
    period: 'Period examined',
    periodDerived: 'from the evidence: the first and last record it holds',
    derived: (what: string, capped: number) => `from the evidence: ${what}${capped ? ` (the ${fmtNum(capped)} most frequent; it names more)` : ''}`,
    systemsIn: 'Systems in scope',
    systemsOut: 'Systems out of scope',
    systemsWhat: 'the hosts its records come from',
    accountsIn: 'Accounts in scope',
    accountsOut: 'Accounts out of scope',
    accountsWhat: 'the user accounts its records name',
    evidence: 'Evidence',
    evidenceFiles: (k: number) => `${fmtNum(k)} file${s(k)}, listed with their digests under Evidence and chain of custody`,
    noDate: 'no date',
    containmentHead: ['date', 'action', 'by'],
    containmentIntro: 'The containment and eradication actions taken, as the analyst recorded them.',
    short: 'Short term',
    medium: 'Medium term',
    long: 'Long term',
    initialAccess: 'Initial access',
    rootCause: 'Root cause',
    impactIntro:
      'The accounts and hosts the confirmed items name, printed or not: the people a confirmed chain or story is about, the hosts it ran on, and the accounts and hosts of the findings confirmed with them. Machine, service and built-in accounts are left out.',
    impactNote: "the analyst's account of the impact",
    impactNoteDocx: "The analyst's account of the impact.",
    impactNone: 'No confirmed item names an account or a host.',
    impactHead: ['', 'first seen (UTC)', 'last seen (UTC)', 'worst severity', 'named by'],
    account: 'account',
    host: 'host',
    also: (aliases: string) => ` (also ${aliases})`,
    item: {
      chain: (label: string) => `chain ${label}`,
      incident: (title: string) => `incident ${title}`,
      unprinted: (title: string) => (title ? `confirmed item not printed (${title})` : 'confirmed item not printed'),
      story: (title: string) => `story ${title}`,
      finding: (title: string, ruleId: string) => `confirmed finding ${title} (${ruleId})`,
      lookup: (sources: string[]) => `reputation lookup${sources.length ? ` (seen in ${sources.join(', ')})` : ''}`,
    },
  },

  indicator: {
    head: ['kind', 'indicator', 'where it comes from', 'reputation'],
    notLookedUp: 'not looked up',
    intro:
      "The addresses, domains, mail senders, URLs and hashes the confirmed chains, stories and findings name, whether or not a reputation lookup ran, and those a reputation service flagged. Addresses that are not public and the case's own domains are left out. Values are defanged.",
    left: (k: number, max: number) => `${fmtNum(k)} more indicator${k === 1 ? ' is' : 's are'} not listed: the appendix holds ${fmtNum(max)}.`,
    none: 'No confirmed item names an outside address, domain, sender, URL or hash, and no reputation service flagged one.',
  },

  technique: {
    head: ['technique', 'tactic', 'findings', 'rules', 'confirmed'],
    unmapped: 'not mapped to a tactic',
    yes: 'yes',
    no: 'no',
    intro:
      'Each ATT&CK technique the printed findings carry, false positives left out, and those of the confirmed findings left out of the print: its tactic, how many findings, which rules, and whether a confirmed item carries it.',
  },

  evidence: {
    head: ['file', 'kind', 'size', 'rows', 'SHA-256', 'integrity', 'read', 'added (UTC)'],
    incomplete: (issue: string) => `incomplete: ${issue}`,
    complete: 'complete',
    none: 'No evidence file.',
    packages: 'Investigation package coverage',
    packageHead: ['package', 'coverage'],
    noIssues: 'No reported import issues',
  },

  relationship: {
    intro: 'Analyst-selected connections. Observation and collection times remain distinct; shared entities do not establish causation.',
    aliases: (json: string) => `Explicit aliases: ${json}`,
    head: ['Source', 'Record', 'Time (UTC)', 'SHA-256'],
    record: (source: string, id: string | number | null, evidence: number | null, row: number) => `${source} #${id} · evidence #${evidence} · source row ${row}`,
    collected: (at: string) => `Collected: ${at}`,
    event: (at: string) => `Event: ${at}`,
  },

  timeline: { head: ['when (UTC)', 'entry', 'from'] },

  settingsLine: (o: { domains: string; vips: string; start: number; end: number; tz: string; lookups: number; floor: string; onlyReviewed: boolean; fp: boolean; detail: string }) =>
    `internal domains: ${o.domains || '—'} · VIPs: ${o.vips || '—'} · business hours ${o.start}h–${o.end}h (${o.tz}) · reputation lookups ${o.lookups ? `run on ${fmtNum(o.lookups)} indicator${s(o.lookups)}` : 'not run'} · report floor ${o.floor}${o.onlyReviewed ? ' · reviewed items only' : ''}${o.fp ? ' · false positives included' : ''} · chain steps: ${o.detail}`,

  docx: {
    generated: (at: string, analyst: string) => `Generated ${at} · ${analyst}`,
    final: (at: string) => `final, issued ${at}`,
    draft: 'DRAFT, not issued',
    completeness: (level: string) => `Completeness ${level}: `,
    completenessSub: 'How complete the review is, not how sure its conclusion is.',
    analystConfidence: (level: string, basis: boolean) => `Analyst's confidence ${level}${basis ? ': ' : ''}`,
    analystConfidenceSub: "The analyst's own assessment of the conclusion.",
    bySeverity: (bySev: string, c: number, r: number, f: number, u: number, verified: string) =>
      `By severity: ${bySev}. Decisions: ${c} confirmed, ${r} reviewed or unsure, ${f} false positive${s(f)}${u ? `, ${u} without a decision` : ', every item decided'}. ${verified} evidence files verified by digest.`,
    profile: (confirmed: string, observed: string) => `Threat profile: ${[confirmed ? `confirmed: ${confirmed}` : '', observed ? `observed: ${observed}` : ''].filter(Boolean).join('. ')}.`,
    footer: (brand: string, name: string, verdict: string, draft: boolean) => `${brand} · ${name} · ${verdict}${draft ? ' · draft' : ''} · page `,
  },

  print: {
    /** the running page number in print, as CSS content around counter(page) and counter(pages) */
    page: 'page ',
    of: ' of ',
  },

  preflight: {
    unknown: 'the state of the last rule run is not known',
    notRun: 'the detection rules have not run on this case',
    failed: (k: number) => `${k} rule(s) failed in the last run`,
    after: (k: number) => `${k} evidence file(s) were added after the last rule run`,
    rules: 'Detection rules ran on all the evidence',
    rulesOk: 'the last run covered every file',
    read: 'Every evidence file was read completely',
    readList: (names: string[], more: number) => `${names.join(', ')}${more > 0 ? ` and ${more} more` : ''}`,
    readOk: 'no parse error, limit or unread member',
    integrity: 'Every evidence file has a verified digest',
    integrityBad: (k: number) => `${k} file(s) without a verified SHA-256`,
    integrityOk: 'browser and server digests match',
    decided: 'Every item has a decision',
    decidedBad: (k: number) => `${k} item(s) without a decision`,
    decidedOk: 'the review is complete',
    ai: 'Decisions taken from the model were checked',
    aiBad: (k: number) => `${k} decision(s) came from the model's proposals`,
    aiOk: 'every decision is the analyst’s',
    printed: 'Every confirmed item is printed',
    printedBad: (k: number) => `${k} confirmed item(s) below the severity floor or left out`,
    printedOk: 'the report carries every confirmed item',
    claims: 'What the report says holds against the rows it cites',
    claimsPending: 'the printed findings and texts are still being checked against their rows',
    contradicted: (k: number) => `${k} finding(s) contradicted by their rows`,
    unsupported: (k: number) => `${k} finding(s) whose rows are not all in the case`,
    textsUnsupported: (k: number) => `${k} text(s) naming values their rows do not hold`,
    claimsOk: (k: number, texts: number) => `${k} finding(s) and ${texts} text(s) read back against their rows`,
  },

  /** what a story build could not read (data/stories.ts storyCoverageWarnings), with its caps */
  storyCut: {
    flagged: (cap: number, left: number) => `More than ${fmtNum(cap)} records carry findings: the stories read the first ${fmtNum(cap)}${left ? ` and left ${fmtNum(left)} out` : ''}.`,
    refs: (k: number, cap: number) => `${k ? fmtNum(k) : 'Some'} finding(s) cite more than ${fmtNum(cap)} records: the stories read the first ${fmtNum(cap)} of each.`,
    identities: (cap: number) =>
      `The records naming the flagged people passed ${fmtNum(cap)}: the stories read the tasks, services and account changes among them first, then those nearest the flags.`,
    addresses: (cap: number) =>
      `The records from the flagged addresses passed ${fmtNum(cap)}: the stories read the tasks, services and account changes among them first, then those nearest the flags.`,
    hosts: (cap: number) =>
      `The logons, processes and services on the flagged hosts passed ${fmtNum(cap)}: the stories read the tasks, services and account changes among them first, then those nearest the flags.`,
    context: (cap: number, people: number, addresses: number, hosts: number) => {
      const left = [
        people ? `${fmtNum(people)} naming the flagged people` : '',
        addresses ? `${fmtNum(addresses)} from the flagged addresses` : '',
        hosts ? `${fmtNum(hosts)} on the flagged hosts` : '',
      ].filter(Boolean)
      return `The records around the flags passed ${fmtNum(cap)}, which a browser case reads under one cap for the flagged people, addresses and hosts together: the stories read the tasks, services and account changes among them first, then those nearest the flags${left.length ? ` and left out ${left.join(', ')}` : ''}.`
    },
    flaggedMails: (cap: number, left: number) => `More than ${fmtNum(cap)} mails carry findings: the stories read the first ${fmtNum(cap)}${left ? ` and left ${fmtNum(left)} out` : ''}.`,
    seeds: (left: number, cap: number, risk: number) => `${left ? fmtNum(left + cap) : `More than ${cap}`} mails score a risk of ${risk} or more: the stories read the ${cap} riskiest.`,
    undated: (k: number) => `${k ? fmtNum(k) : 'Some'} flagged or high-risk mail(s) carry no date: no story can place them, so none reads them.`,
    windows: (k: number, most: number) =>
      `The flags fall in ${k ? fmtNum(k) : `more than ${most}`} separate periods: the stories read one period from the first flag to the last instead, where the caps are reached sooner.`,
    replies: (cap: number) => `Only ${fmtNum(cap)} of the mails the flagged people sent were read, those nearest the flags.`,
    dns: (cap: number) => `The DNS answers on the flagged hosts passed ${fmtNum(cap)}: the addresses they give to hosts come from those nearest the flags.`,
    dhcp: (cap: number) => `The DHCP leases passed ${fmtNum(cap)}: the addresses they give to hosts come from the first ones.`,
    dc: (cap: number) =>
      `The domain controllers' Kerberos and NTLM records of the flagged people, hosts and addresses passed ${fmtNum(cap)}: the stories read those naming a flagged account or host first, then those nearest the flags, so a hop may miss the ticket that names its source.`,
    nameKeys: 'The flagged records name more than 2,000 accounts: the stories read the records of the 2,000 they name most.',
    hostKeys: 'More than 500 hosts carry flags: the stories read the logons, processes and services of the 500 with the most.',
    addressKeys: 'The flags name more than 500 outside addresses: the stories read the records from the 500 they name most.',
    trimmed: (mib: number, k: number, to: number) =>
      `The rows of the build passed ${mib} MiB, more than the server takes in one request: the long text of ${fmtNum(k)} record(s) (command lines, script blocks, summaries) was cut to ${fmtNum(to)} characters.`,
    size: (mib: number, k: number) => `The rows of the build passed ${mib} MiB even so: ${fmtNum(k)} of them were left out, the records around the flags first.`,
    accounts: (cap: number) => `The case writes its accounts in more than ${fmtNum(cap)} ways: who is who reads the most frequent ones and those of the records the stories read.`,
    identityRows:
      'Who is who was read from the records this build read, not the whole case: a bare account name is joined to the only account of that name among them, though the case may hold another.',
    storiesTruncated: 'Only the highest-scoring 200 stories are kept: the flags of the others are listed with those in no story.',
    noWayIn: 'No record of the story shows how it started: initial access is not in the evidence it reads.',
  },

  /** why a story build no longer reads the case as it is (data/stories.ts storiesStaleness) */
  storyStale: {
    unknown: 'they were built before REMN kept what a build reads, so they may not match the findings',
    findings: 'the findings changed since they were built (a rule run, a false positive or a severity set by hand)',
    evidence: 'the evidence changed since they were built',
    settings: "the case's settings changed since they were built",
  },

  /** what a chain build could not read (data/chains.ts chainCoverageWarnings), by the stat that says so */
  chainCut: {
    eventsTruncated: 'Mail correlation: only the first 50,000 matching events were considered.',
    authEventsTruncated: 'Authentication campaigns: only the first 50,000 authentication events were considered.',
    seedsTruncated: 'Mail seed selection reached its limit (300 seeds or 500 finding references).',
    repliesTruncated: 'Only the first 5,000 matching replies were considered.',
    chainsTruncated: 'Only the highest-scoring chains are displayed.',
  } as Record<string, string>,

  /** what an investigation package did not read or account for (data/packageCoverage.ts) */
  packageIssue: {
    errors: (k: number) => `${k} failed members`,
    unsupported: (k: number) => `${k} unsupported members`,
    skipped: (k: number) => `${k} skipped members`,
    inventory: 'incomplete member inventory',
    discrepancies: (k: number) => `${k} collection summary discrepancies or unresolved entries`,
  },

  /** what the rules were measured on (data/ruleMeasures.ts measuredOn) */
  measuredOn: {
    sigma: (k: number) => `${fmtNum(k)} SigmaHQ regression samples`,
    attackSamples: (k: number) => `${fmtNum(k)} EVTX-ATTACK-SAMPLES recordings`,
    attackData: (k: number) => `${fmtNum(k)} Microsoft 365 and Entra ID datasets of Splunk attack_data`,
    attackDataWindows: (k: number) => `${fmtNum(k)} Windows event-log datasets of Splunk attack_data`,
    evtxToMitre: (k: number) => `${fmtNum(k)} EVTX-to-MITRE-Attack recordings`,
    sentence: (on: string, recorded: string[], clean: { machines: number; tag: string; events: number } | null) =>
      `Measured on ${on}${recorded.length ? ` on ${enList(recorded, 'and')}` : ''}${clean ? `, and on the logs of ${fmtNum(clean.machines)} clean Windows machines of evtx-baseline ${clean.tag} (${fmtNum(clean.events)} events)` : ''}.`,
  },
}

export type ReportText = typeof en

// ---------------------------------------------------------------------------
// French: plain professional French, as a responder writes to a client
// ---------------------------------------------------------------------------

const frNum = (x: number | null | undefined) => (x == null || !Number.isFinite(x) ? '' : x.toLocaleString('fr-FR'))
/** in French a count of zero or one takes the singular */
const p = (k: number, one: string, many: string) => (Math.abs(k) < 2 ? one : many)
const frTs = (ms: number | null | undefined) => {
  if (ms == null || !Number.isFinite(ms)) return ''
  const d = new Date(ms)
  if (Number.isNaN(d.getTime())) return ''
  return `${pad(d.getUTCDate())}/${pad(d.getUTCMonth() + 1)}/${d.getUTCFullYear()} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`
}
const FR_UNITS: Record<string, string> = { B: 'o', KB: 'Ko', MB: 'Mo', GB: 'Go', TB: 'To' }
const frBytes = (b: number | null | undefined) => {
  const m = /^([\d.]+) ([A-Z]+)$/.exec(fmtBytes(b))
  return m ? `${m[1].replace('.', ',')} ${FR_UNITS[m[2]] ?? m[2]}` : ''
}
const FR_SEV: Record<string, string> = { critical: 'critique', high: 'haute', medium: 'moyenne', low: 'basse', info: 'info' }
const frSev = (sev: string) => FR_SEV[sev] ?? sev
/** a date the analyst entered (yyyy-mm-dd) as French writes it; anything else is printed as written */
const frDay = (iso: string) => {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso.trim())
  return m ? `${m[3]}/${m[2]}/${m[1]}` : iso
}
/** a list the way French writes it: a, b et c */
const frList = (xs: string[], join: string) => (xs.length <= 2 ? xs.join(` ${join} `) : `${xs.slice(0, -1).join(', ')} ${join} ${xs[xs.length - 1]}`)
const frDur = (ms: number) => {
  if (!Number.isFinite(ms)) return ''
  const sec = Math.round(ms / 1000)
  if (sec < 60) return `${sec} s`
  const m = Math.floor(sec / 60)
  if (m < 60) return `${m} min ${sec % 60} s`
  const h = Math.floor(m / 60)
  if (h < 48) return `${h} h ${m % 60} min`
  return `${Math.floor(h / 24)} j ${h % 24} h`
}
const FR_CLOUD: Record<string, string> = {
  ual: "enregistrement d'audit",
  entra: 'connexion',
  'entra-audit': "audit de l'annuaire",
  'entra-risk': 'détection de risque',
  'entra-riskyuser': 'utilisateur à risque',
  'exo-trace': 'suivi de message',
}
const frRecord = (at: RecordPlace): string => {
  switch (at.kind) {
    case 'message':
      return `message ${frNum(at.n)}`
    case 'message-id':
      return `Message-ID ${at.id}`
    case 'cloud':
      return `${FR_CLOUD[at.what] ?? 'enregistrement'} ${at.id}`
    case 'record':
      return `enregistrement ${frNum(at.n)}${at.channel && at.computer ? ` (${at.channel} sur ${at.computer})` : ''}`
    default:
      return `ligne ${typeof at.n === 'number' ? frNum(at.n) : at.n}`
  }
}
const frWhere = (w: GapWhere) =>
  w.channel && w.computer
    ? `${w.channel} sur ${w.computer} (${w.file})`
    : w.channels != null || w.computers != null
      ? `${w.file} (${frNum(w.channels ?? 1)} ${p(w.channels ?? 1, 'canal', 'canaux')} de ${frNum(w.computers ?? 1)} ${p(w.computers ?? 1, 'ordinateur', 'ordinateurs')})`
      : w.file
const FR_CAPS: Record<ExportSource, { records: string; limits: Record<number, string>; missing: string }> = {
  ual: {
    records: "enregistrements du journal d'audit unifié",
    limits: { 5000: 'le maximum que renvoie un appel à Search-UnifiedAuditLog', 50000: 'le maximum que renvoie une recherche en grand volume' },
    missing: 'Les enregistrements',
  },
  'message-trace': {
    records: 'lignes de suivi des messages',
    limits: { 1000: 'le nombre que Get-MessageTrace et Get-MessageTraceV2 renvoient par défaut', 5000: 'le maximum que renvoie Get-MessageTraceV2' },
    missing: 'Les messages',
  },
  'entra-audit': { records: "enregistrements d'audit de l'annuaire", limits: { 250000: "le maximum que le centre d'administration Entra télécharge en un fichier" }, missing: 'Les enregistrements' },
}
const frGap = (g: GapSay): string => {
  switch (g.kind) {
    case 'record-holes': {
      const floor = g.floor ? 'au moins ' : ''
      const [a, b] = g.largest
      return (
        `${frWhere(g.where)} : ${floor}${frNum(g.missing)} ${p(g.missing, 'enregistrement manque', 'enregistrements manquent')} dans sa numérotation, en ${floor}${frNum(g.gaps)} ${p(g.gaps, 'trou', 'trous')} ` +
        `entre l'enregistrement ${frNum(g.first)} et l'enregistrement ${frNum(g.last)} (le plus grand : ${frNum(a)}${b > a ? `–${frNum(b)}` : ''}). ` +
        "Des enregistrements ont été supprimés du journal, ou se trouvent dans une partie qui n'a pas pu être lue."
      )
    }
    case 'checksum-data':
      return `${g.file} : ${frNum(g.bad)} ${p(g.bad, 'bloc', 'blocs')} sur ${frNum(g.chunks)} ${p(g.bad, 'échoue', 'échouent')} au contrôle de somme. Leurs enregistrements ont été modifiés après leur écriture par Windows, ou endommagés ; ils ont été lus malgré tout.`
    case 'checksum-header':
      return `${g.file} : ${[g.headers ? `${frNum(g.headers)} ${p(g.headers, 'en-tête de bloc', 'en-têtes de bloc')}` : '', g.fileHeader ? "l'en-tête du fichier" : ''].filter(Boolean).join(' et ')} ${g.headers + (g.fileHeader ? 1 : 0) > 1 ? 'échouent' : 'échoue'} au contrôle de somme : la structure du fichier a été modifiée après son écriture.`
    case 'clock-logs':
      return `Sur ${g.computer}, ${frNum(g.logs)} journaux reculent ensemble à ${frTs(g.from)}, de ${frDur(g.from - g.to)} au plus : son horloge a été retardée, et aucun journal collecté n'enregistre ce changement. Les événements horodatés entre ${frTs(g.to)} et ${frTs(g.from)} peuvent s'être produits avant ou après, leurs heures n'en donnent donc pas l'ordre.`
    case 'clock-set':
      return `L'horloge de ${g.computer} a été retardée de ${frDur(g.from - g.to)} à ${frTs(g.from)}, pour indiquer ${frTs(g.to)} : les événements horodatés entre ces deux heures peuvent s'être produits avant ou après le changement, leurs heures n'en donnent donc pas l'ordre.`
    case 'time-backwards':
      return (
        `${frWhere(g.where)} : les heures d'écriture reculent ${frNum(g.steps)} fois entre des enregistrements consécutifs, sans changement d'horloge ni démarrage du service de journalisation dans les éléments de preuve pour ${g.steps === 1 ? "l'expliquer" : 'les expliquer'} ` +
        `(le plus grand recul : ${frDur(g.largest)}, à l'enregistrement ${frNum(g.record)}${g.unread ? ` ; ${frNum(g.unread)} autres reculs n'ont pas été examinés` : ''}). ` +
        "Un enregistrement a été inséré après coup, ou l'horloge a changé sans qu'un journal collecté ne l'enregistre (System et Security enregistrent les changements d'horloge)."
      )
    case 'missing-between-files':
      return `${g.channel} sur ${g.computer} : ${g.from === g.to ? `l'enregistrement ${frNum(g.from)} ne figure` : `les enregistrements ${frNum(g.from)}–${frNum(g.to)} ne figurent`} dans aucun des fichiers lus (${g.before} s'arrête à l'enregistrement ${frNum(g.beforeLast)}, ${g.after} commence à l'enregistrement ${frNum(g.afterFirst)}) : une archive ou un export manque.`
    case 'log-starts-late':
      return `Sur ${g.computer}, ${g.count === 1 ? 'un journal commence' : `${frNum(g.count)} journaux commencent`} après la première détection (${frTs(g.start)}) : ${g.logs.map(([channel, ts]) => `${channel} à ${frTs(ts)}`).join(', ')}${g.count > g.logs.length ? ` et ${frNum(g.count - g.logs.length)} de plus` : ''}. Les événements antérieurs y ont été écrasés ou n'ont pas été collectés.`
    case 'export-cap': {
      const cap = FR_CAPS[g.source]
      return `${g.file} : exactement ${frNum(g.records)} ${cap.records}, ${cap.limits[g.records] ?? ''}. ${cap.missing} postérieurs à ce point de sa période manquent probablement.`
    }
    case 'xml-export':
      return (
        `${g.file} : ${frNum(g.records)} ${g.records < 2 ? "enregistrement d'événement exporté" : "enregistrements d'événements exportés"} en XML. Un export contient ce que sa requête a sélectionné, sans la numérotation propre du fichier journal : ` +
        "un enregistrement supprimé du journal avant l'export ne se distingue pas d'un enregistrement que l'export a laissé de côté ; le fichier journal lui-même (wevtutil epl) permet de le vérifier."
      )
    case 'parse-limit':
      return `${g.file} : lu jusqu'à la limite d'analyse et pas au-delà (${frNum(g.kept)} ${p(g.kept, 'ligne conservée', 'lignes conservées')}). Les enregistrements situés après ce point du fichier ne sont pas dans le dossier.`
    case 'read-in-part':
      return `${g.file} : lu en partie (${g.note}). Ce que le fichier contient après ce point n'est pas dans le dossier.`
    case 'mail-throttled':
      return `MailItemsAccessed a été limité pour ${g.user} à partir de ${frTs(g.from)} : pendant les 24 heures suivantes, les lectures d'éléments de la boîte n'ont pas été enregistrées une à une, la liste des messages lus pendant cette période ne peut donc pas être établie.`
    case 'signins-start-late':
      return `Les connexions Entra commencent à ${frTs(g.first)}, après la première détection (${frTs(g.start)}) : les connexions antérieures ne sont pas dans les éléments de preuve. Entra les conserve 7 jours sans licence P1 ou P2, 30 jours avec.`
  }
}
const frClaim = (w: ClaimWhy): string => {
  switch (w.kind) {
    case 'no-rows':
      return 'aucune ligne citée'
    case 'rows-missing':
      return `${frNum(w.missing)} des ${frNum(w.checked)} ${p(w.checked, 'ligne citée', 'lignes citées')} ${w.missing < 2 ? "n'est plus" : 'ne sont plus'} dans le dossier : ${p(w.missing, 'supprimée, ou renumérotée', 'supprimées, ou renumérotées')} quand des éléments de preuve ont été ajoutés à nouveau`
    case 'no-match':
      return `${w.records.map((r) => `${r.file} ${frRecord(r.at)}`).join(' et ')}${w.more ? ` et ${frNum(w.more)} de plus` : ''} ${w.records.length + w.more === 1 ? 'ne correspond plus' : 'ne correspondent plus'} à la règle`
    case 'value-absent':
      return `elle indique ${w.field} ${w.values.join(', ')}, qu'aucune de ses lignes ne contient`
    case 'time':
      return `son heure, ${frTs(w.ts)}, n'est pas celle de sa première ligne (${frTs(w.first)})`
    case 'text-absent':
      return `${w.values.join(', ')}${w.more ? ` et ${frNum(w.more)} de plus` : ''} ${w.values.length + w.more === 1 ? "n'apparaît" : "n'apparaissent"} dans aucune de ses ${frNum(w.rows)} ${p(w.rows, 'ligne', 'lignes')}`
    case 'text-absent-case':
      return `${w.values.join(', ')}${w.more ? ` et ${frNum(w.more)} de plus` : ''} ${w.values.length + w.more === 1 ? "n'apparaît" : "n'apparaissent"} dans aucune ligne des éléments de preuve`
  }
}
/** REMN's own scenarios, facets and questions (tools/dfiq_remn.yaml), as the French report writes them */
const FR_CATALOG: Record<string, string> = {
  S0001: "Durée de présence (première et dernière activité de l'attaquant)",
  S0002: 'Exposition à une compromission de messagerie (BEC)',
  F0001: "Quand l'attaquant est-il entré pour la première fois ?",
  F0002: "Quand l'attaquant a-t-il été actif pour la dernière fois, et est-ce terminé ?",
  F0003: 'Que manque-t-il aux éléments de preuve entre la première et la dernière activité ?',
  F0004: "Le compte a-t-il été pris en main par l'attaquant ?",
  F0005: "L'attaquant a-t-il laissé quelque chose dans la boîte aux lettres ou le tenant ?",
  F0006: "Qu'est-ce que l'attaquant a lu ou emporté ?",
  F0007: "L'attaquant a-t-il envoyé des messages depuis le compte ou atteint d'autres personnes ?",
  Q0001: "Quelle est la première activité liée à l'attaquant ?",
  Q0002: "Comment l'attaquant est-il entré (hameçonnage, compte valide, service exposé) ?",
  Q0003: "Les journaux remontent-ils avant la première activité de l'attaquant ?",
  Q0004: "Quelle est la dernière activité liée à l'attaquant ?",
  Q0005: "Les comptes de l'attaquant ont-ils été désactivés ou leurs mots de passe réinitialisés, et l'activité s'est-elle arrêtée ensuite ?",
  Q0006: "Existe-t-il une persistance qui survivrait à l'endiguement ?",
  Q0007: "Quels hôtes et quels comptes l'attaquant a-t-il touchés ?",
  Q0008: "Les journaux présentent-ils des trous pendant la période de l'attaque ?",
  Q0009: 'Y a-t-il eu des connexions réussies depuis des pays, des adresses ou des clients inattendus ?',
  Q0010: "L'authentification multifacteur a-t-elle été contournée ou modifiée, ou une nouvelle méthode d'authentification enregistrée ?",
  Q0011: 'Le compte a-t-il été visé par une pulvérisation de mots de passe ou une attaque par force brute ?',
  Q0012: 'Des règles de boîte de réception ont-elles été créées ou modifiées pour transférer, masquer ou supprimer des messages ?',
  Q0013: "Des messages ont-ils été transférés hors de l'organisation (transfert de boîte aux lettres, règles de transport) ?",
  Q0014: 'Des applications ont-elles reçu un consentement, des identifiants ont-ils été ajoutés à une application ou un accès délégué accordé ?',
  Q0015: "À quels éléments de messagerie l'attaquant a-t-il accédé ?",
  Q0016: 'Des boîtes aux lettres ont-elles été fouillées ou exportées ?',
  Q0017: 'Des fichiers ont-ils été téléchargés depuis SharePoint ou OneDrive ?',
  Q0018: "L'attaquant a-t-il envoyé des messages depuis le compte ?",
  Q0019: "Des changements de coordonnées de paiement ou bancaires ont-ils été demandés, dans un sens ou dans l'autre ?",
  Q0020: "La même campagne a-t-elle atteint d'autres personnes de l'organisation ?",
}
/** the kinds of evidence a question lists (tools/dfiq_remn.yaml evidence), with the article French puts before them */
const FR_EVIDENCE: Record<string, string> = {
  security: 'le journal Security',
  system: 'le journal System',
  application: 'le journal Application',
  sysmon: 'le journal Sysmon',
  powershell: "les journaux ou l'historique PowerShell",
  'task-scheduler': 'le journal du Planificateur de tâches',
  defender: 'le journal de Defender',
  print: "le journal du service d'impression",
  'dns-client': 'le journal du client DNS',
  rdp: 'les journaux du Bureau à distance',
  smb: 'les journaux ou sessions SMB',
  'm365-audit': "le journal d'audit unifié",
  'm365-exchange': "les enregistrements d'audit Exchange",
  'm365-files': "les enregistrements d'audit SharePoint et OneDrive",
  'm365-directory': "les enregistrements d'audit de l'annuaire Entra",
  'entra-signin': 'les journaux de connexion Entra',
  'entra-risk': "les détections de risque et utilisateurs à risque d'Entra ID Protection",
  'message-trace': "le suivi des messages d'Exchange Online",
  mail: 'les boîtes aux lettres',
  browser: "l'historique de navigation",
  files: 'les enregistrements du système de fichiers (MFT, USN, LNK, listes de raccourcis)',
  execution: "les artefacts d'exécution (Prefetch, Amcache, ShimCache, BAM, UserAssist)",
  processes: 'la liste des processus',
  programs: 'les programmes installés',
  autoruns: 'les autoruns et le registre',
  services: 'la liste des services',
  tasks: 'la liste des tâches planifiées',
  accounts: 'la liste des utilisateurs et des groupes',
  network: 'les connexions réseau et SRUM',
}

const fr: ReportText = {
  lang: 'fr',
  wordLang: 'fr-FR',
  num: frNum,
  ts: frTs,
  bytes: frBytes,
  day: frDay,
  to: 'au',
  andMore: (k: number) => `et ${frNum(k)} de plus`,
  plusMore: (k: number) => `+${frNum(k)} de plus`,
  noEventTime: "pas d'horodatage",
  dur: frDur,
  record: frRecord,
  gap: frGap,
  claim: {
    reason: frClaim,
    about: (a: TextAbout): string =>
      a.kind === 'chain' ? `le récit de la chaîne « ${a.title} »` : a.kind === 'incident' ? `les notes sur « ${a.title} »` : a.kind === 'story' ? `la note sur le récit « ${a.title} »` : 'la synthèse',
  },

  sev: FR_SEV,
  status: { new: 'non examiné', reviewed: 'examiné', escalated: 'confirmé', false_positive: 'faux positif' },
  chainVerdict: { confirmed: 'confirmé', unsure: 'incertain', benign: 'bénin' },
  storyVerdict: { open: 'ouvert', reviewed: 'examiné', confirmed: 'incident confirmé', benign: 'bénin', false_positive: 'faux positif' },
  answer: { open: 'ouverte', answered: 'répondue', cannot: 'sans réponse possible avec ces éléments' },
  level: { high: 'élevée', medium: 'moyenne', low: 'faible' },
  analytic: { high: 'élevée', moderate: 'modérée', low: 'faible' },
  tie: { strong: 'fort', medium: 'moyen', weak: 'faible' },
  phase: {
    reconnaissance: 'Reconnaissance',
    'resource-development': 'Développement de ressources',
    'initial-access': 'Accès initial',
    execution: 'Exécution',
    persistence: 'Persistance',
    'privilege-escalation': 'Élévation de privilèges',
    stealth: 'Furtivité',
    'defense-impairment': 'Neutralisation des défenses',
    'credential-access': 'Accès aux identifiants',
    discovery: 'Découverte',
    'lateral-movement': 'Mouvement latéral',
    collection: 'Collecte',
    'command-and-control': 'Commande et contrôle',
    exfiltration: 'Exfiltration',
    impact: 'Impact',
    context: 'contexte',
  },
  tactic: {
    'initial-access': 'Accès initial',
    execution: 'Exécution',
    persistence: 'Persistance',
    privilege: 'Élévation de privilèges',
    'defense-evasion': 'Contournement des défenses',
    credential: 'Accès aux identifiants',
    discovery: 'Découverte',
    lateral: 'Mouvement latéral',
    collection: 'Collecte',
    c2: 'Commande et contrôle',
    exfil: 'Exfiltration',
    impact: 'Impact',
    unwanted: 'Logiciel indésirable',
  },
  tacticCode: {
    'initial-access': 'AI',
    execution: 'EX',
    persistence: 'PE',
    privilege: 'EP',
    'defense-evasion': 'CD',
    credential: 'ID',
    discovery: 'DC',
    lateral: 'ML',
    collection: 'CO',
    c2: 'C2',
    exfil: 'EF',
    impact: 'IM',
    unwanted: 'LI',
  },
  transport: {
    browser: "Ollama sur le poste de l'analyste",
    openai: 'un serveur de modèles local compatible OpenAI',
    server: 'Ollama sur le serveur REMN',
    claude: 'Claude Code (Anthropic)',
  },
  claimWord: { verified: 'lignes vérifiées', unsupported: 'lignes manquantes', contradicted: 'lignes en désaccord' },
  integrity: { pending: 'en attente', verified: 'vérifiée', mismatch: 'divergente' },
  indicatorKind: { ip: 'IP', domain: 'domaine', email: 'adresse mail', url: 'URL', hash: 'empreinte' },
  lane: { mail: 'messagerie', m365: 'Microsoft 365', host: 'hôte' },

  section: {
    engagement: 'Mission',
    summary: 'Synthèse',
    scope: 'Périmètre',
    conclusion: 'Conclusion',
    happened: 'Déroulé des faits',
    impact: 'Impact',
    containment: 'Endiguement',
    recommendations: 'Recommandations',
    questions: 'Questions',
    stories: 'Récits',
    chains: "Chaînes d'attaque",
    incidents: 'Incidents',
    evidence: 'Éléments de preuve et chaîne de possession',
    relationships: 'Liens examinés entre éléments de preuve',
    iocs: 'Indicateurs de compromission',
    techniques: 'Techniques ATT&CK',
    timeline: 'Chronologie du dossier',
    tasks: 'Tâches',
    notes: "Notes de l'analyste",
    findings: 'Détections par règle',
    ai: "Recours à l'IA",
    method: 'Méthode et limites',
    settings: 'Paramètres du dossier',
  },

  cover: {
    title: (name: string) => `Rapport REMN · ${name}`,
    tag: "rapport d'analyse forensique",
    subtitle: "Rapport d'analyse forensique REMN",
    analyst: (name: string) => `analyste ${name}`,
    noAnalyst: 'analyste non renseigné',
    final: (at: string) => `définitif · émis le ${at}`,
    draft: 'projet · non émis',
    draftMark: 'PROJET',
    preparedFor: (client: string) => `Établi pour ${client}`,
    engagement: (ref: string) => `mission ${ref}`,
    meta: (floor: string, onlyReviewed: boolean, fp: boolean) =>
      `Heures en UTC · détections de gravité ${frSev(floor)} et au-delà${onlyReviewed ? ', éléments examinés uniquement' : ''}${fp ? ', faux positifs inclus' : ''}`,
    seal: 'verdict',
    bottomLine: "l'essentiel",
    completeness: (level: string) => `complétude ${level}`,
    completenessSub: "mesure l'avancement de l'examen, pas la certitude de la conclusion",
    analystConfidence: (level: string) => `confiance de l'analyste ${level}`,
    analystConfidenceSub: "l'appréciation de l'analyste sur sa conclusion",
    kpi: ['fichiers de preuve', 'lignes analysées', 'détections', 'incidents · chaînes', 'confirmés', 'indicateurs signalés'],
    legend: (c: number, r: number, f: number, u: number, b: (k: number) => string) =>
      `· Décisions : ${b(c)} ${p(c, 'confirmé', 'confirmés')} · ${b(r)} ${p(r, 'examiné ou incertain', 'examinés ou incertains')} · ${b(f)} ${p(f, 'faux positif', 'faux positifs')}${u ? ` · ${b(u)} ${p(u, 'élément sans décision', 'éléments sans décision')}` : ' · chaque élément est décidé'}`,
    profile: 'profil de menace',
    profileCount: (confirmed: number, seen: number, all: number) =>
      `${confirmed ? `${confirmed} ${p(confirmed, 'confirmée', 'confirmées')} · ` : ''}${seen} ${p(seen, 'tactique observée', 'tactiques observées')} sur ${all}`,
    badgeTitle: (label: string, k: number) => `${label} : ${k} ${p(k, 'détection', 'détections')}`,
    verified: 'fichiers de preuve vérifiés par empreinte',
    undecided: (k: string) => `${k} sans décision`,
    reviewComplete: 'examen terminé',
    engine: 'moteur de détection externe utilisé',
    aiText: 'textes rédigés par un modèle, signalés là où ils figurent',
    noAiText: 'aucun texte rédigé par un modèle',
    notEnriched: 'indicateurs non enrichis',
    generated: (at: string) => `produit le ${at}`,
  },

  verdict: {
    notPrinted: (k: number) => ` ${k} d'entre eux ${p(k, "n'est pas imprimé", 'ne sont pas imprimés')} (sous le seuil de gravité ou écartés).`,
    unwanted: 'Logiciel indésirable',
    unwantedDetail: (k: number, sev: string) =>
      `${k} ${p(k, 'élément confirmé décrit', 'éléments confirmés décrivent')} un logiciel indésirable ou publicitaire, de gravité ${frSev(sev)}, sans intrusion.`,
    compromise: 'Compromission confirmée',
    compromiseDetail: (k: number, sev: string) => `${k} ${p(k, 'élément confirmé', 'éléments confirmés')}, le plus grave de gravité ${frSev(sev)}.`,
    suspicious: 'Activité suspecte confirmée',
    suspiciousDetail: (k: number, sev: string) => `${k} ${p(k, 'élément confirmé', 'éléments confirmés')} de gravité ${frSev(sev)} ; aucun n'atteint le niveau haut.`,
    unconfirmed: 'Rien de confirmé',
    unconfirmedDetail: (k: number, undecided: number) => `${k} ${p(k, 'élément examiné', 'éléments examinés')} sans confirmation${undecided ? `, ${undecided} encore sans décision` : ''}.`,
    pending: 'Examen inachevé',
    pendingDetail: (k: number) => `${k} ${p(k, 'élément', 'éléments')} sans décision ; le verdict les attend.`,
    clean: 'Aucune menace confirmée',
    cleanEmpty: "Aucune détection n'a franchi le seuil de gravité ; il n'y avait rien à décider.",
    cleanDetail: (fps: number) => (fps ? `Chaque élément a été examiné ; ${fps} ${p(fps, 'faux positif', 'faux positifs')}.` : "Chaque élément a été examiné et aucun n'a été confirmé."),
  },

  completeness: {
    complete: 'chaque élément décidé, preuves vérifiées, analyse complète',
    undecided: (k: number) => `${k} ${p(k, 'élément non décidé', 'éléments non décidés')}`,
    unverified: (k: number) => `${k} ${p(k, 'fichier de preuve', 'fichiers de preuve')} sans empreinte vérifiée`,
    packages: (k: number) => `couverture des paquets : ${k} ${p(k, 'problème signalé', 'problèmes signalés')}`,
    incomplete: (k: number) => `${k} ${p(k, "fichier de preuve n'a pas été lu", "fichiers de preuve n'ont pas été lus")} entièrement`,
    chains: (k: number) => `analyse des chaînes incomplète (${k} ${p(k, 'limite atteinte', 'limites atteintes')})`,
    rulesNotRun: "les règles n'ont pas été exécutées sur ce dossier",
    evidenceAfter: (k: number) => `${k} ${p(k, 'fichier de preuve ajouté', 'fichiers de preuve ajoutés')} après la dernière exécution des règles`,
    rulesFailed: (k: number) => `${k} ${p(k, 'règle en échec', 'règles en échec')} lors de la dernière exécution`,
    notEnriched: "indicateurs non enrichis (aucune vérification de réputation n'a été faite)",
  },

  evidenceIssue: {
    stopped: (error: string) => (error ? `lecture interrompue : ${error}` : 'lecture interrompue'),
    errors: (k: number) => `${k} ${p(k, 'erreur de lecture', 'erreurs de lecture')}`,
    unread: (k: number) => `${k} ${p(k, "membre d'archive non lu", "membres d'archive non lus")}`,
  },

  ai: {
    intro:
      "Un modèle de langage a assisté cette investigation : il a lu le dossier au moyen d'outils en lecture seule et a fait des propositions ; aucune modification proposée n'a pris effet sans l'accord de l'analyste. Chaque exécution, appel d'outil, proposition et décision est consigné dans le registre IA du dossier, chaîné par empreinte.",
    facts: (runs: number, calls: number, span: string, models: string[], where: string[]) =>
      `${frNum(runs)} ${p(runs, 'exécution', 'exécutions')} · ${frNum(calls)} ${p(calls, "appel d'outil", "appels d'outils")} · ${span}${models.length ? ` · ${p(models.length, 'modèle', 'modèles')} : ${models.join(', ')}` : ''}${where.length ? ` · via ${where.join(', ')}` : ''}`,
    head: ['proposition', 'nombre', 'acceptées', 'rejetées'],
    none: "Le modèle n'a proposé aucune modification du dossier.",
    decisions: (accepted: number, rejected: number, undone: number, notices: number) =>
      `${frNum(accepted)} ${p(accepted, 'acceptée', 'acceptées')}, ${frNum(rejected)} ${p(rejected, 'rejetée', 'rejetées')}${undone ? `, ${frNum(undone)} ${p(undone, 'annulée', 'annulées')} après acceptation` : ''}${notices ? ` · ${frNum(notices)} ${p(notices, 'fois', 'fois')} les preuves contenaient un texte adressé à un modèle (signalé à l'analyste)` : ''}`,
    ledgerIntact: (entries: number) => `registre : ${frNum(entries)} ${p(entries, 'entrée', 'entrées')}, chaîne intacte, tête`,
    ledgerBroken: (entries: number, at: number) => `registre : ${frNum(entries)} ${p(entries, 'entrée', 'entrées')}, chaîne rompue à l'entrée ${frNum(at)}`,
    ledgerBrokenWhy: ' : une entrée a été modifiée ou supprimée après son écriture',
    kind: { decision: 'décision', note: 'note', row_mark: 'marque de ligne', rule: 'règle', summary: 'synthèse' },
    ledgerScope:
      "La chaîne révèle une entrée modifiée après son écriture, une entrée supprimée parmi des entrées plus récentes et un trou dans la numérotation. Elle ne révèle ni la suppression des entrées les plus récentes, ni une chaîne réécrite, à partir de n'importe quelle entrée, par quiconque détient le dossier : aucune clé ne la protège, et elle est conservée dans la base de données du navigateur et dans l'export du dossier. La tête est imprimée en entier : une copie ultérieure du dossier dont le registre contient encore une entrée portant cette empreinte a toutes ses entrées jusqu'à celle-ci telles qu'elles étaient à l'établissement de ce rapport.",
  },

  chain: {
    key: ["message d'amorce", 'étape, colorée selon sa détection la plus grave', 'étapes routinières regroupées', 'lien avec le message'],
    campaignKey: ['personne, colorée selon la chaîne', 'expéditeur ou domaine partagé', 'machine ou IP partagée', 'dans une seule chaîne'],
    scoreParts: { seed: 'amorce', links: 'liens', steps: 'étapes', findings: 'détections', sources: 'sources', score: 'score' },
    score: (score: number, cap?: number | null) => `score ${score}${cap ? ` (plafonné à ${cap})` : ''}`,
    // the model's words are quoted as it wrote them, in whatever language that was: the mark says so
    narrativeByAi: "récit rédigé par le modèle pendant le tri, cité tel qu'il l'a écrit, sans traduction",
    narrativeByAiDocx: "Récit rédigé par le modèle d'analyse, cité tel qu'il l'a écrit, sans traduction.",
    seed: (kind: 'event' | 'mail', subject: string, from: string, at: string, risk: number) =>
      `Amorce : ${kind === 'event' ? 'événement' : 'message'} « ${subject} » de ${from} le ${at} (risque ${risk})`,
    steps: (k: number, from: string, to: string) => `${k} ${p(k, 'étape', 'étapes')} du ${from} au ${to}`,
    ties: (k: number) => `${k} ${p(k, "lien d'artefact", "liens d'artefacts")}`,
    attacker: 'attaquant',
    ips: 'IP',
    hosts: 'hôtes',
    graphAlt: (label: string) => `graphe de la chaîne de ${label}`,
    graphCaption: 'Étapes par couloir, le temps de gauche à droite.',
    head: ['heure (UTC)', 'décalage', 'source', 'étape', 'liens avec le message / détections'],
    minutes: 'min',
    left: (k: number) => `${k} ${p(k, "ligne d'étape non imprimée", "lignes d'étapes non imprimées")} (la liste complète est dans la chaîne, dans REMN)`,
    hidden: (k: number, detail: string) => `${k} ${p(k, 'étape routinière non imprimée', 'étapes routinières non imprimées')} au niveau de détail « ${detail} »`,
    members: (k: number) => `${k} ${p(k, 'détection liée', 'détections liées')} à cette chaîne, ${p(k, 'décidée', 'décidées')} avec elle`,
    triage: (reason: string) => `Note de tri (modèle, citée telle qu'il l'a écrite) : ${reason}`,
    fallbackTitle: 'chaîne',
    verdict: (v: string) => `verdict ${v}`,
    noVerdict: 'sans verdict',
    stepCount: (k: number) => `${frNum(k)} ${p(k, 'étape', 'étapes')}`,
    intro:
      "Une chaîne part d'un message suspect et suit ce que les comptes et les machines du destinataire ont fait ensuite ; son score tient compte de l'amorce, des liens avec le message, des étapes, des détections et des sources en jeu. Les faits, dans l'ordre. Les détections dont les lignes sont des étapes d'une chaîne sont décidées avec elle. Les intitulés des étapes et le résumé automatique sont écrits en anglais par l'analyse des chaînes.",
    introDocx:
      "Une chaîne part d'un message suspect et suit ce que les comptes et les machines du destinataire ont fait ensuite ; son score tient compte de l'amorce, des liens avec le message, des étapes, des détections et des sources en jeu. Les détections dont les lignes sont des étapes d'une chaîne sont décidées avec elle. Les intitulés des étapes et le résumé automatique sont écrits en anglais par l'analyse des chaînes.",
    shared: 'Éléments partagés entre chaînes',
    campaignAlt: 'graphe de campagne',
    campaignCaption: 'Les personnes au centre, les expéditeurs et domaines qui les ont atteintes à gauche, les machines et IP touchées à droite.',
    nothingShared: "aucun expéditeur, domaine, IP ou hôte n'est partagé entre les chaînes",
    graphsInHtml: 'Les graphes des chaînes figurent dans le rapport HTML.',
    appears: (what: string, label: string, chains: number) => `${what} ${label} : présent dans ${chains} chaînes`,
    node: { sender: 'expéditeur', 'attacker address': "adresse de l'attaquant", 'link domain': 'domaine de lien', ip: 'IP', host: 'hôte' },
  },

  story: {
    decided: (label: string, reason: string) => `Décision de l'analyste : ${label}${reason ? ` ; ${reason}` : '.'}`,
    merged: (title: string, orgs: string[] | undefined, reason: string) => `Fusionné par l'analyste : le récit de ${title}${orgs ? ` (autre organisation, ${orgs.join(' et ')})` : ''} ; ${reason}`,
    split: (second: boolean, title: string, at: string, reason: string) => `${second ? "Seconde partie d'un récit scindé par l'analyste" : "Scindé par l'analyste"} à « ${title} » (${at}) ; ${reason}`,
    out: (title: string, k: number, reason: string) => `Retiré par l'analyste : « ${title} » (${frNum(k)} ${p(k, 'enregistrement', 'enregistrements')}) ; ${reason}`,
    disputed: (title: string, at: string, reason: string) => `Contesté par l'analyste et exclu des phases et de la gravité : « ${title} » (${at})${reason ? ` ; ${reason}` : ''}`,
    confirmedSteps: (k: number) => `${frNum(k)} ${p(k, 'étape confirmée', 'étapes confirmées')} par l'analyste.`,
    spine: (k: number, of: number) => `Fil du récit : ${frNum(k)} ${p(k, 'étape', 'étapes')} sur ${frNum(of)}`,
    spineHead: ['quand (UTC)', 'phase', 'étape', 'pourquoi elle est dans le récit'],
    on: 'sur',
    wayIn: "point d'entrée",
    anchor: 'point culminant',
    phases: 'Phases',
    phaseHead: ['phase', 'quand (UTC)', 'étapes', 'ce qui la caractérise'],
    host: 'Hôte',
    person: 'Personne',
    secondPart: ' (seconde partie)',
    firstPart: ' (première partie)',
    confidence: (level: string) => `confiance ${level}`,
    records: (records: number, steps: number) => `${frNum(records)} ${p(records, 'enregistrement', 'enregistrements')} en ${frNum(steps)} ${p(steps, 'étape', 'étapes')}`,
    hosts: 'hôtes',
    from: 'depuis',
    note: "la lecture du récit par l'analyste",
    noteDocx: "La lecture du récit par l'analyste.",
    stops: 'Limites :',
    intrusion: (label: string) => `Une même intrusion : ${label}`,
    count: (k: number) => `${frNum(k)} ${p(k, 'récit', 'récits')}`,
    whyOne: (bases: string) => `Pourquoi ils forment un tout : ${bases}`,
    unprinted: (k: number) =>
      `${frNum(k)} autre${p(k, '', 's')} de ses récits ${p(k, "n'est pas imprimé", 'ne sont pas imprimés')} : sous le seuil de gravité, sans note, ou au-delà des vingt premiers.`,
    cut: (k: number) => `${frNum(k)} ${p(k, 'autre récit lié en est écarté', 'autres récits liés en sont écartés')} : un incident compte au plus vingt récits.`,
    intro:
      "Un récit décrit ce qui est arrivé à une personne, ou sur un hôte, au cours d'un incident : les enregistrements autour de ce qui a déclenché une alerte, lus selon les tactiques ATT&CK dans l'ordre où ils se sont produits, chacun rattaché au récit par son compte, sa session, son accès à l'hôte ou le processus qui l'a lancé. La décision de l'analyste y figure : un récit confirmé compte dans le verdict comme un incident confirmé, un récit jugé bénin ou faux positif n'est pas imprimé, et une étape contestée par l'analyste est exclue des phases et de la gravité du récit et listée sous celui-ci. Chacun indique où s'arrêtent ses preuves. Les intitulés des étapes, ce qui les rattache au récit, ce qui marque chaque phase, la trame et le résumé automatique sont écrits en anglais par l'analyse des récits.",
    stale: (why: string) => `Périmés : ${why}. Ces récits reflètent le dossier tel qu'il était : reconstruisez-les sur la page Stories avant de vous y fier.`,
    cutBuild: (why: string) => `Incomplets : ${why} Une étape ou un récit absent n'est pas un résultat négatif.`,
    orphanedNotes: (k: number) =>
      `${frNum(k)} ${p(k, "note de l'analyste porte", "notes de l'analyste portent")} sur un récit que cette construction ne contient plus : la page Stories ${p(k, 'la liste', 'les liste')} pour les rattacher.`,
    orphanedDecisions: (k: number) =>
      `${frNum(k)} ${p(k, "décision de l'analyste porte", "décisions de l'analyste portent")} sur un récit que cette construction ne contient plus : la page Stories ${p(k, 'la liste', 'les liste')} pour les rattacher, et le rapport n'en tient pas compte.`,
    left: (k: number, onlyReviewed: boolean) =>
      `${frNum(k)} ${p(k, "autre récit n'est pas imprimé", 'autres récits ne sont pas imprimés')} : sous le seuil de gravité${onlyReviewed ? ', sans note ni décision (éléments examinés uniquement)' : ''} ou au-delà des vingt premiers.`,
    dismissed: (k: number) => `${frNum(k)} ${p(k, "récit jugé bénin ou faux positif par l'analyste n'est pas imprimé", "récits jugés bénins ou faux positifs par l'analyste ne sont pas imprimés")}.`,
    startFrom: (title: string, ways: string[], first: string) => `D'après le récit de ${title} : ${ways.length ? `l'accès se lit comme ${ways.join(' ; puis ')}` : `son fil commence par ${first}`}.`,
    startWorst: (step: string) => `Son étape la plus grave : ${step}.`,
    startAt: (title: string, host: string | null, at: string) => `${title}${host ? ` sur ${host}` : ''} le ${at}`,
    title: (title: string) => `Récit de ${title}`,
  },

  finding: {
    lead: 'piste',
    noisy: 'se déclenche aussi sur des machines saines',
    nothingToCheck: "Il ne cite aucune adresse, aucun compte ni aucune empreinte : rien n'a pu être vérifié dans les preuves.",
    checked: (reasons: string) => `Vérifié par rapport à ses lignes : ${reasons}.`,
    groupHead: ['gravité', 'détection', 'détections · lignes', 'quand (UTC)', 'ATT&CK', 'valeurs relevées'],
    ruleHead: ['gravité', 'règle', 'détections · lignes', 'quand (UTC)', 'statut', 'valeurs relevées'],
    ruleHeadDocx: ['gravité', 'règle', 'détections · lignes', 'quand (UTC)', 'statut', 'ATT&CK', 'valeurs relevées'],
    ruleSeverity: (sev: string) => `règle : ${frSev(sev)}`,
    by: (author: string) => `auteur : ${author}`,
    authors: "Les règles Sigma sont l'œuvre des auteurs cités à côté d'elles, publiées par SigmaHQ sous la Detection Rule License 1.1.",
    intro:
      'Chaque détection imprimée, une ligne par règle : combien de détections et de lignes, quand, et les valeurs relevées. Les incidents ci-dessus présentent les mêmes détections dans leur contexte.',
    none: 'Aucune détection ne franchit le seuil de gravité.',
  },

  incident: {
    subtitle: (a: IncidentAbout): string => {
      const found = (k: number, rules: number) => `${k} ${p(k, 'détection', 'détections')} de ${rules} ${p(rules, 'règle', 'règles')}`
      switch (a.kind) {
        case 'chain':
          return `score ${a.score} · ${a.steps} ${p(a.steps, 'étape', 'étapes')} · ${a.linked} ${p(a.linked, 'détection liée', 'détections liées')}`
        case 'mail':
          return `${a.from ? `de ${a.from} · ` : ''}${found(a.findings, a.rules)}`
        case 'entity':
          return `${a.lead} · ${found(a.findings, a.rules)}${a.seenAs.length ? ` · aussi vu comme ${a.seenAs.join(', ')}` : ''}`
        case 'group':
          return a.entities.map(([k, v]) => `${k}=${v}`).join(' · ') || `${a.rows} ${p(a.rows, 'ligne', 'lignes')}`
        default:
          return found(a.findings, a.rules)
      }
    },
    rows: (k: number) => `${frNum(k)} ${p(k, 'ligne', 'lignes')}`,
    noteByAi: "note rédigée par le modèle pendant le tri, citée telle qu'il l'a écrite, sans traduction",
    noteByAiDocx: "Note rédigée par le modèle pendant le tri, citée telle qu'il l'a écrite, sans traduction.",
    intro:
      "Les détections portant sur un même message, ou sur un même utilisateur, hôte ou IP à moins de six heures d'intervalle, forment un incident. Chaque tableau regroupe les détections de l'incident par règle : une ligne par règle, avec le nombre, la période et les valeurs relevées.",
    introDocx:
      "Les détections portant sur un même message, ou sur un même utilisateur, hôte ou IP à moins de six heures d'intervalle, forment un incident. Chaque tableau regroupe les détections de l'incident par règle.",
    none: "Aucun incident hors des chaînes d'attaque ne franchit le seuil de gravité.",
  },

  happened: {
    confirmed: "Les éléments confirmés, dans l'ordre où ils se sont produits.",
    reviewed: "Rien n'a été confirmé ; les éléments examinés, dans l'ordre où ils se sont produits.",
    times: 'Les dates sont celles des événements, en UTC.',
    first: (k: number, total: number) => `Les ${k} premiers sur ${total} sont listés ; les ${total - k} autres, les plus récents, figurent en entier dans les sections incidents et chaînes.`,
    firstDocx: (k: number, total: number) => `Les ${k} premiers sur ${total} sont listés.`,
    noDated: 'Aucun élément daté à placer.',
    noDecision: "Aucun élément n'a encore été décidé : faites l'examen avant d'imprimer.",
    collected: 'artefact collecté',
    head: ['quand (UTC)', 'gravité', 'quoi', 'décision', 'note'],
  },

  summary: {
    byAi: "rédigé par le modèle d'analyse à partir des éléments examinés et cité tel qu'il l'a écrit, sans traduction ; les décisions sur lesquelles il s'appuie sont celles de l'analyste",
    byAiDocx: "Rédigé par le modèle d'analyse à partir des éléments examinés et cité tel qu'il l'a écrit, sans traduction ; les décisions sur lesquelles il s'appuie sont celles de l'analyste.",
    stale: 'rédigé avant la dernière modification des détections : les chiffres et identifiants cités peuvent décrire un état antérieur du dossier',
    staleDocx: 'Rédigé avant la dernière modification des détections : les chiffres et identifiants cités peuvent décrire un état antérieur du dossier.',
  },

  produced: {
    title: 'Comment ce rapport a été produit',
    evidence: (k: number, kinds: string, rows: number) =>
      `${frNum(k)} ${p(k, 'fichier de preuve', 'fichiers de preuve')} (${kinds || 'aucun'}), ${frNum(rows)} ${p(rows, 'ligne analysée', 'lignes analysées')}`,
    rules: (k: number, engine: number) =>
      `${frNum(k)} ${p(k, 'règle a produit', 'règles ont produit')} les détections imprimées${engine ? ` ; ${frNum(engine)} ${p(engine, 'détection provient', 'détections proviennent')} d'un moteur de détection externe` : ''}`,
    claims: (rows: number, verified: number, unsupported: number, contradicted: number) =>
      `chaque détection imprimée a été relue par rapport aux lignes qu'elle cite (les ${frNum(rows)} premières de chacune) : ${frNum(verified)} dont les lignes correspondent à la règle, aux valeurs et à l'heure, ${frNum(unsupported)} non ${p(unsupported, 'étayée', 'étayées')}, ${frNum(contradicted)} ${p(contradicted, 'contredite', 'contredites')}`,
    texts: (k: number, verified: number, nothing: number, unsupported: number) =>
      ` ; ${frNum(k)} ${p(k, 'texte', 'textes')} (récits des chaînes, notes des incidents et des récits, synthèse) ${p(k, 'relu', 'relus')} pour les adresses, comptes et empreintes ${p(k, "qu'il cite", "qu'ils citent")} : ${frNum(verified)} dont les lignes contiennent chaque valeur citée, ${frNum(nothing)} n'en citant aucune (rien à vérifier), ${frNum(unsupported)} citant une valeur absente des lignes`,
    measures: (detects: number, leads: number, on: string) =>
      `parmi ces règles, ${frNum(detects)} se ${p(detects, 'déclenche', 'déclenchent')} sur des attaques enregistrées de ce qu'${p(detects, 'elle cherche', 'elles cherchent')} et ${frNum(leads)} ne ${p(leads, "l'a", "l'ont")} jamais fait (leurs détections sont marquées piste)${on ? `. ${on}` : ''}`,
    floor: (sev: string, onlyReviewed: boolean, fp: boolean, dismissed: number) =>
      `les détections de gravité inférieure à ${frSev(sev)} ne sont pas imprimées${onlyReviewed ? ' ; seuls les éléments examinés sont imprimés' : ''}${fp ? ' ; les faux positifs sont imprimés' : ' ; les faux positifs ne sont pas imprimés'}${dismissed ? ` ; ${frNum(dismissed)} ${p(dismissed, 'récit jugé bénin ou faux positif', 'récits jugés bénins ou faux positifs')} ${p(dismissed, "n'est pas imprimé", 'ne sont pas imprimés')}` : ''}`,
    decisions: (c: number, r: number, f: number, u: number) =>
      `${c} ${p(c, 'confirmé', 'confirmés')}, ${r} ${p(r, 'examiné ou incertain', 'examinés ou incertains')}, ${f} ${p(f, 'faux positif', 'faux positifs')}, ${u} sans décision`,
    aiTexts: (k: number) =>
      k
        ? `${k} ${p(k, 'texte de ce rapport a été rédigé', 'textes de ce rapport ont été rédigés')} par le modèle d'analyse et ${p(k, 'est signalé', 'sont signalés')} comme tel${p(k, '', 's')} ; les décisions sont celles de l'analyste`
        : "aucun texte de ce rapport n'a été rédigé par un modèle",
  },

  limit: {
    title: 'Limites',
    draft: (open: string) => `Ceci est un projet. Points ouverts avant qu'il puisse être définitif : ${open || "l'analyste ne l'a pas émis"}.`,
    waived: (label: string, reason: string) => `Émis avec un contrôle ouvert : ${label}. Motif de l'analyste : ${reason}`,
    questionsOpen: (k: number, uncovered: number) =>
      `${frNum(k)} ${p(k, "question d'investigation reste ouverte", "questions d'investigation restent ouvertes")}${uncovered ? ` ; pour ${frNum(uncovered)} d'entre elles, aucune preuve du dossier ne permet d'y répondre` : ''}.`,
    questionsCannot: (k: number) => `${frNum(k)} ${p(k, "question d'investigation ne peut", "questions d'investigation ne peuvent")} pas recevoir de réponse avec ces preuves.`,
    findingClaim: (title: string, ruleId: string, contradicted: boolean, reasons: string) =>
      `La détection « ${title} » (${ruleId}) est ${contradicted ? 'contredite par ses lignes' : 'non étayée'} : ${reasons}.`,
    textClaim: (what: string, reasons: string) => `Non étayé : ${what} ; ${reasons}.`,
    moreClaims: (k: number) => `${frNum(k)} autres affirmations ne tiennent pas face à leurs lignes ; la page Report les liste.`,
    leads: (k: number) =>
      `${frNum(k)} ${p(k, 'détection imprimée provient', 'détections imprimées proviennent')} de règles jamais vues détecter ce qu'elles cherchent sur des attaques enregistrées (marquées piste) : chacune indique où chercher, et ne vaut que par les lignes qu'elle cite et la décision de l'analyste.`,
    times: "Les heures sont en UTC. Les règles et les chronologies décrivent ce que les preuves enregistrent ; l'absence de détection ne prouve pas l'absence de l'activité.",
    snapshots: 'Les instantanés de collecte indiquent quand un artefact a été collecté, pas quand il a été créé ou exécuté.',
    chains: (w: string) => `Analyse des chaînes incomplète : ${w}`,
    storiesStale: (why: string) => `Récits périmés : ${why}.`,
    storiesCut: (w: string) => `Récits incomplets : ${w}`,
    packages: (x: string) => `Couverture des paquets : ${x}`,
    iocsChecked: (k: number, total: number) => `${k} indicateurs sur ${total} ont été vérifiés auprès de services de réputation.`,
    iocsNone: "Aucun indicateur n'a été vérifié auprès d'un service de réputation ; les indicateurs ne sont pas enrichis.",
    rulesNotRun: "Les règles de détection n'avaient pas été exécutées sur ce dossier quand le rapport a été produit.",
    evidenceAfter: (k: number) => `${k} ${p(k, 'fichier de preuve a été ajouté', 'fichiers de preuve ont été ajoutés')} après la dernière exécution des règles ; leurs détections peuvent manquer.`,
    file: (name: string, issue: string) => `${name} : ${issue}.`,
    completeness: (r: string) => `Complétude : ${r}.`,
    initialAccessDraft: "L'accès initial proposé à partir du fil d'un récit n'a pas été réécrit par l'analyste ; le rapport ne l'imprime pas comme une conclusion.",
    noConclusion: "L'analyste n'a indiqué ni l'accès initial ni la cause première.",
  },

  question: {
    catalog: FR_CATALOG,
    evidenceKind: FR_EVIDENCE,
    coverage: (held: { label: string; count: number }[], missing: string[]) =>
      held.length
        ? `couvert par ${frList(
            held.map((x) => `${x.label} (${frNum(x.count)} ${p(x.count, 'ligne', 'lignes')})`),
            'et',
          )}`
        : missing.length === 1
          ? `non couvert : ce dossier ne contient pas ${missing[0]}`
          : `non couvert : ce dossier ne contient ni ${missing.join(' ni ')}`,
    finding: 'détection',
    noCitation: 'aucun enregistrement cité',
    unanswered: 'sans réponse',
    evidence: (coverage: string) => `Preuves : ${coverage}`,
    intro: (answered: number, cannot: number, open: number, uncovered: number) =>
      `Les questions auxquelles l'investigation devait répondre, issues des scénarios choisis pour le dossier (DFIQ, dfiq.org, et ceux de REMN, dont les identifiants commencent par 0). Les questions de DFIQ sont citées en anglais, telles que DFIQ les publie ; celles de REMN sont traduites. Chacune porte la réponse de l'analyste et les enregistrements ou détections sur lesquels elle repose. ${frNum(answered)} ${p(answered, 'répondue', 'répondues')}, ${frNum(cannot)} sans réponse possible avec ces preuves, ${frNum(open)} encore ${p(open, 'ouverte', 'ouvertes')}${uncovered ? `, dont ${frNum(uncovered)} pour lesquelles aucune preuve du dossier ne permet de répondre` : ''}.`,
  },

  client: {
    client: 'Client',
    reference: 'Référence de la mission',
    dates: 'Dates de la mission',
    requestedBy: 'Demandé par',
    between: (from: string, to: string) => `du ${from} au ${to}`,
    from: (from: string) => `à partir du ${from}`,
    until: (to: string) => `jusqu'au ${to}`,
    distribution: 'Diffusion',
    versions: 'Historique des versions',
    versionHead: ['version', 'date', 'auteur', 'modifications'],
    period: 'Période examinée',
    periodDerived: 'selon les preuves : le premier et le dernier enregistrement',
    derived: (what: string, capped: number) => `selon les preuves : ${what}${capped ? ` (les ${frNum(capped)} plus fréquents ; elles en citent davantage)` : ''}`,
    systemsIn: 'Systèmes dans le périmètre',
    systemsOut: 'Systèmes hors périmètre',
    systemsWhat: 'les hôtes dont proviennent les enregistrements',
    accountsIn: 'Comptes dans le périmètre',
    accountsOut: 'Comptes hors périmètre',
    accountsWhat: 'les comptes utilisateurs cités par les enregistrements',
    evidence: 'Preuves',
    evidenceFiles: (k: number) =>
      `${frNum(k)} ${p(k, 'fichier', 'fichiers')}, ${p(k, 'listé', 'listés')} avec ${p(k, 'son empreinte', 'leurs empreintes')} sous Éléments de preuve et chaîne de possession`,
    noDate: 'sans date',
    containmentHead: ['date', 'action', 'par'],
    containmentIntro: "Les actions d'endiguement et d'éradication menées, telles que l'analyste les a consignées.",
    short: 'Court terme',
    medium: 'Moyen terme',
    long: 'Long terme',
    initialAccess: 'Accès initial',
    rootCause: 'Cause première',
    impactIntro:
      'Les comptes et les hôtes cités par les éléments confirmés, imprimés ou non : les personnes visées par une chaîne ou un récit confirmé, les hôtes concernés, et les comptes et hôtes des détections confirmées avec eux. Les comptes machine, de service et intégrés sont exclus.',
    impactNote: "l'appréciation de l'impact par l'analyste",
    impactNoteDocx: "L'appréciation de l'impact par l'analyste.",
    impactNone: "Aucun élément confirmé ne cite de compte ni d'hôte.",
    impactHead: ['', 'première occurrence (UTC)', 'dernière occurrence (UTC)', 'gravité maximale', 'cité par'],
    account: 'compte',
    host: 'hôte',
    also: (aliases: string) => ` (aussi ${aliases})`,
    item: {
      chain: (label: string) => `chaîne ${label}`,
      incident: (title: string) => `incident ${title}`,
      unprinted: (title: string) => (title ? `élément confirmé non imprimé (${title})` : 'élément confirmé non imprimé'),
      story: (title: string) => `récit ${title}`,
      finding: (title: string, ruleId: string) => `détection confirmée ${title} (${ruleId})`,
      lookup: (sources: string[]) => `vérification de réputation${sources.length ? ` (vu dans ${sources.join(', ')})` : ''}`,
    },
  },

  indicator: {
    head: ['type', 'indicateur', 'provenance', 'réputation'],
    notLookedUp: 'non vérifié',
    intro:
      "Les adresses, domaines, expéditeurs, URL et empreintes cités par les chaînes, récits et détections confirmés, qu'une vérification de réputation ait été faite ou non, ainsi que ceux signalés par un service de réputation. Les adresses non publiques et les domaines propres au dossier sont exclus. Les valeurs sont neutralisées.",
    left: (k: number, max: number) => `${frNum(k)} ${p(k, "autre indicateur n'est pas listé", 'autres indicateurs ne sont pas listés')} : l'annexe en compte ${frNum(max)} au plus.`,
    none: "Aucun élément confirmé ne cite d'adresse, de domaine, d'expéditeur, d'URL ou d'empreinte externe, et aucun service de réputation n'en a signalé.",
  },

  technique: {
    head: ['technique', 'tactique', 'détections', 'règles', 'confirmée'],
    unmapped: 'non rattachée à une tactique',
    yes: 'oui',
    no: 'non',
    intro:
      'Chaque technique ATT&CK portée par les détections imprimées, faux positifs exclus, et par les détections confirmées non imprimées : sa tactique, le nombre de détections, les règles, et si un élément confirmé la porte.',
  },

  evidence: {
    head: ['fichier', 'type', 'taille', 'lignes', 'SHA-256', 'intégrité', 'lecture', 'ajouté (UTC)'],
    incomplete: (issue: string) => `incomplète : ${issue}`,
    complete: 'complète',
    none: 'Aucun fichier de preuve.',
    packages: "Couverture des paquets d'investigation",
    packageHead: ['paquet', 'couverture'],
    noIssues: "Aucun problème d'import signalé",
  },

  relationship: {
    intro: "Liens retenus par l'analyste. Les heures d'observation et de collecte restent distinctes ; des entités partagées n'établissent pas de lien de cause à effet.",
    aliases: (json: string) => `Alias explicites : ${json}`,
    head: ['Source', 'Enregistrement', 'Heure (UTC)', 'SHA-256'],
    record: (source: string, id: string | number | null, evidence: number | null, row: number) => `${source} n° ${id} · preuve n° ${evidence} · ligne source ${row}`,
    collected: (at: string) => `Collecté : ${at}`,
    event: (at: string) => `Événement : ${at}`,
  },

  timeline: { head: ['quand (UTC)', 'entrée', 'origine'] },

  settingsLine: (o) =>
    `domaines internes : ${o.domains || '—'} · VIP : ${o.vips || '—'} · heures ouvrées ${o.start} h–${o.end} h (${o.tz}) · vérifications de réputation ${o.lookups ? `faites sur ${frNum(o.lookups)} ${p(o.lookups, 'indicateur', 'indicateurs')}` : 'non faites'} · seuil du rapport ${frSev(o.floor)}${o.onlyReviewed ? ' · éléments examinés uniquement' : ''}${o.fp ? ' · faux positifs inclus' : ''} · étapes des chaînes : ${o.detail}`,

  docx: {
    generated: (at: string, analyst: string) => `Produit le ${at} · ${analyst}`,
    final: (at: string) => `définitif, émis le ${at}`,
    draft: 'PROJET, non émis',
    completeness: (level: string) => `Complétude ${level} : `,
    completenessSub: "Mesure l'avancement de l'examen, pas la certitude de la conclusion.",
    analystConfidence: (level: string, basis: boolean) => `Confiance de l'analyste ${level}${basis ? ' : ' : ''}`,
    analystConfidenceSub: "L'appréciation de l'analyste sur sa conclusion.",
    bySeverity: (bySev: string, c: number, r: number, f: number, u: number, verified: string) =>
      `Par gravité : ${bySev}. Décisions : ${c} ${p(c, 'confirmé', 'confirmés')}, ${r} ${p(r, 'examiné ou incertain', 'examinés ou incertains')}, ${f} ${p(f, 'faux positif', 'faux positifs')}${u ? `, ${u} sans décision` : ', chaque élément est décidé'}. ${verified} fichiers de preuve vérifiés par empreinte.`,
    profile: (confirmed: string, observed: string) => `Profil de menace : ${[confirmed ? `confirmé : ${confirmed}` : '', observed ? `observé : ${observed}` : ''].filter(Boolean).join('. ')}.`,
    footer: (brand: string, name: string, verdict: string, draft: boolean) => `${brand} · ${name} · ${verdict}${draft ? ' · projet' : ''} · page `,
  },

  print: { page: 'page ', of: ' sur ' },

  preflight: {
    unknown: "l'état de la dernière exécution des règles n'est pas connu",
    notRun: "les règles de détection n'ont pas été exécutées sur ce dossier",
    failed: (k: number) => `${k} ${p(k, 'règle en échec', 'règles en échec')} lors de la dernière exécution`,
    after: (k: number) => `${k} ${p(k, 'fichier de preuve ajouté', 'fichiers de preuve ajoutés')} après la dernière exécution des règles`,
    rules: 'Les règles de détection ont porté sur toutes les preuves',
    rulesOk: 'la dernière exécution a couvert chaque fichier',
    read: 'Chaque fichier de preuve a été lu entièrement',
    readList: (names: string[], more: number) => `${names.join(', ')}${more > 0 ? ` et ${more} de plus` : ''}`,
    readOk: 'aucune erreur de lecture, limite ou membre non lu',
    integrity: 'Chaque fichier de preuve a une empreinte vérifiée',
    integrityBad: (k: number) => `${k} ${p(k, 'fichier', 'fichiers')} sans SHA-256 vérifié`,
    integrityOk: 'les empreintes du navigateur et du serveur concordent',
    decided: 'Chaque élément a une décision',
    decidedBad: (k: number) => `${k} ${p(k, 'élément', 'éléments')} sans décision`,
    decidedOk: "l'examen est terminé",
    ai: 'Les décisions reprises du modèle ont été vérifiées',
    aiBad: (k: number) => `${k} ${p(k, 'décision provient', 'décisions proviennent')} des propositions du modèle`,
    aiOk: "chaque décision est celle de l'analyste",
    printed: 'Chaque élément confirmé est imprimé',
    printedBad: (k: number) => `${k} ${p(k, 'élément confirmé', 'éléments confirmés')} sous le seuil de gravité ou ${p(k, 'écarté', 'écartés')}`,
    printedOk: 'le rapport contient chaque élément confirmé',
    claims: 'Ce que dit le rapport tient face aux lignes citées',
    claimsPending: 'les détections et textes imprimés sont encore en cours de vérification',
    contradicted: (k: number) => `${k} ${p(k, 'détection contredite', 'détections contredites')} par ses lignes`,
    unsupported: (k: number) => `${k} ${p(k, 'détection dont les lignes ne sont', 'détections dont les lignes ne sont')} pas toutes dans le dossier`,
    textsUnsupported: (k: number) => `${k} ${p(k, 'texte citant', 'textes citant')} des valeurs absentes de leurs lignes`,
    claimsOk: (k: number, texts: number) => `${k} ${p(k, 'détection', 'détections')} et ${texts} ${p(texts, 'texte', 'textes')} relus par rapport à leurs lignes`,
  },

  storyCut: {
    flagged: (cap: number, left: number) =>
      `Plus de ${frNum(cap)} enregistrements portent des détections : les récits lisent les ${frNum(cap)} premiers${left ? ` et en écartent ${frNum(left)}` : ''}.`,
    refs: (k: number, cap: number) =>
      `${k ? `${frNum(k)} ${p(k, 'détection cite', 'détections citent')}` : 'Des détections citent'} plus de ${frNum(cap)} enregistrements : les récits lisent les ${frNum(cap)} premiers de chacune.`,
    identities: (cap: number) =>
      `Les enregistrements qui nomment les personnes signalées dépassent ${frNum(cap)} : les récits lisent d'abord les tâches, services et modifications de comptes parmi eux, puis les plus proches des alertes.`,
    addresses: (cap: number) =>
      `Les enregistrements venant des adresses signalées dépassent ${frNum(cap)} : les récits lisent d'abord les tâches, services et modifications de comptes parmi eux, puis les plus proches des alertes.`,
    hosts: (cap: number) =>
      `Les ouvertures de session, processus et services des hôtes signalés dépassent ${frNum(cap)} : les récits lisent d'abord les tâches, services et modifications de comptes parmi eux, puis les plus proches des alertes.`,
    context: (cap: number, people: number, addresses: number, hosts: number) => {
      const left = [
        people ? `${frNum(people)} qui nomment les personnes signalées` : '',
        addresses ? `${frNum(addresses)} venant des adresses signalées` : '',
        hosts ? `${frNum(hosts)} sur les hôtes signalés` : '',
      ].filter(Boolean)
      return `Les enregistrements autour des alertes dépassent ${frNum(cap)}, plafond qu'un dossier du navigateur applique ensemble aux personnes, adresses et hôtes signalés : les récits lisent d'abord les tâches, services et modifications de comptes parmi eux, puis les plus proches des alertes${left.length ? `, et en écartent ${left.join(', ')}` : ''}.`
    },
    flaggedMails: (cap: number, left: number) => `Plus de ${frNum(cap)} messages portent des détections : les récits lisent les ${frNum(cap)} premiers${left ? ` et en écartent ${frNum(left)}` : ''}.`,
    seeds: (left: number, cap: number, risk: number) =>
      `${left ? frNum(left + cap) : `Plus de ${frNum(cap)}`} messages ont un score de risque de ${risk} ou plus : les récits lisent les ${frNum(cap)} plus risqués.`,
    undated: (k: number) =>
      `${k ? `${frNum(k)} ${p(k, 'message signalé ou à risque élevé ne porte', 'messages signalés ou à risque élevé ne portent')}` : 'Des messages signalés ou à risque élevé ne portent'} aucune date : aucun récit ne peut les placer, aucun ne les lit donc.`,
    windows: (k: number, most: number) =>
      `Les alertes se répartissent sur ${k ? frNum(k) : `plus de ${most}`} périodes distinctes : les récits lisent à la place une seule période, de la première alerte à la dernière, où les plafonds sont atteints plus tôt.`,
    replies: (cap: number) => `Seuls ${frNum(cap)} des messages envoyés par les personnes signalées ont été lus, les plus proches des alertes.`,
    dns: (cap: number) => `Les réponses DNS des hôtes signalés dépassent ${frNum(cap)} : les adresses qu'elles attribuent aux hôtes viennent des plus proches des alertes.`,
    dhcp: (cap: number) => `Les baux DHCP dépassent ${frNum(cap)} : les adresses qu'ils attribuent aux hôtes viennent des premiers.`,
    dc: (cap: number) =>
      `Les enregistrements Kerberos et NTLM des contrôleurs de domaine concernant les personnes, hôtes et adresses signalés dépassent ${frNum(cap)} : les récits lisent d'abord ceux qui nomment un compte ou un hôte signalé, puis les plus proches des alertes ; un rebond peut donc manquer le ticket qui en nomme la source.`,
    nameKeys: 'Les enregistrements signalés nomment plus de 2 000 comptes : les récits lisent les enregistrements des 2 000 les plus cités.',
    hostKeys: 'Plus de 500 hôtes portent des alertes : les récits lisent les ouvertures de session, processus et services des 500 qui en portent le plus.',
    addressKeys: 'Les alertes nomment plus de 500 adresses extérieures : les récits lisent les enregistrements des 500 les plus citées.',
    trimmed: (mib: number, k: number, to: number) =>
      `Les lignes de la construction dépassent ${frNum(mib)} Mio, plus que le serveur n'accepte en une requête : le texte long de ${frNum(k)} ${p(k, 'enregistrement', 'enregistrements')} (lignes de commande, blocs de script, résumés) a été coupé à ${frNum(to)} caractères.`,
    size: (mib: number, k: number) =>
      `Les lignes de la construction dépassent malgré tout ${frNum(mib)} Mio : ${frNum(k)} d'entre elles ont été écartées, en commençant par les enregistrements autour des alertes.`,
    accounts: (cap: number) =>
      `Le dossier écrit ses comptes de plus de ${frNum(cap)} façons : l'identification des personnes lit les plus fréquentes et celles des enregistrements que lisent les récits.`,
    identityRows:
      "L'identification des personnes a été faite à partir des enregistrements lus par cette construction, non du dossier entier : un nom de compte seul est rattaché au seul compte de ce nom parmi eux, alors que le dossier peut en contenir un autre.",
    storiesTruncated: 'Seuls les 200 récits au score le plus élevé sont conservés : les alertes des autres sont listées avec celles qui ne figurent dans aucun récit.',
    noWayIn: "Aucun enregistrement du récit ne montre comment il a commencé : l'accès initial ne figure pas dans les preuves qu'il lit.",
  },

  storyStale: {
    unknown: "ils ont été construits avant que REMN ne conserve ce qu'une construction lit, ils peuvent donc ne pas correspondre aux détections",
    findings: 'les détections ont changé depuis leur construction (exécution des règles, faux positif ou gravité fixée à la main)',
    evidence: 'les éléments de preuve ont changé depuis leur construction',
    settings: 'les paramètres du dossier ont changé depuis leur construction',
  },

  chainCut: {
    eventsTruncated: 'Corrélation des messages : seuls les 50 000 premiers événements correspondants ont été pris en compte.',
    authEventsTruncated: "Campagnes d'authentification : seuls les 50 000 premiers événements d'authentification ont été pris en compte.",
    seedsTruncated: "La sélection des messages d'amorce a atteint sa limite (300 amorces ou 500 références de détections).",
    repliesTruncated: 'Seules les 5 000 premières réponses correspondantes ont été prises en compte.',
    chainsTruncated: 'Seules les chaînes au score le plus élevé sont affichées.',
  },

  packageIssue: {
    errors: (k: number) => `${frNum(k)} ${p(k, 'membre en échec', 'membres en échec')}`,
    unsupported: (k: number) => `${frNum(k)} ${p(k, 'membre non pris en charge', 'membres non pris en charge')}`,
    skipped: (k: number) => `${frNum(k)} ${p(k, 'membre ignoré', 'membres ignorés')}`,
    inventory: 'inventaire des membres incomplet',
    discrepancies: (k: number) => `${frNum(k)} ${p(k, 'écart ou entrée non résolue', 'écarts ou entrées non résolues')} dans le résumé de collecte`,
  },

  measuredOn: {
    sigma: (k: number) => `${frNum(k)} ${p(k, 'échantillon', 'échantillons')} de régression de SigmaHQ`,
    attackSamples: (k: number) => `${frNum(k)} ${p(k, 'enregistrement', 'enregistrements')} d'EVTX-ATTACK-SAMPLES`,
    attackData: (k: number) => `${frNum(k)} ${p(k, 'jeu', 'jeux')} de données Microsoft 365 et Entra ID de Splunk attack_data`,
    attackDataWindows: (k: number) => `${frNum(k)} ${p(k, 'jeu', 'jeux')} de journaux d'événements Windows de Splunk attack_data`,
    evtxToMitre: (k: number) => `${frNum(k)} ${p(k, 'enregistrement', 'enregistrements')} d'EVTX-to-MITRE-Attack`,
    sentence: (on: string, recorded: string[], clean: { machines: number; tag: string; events: number } | null) =>
      `Mesuré le ${frDay(on)}${recorded.length ? ` sur ${frList(recorded, 'et')}` : ''}${clean ? `, et sur les journaux de ${frNum(clean.machines)} machines Windows saines d'evtx-baseline ${clean.tag} (${frNum(clean.events)} événements)` : ''}.`,
  },
}

export const EN: ReportText = en
const BY_LANGUAGE: Record<ReportLanguage, ReportText> = { en, fr }

/** The dictionary of a language; English for anything else. */
export const reportText = (lang: unknown): ReportText => (lang === 'fr' ? BY_LANGUAGE.fr : BY_LANGUAGE.en)

// ---------------------------------------------------------------------------
// the firm's logo
// ---------------------------------------------------------------------------

/** the largest logo the report embeds, in bytes of the image file: the HTML report and the Word file carry it whole */
export const LOGO_MAX_BYTES = 200 * 1024

export interface LogoImage {
  dataUrl: string
  mime: 'image/png' | 'image/jpeg'
  /** the extension the Word file names it with */
  ext: 'png' | 'jpeg'
  bytes: Uint8Array
  width: number
  height: number
}

/** The width and height a PNG or JPEG file states, or null when the bytes are neither. */
function imageSize(b: Uint8Array): { mime: LogoImage['mime']; width: number; height: number } | null {
  const u16 = (i: number) => (b[i] << 8) | b[i + 1]
  const u32 = (i: number) => ((b[i] << 24) >>> 0) + ((b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3])
  const PNG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]
  if (b.length >= 24 && PNG.every((x, i) => b[i] === x) && String.fromCharCode(...b.subarray(12, 16)) === 'IHDR') return { mime: 'image/png', width: u32(16), height: u32(20) }
  if (b.length < 4 || b[0] !== 0xff || b[1] !== 0xd8) return null
  // a JPEG states its size in its start-of-frame segment; the segments before it say how long they are
  let i = 2
  while (i + 9 < b.length) {
    if (b[i] !== 0xff) return null
    const marker = b[i + 1]
    if (marker === 0xff) {
      i++
      continue
    }
    if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) return { mime: 'image/jpeg', width: u16(i + 7), height: u16(i + 5) }
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd8)) {
      i += 2
      continue
    }
    i += 2 + u16(i + 2)
  }
  return null
}

/**
 * The logo as the report embeds it: a PNG or JPEG data URL whose bytes are what the type says, with
 * a width and a height, no larger than LOGO_MAX_BYTES; null for anything else, which the report
 * leaves out.
 */
export function logoImage(dataUrl: unknown): LogoImage | null {
  if (typeof dataUrl !== 'string') return null
  const m = /^data:(image\/(?:png|jpeg));base64,([A-Za-z0-9+/]+={0,2})$/.exec(dataUrl)
  if (!m || (m[2].length * 3) / 4 > LOGO_MAX_BYTES + 3) return null
  let bin: string
  try {
    bin = atob(m[2])
  } catch {
    return null
  }
  if (bin.length > LOGO_MAX_BYTES) return null
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0))
  const size = imageSize(bytes)
  if (!size || size.mime !== m[1] || !size.width || !size.height) return null
  return { dataUrl, mime: size.mime, ext: size.mime === 'image/png' ? 'png' : 'jpeg', bytes, width: size.width, height: size.height }
}
