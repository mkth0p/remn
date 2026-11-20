import { fmtBytes, fmtNum, fmtUtc } from '../util/format'
import { STORY_VERDICT_LABEL } from './storyDecisions'
import { ANSWER_LABEL } from './questions/answers'

/**
 * The words of the printed report, one dictionary per language, and the firm's logo it carries. The HTML and the Word report take
 * every label, heading and sentence of their own from here, with the numbers, times and sizes
 * written the way the language writes them. The interface stays English; only the report changes.
 *
 * What the analysis itself writes (the limits of the evidence, the reasons a claim does not hold,
 * the basis of a story's spine, rule titles, the questions of DFIQ) and what the analyst writes are
 * printed as they are, whatever the language.
 */

export type ReportLanguage = 'en' | 'fr'
export const REPORT_LANGUAGES: { id: ReportLanguage; label: string }[] = [
  { id: 'en', label: 'English' },
  { id: 'fr', label: 'French' },
]

const pad = (x: number) => String(x).padStart(2, '0')
/** in English the plural takes an s past one; the callers say which word */
const s = (k: number) => (k === 1 ? '' : 's')

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

  sev: { critical: 'critical', high: 'high', medium: 'medium', low: 'low', info: 'info' } as Record<string, string>,
  status: { new: 'not reviewed', reviewed: 'reviewed', escalated: 'confirmed', false_positive: 'false positive' } as Record<string, string>,
  chainVerdict: { confirmed: 'confirmed', unsure: 'unsure', benign: 'benign' } as Record<string, string>,
  storyVerdict: STORY_VERDICT_LABEL as Record<string, string>,
  answer: ANSWER_LABEL as Record<string, string>,
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

const fr: ReportText = {
  lang: 'fr',
  wordLang: 'fr-FR',
  num: frNum,
  ts: frTs,
  bytes: frBytes,
  day: (iso: string) => {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso.trim())
    return m ? `${m[3]}/${m[2]}/${m[1]}` : iso
  },
  to: 'au',
  andMore: (k: number) => `et ${frNum(k)} de plus`,
  plusMore: (k: number) => `+${frNum(k)} de plus`,
  noEventTime: "pas d'horodatage",

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
  },

  chain: {
    key: ["message d'amorce", 'étape, colorée selon sa détection la plus grave', 'étapes routinières regroupées', 'lien avec le message'],
    campaignKey: ['personne, colorée selon la chaîne', 'expéditeur ou domaine partagé', 'machine ou IP partagée', 'dans une seule chaîne'],
    scoreParts: { seed: 'amorce', links: 'liens', steps: 'étapes', findings: 'détections', sources: 'sources', score: 'score' },
    score: (score: number, cap?: number | null) => `score ${score}${cap ? ` (plafonné à ${cap})` : ''}`,
    narrativeByAi: 'récit rédigé par le modèle pendant le tri',
    narrativeByAiDocx: "Récit rédigé par le modèle d'analyse.",
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
    triage: (reason: string) => `Note de tri (modèle) : ${reason}`,
    fallbackTitle: 'chaîne',
    verdict: (v: string) => `verdict ${v}`,
    noVerdict: 'sans verdict',
    stepCount: (k: number) => `${frNum(k)} ${p(k, 'étape', 'étapes')}`,
    intro:
      "Une chaîne part d'un message suspect et suit ce que les comptes et les machines du destinataire ont fait ensuite ; son score tient compte de l'amorce, des liens avec le message, des étapes, des détections et des sources en jeu. Les faits, dans l'ordre. Les détections dont les lignes sont des étapes d'une chaîne sont décidées avec elle.",
    introDocx:
      "Une chaîne part d'un message suspect et suit ce que les comptes et les machines du destinataire ont fait ensuite ; son score tient compte de l'amorce, des liens avec le message, des étapes, des détections et des sources en jeu. Les détections dont les lignes sont des étapes d'une chaîne sont décidées avec elle.",
    shared: 'Éléments partagés entre chaînes',
    campaignAlt: 'graphe de campagne',
    campaignCaption: 'Les personnes au centre, les expéditeurs et domaines qui les ont atteintes à gauche, les machines et IP touchées à droite.',
    nothingShared: "aucun expéditeur, domaine, IP ou hôte n'est partagé entre les chaînes",
    graphsInHtml: 'Les graphes des chaînes figurent dans le rapport HTML.',
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
      "Un récit décrit ce qui est arrivé à une personne, ou sur un hôte, au cours d'un incident : les enregistrements autour de ce qui a déclenché une alerte, lus selon les tactiques ATT&CK dans l'ordre où ils se sont produits, chacun rattaché au récit par son compte, sa session, son accès à l'hôte ou le processus qui l'a lancé. La décision de l'analyste y figure : un récit confirmé compte dans le verdict comme un incident confirmé, un récit jugé bénin ou faux positif n'est pas imprimé, et une étape contestée par l'analyste est exclue des phases et de la gravité du récit et listée sous celui-ci. Chacun indique où s'arrêtent ses preuves.",
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
    rows: (k: number) => `${frNum(k)} ${p(k, 'ligne', 'lignes')}`,
    noteByAi: 'note rédigée par le modèle pendant le tri',
    noteByAiDocx: 'Note rédigée par le modèle pendant le tri.',
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
    byAi: "rédigé par le modèle d'analyse à partir des éléments examinés ; les décisions sur lesquelles il s'appuie sont celles de l'analyste",
    byAiDocx: "Rédigé par le modèle d'analyse à partir des éléments examinés ; les décisions sur lesquelles il s'appuie sont celles de l'analyste.",
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
    finding: 'détection',
    noCitation: 'aucun enregistrement cité',
    unanswered: 'sans réponse',
    evidence: (coverage: string) => `Preuves : ${coverage}`,
    intro: (answered: number, cannot: number, open: number, uncovered: number) =>
      `Les questions auxquelles l'investigation devait répondre, issues des scénarios choisis pour le dossier (DFIQ, dfiq.org, et ceux de REMN, dont les identifiants commencent par 0). Chacune porte la réponse de l'analyste et les enregistrements ou détections sur lesquels elle repose. ${frNum(answered)} ${p(answered, 'répondue', 'répondues')}, ${frNum(cannot)} sans réponse possible avec ces preuves, ${frNum(open)} encore ${p(open, 'ouverte', 'ouvertes')}${uncovered ? `, dont ${frNum(uncovered)} pour lesquelles aucune preuve du dossier ne permet de répondre` : ''}.`,
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
