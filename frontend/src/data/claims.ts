/**
 * The report's claims about rows, checked against the rows. A finding says the rows it cites
 * match its rule, hold the values it names and begin at its time; a chain narrative or an
 * incident note names addresses, accounts and hashes that its own rows should hold; the executive
 * summary names values the evidence should hold. Each claim is:
 *
 * - verified: every row it cites is in the case and says what the claim says;
 * - unsupported: a row it cites is no longer in the case (removed, or numbered anew when its file
 *   was added again), or a value it names is in none of its rows;
 * - contradicted: its rows say otherwise: a row no longer matches the rule, none holds a value the
 *   finding names, or its time is not its first row's.
 *
 * The rows are read back through the case's data source, so browser and server cases are checked
 * the same way, and named by their place in their own file (data/recordKeys.ts), which a reader
 * can check without REMN.
 */
import type { Evidence, Finding } from '../db/schema'
import { compileCond, ruleReadFields, timePred, type Rule } from '../rules/engine'
import { getPath, type SettingsLike } from '../rules/filter'
import { fmtNum, fmtUtc } from '../util/format'
import type { DataSource } from './source'
import { recordRef, type RecordRef } from './recordKeys'
import { citationsIn, SeenSet } from '../ai/evidence'

export type ClaimStatus = 'verified' | 'unsupported' | 'contradicted'

export interface ClaimCheck {
  status: ClaimStatus
  /** rows it cites, and how many of them were read back to check */
  cited: number
  checked: number
  /** why it is not verified, in words */
  reasons: string[]
  /** the first rows it cites, by their place in their file */
  records: RecordRef[]
  /** what could not be checked, when something could not */
  partial?: string
}

export interface TextCheck {
  status: ClaimStatus
  /** the values it names that the check looked for */
  named: string[]
  reasons: string[]
}

type Row = Record<string, unknown>

/** Rows read back per finding: a finding of 5,000 rows is checked on its first ones, and says so. */
export const CHECKED_ROWS = 50
/** a finding's time is its first row's; a second apart is the same */
const TIME_SLACK_MS = 1000
/** reasons listed per claim */
const REASONS = 3
const BODY_FIELDS = ['bodyText', 'bodyHtml', 'headersText', 'visibleText']

const str = (v: unknown): string => (v == null ? '' : Array.isArray(v) ? v.map(String).join(',') : typeof v === 'object' ? JSON.stringify(v) : String(v))

/**
 * A value as either engine writes it into a finding: the browser joins a list with commas, the
 * server prints Python's form (['a', 'b'], True, 1.0); both cut it at 200 characters.
 */
function sameValue(have: string, want: string): boolean {
  const norm = (x: string) =>
    x
      .toLowerCase()
      .replace(/^\[|\]$/g, '')
      .replace(/['"]/g, '')
      .replace(/\s*,\s*/g, ',')
      .trim()
  const h = norm(have)
  const w = norm(want)
  if (h === w || (want.length >= 200 && h.startsWith(w.slice(0, 180)))) return true
  const hn = Number(h)
  const wn = Number(w)
  return h !== '' && w !== '' && Number.isFinite(hn) && Number.isFinite(wn) && hn === wn
}
const plural = (n: number, one: string, many = `${one}s`) => (n === 1 ? one : many)

/** The columns a rule reads that the rows read back do not carry (a search may leave out raw XML or a mail's body). */
function unreadable(rule: Rule, rows: Row[]): string[] {
  const out: string[] = []
  for (const f of ruleReadFields(rule)) {
    const top = f.split('.')[0]
    const heavy = top === 'raw' || top === 'data' || BODY_FIELDS.includes(top)
    if (heavy && rows.length && rows.every((r) => r[top] === undefined)) out.push(top)
  }
  return [...new Set(out)]
}

export interface FindingCheckInput {
  finding: Finding
  /** the cited rows read back, by id (a missing id is a row no longer in the case) */
  rows: Map<number, Row>
  /** the rule as it is now, when it is one */
  rule?: Rule
  settings?: SettingsLike
  evidence?: Map<number, Evidence>
}

/** A finding against the rows it cites. */
export function checkFinding({ finding: f, rows, rule, settings, evidence }: FindingCheckInput): ClaimCheck {
  const checkedIds = f.refs.slice(0, CHECKED_ROWS)
  const read = checkedIds.map((id) => rows.get(id)).filter((r): r is Row => !!r)
  const refOf = (r: Row) => recordRef(r, f.source, evidence?.get(Number(r.evidenceId)))
  const records = read.slice(0, 3).map(refOf)
  const contradicted: string[] = []
  const unsupported: string[] = []
  let partial: string | undefined
  if (!f.refs.length) unsupported.push('it cites no row')
  const missing = checkedIds.length - read.length
  if (missing)
    unsupported.push(
      `${fmtNum(missing)} of the ${fmtNum(checkedIds.length)} ${plural(checkedIds.length, 'row')} it cites ${missing === 1 ? 'is' : 'are'} not in the case: removed, or numbered anew when evidence was added again`,
    )
  const tsField = f.source === 'mails' ? 'date' : 'ts'
  let matching = read
  if (rule && rule.source === f.source && rule.where && read.length) {
    const lacking = unreadable(rule, read)
    if (lacking.length) partial = `the rule reads ${lacking.join(' and ')}, which the rows read back do not carry: it was not checked against them`
    else {
      const where = compileCond(rule.where, settings)
      const exclude = rule.exclude ? compileCond(rule.exclude, settings) : null
      const time = timePred(rule, settings, tsField)
      const then = rule.then?.where ? compileCond(rule.then.where, settings) : null
      const main = (r: Row) => where(r) && !(exclude && exclude(r)) && (!time || time(r))
      const off = read.filter((r) => !main(r) && !(then && then(r)))
      matching = read.filter(main)
      if (off.length)
        contradicted.push(
          `${off
            .slice(0, 2)
            .map((r) => `${refOf(r).file} ${refOf(r).record}`)
            .join(' and ')}${off.length > 2 ? ` and ${fmtNum(off.length - 2)} more` : ''} no longer ${off.length === 1 ? 'matches' : 'match'} the rule`,
        )
    }
  } else if (!rule && !['chain'].includes(f.ruleId) && !f.ruleId.startsWith('engine:')) partial = 'its rule is no longer loaded: the rows were not checked against it'
  // the values it names: from its first row, or listed from all its rows for a distinct count
  // (with rows missing, a value may be in one of them: that is unsupported, said above). When
  // it cites more rows than were read back, only a group's own key is the same in every row.
  if (read.length && !missing && f.ruleId !== 'chain') {
    const distinct = rule?.distinct
    const all = f.refs.length <= checkedIds.length
    const keys = new Set(rule?.group_by ?? [])
    for (const [field, value] of Object.entries(f.entities ?? {})) {
      if (value == null || value === '' || (!all && (!keys.has(field) || field === distinct))) continue
      const wanted = field === distinct ? String(value).split(', ') : [String(value)]
      const holds = (w: string) => read.some((r) => sameValue(str(getPath(r, field)), w))
      const absent = wanted.filter((w) => !holds(w))
      // a column a server search leaves out cannot be said to be absent
      if (absent.length && read.some((r) => getPath(r, field) !== undefined)) contradicted.push(`it names ${field} ${absent.slice(0, 2).join(', ')}, which none of its rows holds`)
    }
  }
  // its time is its first matching row's, when its first rows were all read back
  const times = matching.map((r) => r[tsField]).filter((t): t is number => typeof t === 'number')
  if (f.ts != null && times.length && !missing && f.ruleId !== 'chain') {
    const first = Math.min(...times)
    if (Math.abs(f.ts - first) > TIME_SLACK_MS) contradicted.push(`its time, ${fmtUtc(f.ts)}, is not its first row's (${fmtUtc(first)})`)
  }
  const status: ClaimStatus = contradicted.length ? 'contradicted' : unsupported.length ? 'unsupported' : 'verified'
  return { status, cited: f.refs.length, checked: checkedIds.length, reasons: [...contradicted, ...unsupported].slice(0, REASONS), records, partial }
}

// ---------------------------------------------------------------------------
// values named in text
// ---------------------------------------------------------------------------

// an address may end a sentence (its full stop is not a fifth part); one more part, or a digit, makes it something else
const IPV4 = /(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?!\d|\.\d)/g
const EMAIL = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g
const HASH = /(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])/g

/** The addresses and hashes a text names, and the case's names (hosts, accounts) it mentions. */
export function namedValues(text: string, names: Iterable<string> = []): string[] {
  const out = new Set<string>()
  for (const re of [IPV4, EMAIL, HASH]) for (const m of text.matchAll(re)) out.add(m[0].toLowerCase().replace(/\.$/, ''))
  const lower = text.toLowerCase()
  for (const n of names) {
    const name = n.trim().toLowerCase()
    // a name of a few letters is a word, not a mention
    if (name.length < 4 || out.has(name)) continue
    const at = lower.indexOf(name)
    if (at >= 0 && !/[\w-]/.test(lower[at - 1] ?? '') && !/[\w-]/.test(lower[at + name.length] ?? '')) out.add(name)
  }
  return [...out]
}

function rowText(r: Row): string {
  const parts: string[] = []
  const walk = (v: unknown, depth: number) => {
    if (v == null || depth > 4) return
    if (typeof v === 'string' || typeof v === 'number') parts.push(String(v))
    else if (Array.isArray(v)) for (const x of v) walk(x, depth + 1)
    else if (typeof v === 'object') for (const x of Object.values(v as Row)) walk(x, depth + 1)
  }
  walk(r, 0)
  return parts.join('\n').toLowerCase()
}

/** A text against the rows it is about: every address, hash and case name it names should be in them. */
export function checkText(text: string, rows: Row[], names: Iterable<string> = []): TextCheck {
  const named = namedValues(text, names)
  if (!named.length) return { status: 'verified', named, reasons: [] }
  const hay = rows.map(rowText).join('\n')
  const absent = named.filter((v) => !hay.includes(v))
  return {
    status: absent.length ? 'unsupported' : 'verified',
    named,
    reasons: absent.length
      ? [`it names ${absent.slice(0, 4).join(', ')}${absent.length > 4 ? ` and ${fmtNum(absent.length - 4)} more` : ''}, which none of its ${fmtNum(rows.length)} ${plural(rows.length, 'row')} holds`]
      : [],
  }
}

/**
 * A text with no rows of its own (the executive summary): every address and hash it names should be
 * somewhere in the evidence. The indicators extracted at ingest answer first; a value they lack
 * is looked for in the rows' text, for the first few only, since that reads every row.
 */
export async function checkTextInCase(text: string, source: DataSource): Promise<TextCheck> {
  const named = namedValues(text)
  if (!named.length) return { status: 'verified', named, reasons: [] }
  const absent: string[] = []
  let scanned = 0
  for (const v of named.slice(0, 40)) {
    const iocs = await source.listIocs({ q: v, limit: 5 }).catch(() => null)
    if (iocs?.rows.some((i) => i.value.toLowerCase() === v)) continue
    if (scanned++ >= 10) {
      absent.push(v)
      continue
    }
    const [ev, ml] = await Promise.all([source.searchEvents({ text: v }, 1).catch(() => ({ rows: [] as unknown[] })), source.searchMails({ text: v }, 1).catch(() => ({ rows: [] as unknown[] }))])
    if (!ev.rows.length && !ml.rows.length) absent.push(v)
  }
  return {
    status: absent.length ? 'unsupported' : 'verified',
    named,
    reasons: absent.length ? [`it names ${absent.slice(0, 4).join(', ')}${absent.length > 4 ? ` and ${fmtNum(absent.length - 4)} more` : ''}, which no row of the evidence holds`] : [],
  }
}

// ---------------------------------------------------------------------------
// reading the rows back
// ---------------------------------------------------------------------------

/** The rows of the given ids, by id; an id not returned is not in the case. */
export async function readRows(source: DataSource, kind: 'events' | 'mails', ids: number[], withBodies = false): Promise<Map<number, Row>> {
  const out = new Map<number, Row>()
  const unique = [...new Set(ids.filter((id) => Number.isInteger(id)))]
  if (kind === 'mails' && withBodies) {
    for (const id of unique) {
      const m = await source.getMail(id).catch(() => null)
      if (m) out.set(id, { ...m.row, ...(m.body ?? {}) } as Row)
    }
    return out
  }
  for (let i = 0; i < unique.length; i += 500) {
    const chunk = unique.slice(i, i + 500)
    const filter = { conditions: [{ field: 'id', op: 'in' as const, value: chunk }] }
    const res = kind === 'events' ? await source.searchEvents(filter, chunk.length) : await source.searchMails(filter, chunk.length)
    for (const r of res.rows as Row[]) if (typeof r.id === 'number') out.set(r.id, r)
  }
  return out
}

/** Every finding against the rows it cites (the first CHECKED_ROWS of them), by finding id. */
export async function checkFindings(findings: Finding[], rules: Map<string, Rule>, source: DataSource, settings: SettingsLike, evidence: Evidence[]): Promise<Map<number, ClaimCheck>> {
  const byEvidence = new Map(evidence.filter((e) => e.id != null).map((e) => [e.id!, e]))
  const want = { events: [] as number[], mails: [] as number[], bodies: [] as number[] }
  for (const f of findings) {
    const ids = f.refs.slice(0, CHECKED_ROWS)
    const rule = rules.get(f.ruleId)
    if (f.source === 'mails' && rule && [...ruleReadFields(rule)].some((x) => BODY_FIELDS.includes(x.split('.')[0]))) want.bodies.push(...ids)
    else want[f.source].push(...ids)
  }
  const [events, mails, bodies] = await Promise.all([readRows(source, 'events', want.events), readRows(source, 'mails', want.mails), readRows(source, 'mails', want.bodies, true)])
  for (const [id, r] of bodies) mails.set(id, r)
  const out = new Map<number, ClaimCheck>()
  for (const f of findings) {
    if (f.id == null) continue
    out.set(f.id, checkFinding({ finding: f, rows: f.source === 'events' ? events : mails, rule: rules.get(f.ruleId), settings, evidence: byEvidence }))
  }
  return out
}

// ---------------------------------------------------------------------------
// the report's claims
// ---------------------------------------------------------------------------

export interface ReportClaims {
  /** each printed finding, by finding id */
  findings: Record<number, ClaimCheck>
  /** each text the report prints about rows: a chain's narrative (chain:<id>), an incident's notes (incident:<lead finding id>), the summary */
  texts: { key: string; what: string; check: TextCheck }[]
}

interface ChainLike {
  id: string
  title?: string
  seed?: { source?: 'mails' | 'events'; id: number }
  steps: { source: 'mails' | 'events'; id: number | null; refs?: number[] }[]
}
interface IncidentLike {
  title: string
  findings: Finding[]
  lead: { id?: number; notes?: string; aiReason?: string }
}

/** Values the findings name (hosts, accounts, addresses): a text that mentions one should be about rows that hold it. */
function caseNames(findings: Finding[]): string[] {
  const out = new Set<string>()
  for (const f of findings)
    for (const v of Object.values(f.entities ?? {})) {
      const s = String(v ?? '').trim()
      if (s.length >= 4 && s.length <= 120 && !/^[\d\s.,:-]+$/.test(s) && !s.includes(', ')) out.add(s)
    }
  return [...out]
}

export async function loadReportClaims(input: {
  source: DataSource
  findings: Finding[]
  rules: Map<string, Rule>
  settings: SettingsLike
  evidence: Evidence[]
  chains: ChainLike[]
  narratives: Record<string, string | undefined>
  incidents: IncidentLike[]
  summary: string
  /** the analyst's notes on the printed stories, each with its story's rows (data/stories.ts storyRowIds) */
  stories?: { key: string; title: string; note: string; ids: { events: number[]; mails: number[] } }[]
}): Promise<ReportClaims> {
  const { source, findings } = input
  const checks = await checkFindings(findings, input.rules, source, input.settings, input.evidence)
  const names = caseNames(findings)
  const texts: ReportClaims['texts'] = []
  for (const c of input.chains) {
    const narrative = input.narratives[c.id]
    if (!narrative?.trim()) continue
    const ids = { events: [] as number[], mails: [] as number[] }
    if (c.seed) ids[c.seed.source ?? 'mails'].push(c.seed.id)
    for (const s of c.steps) {
      if (s.id != null) ids[s.source].push(s.id)
      ids[s.source].push(...(s.refs ?? []).slice(0, CHECKED_ROWS))
    }
    const [ev, ml] = await Promise.all([readRows(source, 'events', ids.events), readRows(source, 'mails', ids.mails)])
    texts.push({ key: `chain:${c.id}`, what: `the narrative of chain "${c.title ?? c.id}"`, check: checkText(narrative, [...ev.values(), ...ml.values()], names) })
  }
  for (const i of input.incidents) {
    const text = [i.lead.notes, i.lead.aiReason].filter(Boolean).join('\n')
    if (!text.trim()) continue
    const ids = { events: [] as number[], mails: [] as number[] }
    for (const f of i.findings) ids[f.source].push(...f.refs.slice(0, CHECKED_ROWS))
    const [ev, ml] = await Promise.all([readRows(source, 'events', ids.events), readRows(source, 'mails', ids.mails)])
    texts.push({ key: `incident:${i.lead.id ?? i.title}`, what: `the notes on "${i.title}"`, check: checkText(text, [...ev.values(), ...ml.values()], names) })
  }
  for (const st of input.stories ?? []) {
    if (!st.note.trim()) continue
    const [ev, ml] = await Promise.all([readRows(source, 'events', st.ids.events), readRows(source, 'mails', st.ids.mails)])
    texts.push({ key: `story:${st.key}`, what: `the note on the story "${st.title}"`, check: checkText(st.note, [...ev.values(), ...ml.values()], names) })
  }
  if (input.summary.trim()) texts.push({ key: 'summary', what: 'the executive summary', check: await checkTextInCase(input.summary, source) })
  return { findings: Object.fromEntries(checks), texts }
}

// ---------------------------------------------------------------------------
// the analyst model's answers
// ---------------------------------------------------------------------------

const CITATION = /\[((?:ev|event|evt|mail|msg|finding|chain)\s*[:#][^\]\n]{1,300})\]/gi

export interface AnswerCheck {
  /** sentences that cite rows, read against them */
  sentences: number
  /** those that name what their cited rows do not hold, or cite rows no longer in the case */
  unsupported: { sentence: string; reason: string }[]
}

/**
 * Each sentence of an answer that cites event or mail rows, against those rows: an address, an
 * account of the case or a hash it names should be in them. That the tools returned a row says
 * only that the model saw it; this says whether the sentence is about it.
 */
export async function checkCitedSentences(text: string, source: DataSource, names: Iterable<string> = []): Promise<AnswerCheck> {
  const nameList = [...names]
  const out: AnswerCheck = { sentences: 0, unsupported: [] }
  const sentences = text.split(/(?<=[.!?])\s+|\n+/).filter((s) => /\[(?:ev|event|evt|mail|msg)\s*[:#]/i.test(s))
  for (const sentence of sentences.slice(0, 30)) {
    const refs = citationsIn(sentence, new SeenSet()).map((c) => c.ref)
    const ids = { events: [] as number[], mails: [] as number[] }
    for (const r of refs) if ((r.source === 'events' || r.source === 'mails') && Number.isInteger(Number(r.id))) ids[r.source].push(Number(r.id))
    if (!ids.events.length && !ids.mails.length) continue
    const [ev, ml] = await Promise.all([readRows(source, 'events', ids.events), readRows(source, 'mails', ids.mails)])
    const rows = [...ev.values(), ...ml.values()]
    const bare = sentence.replace(CITATION, ' ').replace(/\s+/g, ' ').trim()
    out.sentences++
    if (!rows.length) out.unsupported.push({ sentence: bare.slice(0, 240), reason: 'the rows it cites are not in the case' })
    else {
      const c = checkText(bare, rows, nameList)
      if (c.status !== 'verified') out.unsupported.push({ sentence: bare.slice(0, 240), reason: c.reasons[0] })
    }
  }
  return out
}
