/**
 * The agent's tools, executed in the browser against the case data source (IndexedDB or the
 * server store). Only what these functions return reaches the model, wrapped as evidence
 * (ai/evidence.ts). Read tools return rows with a `ref` the answer cites; the investigation tools
 * keep the plan and the hypothesis board; the propose_* tools queue proposals in the approval inbox
 * (ai/inbox.ts) and never change the case themselves. The schemas the model sees come from the
 * server (backend/services/ai/tools.py); TOOL_GROUPS says which a case can use.
 */
import { getDb, type Case, type Finding, type RowMarkVerdict } from '../db/schema'
import { lookupReputation } from '../api/client'
import { getSource, type DataSource } from '../data/source'
import type { Filter } from '../rules/filter'
import type { Bucket } from '../data/queries'
import { loadChains } from '../data/chains'
import { loadStories, PHASE_LABEL, refRow, storyGaps, type Story } from '../data/stories'
import { chainMembership } from '../rules/incidents'
import { normaliseDecision, type Decision } from '../data/aiReview'
import { stepVisible } from '../data/review'
import { listNotes } from '../data/caseNotes'
import { dryRunRule, loadRules, parseRuleYaml } from '../data/rules'
import { runQuery } from '../data/queryClient'
import { useStore } from '../state/store'
import { evRef, findInstructions, mailRef, parseRef, parseRefs, refKey, wrapEvidence, type RowRef, type SeenSet, type Suspect } from './evidence'
import { recordHypothesis, type HypothesisStatus } from './hypotheses'
import { loadInbox, pendingCount, propose, type Proposal } from './inbox'
import { loadBoard } from './hypotheses'

const EVENT_COLS = [
  'tsIso',
  'eventId',
  'provider',
  'channel',
  'computer',
  'operation',
  'upn',
  'artifactType',
  'sourceFile',
  'summary',
  'targetUser',
  'targetDomain',
  'subjectUser',
  'logonType',
  'targetLogonId',
  'subjectLogonId',
  'ipAddress',
  'workstation',
  'statusText',
  'processName',
  'newProcessId',
  'commandLine',
  'parentProcessName',
  'processGuid',
  'parentProcessGuid',
  'serviceName',
  'serviceFile',
  'taskName',
  'memberName',
  'groupName',
  'shareName',
  'relativeTargetName',
  'image',
  'destinationIp',
  'destinationPort',
  'query',
  'targetFilename',
  'targetObject',
  'threatName',
  'path',
]
const MAIL_COLS = [
  'dateIso',
  'subject',
  'folder',
  'fromName',
  'fromAddr',
  'fromDomain',
  'replyTo',
  'returnPath',
  'originIp',
  'risk',
  'flags',
  'urlCount',
  'attachmentCount',
  'maxAttachmentRisk',
  'textPreview',
]

const MAX_ROWS = 100
const MAX_CHARS = 60_000
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

/** Which tools a case can use; the others are not offered to the model. */
export const TOOL_GROUPS = {
  core: ['get_case_summary', 'list_evidence', 'list_findings', 'get_finding', 'list_iocs', 'get_case_notes', 'facet_values', 'pivot', 'regex_test', 'search_rules', 'test_rule'],
  events: ['search_events', 'count_events', 'aggregate_events', 'timeline_events', 'get_event', 'process_tree', 'logon_session'],
  mails: ['search_mails', 'count_mails', 'aggregate_mails', 'timeline_mails', 'get_mail'],
  chains: ['get_chain'],
  stories: ['get_story'],
  network: ['lookup_ioc'],
  server: ['sql'],
  agent: ['update_plan', 'record_hypothesis', 'finish'],
  propose: ['propose_decision', 'propose_note', 'propose_row_mark', 'propose_rule', 'propose_summary'],
} as const

export interface CaseShape {
  events: number
  mails: number
  chains: number
  /** the stories of the last story build */
  stories?: number
}

export function toolNamesFor(kase: Case, shape: CaseShape, agent: boolean): string[] {
  const out: string[] = [...TOOL_GROUPS.core]
  // an empty case still gets the event tools: the question may be about what is missing
  if (shape.events > 0 || shape.mails === 0) out.push(...TOOL_GROUPS.events)
  if (shape.mails > 0) out.push(...TOOL_GROUPS.mails)
  if (shape.chains > 0) out.push(...TOOL_GROUPS.chains)
  if ((shape.stories ?? 0) > 0) out.push(...TOOL_GROUPS.stories)
  if (kase.settings.networkAllowed) out.push(...TOOL_GROUPS.network)
  if (kase.storage === 'server' && kase.serverKey) out.push(...TOOL_GROUPS.server)
  if (agent) out.push(...TOOL_GROUPS.agent, ...TOOL_GROUPS.propose)
  return out
}

/** How many events, mails and chains a case holds, for toolNamesFor. */
export async function caseShape(kase: Case): Promise<CaseShape> {
  const db = getDb()
  const chains = ((await db.kv.get(`chains-${kase.id}`))?.value as { chains?: unknown[] } | undefined)?.chains?.length ?? 0
  const stories = ((await db.kv.get(`stories-${kase.id}`))?.value as { stories?: unknown[] } | undefined)?.stories?.length ?? 0
  const st = useStore.getState()
  if (st.currentCase?.id === kase.id && (st.counts.events || st.counts.mails)) return { events: st.counts.events, mails: st.counts.mails, chains, stories }
  // another case, or counts not loaded yet: what its evidence files hold (a package may hold both)
  const ev = await db.evidence.where('caseId').equals(kase.id!).toArray()
  const events = ev.filter((e) => e.kind !== 'mail').reduce((n, e) => n + (e.count || 1), 0)
  const mails = ev.filter((e) => e.kind !== 'evtx').reduce((n, e) => n + (e.count || 1), 0)
  return { events, mails, chains, stories }
}

export interface PlanStep {
  title: string
  status: 'todo' | 'doing' | 'done' | 'skipped'
}

export interface FinalAnswer {
  answer: string
  confidence?: string
  openQuestions?: string[]
}

export interface ToolContext {
  kase: Case
  /** the refs this conversation may cite; the tool adds what it returns */
  seen: SeenSet
  signal?: AbortSignal
  model?: string
  session?: number
  /** whether the run has already read text addressed to a model */
  exposed?: () => boolean
}

export interface ToolOutput {
  /** what the model reads */
  content: string
  /** refs this result returned */
  refs: string[]
  suspects: Suspect[]
  plan?: PlanStep[]
  final?: FinalAnswer
  proposal?: Proposal
  error?: boolean
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
function project(row: Record<string, unknown>, cols: string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const c of cols) {
    const v = row[c]
    if (v == null || v === '' || (Array.isArray(v) && !v.length)) continue
    out[c] = typeof v === 'string' && v.length > 400 ? v.slice(0, 400) + '…' : v
  }
  return out
}

const eventOut = (r: Record<string, unknown>, cols = EVENT_COLS) => ({ ref: evRef(r.id as number), ...project(r, cols) })

function clampFilter(f: unknown): Filter {
  if (!f || typeof f !== 'object') return {}
  const x = f as Filter
  return { ...x, limit: undefined }
}

function cap(obj: unknown): string {
  let s = JSON.stringify(obj)
  if (s.length > MAX_CHARS) s = s.slice(0, MAX_CHARS) + `…[truncated ${s.length - MAX_CHARS} chars]`
  return s
}

const iso = (t: number | null | undefined) => (t ? new Date(t).toISOString() : null)
const str = (v: unknown) => (v == null ? '' : String(v).trim())
const num = (v: unknown, dflt: number, max: number) => Math.max(1, Math.min(Number(v) || dflt, max))

/** A finding as the model reads it. */
function findingOut(f: Finding) {
  return {
    ref: `finding:${f.id}`,
    ruleId: f.ruleId,
    title: f.title,
    severity: f.severityOverride ?? f.severity,
    source: f.source,
    tsIso: iso(f.ts),
    count: f.count,
    entities: f.entities,
    attack: f.attack,
    status: f.status,
    rows: f.refs.slice(0, 10).map((id) => (f.source === 'mails' ? mailRef(id) : evRef(id))),
  }
}

/** Every "ref" string anywhere in a result. */
function refsIn(value: unknown, out: string[] = [], depth = 0): string[] {
  if (depth > 8 || value == null) return out
  if (Array.isArray(value)) for (const v of value) refsIn(v, out, depth + 1)
  else if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (k === 'ref' && typeof v === 'string') {
        if (parseRef(v)) out.push(v)
      } else if (k === 'rows' && Array.isArray(v) && v.every((x) => typeof x === 'string')) {
        for (const x of v) if (parseRef(x)) out.push(x as string)
      } else refsIn(v, out, depth + 1)
    }
  }
  return out
}

/** The refs a model cited that the conversation has seen, and those it has not. */
function checkCites(list: unknown, seen: SeenSet, fallback?: 'ev' | 'mail' | 'finding'): { ok: RowRef[]; unseen: string[]; bad: string[] } {
  const { refs, bad } = parseRefs(list, fallback)
  const ok: RowRef[] = []
  const unseen: string[] = []
  for (const r of refs) {
    if (seen.has(r)) ok.push(r)
    else unseen.push(refKey(r))
  }
  return { ok, unseen, bad }
}

/**
 * Whether an indicator appears in the case as written: among its extracted indicators, or in the
 * text of an event or a mail. A lookup sends the value to a third party, and the model could
 * otherwise put anything in it (a host name joined to a password, say).
 */
async function valueInCase(kase: Case, kind: string, value: string, signal?: AbortSignal): Promise<boolean> {
  const v = value.trim().toLowerCase()
  if (v.length < 4) return false
  const iocs = await getDb().iocs.where('[caseId+kind]').equals([kase.id!, kind]).toArray()
  if (iocs.some((i) => i.value.trim().toLowerCase() === v)) return true
  const ds = getSource(kase)
  if ((await ds.countEvents({ text: v }, signal)) > 0) return true
  return (await ds.countMails({ text: v }, signal)) > 0
}

const fail = (error: string): ToolOutput => ({ content: JSON.stringify({ error }), refs: [], suspects: [], error: true })

async function withTotal<T>(ds: DataSource, source: 'events' | 'mails', filter: Filter, res: { rows: T[]; truncated: boolean }, signal?: AbortSignal) {
  if (!res.truncated) return res.rows.length
  return source === 'events' ? ds.countEvents(filter, signal) : ds.countMails(filter, signal)
}

// ---------------------------------------------------------------------------
// the tools
// ---------------------------------------------------------------------------
async function read(name: string, args: Record<string, unknown>, ctx: ToolContext): Promise<unknown> {
  const { kase, signal } = ctx
  const caseId = kase.id!
  const ds = getSource(kase)
  const db = getDb()
  switch (name) {
    case 'get_case_summary': {
      const sum = (await ds.summary()) as Record<string, unknown>
      const findings = await db.findings.where('caseId').equals(caseId).toArray()
      const bySeverity: Record<string, number> = {}
      for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1
      const [inbox, board, notes] = await Promise.all([loadInbox(caseId), loadBoard(caseId), db.caseNotes.where('caseId').equals(caseId).count()])
      return {
        storage: ds.kind,
        ...sum,
        findingsBySeverity: bySeverity,
        topFindings: findings
          .sort((a, b) => SEVERITY_ORDER.indexOf(a.severityOverride ?? a.severity) - SEVERITY_ORDER.indexOf(b.severityOverride ?? b.severity))
          .slice(0, 15)
          .map(findingOut),
        caseNotes: notes,
        openProposals: pendingCount(inbox),
        hypotheses: board.map((h) => ({ id: h.id, status: h.status, statement: h.statement.slice(0, 160) })),
      }
    }
    case 'list_evidence': {
      const ev = await db.evidence.where('caseId').equals(caseId).toArray()
      return {
        evidence: ev.map((e) => ({
          id: e.id,
          name: e.name,
          kind: e.kind,
          format: e.format,
          status: e.status,
          rows: e.count,
          size: e.size,
          sha256: e.sha256Client?.slice(0, 16),
          addedAt: iso(e.addedAt),
          note: e.note,
          error: e.error,
        })),
      }
    }
    case 'search_events': {
      const limit = num(args.limit, 30, MAX_ROWS)
      const filter = clampFilter(args.filter)
      const res = await ds.searchEvents(filter, limit, signal)
      const cols = Array.isArray(args.fields) && args.fields.length ? ['tsIso', 'eventId', ...(args.fields as string[]).map(String)] : EVENT_COLS
      return { total: await withTotal(ds, 'events', filter, res, signal), returned: res.rows.length, rows: res.rows.map((r) => eventOut(r as Record<string, unknown>, cols)) }
    }
    case 'count_events':
    case 'count_mails': {
      const filter = clampFilter(args.filter)
      const events = name === 'count_events'
      const field = str(args.group_by)
      if (field) {
        const res = events ? await ds.aggregateEvents(filter, field, num(args.limit, 25, 100), signal) : await ds.aggregateMails(filter, field, num(args.limit, 25, 100), signal)
        return { field, total: res.total, distinct: res.distinct, groups: res.groups.map((g) => ({ value: g.value, count: g.count, firstIso: iso(g.first), lastIso: iso(g.last) })) }
      }
      return { total: events ? await ds.countEvents(filter, signal) : await ds.countMails(filter, signal) }
    }
    case 'aggregate_events': {
      const res = await ds.aggregateEvents(clampFilter(args.filter), str(args.field) || 'eventId', num(args.limit, 25, 100), signal)
      return { field: args.field, total: res.total, distinct: res.distinct, groups: res.groups.map((g) => ({ ...g, firstIso: iso(g.first), lastIso: iso(g.last) })) }
    }
    case 'timeline_events': {
      const bucket = (['minute', 'hour', 'day'].includes(String(args.bucket)) ? args.bucket : 'hour') as Bucket
      const res = await ds.timelineEvents(clampFilter(args.filter), bucket, signal)
      const limit = num(args.limit, 200, 500)
      const top =
        res.length > limit
          ? [...res]
              .sort((a, b) => b.count - a.count)
              .slice(0, limit)
              .sort((a, b) => a.t - b.t)
          : res
      return { bucket, buckets: res.length, shown: top.length, series: top.map((b) => ({ tIso: iso(b.t), count: b.count })) }
    }
    case 'get_event': {
      const ref = parseRef(args.id, 'ev')
      if (!ref || ref.source !== 'events') return { error: 'give the ref of an event, e.g. "ev:123"' }
      const row = await ds.getEvent(Number(ref.id))
      if (!row) return { error: 'not found' }
      const { raw, ...rest } = row
      void raw
      return { ref: evRef(row.id), ...rest }
    }
    case 'process_tree':
      return processTree(ds, args, signal)
    case 'logon_session':
      return logonSession(ds, args, signal)
    case 'search_mails': {
      const limit = num(args.limit, 30, MAX_ROWS)
      const filter = clampFilter(args.filter)
      const res = await ds.searchMails(filter, limit, signal)
      return {
        total: await withTotal(ds, 'mails', filter, res, signal),
        returned: res.rows.length,
        rows: res.rows.map((r) => ({
          ref: mailRef(r.id),
          ...project(r as Record<string, unknown>, MAIL_COLS),
          attachments: (r.attachments ?? []).map((a) => ({ name: a.name, realExt: a.realExt, size: a.size, risk: a.risk, flags: a.flags })),
          urls: (r.urls ?? []).slice(0, 10).map((u) => ({ url: u.defanged, flags: u.flags })),
        })),
      }
    }
    case 'aggregate_mails': {
      const res = await ds.aggregateMails(clampFilter(args.filter), str(args.field) || 'fromDomain', num(args.limit, 25, 100), signal)
      return { field: args.field, total: res.total, distinct: res.distinct, groups: res.groups.map((g) => ({ ...g, firstIso: iso(g.first), lastIso: iso(g.last) })) }
    }
    case 'timeline_mails': {
      const bucket = (['minute', 'hour', 'day'].includes(String(args.bucket)) ? args.bucket : 'day') as Bucket
      const res = await ds.timelineMails(clampFilter(args.filter), bucket, signal)
      return { bucket, series: res.slice(0, 500).map((b) => ({ tIso: iso(b.t), count: b.count })) }
    }
    case 'get_mail': {
      const ref = parseRef(args.id, 'mail')
      if (!ref || ref.source !== 'mails') return { error: 'give the ref of a mail, e.g. "mail:12"' }
      const r = await ds.getMail(Number(ref.id))
      if (!r) return { error: 'not found' }
      const row = r.row
      const out: Record<string, unknown> = {
        ref: mailRef(row.id),
        ...row,
        attachments: (row.attachments ?? []).map((a) => ({ ...a, details: undefined })),
        urls: (row.urls ?? []).slice(0, 40).map((u) => ({ url: u.defanged, host: u.host, flags: u.flags, text: u.text })),
      }
      if (args.includeBody && r.body) {
        out.bodyText = (r.body.bodyText || r.body.visibleText || '').slice(0, 6000)
        if (r.body.headersText) out.headersText = r.body.headersText.slice(0, 6000)
      }
      delete out.bodyHtml
      delete out.id
      return out
    }
    case 'list_findings': {
      const sev = str(args.severity).toLowerCase()
      const src = str(args.source)
      const status = str(args.status)
      const rule = str(args.rule).toLowerCase()
      const q = str(args.q).toLowerCase()
      const rows = await db.findings
        .where('caseId')
        .equals(caseId)
        .filter(
          (f) =>
            (!sev || (f.severityOverride ?? f.severity) === sev) &&
            (!src || f.source === src) &&
            (!status || f.status === status) &&
            (!rule || f.ruleId.toLowerCase().includes(rule)) &&
            (!q || f.title.toLowerCase().includes(q)),
        )
        .toArray()
      rows.sort((a, b) => SEVERITY_ORDER.indexOf(a.severityOverride ?? a.severity) - SEVERITY_ORDER.indexOf(b.severityOverride ?? b.severity) || (a.ts ?? 0) - (b.ts ?? 0))
      const limit = num(args.limit, 50, 200)
      return { total: rows.length, returned: Math.min(limit, rows.length), findings: rows.slice(0, limit).map(findingOut) }
    }
    case 'get_finding': {
      const ref = parseRef(args.id, 'finding')
      if (!ref || ref.source !== 'findings') return { error: 'give the ref of a finding, e.g. "finding:7"' }
      const f = await db.findings.get(Number(ref.id))
      if (!f || f.caseId !== caseId) return { error: `no finding ${refKey(ref)}` }
      const n = num(args.rows, 10, 25)
      const rows: unknown[] = []
      for (const id of f.refs.slice(0, n)) {
        if (f.source === 'mails') {
          const m = await ds.getMail(id)
          if (m) rows.push({ ref: mailRef(id), ...project(m.row as unknown as Record<string, unknown>, MAIL_COLS) })
        } else {
          const e = await ds.getEvent(id)
          if (e) rows.push(eventOut(e as unknown as Record<string, unknown>))
        }
      }
      return { ...findingOut(f), description: f.description, notes: f.notes, rowsTotal: f.refs.length, rows }
    }
    case 'get_chain':
      return getChain(caseId, args)
    case 'get_story':
      return getStory(caseId, args)
    case 'list_iocs': {
      const res = await ds.listIocs({ kind: str(args.kind) || undefined, q: str(args.q) || undefined, onlyBad: args.only_bad === true, limit: num(args.limit, 50, 200) })
      return {
        total: res.total,
        kinds: res.kinds,
        iocs: res.rows.map((i) => ({
          kind: i.kind,
          value: i.value,
          count: i.count,
          firstIso: iso(i.firstSeen),
          lastIso: iso(i.lastSeen),
          verdict: i.verdict ?? undefined,
          tags: i.tags,
          sources: i.sources?.slice(0, 5),
        })),
      }
    }
    case 'get_case_notes': {
      const kind = ['note', 'task', 'timeline'].includes(str(args.kind)) ? (str(args.kind) as 'note' | 'task' | 'timeline') : undefined
      const notes = await listNotes(caseId, kind)
      const linkRef = (l: (typeof notes)[number]['link']) =>
        !l ? undefined : l.source === 'events' ? evRef(l.id) : l.source === 'mails' ? mailRef(l.id) : l.source === 'findings' ? `finding:${l.id}` : `chain:${l.id}`
      return { notes: notes.slice(0, 100).map((n) => ({ kind: n.kind, text: n.text.slice(0, 600), atIso: iso(n.ts), done: n.done, ref: linkRef(n.link) })) }
    }
    case 'facet_values': {
      const source = args.source === 'mails' ? 'mails' : 'events'
      const field = str(args.field)
      if (!field) return { error: 'field is required' }
      return { source, field, values: await ds.facets(source, field, num(args.limit, 30, 100), str(args.q) || undefined) }
    }
    case 'pivot':
      return ds.pivot(str(args.value), signal)
    case 'regex_test': {
      const pattern = str(args.pattern)
      const flags = str(args.flags) || 'i'
      if (!pattern || pattern.length > 500) return { error: 'give a pattern of at most 500 characters' }
      if (args.sample != null) {
        const timeout = AbortSignal.timeout(3000)
        try {
          const any = (AbortSignal as unknown as { any?: (s: AbortSignal[]) => AbortSignal }).any
          return await runQuery('regexSample', [pattern, flags, String(args.sample).slice(0, 4000)], signal && any ? any([signal, timeout]) : timeout)
        } catch (e) {
          if (timeout.aborted) return { error: 'the pattern took more than 3 seconds on the sample: it backtracks too much' }
          throw e
        }
      }
      const source = args.source === 'mails' ? 'mails' : 'events'
      const field = str(args.field) || (source === 'mails' ? 'subject' : 'summary')
      const limit = num(args.limit, 20, MAX_ROWS)
      const filter: Filter = { regex: { field, pattern, flags } }
      if (source === 'mails') {
        const res = await ds.searchMails(filter, limit, signal)
        return { total: await withTotal(ds, 'mails', filter, res, signal), rows: res.rows.map((r) => ({ ref: mailRef(r.id), value: (r as Record<string, unknown>)[field] })) }
      }
      const res = await ds.searchEvents(filter, limit, signal)
      return {
        total: await withTotal(ds, 'events', filter, res, signal),
        rows: res.rows.map((r) => ({ ref: evRef(r.id), tsIso: r.tsIso, eventId: r.eventId, value: (r as Record<string, unknown>)[field] })),
      }
    }
    case 'lookup_ioc': {
      if (!kase.settings.networkAllowed) return { notice: 'External reputation lookups are disabled for this case.' }
      const kind = str(args.kind)
      const value = str(args.value)
      if (!['ip', 'domain', 'url', 'hash'].includes(kind) || !value) return { error: 'kind must be ip|domain|url|hash and value non-empty' }
      // Only a value the case holds leaves the machine, so evidence cannot be encoded into a lookup
      if (!(await valueInCase(kase, kind, value, signal))) return { error: `"${value.slice(0, 80)}" does not appear in this case; only indicators found in the evidence can be looked up` }
      const resp = await lookupReputation([{ kind, value }], kase.settings.providers?.length ? kase.settings.providers : undefined)
      return { summary: resp.summary[`${kind}:${value}`] ?? null, verdicts: resp.results.map((r) => ({ provider: r.provider, verdict: r.verdict, score: r.score, tags: r.tags, details: r.details })) }
    }
    case 'sql': {
      if (!ds.sql) return { notice: 'The sql tool is only available for server-stored cases.' }
      const text = str(args.sql)
      const res = await ds.sql(text, num(args.limit, 200, 500))
      // rows of one table with their id stay citable
      const table = /\bfrom\s+"?(events|mails)"?\b/i.exec(text)?.[1]?.toLowerCase()
      if (table && res.columns.includes('id') && !/\bjoin\b/i.test(text))
        return { ...res, rows: res.rows.map((r) => ({ ref: table === 'mails' ? mailRef(r.id as number) : evRef(r.id as number), ...r })) }
      return res
    }
    case 'search_rules': {
      const q = str(args.q).toLowerCase()
      const rules = await loadRules(caseId)
      const counts = new Map<string, number>()
      await db.findings
        .where('caseId')
        .equals(caseId)
        .each((f) => counts.set(f.ruleId, (counts.get(f.ruleId) ?? 0) + 1))
      const hit = rules.filter((r) => {
        if (!q) return true
        const x = r.rule
        return [x.id, x.title, x.description ?? '', ...(x.attack ?? []), ...((x as { tags?: string[] }).tags ?? [])].some((s) => String(s).toLowerCase().includes(q))
      })
      const limit = num(args.limit, 25, 100)
      return {
        total: hit.length,
        rules: hit.slice(0, limit).map((r) => ({
          id: r.rule.id,
          title: r.rule.title,
          severity: r.rule.severity,
          source: r.rule.source,
          attack: r.rule.attack,
          enabled: r.enabled && r.rule.enabled !== false,
          origin: r.origin === 'pack' ? r.pack : r.origin,
          findingsHere: counts.get(r.rule.id) ?? 0,
        })),
      }
    }
    case 'test_rule': {
      const tested = await testRule(kase, str(args.yaml), signal)
      return 'error' in tested ? tested : tested.out
    }
  }
  return { error: `unknown tool ${name}` }
}

async function processTree(ds: DataSource, args: Record<string, unknown>, signal?: AbortSignal) {
  const guid = str(args.process_guid).replace(/[{}]/g, '').toLowerCase()
  const cols = [
    'tsIso',
    'eventId',
    'computer',
    'image',
    'processName',
    'commandLine',
    'parentImage',
    'parentProcessName',
    'processGuid',
    'parentProcessGuid',
    'newProcessId',
    'callerProcessId',
    'subjectUser',
    'targetUser',
  ]
  const created = (rows: unknown[]) => rows.map((r) => eventOut(r as Record<string, unknown>, cols))
  if (guid) {
    const byGuid = (field: string, value: string, limit: number) =>
      ds.searchEvents(
        {
          conditions: [
            { field, op: 'contains', value },
            { field: 'eventId', op: 'eq', value: 1 },
          ],
          sort: { field: 'ts', dir: 'asc' },
        },
        limit,
        signal,
      )
    const self = (await byGuid('processGuid', guid, 1)).rows[0] as Record<string, unknown> | undefined
    const parents: unknown[] = []
    let parentGuid = String(self?.parentProcessGuid ?? '')
      .replace(/[{}]/g, '')
      .toLowerCase()
    for (let i = 0; i < 6 && parentGuid; i++) {
      const p = (await byGuid('processGuid', parentGuid, 1)).rows[0] as Record<string, unknown> | undefined
      if (!p) break
      parents.push(p)
      parentGuid = String(p.parentProcessGuid ?? '')
        .replace(/[{}]/g, '')
        .toLowerCase()
    }
    const children = await byGuid('parentProcessGuid', guid, 30)
    const activity = await ds.aggregateEvents({ conditions: [{ field: 'processGuid', op: 'contains', value: guid }] }, 'eventId', 20, signal)
    if (!self && !children.rows.length && !activity.total) return { error: 'no Sysmon event carries this process GUID' }
    return {
      process: self ? created([self])[0] : null,
      parents: created(parents),
      children: created(children.rows),
      activityByEventId: activity.groups.map((g) => ({ eventId: g.value, count: g.count })),
      note: 'Sysmon: 1 process, 3 network, 7 image load, 8/10 remote thread/process access, 11 file, 12-14 registry, 22 DNS',
    }
  }
  const raw = str(args.pid)
  const n = /^0x[0-9a-f]+$/i.test(raw) ? parseInt(raw, 16) : Number(raw)
  if (!Number.isSafeInteger(n) || n < 0) return { error: 'give process_guid, or computer and pid' }
  const hex = n.toString(16)
  const variants = [String(n), `0x${hex}`, `0x${hex.toUpperCase()}`]
  const host = str(args.computer)
  const on = host ? [{ field: 'computer', op: 'contains' as const, value: host }] : []
  const selfRes = await ds.searchEvents(
    { conditions: [...on, { field: 'eventId', op: 'in', value: [4688, 1] }, { field: 'newProcessId', op: 'in', value: variants }], sort: { field: 'ts', dir: 'desc' } },
    3,
    signal,
  )
  const sysmon = selfRes.rows.length
    ? selfRes
    : await ds.searchEvents({ conditions: [...on, { field: 'eventId', op: 'eq', value: 1 }, { field: 'callerProcessId', op: 'in', value: variants }], sort: { field: 'ts', dir: 'desc' } }, 3, signal)
  const self = sysmon.rows[0] as Record<string, unknown> | undefined
  const children = await ds.searchEvents(
    { conditions: [...on, { field: 'eventId', op: 'eq', value: 4688 }, { field: 'callerProcessId', op: 'in', value: variants }], sort: { field: 'ts', dir: 'asc' } },
    30,
    signal,
  )
  const parents: unknown[] = []
  let parentPid = self && self.eventId === 4688 ? str(self.callerProcessId) : ''
  for (let i = 0; i < 6 && parentPid; i++) {
    const p = (
      await ds.searchEvents(
        {
          conditions: [...on, { field: 'eventId', op: 'eq', value: 4688 }, { field: 'newProcessId', op: 'eq', value: parentPid }],
          timeRange: self?.ts ? { to: new Date(Number(self.ts)).toISOString() } : undefined,
          sort: { field: 'ts', dir: 'desc' },
        },
        1,
        signal,
      )
    ).rows[0] as Record<string, unknown> | undefined
    if (!p) break
    parents.push(p)
    parentPid = str(p.callerProcessId)
  }
  if (!self && !children.rows.length) return { error: `no process creation (4688 or Sysmon 1) with pid ${raw}${host ? ` on ${host}` : ''}` }
  return {
    process: self ? created([self])[0] : null,
    otherMatches: created(sysmon.rows.slice(1)),
    parents: created(parents),
    children: created(children.rows),
    note: 'process ids are reused: check the times, and prefer process_guid when Sysmon is there',
  }
}

async function logonSession(ds: DataSource, args: Record<string, unknown>, signal?: AbortSignal) {
  const id = str(args.logon_id)
  if (!id) return { error: 'logon_id is required (TargetLogonId of the 4624)' }
  const variants = Array.from(new Set([id, id.toLowerCase(), id.toUpperCase().replace(/^0X/, '0x')]))
  const host = str(args.computer)
  const on = host ? [{ field: 'computer', op: 'contains' as const, value: host }] : []
  const cols = [
    'tsIso',
    'eventId',
    'computer',
    'summary',
    'targetUser',
    'subjectUser',
    'logonType',
    'ipAddress',
    'workstation',
    'processName',
    'commandLine',
    'serviceName',
    'taskName',
    'objectName',
    'shareName',
  ]
  const logon = await ds.searchEvents(
    { conditions: [...on, { field: 'eventId', op: 'in', value: [4624, 4648, 4672] }, { field: 'targetLogonId', op: 'in', value: variants }], sort: { field: 'ts', dir: 'asc' } },
    5,
    signal,
  )
  const actFilter: Filter = { conditions: [...on, { field: 'subjectLogonId', op: 'in', value: variants }], sort: { field: 'ts', dir: 'asc' } }
  const acts = await ds.searchEvents(actFilter, 60, signal)
  const byEvent = await ds.aggregateEvents(actFilter, 'eventId', 20, signal)
  const logoff = await ds.searchEvents({ conditions: [...on, { field: 'eventId', op: 'in', value: [4634, 4647] }, { field: 'targetLogonId', op: 'in', value: variants }] }, 3, signal)
  if (!logon.rows.length && !acts.rows.length) return { error: `no event carries logon id ${id}${host ? ` on ${host}` : ''}` }
  const out = (rs: unknown[]) => rs.map((r) => eventOut(r as Record<string, unknown>, cols))
  return {
    logon: out(logon.rows),
    activityTotal: await withTotal(ds, 'events', actFilter, acts, signal),
    activityByEventId: byEvent.groups.map((g) => ({ eventId: g.value, count: g.count })),
    activity: out(acts.rows),
    logoff: out(logoff.rows),
  }
}

async function getChain(caseId: number, args: Record<string, unknown>) {
  const res = await loadChains(caseId)
  const chains = res?.chains ?? []
  const wantId = str(args.chain_id).replace(/^chain:/, '')
  const wantUser = str(args.user).toLowerCase()
  const c = chains.find((x) => x.id === wantId) ?? (wantUser ? chains.find((x) => x.identity.toLowerCase() === wantUser || x.identityLabel.toLowerCase().includes(wantUser)) : undefined)
  if (!c) return { error: 'no such chain', chains: chains.slice(0, 30).map((x) => ({ ref: `chain:${x.id}`, recipient: x.identityLabel, score: x.score, severity: x.severity, steps: x.steps.length })) }
  const db = getDb()
  const findings = await db.findings.where('caseId').equals(caseId).toArray()
  const membership = chainMembership(findings, chains)
  const linked = findings.filter((f) => f.id != null && membership.get(f.id) === c.id && f.ruleId !== 'chain')
  const unlinked = findings.filter((f) => f.chainUnlinked)
  const seedSource = c.seed.source ?? 'mails'
  return {
    ref: `chain:${c.id}`,
    recipient: c.identityLabel,
    score: c.score,
    severity: c.severity,
    scoreBreakdown: c.scoreBreakdown ?? null,
    artifactLinks: c.artifactLinks,
    from: iso(c.start),
    to: iso(c.end),
    summary: c.summary,
    seed: {
      ref: seedSource === 'mails' ? mailRef(c.seed.id) : evRef(c.seed.id),
      subject: c.seed.subject,
      from: c.seed.fromAddr,
      at: iso(c.seed.ts),
      risk: c.seed.risk,
      flags: c.seed.flags,
      findings: c.seed.findings.map((f) => f.title),
    },
    entities: c.entities,
    steps: c.steps
      .filter((st) => stepVisible(st, 'weighted'))
      .slice(0, 40)
      .map((st) => ({
        ref: st.kind === 'mail' ? mailRef(st.id) : evRef(st.id),
        at: iso(st.ts),
        offsetMin: Math.round(st.offsetMin),
        kind: st.kind === 'mail' ? 'mail' : (st.origin ?? 'host'),
        title: st.title,
        weight: st.weight,
        ties: st.artifacts,
        findings: st.findings.map((f) => f.title),
      })),
    stepsTotal: c.steps.length,
    linkedFindings: linked
      .slice(0, 40)
      .map((f) => ({ ref: `finding:${f.id}`, ruleId: f.ruleId, severity: f.severityOverride ?? f.severity, title: f.title, source: f.source, rows: f.count, status: f.status })),
    unlinkedFindings: unlinked.slice(0, 20).map((f) => ({ ref: `finding:${f.id}`, ruleId: f.ruleId, title: f.title })),
  }
}

/** One story (data/stories.ts), or the list of them to choose from: its phases, its steps with why each is in it, and where it stops. */
async function getStory(caseId: number, args: Record<string, unknown>) {
  const res = await loadStories(caseId)
  const stories = res?.stories ?? []
  const wantId = str(args.story_id)
  const wantUser = str(args.user).toLowerCase()
  const s = stories.find((x) => x.id === wantId) ?? (wantUser ? stories.find((x) => x.title.toLowerCase().includes(wantUser) || x.hosts.includes(wantUser)) : undefined)
  const brief = (x: Story) => ({
    id: x.id,
    about: x.title,
    kind: x.kind,
    severity: x.severity,
    score: x.score,
    phases: x.phases.map((p) => p.label),
    from: iso(x.start),
    to: iso(x.end),
    steps: x.steps.length,
  })
  if (!s) return { error: 'no such story', stories: stories.slice(0, 40).map(brief) }
  const ref = (r: string) => {
    const row = refRow(r)
    return row ? (row.source === 'mails' ? mailRef(row.id) : evRef(row.id)) : r
  }
  return {
    ...brief(s),
    headline: s.headline,
    summary: s.summary,
    confidence: s.confidence,
    hosts: s.hosts,
    sources: s.attackerAddresses,
    phases: s.phases.map((p) => ({ phase: p.label, from: iso(p.first), to: iso(p.last), steps: p.steps, worst: p.severity })),
    steps: s.steps.slice(0, 60).map((st) => ({
      refs: st.refs.slice(0, 5).map(ref),
      records: st.count,
      at: iso(st.ts),
      phase: st.phase ? PHASE_LABEL[st.phase] : null,
      why: `${st.tie.confidence}: ${st.tie.basis}`,
      title: st.title,
      host: st.host,
      ip: st.ip,
      findings: st.findings.map((f) => `${f.title} (${f.severity})`),
    })),
    stepsTotal: s.steps.length,
    hops: s.lineage.hops.slice(0, 20).map((h) => `${h.kind} ${h.from.host ?? h.from.ip ?? '?'} -> ${h.to}${h.account ? ` as ${h.account}` : ''} at ${iso(h.ts)} (${h.confidence}: ${h.basis})`),
    whereItStops: storyGaps(s, res?.stats),
    campaigns: (res?.campaigns ?? []).filter((c) => c.stories.includes(s.id)).map((c) => ({ label: c.label, stories: c.stories.length, otherAccounts: c.targets.length })),
  }
}

async function testRule(kase: Case, text: string, signal?: AbortSignal) {
  if (!text) return { error: 'yaml is required' }
  const parsed = parseRuleYaml(text.replace(/^```(?:yaml)?\s*/m, '').replace(/```\s*$/m, ''))
  if (parsed.errors.length) return { error: `the rule does not validate: ${parsed.errors.slice(0, 3).join('; ')}` }
  if (parsed.rules.length !== 1) return { error: 'give exactly one rule' }
  const rule = parsed.rules[0]
  const res = await dryRunRule(kase, rule, signal)
  const src = rule.source === 'mails' ? 'mails' : 'events'
  return {
    rule,
    res,
    out: {
      ruleId: rule.id,
      findings: res.findings,
      errors: res.errors.slice(0, 5),
      silent: res.diagnostics.filter((d) => d.ruleId === rule.id).map((d) => `${d.reason}${d.detail ? `: ${d.detail}` : ''}`),
      first: res.sample.slice(0, 8).map((f) => ({
        title: f.title,
        severity: f.severity,
        tsIso: iso(f.ts),
        count: f.count,
        entities: f.entities,
        rows: f.refs.slice(0, 5).map((id) => (src === 'mails' ? mailRef(id) : evRef(id))),
      })),
    },
  }
}

// ---------------------------------------------------------------------------
// the investigation and the proposals
// ---------------------------------------------------------------------------
const STATUSES: HypothesisStatus[] = ['open', 'supported', 'refuted', 'inconclusive']

function citeError(unseen: string[], bad: string[]): string {
  const parts: string[] = []
  if (unseen.length) parts.push(`not returned by any tool in this conversation: ${unseen.slice(0, 8).join(', ')}`)
  if (bad.length) parts.push(`not refs: ${bad.slice(0, 5).join(', ')}`)
  return parts.join('; ')
}

async function agentTool(name: string, args: Record<string, unknown>, ctx: ToolContext): Promise<ToolOutput> {
  const { kase, seen } = ctx
  const caseId = kase.id!
  const base = { by: 'agent' as const, model: ctx.model, session: ctx.session, exposed: ctx.exposed?.() || undefined }
  const done = (obj: unknown, extra: Partial<ToolOutput> = {}): ToolOutput => ({ content: JSON.stringify(obj), refs: [], suspects: [], ...extra })
  switch (name) {
    case 'update_plan': {
      const steps = (Array.isArray(args.steps) ? args.steps : [])
        .map((s) => (typeof s === 'string' ? { title: s } : (s as Record<string, unknown>)))
        .map((s) => ({ title: str(s.title).slice(0, 160), status: (['todo', 'doing', 'done', 'skipped'].includes(str(s.status)) ? str(s.status) : 'todo') as PlanStep['status'] }))
        .filter((s) => s.title)
        .slice(0, 12)
      if (!steps.length) return fail('give steps: [{title, status}]')
      return done({ recorded: true, steps: steps.length }, { plan: steps })
    }
    case 'record_hypothesis': {
      const statement = str(args.statement)
      const id = str(args.id)
      if (!statement && !id) return fail('give a statement (or the id of a hypothesis to update)')
      const status = STATUSES.includes(str(args.status) as HypothesisStatus) ? (str(args.status) as HypothesisStatus) : undefined
      const confidence = ['low', 'medium', 'high'].includes(str(args.confidence)) ? (str(args.confidence) as 'low' | 'medium' | 'high') : undefined
      const support = checkCites(args.cites, seen)
      const against = checkCites(args.against, seen)
      const h = await recordHypothesis(
        caseId,
        { id: id || undefined, statement: statement || undefined, status, confidence, support: support.ok, against: against.ok, next: args.next_check != null ? str(args.next_check) : undefined },
        'ai',
      )
      const dropped = citeError([...support.unseen, ...against.unseen], [...support.bad, ...against.bad])
      return done({ recorded: h.id, status: h.status, for: h.support.length, against: h.against.length, ...(dropped ? { droppedCitations: dropped } : {}) })
    }
    case 'finish': {
      const answer = str(args.answer)
      if (!answer) return fail('give the answer')
      const openQuestions = Array.isArray(args.open_questions) ? args.open_questions.map(str).filter(Boolean).slice(0, 10) : undefined
      return done({ recorded: true }, { final: { answer, confidence: str(args.confidence) || undefined, openQuestions } })
    }
    case 'propose_decision':
    case 'suggest_review': {
      const reason = str(args.reason)
      if (!reason) return fail('reason is required')
      const sevRaw = str(args.severity).toLowerCase()
      const severity = SEVERITY_ORDER.includes(sevRaw) ? (sevRaw as Finding['severity']) : undefined
      let target: string
      let label: string
      let kind: 'chain' | 'incident' = 'incident'
      const cites = checkCites(args.cites, seen)
      if (args.chain_id) {
        const chainId = str(args.chain_id).replace(/^chain:/, '')
        const c = (await loadChains(caseId))?.chains.find((x) => x.id === chainId)
        if (!c) return fail(`no chain ${chainId}; use get_chain or list_findings`)
        target = `chain:${c.id}`
        label = `chain ${c.identityLabel}`
        kind = 'chain'
        if (seen.has(target) && !cites.ok.some((r) => refKey(r) === target)) cites.ok.unshift({ source: 'chains', id: c.id })
      } else if (args.finding_id != null) {
        const ref = parseRef(args.finding_id, 'finding')
        const f = ref?.source === 'findings' ? await getDb().findings.get(Number(ref.id)) : undefined
        if (!f || f.caseId !== caseId) return fail(`no finding ${str(args.finding_id)}`)
        target = `finding:${f.id}`
        label = f.title
        if (seen.has(target) && !cites.ok.some((r) => refKey(r) === target)) cites.ok.unshift({ source: 'findings', id: f.id! })
      } else return fail('give finding_id or chain_id')
      const decision = args.decision != null ? (normaliseDecision(args.decision, kind) ?? undefined) : undefined
      if (args.decision != null && !decision) return fail(`decision for ${kind === 'chain' ? 'a chain: confirmed, benign or unsure' : 'an incident: escalated, reviewed or false_positive'}`)
      if (!cites.ok.length) return fail(`cite at least one row, finding or chain you retrieved (${citeError(cites.unseen, cites.bad) || 'no citation given'})`)
      const unlink = Array.isArray(args.unlink_finding_ids) ? args.unlink_finding_ids.map((x) => Number(parseRef(x, 'finding')?.id)).filter((n) => Number.isFinite(n)) : []
      const p = await propose(caseId, {
        kind: 'decision',
        title: `${decision ?? 'assess'}${severity ? ` · ${severity}` : ''} · ${label}`.slice(0, 200),
        reason: reason.slice(0, 900),
        citations: cites.ok,
        target,
        decision: { decision: decision as Decision | undefined, severity, include: typeof args.include === 'boolean' ? args.include : undefined, unlink: unlink.length ? unlink : undefined },
        ...base,
      })
      return done(
        { queued: p.id, target, note: 'waiting in the analyst inbox; it changes nothing until accepted', ...(cites.unseen.length ? { droppedCitations: citeError(cites.unseen, []) } : {}) },
        { proposal: p },
      )
    }
    case 'propose_note': {
      const kindRaw = str(args.kind)
      const kind = (['note', 'task', 'timeline'].includes(kindRaw) ? kindRaw : 'note') as 'note' | 'task' | 'timeline'
      const text = str(args.text)
      if (!text) return fail('text is required')
      const cites = checkCites(args.cites, seen)
      if (kind !== 'task' && !cites.ok.length) return fail(`cite the rows this ${kind} rests on (${citeError(cites.unseen, cites.bad) || 'no citation given'})`)
      let ts: number | null = null
      if (kind === 'timeline' && args.at) {
        ts = Date.parse(str(args.at))
        if (!Number.isFinite(ts)) return fail('at must be an ISO time, e.g. 2026-01-02T10:15:00Z')
      }
      const first = cites.ok[0]
      const link = kind === 'timeline' && first ? { source: first.source, id: first.id, label: refKey(first) } : undefined
      const p = await propose(caseId, {
        kind: 'note',
        title: `${kind}: ${text}`.slice(0, 200),
        reason: '',
        citations: cites.ok,
        note: { kind, text: text.slice(0, 2000), ts, link: link as never },
        ...base,
      })
      return done({ queued: p.id, note: 'waiting in the analyst inbox' }, { proposal: p })
    }
    case 'propose_row_mark': {
      const verdict = str(args.verdict) as RowMarkVerdict
      if (!['relevant', 'noise', 'pivot'].includes(verdict)) return fail('verdict: relevant, noise or pivot')
      const cites = checkCites(args.refs, seen, 'ev')
      const rows = cites.ok.filter((r) => r.source === 'events' || r.source === 'mails')
      if (!rows.length) return fail(`give refs of events or mails you retrieved (${citeError(cites.unseen, cites.bad) || 'none given'})`)
      const source = rows[0].source as 'events' | 'mails'
      const same = rows.filter((r) => r.source === source).slice(0, 200)
      const tags = (Array.isArray(args.tags) ? args.tags : []).map(str).filter(Boolean).slice(0, 8)
      const p = await propose(caseId, {
        kind: 'row_mark',
        title: `mark ${same.length} ${source === 'events' ? 'event' : 'mail'}(s) ${verdict}${tags.length ? ` · ${tags.join(', ')}` : ''}`,
        reason: str(args.reason).slice(0, 600),
        citations: same,
        mark: { source, refs: same.map((r) => Number(r.id)), verdict, tags },
        ...base,
      })
      return done({ queued: p.id, rows: same.length, note: 'waiting in the analyst inbox' }, { proposal: p })
    }
    case 'propose_rule': {
      const tested = await testRule(kase, str(args.yaml), ctx.signal)
      if ('error' in tested) return fail(String(tested.error))
      const existing = await loadRules(caseId)
      if (existing.some((r) => r.rule.id === tested.rule.id)) return fail(`a rule with id ${tested.rule.id} exists already: choose another id`)
      const yaml = str(args.yaml)
        .replace(/^```(?:yaml)?\s*/m, '')
        .replace(/```\s*$/m, '')
      const p = await propose(caseId, {
        kind: 'rule',
        title: `rule ${tested.rule.id}: ${tested.rule.title} (${tested.res.findings} finding(s) here)`.slice(0, 200),
        reason: str(args.reason).slice(0, 900),
        citations: [],
        rule: { yaml, ruleId: tested.rule.id, test: { findings: tested.res.findings, errors: tested.res.errors.slice(0, 5), sample: tested.res.sample.slice(0, 5).map((f) => f.title) } },
        ...base,
      })
      return done({ queued: p.id, test: tested.out, note: 'waiting in the analyst inbox' }, { proposal: p, refs: refsIn(tested.out) })
    }
    case 'propose_summary': {
      const text = str(args.text)
      if (text.length < 40) return fail('give the summary text')
      const cites = checkCites(args.cites, seen)
      const p = await propose(caseId, { kind: 'summary', title: `executive summary (${text.length} characters)`, reason: '', citations: cites.ok, summary: { text: text.slice(0, 8000) }, ...base })
      return done({ queued: p.id, note: 'waiting in the analyst inbox' }, { proposal: p })
    }
  }
  return fail(`unknown tool ${name}`)
}

const AGENT_TOOLS = new Set<string>([...TOOL_GROUPS.agent, ...TOOL_GROUPS.propose, 'suggest_review'])

/** Run one tool call: the result as the model reads it, with the refs it returned and any text in it addressed to a model. */
export async function runTool(name: string, args: Record<string, unknown>, ctx: ToolContext): Promise<ToolOutput> {
  try {
    if (AGENT_TOOLS.has(name)) {
      const out = await agentTool(name, args, ctx)
      ctx.seen.addAll(out.refs)
      return out
    }
    const result = await read(name, args ?? {}, ctx)
    const refs = refsIn(result)
    ctx.seen.addAll(refs)
    const suspects = findInstructions(result)
    const text = cap(result)
    return { content: wrapEvidence(name, text, suspects), refs, suspects, error: !!(result && typeof result === 'object' && 'error' in (result as object)) }
  } catch (e) {
    if ((e as Error).name === 'AbortError') throw e
    return fail((e as Error).message || String(e))
  }
}
