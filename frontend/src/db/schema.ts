import Dexie, { type Table } from 'dexie'
import { uuid4 } from '../util/uuid'

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type EvidenceKind = 'evtx' | 'mail' | 'package'
export type EvidenceStatus = 'hashing' | 'uploading' | 'parsing' | 'done' | 'error'

export interface CaseSettings {
  internalDomains: string[]
  /** ISO country codes where sign-ins are expected (M365 / Entra rules) */
  expectedCountries?: string[]
  vipNames: string[]
  /** display names of everyone in the organisation (Sublime's $org_display_names); VIPs are the subset that matters most */
  orgDisplayNames?: string[]
  adminAccounts: string[]
  serviceAccounts: string[]
  internalIps: string[]
  businessHours: { start: number; end: number; tz: string }
  weekendDays: number[] // 0 = Sunday ... 6 = Saturday
  brands: string[]
  /** senders (addresses or domains) the analyst trusts: risk capped, spoofing rules skip them */
  trustedSenders: string[]
  /** mailing lists and forwarders whose ARC seal is trusted to vouch for the original authentication */
  trustedArcSealers?: string[]
  networkAllowed: boolean
  providers: string[] // reputation providers enabled (empty = all configured)
  includeRaw: boolean
  /** server store only: run the deep attachment analyzers (macros, PDF, archives) during ingestion */
  deepAttachments?: boolean
  /** server store only: keep mail bodies / raw headers */
  keepBodies?: boolean
  /** run the enabled rules when an ingest finishes so the findings never lag the evidence (default on) */
  autoRunRules?: boolean
}

export const defaultSettings = (): CaseSettings => ({
  internalDomains: [],
  expectedCountries: [],
  vipNames: [],
  orgDisplayNames: [],
  adminAccounts: [],
  serviceAccounts: [],
  internalIps: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '::1', 'fe80::/10', 'fc00::/7'],
  businessHours: { start: 8, end: 19, tz: Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC' },
  weekendDays: [0, 6],
  brands: [],
  trustedSenders: [],
  networkAllowed: false,
  providers: [],
  includeRaw: true,
})

export interface Case {
  id?: number
  name: string
  analyst?: string
  notes?: string
  createdAt: number
  updatedAt: number
  settings: CaseSettings
  /** 'browser' = rows in IndexedDB (portable, small cases); 'server' = rows in a DuckDB case store (GB-scale). */
  storage?: 'browser' | 'server'
  /** UUID of the server case store when storage === 'server'. */
  serverKey?: string
}

export function newServerKey(): string {
  return uuid4().toLowerCase()
}

export interface Evidence {
  id?: number
  caseId: number
  name: string
  size: number
  kind: EvidenceKind
  format?: string
  sha256Client?: string
  sha256Server?: string
  integrity: 'pending' | 'verified' | 'mismatch'
  addedAt: number
  lastModified?: number
  status: EvidenceStatus
  progress?: number
  count: number
  stats?: Record<string, unknown>
  error?: string
  note?: string
  analyst?: string
  /** the Web Lock its import holds while it runs (data/interruptedImports.ts) */
  importLock?: string
}

export interface EventRow {
  recordKind?: 'event' | 'observation'
  artifactType?: string
  observedAt?: number | null
  packageId?: string
  sourceFile?: string
  sourceSha256?: string
  sourceIndex?: number
  memberIndex?: number
  parserVersion?: string
  /** a cloud record's own identity (UAL AuditData.Id, Graph sign-in id): the case holds it once */
  recordKey?: string
  id?: number
  caseId: number
  evidenceId: number
  recordId?: number | null
  ts: number | null
  tsIso?: string | null
  eventId: number | null
  provider?: string | null
  channel?: string | null
  computer?: string | null
  level?: number | null
  levelName?: string | null
  category?: string | null
  description?: string | null
  summary?: string
  targetUser?: string | null
  targetDomain?: string | null
  subjectUser?: string | null
  subjectDomain?: string | null
  logonType?: number | null
  logonTypeName?: string | null
  ipAddress?: string | null
  ipPort?: number | null
  workstation?: string | null
  status?: string | null
  subStatus?: string | null
  statusText?: string | null
  authPackage?: string | null
  processName?: string | null
  commandLine?: string | null
  parentProcessName?: string | null
  serviceName?: string | null
  serviceFile?: string | null
  taskName?: string | null
  memberName?: string | null
  groupName?: string | null
  shareName?: string | null
  relativeTargetName?: string | null
  objectName?: string | null
  scriptBlockText?: string | null
  image?: string | null
  parentImage?: string | null
  destinationIp?: string | null
  destinationPort?: number | null
  query?: string | null
  targetFilename?: string | null
  targetObject?: string | null
  threatName?: string | null
  path?: string | null
  message?: string | null
  data?: Record<string, unknown>
  raw?: string
  [key: string]: unknown
}

export interface AttachmentSummary {
  name: string
  ext: string
  realExt: string
  realMime?: string
  size: number
  sha256: string | null
  md5: string | null
  risk: number
  flags: string[]
  category?: string | null
  inline?: boolean
  details?: Record<string, unknown>
  rescoreLimited?: boolean
}

export interface MailAssessment {
  version: string
  confidence: 'low' | 'medium' | 'high'
  groups: Record<string, number>
  attachmentRisk: number
  expectedSender: boolean
  limitations: string[]
}

export interface UrlEntry {
  url: string
  normalized: string
  defanged: string
  host: string
  domain: string
  scheme?: string
  flags: string[]
  text?: string
  source?: string
}

export interface MailRow {
  id?: number
  caseId: number
  evidenceId: number
  sourceIndex?: number
  sourceFormat?: string
  sourceName?: string
  folder: string
  subject: string
  date: number | null
  dateIso?: string | null
  fromName: string
  fromNameNorm: string
  fromAddr: string
  fromDomain: string
  fromRegistrable: string
  replyTo: { name: string; addr: string; domain: string }[]
  returnPath: string | null
  to: { name: string; addr: string; domain: string }[]
  cc: { name: string; addr: string; domain: string }[]
  bcc: { name: string; addr: string; domain: string }[]
  recipientCount: number
  messageId: string | null
  inReplyTo?: string | null
  references?: string[]
  xMailer?: string | null
  priority?: string | null
  originIp: string | null
  originIpSource?: string | null
  originHelo?: string | null
  originRdns?: string | null
  hopCount: number
  hops: Record<string, unknown>[]
  auth: Record<string, unknown>
  textPreview?: string
  keywordHits: Record<string, string[]>
  hiddenText?: string[]
  urls: UrlEntry[]
  urlCount: number
  htmlInfo?: Record<string, unknown>
  attachments: AttachmentSummary[]
  attachmentCount: number
  maxAttachmentRisk: number
  lookalike: Record<string, unknown>
  replyToLookalike?: Record<string, unknown> | null
  /** sender baseline / campaign enrichment (data/enrich.ts), absent until the pass runs */
  senderPrevalence?: 'new' | 'rare' | 'common'
  senderPriorCount?: number
  senderFirstSeen?: number
  senderDaysKnown?: number
  senderSolicited?: boolean | null
  senderAuthRegression?: boolean
  campaignId?: string
  campaignSize?: number
  campaignSenders?: number
  flags: string[]
  risk: number
  assessment?: MailAssessment
  size?: number | null
  reputation?: { originIp?: { verdict: string }; worst?: string; checkedAt?: number }
  [key: string]: unknown
}

export interface MailBody {
  mailId: number
  caseId: number
  bodyText: string | null
  bodyHtml: string | null
  headersText: string | null
  visibleText: string | null
}

export interface AttachmentRow extends AttachmentSummary {
  id?: number
  caseId: number
  mailId: number
  evidenceId: number
  mailSubject?: string
  fromAddr?: string
  date?: number | null
}

export interface UrlRow extends UrlEntry {
  id?: number
  caseId: number
  mailId: number
  evidenceId: number
}

export interface Finding {
  id?: number
  caseId: number
  ruleId: string
  key: string
  title: string
  description?: string
  severity: Severity
  confidence?: 'low' | 'medium' | 'high'
  source: 'events' | 'mails'
  ts: number | null
  tsEnd?: number | null
  entities: Record<string, string>
  count: number
  refs: number[]
  attack: string[]
  tags?: string[]
  status: 'new' | 'reviewed' | 'false_positive' | 'escalated'
  notes?: string
  createdAt: number
  escalation?: string
  /** analyst rescoring (Review page); the rule severity stays in `severity` */
  severityOverride?: Severity
  /** kept out of the report whatever its severity */
  reportExclude?: boolean
  /** taken out of its attack chain by the analyst (or the model): decided on its own again */
  chainUnlinked?: boolean
  /** who made the last decision on this finding */
  decidedBy?: 'analyst' | 'ai'
  /** the model's reason when it decided (kept apart from the analyst's note) */
  aiReason?: string
  /** who wrote the note last (a note the model drafted is replaced by the next triage; the analyst's is kept) */
  notesBy?: 'analyst' | 'ai'
}

export interface Ioc {
  id?: number
  caseId: number
  kind: 'ip' | 'domain' | 'url' | 'hash' | 'email' | 'user' | 'host'
  value: string
  sources: string[]
  firstSeen: number | null
  lastSeen: number | null
  count: number
  reputation?: Record<string, unknown> | null
  checkedAt?: number | null
  verdict?: string | null
  tags?: string[]
}

export interface Facet {
  id?: number
  caseId: number
  source: 'events' | 'mails'
  field: string
  value: string
  count: number
}

export interface AiSession {
  id?: number
  caseId: number
  title: string
  messages: Record<string, unknown>[]
  createdAt: number
  updatedAt: number
  /** the refs the tools returned in this conversation, which its answers may cite (ai/evidence.ts) */
  seen?: string[]
  /** the investigation plan as the agent last wrote it */
  plan?: { title: string; status: string }[]
}

/**
 * One entry of a case's AI ledger: what the model was asked, which tools it ran (with a hash of each
 * result, not the result), what it proposed and what the analyst decided. Entries are chained by
 * hash (`prev` → `hash`), so an edited or removed entry breaks the chain; see ai/ledger.ts.
 */
export interface AiLedgerEntry {
  id?: number
  caseId: number
  seq: number
  at: number
  kind: 'run' | 'tool' | 'proposal' | 'accepted' | 'rejected' | 'undone' | 'answer' | 'notice' | 'triage'
  text: string
  /** JSON detail (a string, so the hash covers exactly what was stored) */
  data: string
  prev: string
  hash: string
}

export interface SavedSearch {
  id?: number
  caseId: number
  name: string
  source: 'events' | 'mails'
  filter: Record<string, unknown>
  createdAt: number
}

export interface CustomRule {
  id?: number
  caseId: number | null // null = global
  ruleId: string
  yaml: string
  enabled: boolean
  updatedAt: number
}

export interface KV {
  key: string
  value: unknown
}

/** Analyst-authored case material (Case notes view): timeline entries, tasks and notes. */
export type RowMarkVerdict = 'relevant' | 'noise' | 'pivot'

/**
 * What a row was, at the moment it was marked.
 *
 * Row ids are not stable: deleting evidence and re-ingesting it renumbers everything, which is a
 * routine mid-case action when a fuller collection arrives. Recording where the row came from lets
 * a later pass re-attach the mark without any change to this schema.
 */
export interface RowProvenance {
  sourceFile: string | null
  sourceSha256: string | null
  sourceIndex: number | null
  /** EventRecordID for an EVTX row: unique within its channel and file. */
  recordId: number | null
  channel: string | null
  computer: string | null
  messageId: string | null
  ts: number | null
}

/** An analyst's verdict on one evidence row. Never stored on the row itself: that is evidence. */
export interface RowMark {
  id?: number
  caseId: number
  source: 'events' | 'mails'
  rowId: number
  evidenceId: number | null
  verdict: RowMarkVerdict
  tags: string[]
  reason: string
  provenance?: RowProvenance
  by: 'analyst' | 'ai'
  createdAt: number
  updatedAt: number
}

export interface CaseNote {
  id?: number
  caseId: number
  kind: 'note' | 'task' | 'timeline'
  text: string
  /** event time for timeline entries; creation time otherwise */
  ts: number
  /** a timeline entry added from a row with no event time (a collected artefact): ts only orders it */
  untimed?: boolean
  createdAt: number
  updatedAt: number
  done?: boolean
  severity?: string
  /** the row, finding or chain a timeline entry was added from */
  link?: { source: 'events' | 'mails' | 'findings' | 'chains' | 'stories'; id: number | string; label?: string }
}

export class RemnDB extends Dexie {
  cases!: Table<Case, number>
  evidence!: Table<Evidence, number>
  events!: Table<EventRow, number>
  mails!: Table<MailRow, number>
  mailBodies!: Table<MailBody, number>
  attachments!: Table<AttachmentRow, number>
  urls!: Table<UrlRow, number>
  findings!: Table<Finding, number>
  iocs!: Table<Ioc, number>
  facets!: Table<Facet, number>
  aiSessions!: Table<AiSession, number>
  aiLedger!: Table<AiLedgerEntry, number>
  savedSearches!: Table<SavedSearch, number>
  customRules!: Table<CustomRule, number>
  kv!: Table<KV, string>
  caseNotes!: Table<CaseNote, number>
  rowMarks!: Table<RowMark, number>

  constructor(name = 'remn') {
    super(name)
    this.version(1).stores({
      cases: '++id, name, createdAt',
      evidence: '++id, caseId, kind, status, sha256Client',
      events: '++id, caseId, evidenceId, ts, eventId, [caseId+ts], [caseId+eventId], [caseId+evidenceId], computer, targetUser, subjectUser, ipAddress, logonType, channel, provider, category',
      mails: '++id, caseId, evidenceId, date, [caseId+date], [caseId+evidenceId], fromAddr, fromDomain, fromRegistrable, fromNameNorm, originIp, folder, risk, messageId, *flags',
      mailBodies: 'mailId, caseId',
      attachments: '++id, caseId, mailId, evidenceId, sha256, ext, realExt, risk, *flags',
      urls: '++id, caseId, mailId, evidenceId, host, domain, *flags',
      findings: '++id, caseId, ruleId, severity, ts, status, key, [caseId+ruleId], [caseId+status]',
      iocs: '++id, caseId, kind, value, [caseId+kind+value], [caseId+kind], verdict',
      facets: '++id, caseId, [caseId+source+field], [caseId+source+field+value]',
      aiSessions: '++id, caseId, updatedAt',
      savedSearches: '++id, caseId, source',
      customRules: '++id, caseId, ruleId',
      kv: 'key',
    })
    this.version(2).stores({ caseNotes: '++id, caseId, kind, ts, [caseId+kind], [caseId+ts]' })
    this.version(3).stores({
      events:
        '++id, caseId, evidenceId, ts, eventId, [caseId+id], [caseId+artifactType], [caseId+ts], [caseId+eventId], [caseId+evidenceId], computer, targetUser, subjectUser, ipAddress, logonType, channel, provider, category',
      mails: '++id, caseId, evidenceId, date, [caseId+id], [caseId+date], [caseId+evidenceId], fromAddr, fromDomain, fromRegistrable, fromNameNorm, originIp, folder, risk, messageId, *flags',
    })
    // A new table only: existing stores are untouched, so an existing case opens without an
    // upgrade function and without rewriting a single row.
    this.version(4).stores({
      rowMarks: '++id, caseId, [caseId+source+rowId], [caseId+source], [caseId+verdict], evidenceId, *tags',
    })
    // One index more on events, for the record keys of cloud audit and sign-in rows. A row
    // without a key (every event log row) is not in it, so the upgrade adds nothing for those.
    this.version(5).stores({
      events:
        '++id, caseId, evidenceId, ts, eventId, [caseId+id], [caseId+artifactType], [caseId+ts], [caseId+eventId], [caseId+evidenceId], [caseId+recordKey], computer, targetUser, subjectUser, ipAddress, logonType, channel, provider, category',
    })
    // The AI ledger: one row per entry, appended and never rewritten.
    this.version(6).stores({ aiLedger: '++id, caseId, [caseId+seq]' })
  }
}

let _db: RemnDB | null = null
export function getDb(): RemnDB {
  if (!_db) _db = new RemnDB()
  return _db
}
/** Test hook: point the module at another database instance. */
export function setDb(db: RemnDB | null): void {
  _db = db
}

/** kv keys that belong to one case (mirrors CASE_KV_PREFIXES in data/caseState.ts, kept here to avoid a schema -> data import). */
export const CASE_KV_KEYS = (caseId: number) =>
  [
    'chains',
    'ruleDiags',
    'baseline',
    'mail-calibration',
    'report-summary',
    'report-summary-by',
    'report-summary-at',
    'finding-reviews',
    'chain-reviews',
    'report-settings',
    'findingCounts',
    'ai-suggestions',
    'ai-triage',
    // the agent's proposals waiting for the analyst (and the decided ones), and its hypothesis board
    'ai-inbox',
    'ai-hypotheses',
    'relationship-reviews',
    'relationship-aliases',
    'relationship-cache',
    'relationship-stories',
    // the stories and campaigns of the case (data/stories.ts), rebuilt from the evidence, and the analyst's notes on them
    'stories',
    'story-notes',
    // the rule choices in force when the case was exported (packs, disabled rules), for the record
    'rule-context',
    // facet fields whose distinct values passed what one ingest counts
    'facets-capped',
    // the analyst's waivers and the time the report was issued as final
    'report-final',
  ].map((p) => `${p}-${caseId}`)

/** kv keys of one case that carry an extra suffix after the case id (one record per hypothesis). */
export const CASE_KV_PREFIXES_WITH_SUFFIX = (caseId: number) => [`relationship-hypothesis-${caseId}-`]

/**
 * Every table whose rows carry a caseId. One list, because it was previously written twice inside
 * deleteCaseData and a table added to only one of them would be left behind on delete.
 */
export const CASE_TABLES = (db: RemnDB): Table<{ caseId: number }, number>[] =>
  [db.events, db.mails, db.mailBodies, db.attachments, db.urls, db.findings, db.iocs, db.facets, db.aiSessions, db.aiLedger, db.savedSearches, db.evidence, db.caseNotes, db.rowMarks] as Table<
    { caseId: number },
    number
  >[]

export async function deleteCaseData(db: RemnDB, caseId: number): Promise<void> {
  const tables = CASE_TABLES(db)
  await db.transaction('rw', [...tables, db.kv], async () => {
    for (const t of tables) await t.where('caseId').equals(caseId).delete()
    await db.kv.bulkDelete(CASE_KV_KEYS(caseId)) // chain snapshot, diagnostics, calibration state, archived reviews
    await db.kv.where('key').startsWith(`relationship-ai-${caseId}-`).delete()
    await db.kv.where('key').startsWith(`relationship-hypothesis-${caseId}-`).delete()
  })
}

/** Everything of a case, the case row included: rows, derived state, custom rules, and the last-case pointer when it was this one. */
export async function deleteCase(db: RemnDB, caseId: number): Promise<void> {
  await deleteCaseData(db, caseId)
  await db.customRules.where('caseId').equals(caseId).delete()
  await db.cases.delete(caseId)
  const last = await db.kv.get('lastCase')
  if (last?.value === caseId) await db.kv.delete('lastCase')
}

/** The rows of one evidence, and the evidence row itself unless `keepRecord` (an import that stopped keeps its record). */
export async function deleteEvidenceData(db: RemnDB, caseId: number, evidenceId: number, keepRecord = false): Promise<void> {
  await db.transaction('rw', [db.events, db.mails, db.mailBodies, db.attachments, db.urls, db.evidence], async () => {
    await db.events.where('[caseId+evidenceId]').equals([caseId, evidenceId]).delete()
    const mailIds = await db.mails.where('[caseId+evidenceId]').equals([caseId, evidenceId]).primaryKeys()
    if (mailIds.length) {
      await db.mailBodies.where('mailId').anyOf(mailIds).delete()
    }
    await db.mails.where('[caseId+evidenceId]').equals([caseId, evidenceId]).delete()
    await db.attachments.where('evidenceId').equals(evidenceId).delete()
    await db.urls.where('evidenceId').equals(evidenceId).delete()
    if (!keepRecord) await db.evidence.delete(evidenceId)
  })
}

export async function estimateStorage(): Promise<{ usage: number; quota: number; persisted: boolean | null } | null> {
  try {
    if (navigator.storage?.estimate) {
      const e = await navigator.storage.estimate()
      const persisted = navigator.storage.persisted ? await navigator.storage.persisted() : null
      return { usage: e.usage ?? 0, quota: e.quota ?? 0, persisted }
    }
  } catch {
    /* ignore */
  }
  return null
}

/**
 * Ask the browser to keep this site's storage. Without it, a browser short of space may clear the
 * whole IndexedDB of a site it considers idle, and with it every case, finding and decision: in
 * browser-store mode that copy is the only one. Asked when evidence is first added, where it matters.
 */
export async function requestPersistentStorage(): Promise<boolean | null> {
  try {
    if (!navigator.storage?.persist) return null
    if (navigator.storage.persisted && (await navigator.storage.persisted())) return true
    return await navigator.storage.persist()
  } catch {
    return null
  }
}
