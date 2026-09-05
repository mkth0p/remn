import Dexie, { type Table } from 'dexie'
import { uuid4 } from '../util/uuid'

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type EvidenceKind = 'evtx' | 'mail'
export type EvidenceStatus = 'hashing' | 'uploading' | 'parsing' | 'done' | 'error'

export interface CaseSettings {
  internalDomains: string[]
  /** ISO country codes where sign-ins are expected (M365 / Entra rules) */
  expectedCountries?: string[]
  vipNames: string[]
  adminAccounts: string[]
  serviceAccounts: string[]
  internalIps: string[]
  businessHours: { start: number; end: number; tz: string }
  weekendDays: number[] // 0 = Sunday ... 6 = Saturday
  brands: string[]
  /** senders (addresses or domains) the analyst trusts: risk capped, spoofing rules skip them */
  trustedSenders: string[]
  networkAllowed: boolean
  providers: string[] // reputation providers enabled (empty = all configured)
  includeRaw: boolean
  /** server store only: run the deep attachment analyzers (macros, PDF, archives) during ingestion */
  deepAttachments?: boolean
  /** server store only: keep mail bodies / raw headers */
  keepBodies?: boolean
}

export const defaultSettings = (): CaseSettings => ({
  internalDomains: [],
  expectedCountries: [],
  vipNames: [],
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
}

export interface EventRow {
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
  senderSolicited?: boolean
  senderAuthRegression?: boolean
  campaignId?: string
  campaignSize?: number
  campaignSenders?: number
  flags: string[]
  risk: number
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
  savedSearches!: Table<SavedSearch, number>
  customRules!: Table<CustomRule, number>
  kv!: Table<KV, string>

  constructor(name = 'remn') {
    super(name)
    this.version(1).stores({
      cases: '++id, name, createdAt',
      evidence: '++id, caseId, kind, status, sha256Client',
      events:
        '++id, caseId, evidenceId, ts, eventId, [caseId+ts], [caseId+eventId], [caseId+evidenceId], computer, targetUser, subjectUser, ipAddress, logonType, channel, provider, category',
      mails:
        '++id, caseId, evidenceId, date, [caseId+date], [caseId+evidenceId], fromAddr, fromDomain, fromRegistrable, fromNameNorm, originIp, folder, risk, messageId, *flags',
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

export async function deleteCaseData(db: RemnDB, caseId: number): Promise<void> {
  await db.transaction('rw', [db.events, db.mails, db.mailBodies, db.attachments, db.urls, db.findings, db.iocs, db.facets, db.aiSessions, db.savedSearches, db.evidence], async () => {
    for (const t of [db.events, db.mails, db.mailBodies, db.attachments, db.urls, db.findings, db.iocs, db.facets, db.aiSessions, db.savedSearches, db.evidence]) {
      await (t as Table<{ caseId: number }, number>).where('caseId').equals(caseId).delete()
    }
  })
}

export async function deleteEvidenceData(db: RemnDB, caseId: number, evidenceId: number): Promise<void> {
  await db.transaction('rw', [db.events, db.mails, db.mailBodies, db.attachments, db.urls, db.evidence], async () => {
    await db.events.where('[caseId+evidenceId]').equals([caseId, evidenceId]).delete()
    const mailIds = await db.mails.where('[caseId+evidenceId]').equals([caseId, evidenceId]).primaryKeys()
    if (mailIds.length) {
      await db.mailBodies.where('mailId').anyOf(mailIds).delete()
    }
    await db.mails.where('[caseId+evidenceId]').equals([caseId, evidenceId]).delete()
    await db.attachments.where('evidenceId').equals(evidenceId).delete()
    await db.urls.where('evidenceId').equals(evidenceId).delete()
    await db.evidence.delete(evidenceId)
  })
}

export async function estimateStorage(): Promise<{ usage: number; quota: number } | null> {
  try {
    if (navigator.storage?.estimate) {
      const e = await navigator.storage.estimate()
      return { usage: e.usage ?? 0, quota: e.quota ?? 0 }
    }
  } catch {
    /* ignore */
  }
  return null
}
