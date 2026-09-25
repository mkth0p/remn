/**
 * Stories: what happened to each person and each host, read as ATT&CK phases
 * (backend/services/analysis/stories.py builds them; docs/stories.md explains them).
 *
 * A server case asks the API to read its store; a browser case selects the rows around its flags
 * here, as stories_for_store does in SQL, and posts them: the findings' records, then within a
 * day before and three days after each flag the records that name the flagged people, come from
 * the addresses the findings name, or are logons, processes, shares, services and tasks on the
 * flagged hosts. The build also returns the phishing chains of those rows, which are kept for the
 * review and the report as a chain build keeps them.
 */
import { apiPost } from '../api/client'
import { getDb, type Case, type Finding, type MailRow, type Severity } from '../db/schema'
import { effectiveSeverity } from '../rules/incidents'
import { CHAIN_DATA_KEYS, persistChainResult, type ChainResult } from './chains'
import { settingsForRules } from './rules'

export type Confidence = 'strong' | 'medium' | 'weak'
export type TieKind = 'flag' | 'chain' | 'session' | 'hop' | 'process' | 'address' | 'identity'

/** ATT&CK v19's tactics in the order an intrusion reads (mirror of stories.PHASES). */
export const PHASES: { id: string; label: string; short: string }[] = [
  { id: 'reconnaissance', label: 'Reconnaissance', short: 'RE' },
  { id: 'resource-development', label: 'Resource development', short: 'RD' },
  { id: 'initial-access', label: 'Initial access', short: 'IA' },
  { id: 'execution', label: 'Execution', short: 'EX' },
  { id: 'persistence', label: 'Persistence', short: 'PE' },
  { id: 'privilege-escalation', label: 'Privilege escalation', short: 'PR' },
  { id: 'stealth', label: 'Stealth', short: 'ST' },
  { id: 'defense-impairment', label: 'Defense impairment', short: 'DI' },
  { id: 'credential-access', label: 'Credential access', short: 'CA' },
  { id: 'discovery', label: 'Discovery', short: 'DS' },
  { id: 'lateral-movement', label: 'Lateral movement', short: 'LM' },
  { id: 'collection', label: 'Collection', short: 'CO' },
  { id: 'command-and-control', label: 'Command and control', short: 'C2' },
  { id: 'exfiltration', label: 'Exfiltration', short: 'EF' },
  { id: 'impact', label: 'Impact', short: 'IM' },
]
export const PHASE_LABEL: Record<string, string> = Object.fromEntries(PHASES.map((p) => [p.id, p.label]))

export interface StoryFinding {
  ruleId: string
  title: string
  severity: Severity
  key: string | null
}
export interface StoryStep {
  /** event:<id> or mail:<id>: the first record of the step */
  id: string
  refs: string[]
  source: 'events' | 'mails'
  ts: number
  tsEnd: number
  count: number
  title: string
  host: string | null
  ip: string | null
  origin: 'mail' | 'cloud' | 'host'
  phase: string | null
  phaseBasis: string
  findings: StoryFinding[]
  severity: Severity | null
  /** why the step is in the story, and how surely */
  tie: { kind: TieKind; basis: string; confidence: Confidence }
  notes: string[]
  /** identity ids the step's records name */
  accounts: string[]
  session: string | null
  process: string | null
  hops: string[]
  routine: boolean
}
export interface StoryPhase {
  phase: string
  label: string
  first: number
  last: number
  steps: number
  records: number
  findings: number
  severity: Severity | null
}
export interface Session {
  id: string
  host: string
  logonId: string
  account: string
  user?: string | null
  domain?: string | null
  type: number
  typeName: string
  ip: string | null
  workstation: string | null
  from: string | null
  start: number
  end: number | null
  logonRef: string | null
  logoffRef: string | null
  logonSeen: boolean
  rdp: boolean
  privileged: boolean
  elevated: boolean
  reconnects: { ts: number; kind: string; ip: string | null; workstation: string | null; ref: string }[]
  activity: number
  activityKinds: Record<string, number>
  actions: Record<string, number>
}
export interface Hop {
  id: string
  kind: 'rdp' | 'admin-share' | 'remote-service' | 'remote-action' | 'wmi' | 'winrm' | 'explicit-credentials' | 'connection'
  from: { host: string | null; ip: string | null; workstation: string | null; external: boolean; basis: string | null }
  to: string
  account: string | null
  ts: number
  tsEnd: number
  count: number
  session: string | null
  refs: string[]
  evidence: string[]
  basis: string
  confidence: Confidence
}
/** How a hop came to its host, in words. */
export const HOP_LABEL: Record<Hop['kind'], string> = {
  rdp: 'RDP',
  'admin-share': 'admin share',
  'remote-service': 'remote service',
  'remote-action': 'remote action',
  wmi: 'WMI',
  winrm: 'WinRM',
  'explicit-credentials': 'explicit credentials',
  connection: 'connection',
}
/** An Entra device the story's sign-ins came from, and the host of that name when the case has its logs. */
export interface Device {
  key: string
  name: string
  host: string | null
  deviceIds: string[]
  trustTypes: string[]
  accounts: string[]
  signIns: number
  first: number
  last: number
}
export interface Process {
  id: string
  host: string
  pid: number | null
  guid: string | null
  image: string | null
  name: string
  commandLine: string | null
  user: string | null
  parent: string | null
  parentImage: string | null
  ts: number
  refs: string[]
  source: 'sysmon' | '4688' | 'both'
  session: string | null
  children: string[]
}
export interface HostCoverage {
  key: string
  name: string
  ips: string[]
  events: number
  first: number
  last: number
  coverage: Record<string, number>
  cleared: { ts: number; log: string; ref: string }[]
  /** what this host's evidence cannot show, in words */
  limits: string[]
}
export interface IdentityForm {
  kind: 'addr' | 'netbios' | 'dn' | 'object' | 'sid' | 'name' | 'display'
  value: string
  seen: number
  ref: string | null
  confidence: Confidence
}
export interface Identity {
  id: string
  label: string
  kind: 'person' | 'service' | 'machine' | 'builtin'
  org: string | null
  forms: IdentityForm[]
  joins: { a: string; b: string; kinds: string[]; basis: string; confidence: Confidence; ref: string | null; count: number }[]
  possibly: { id: string; label: string; basis: string; ref: string | null }[]
  namesakes: { id: string; label: string; basis: string; ref: string | null }[]
  conflicts: { id: string; a: string; b: string; basis: string; why: string }[]
  notes: string[]
}
export interface Story {
  id: string
  kind: 'person' | 'host'
  subject: { kind: 'person' | 'host'; id: string; label: string; org: string | null }
  title: string
  headline: string
  summary: string
  start: number
  end: number
  severity: Severity
  score: number
  confidence: Confidence
  phases: StoryPhase[]
  steps: StoryStep[]
  records: number
  hosts: string[]
  accounts: string[]
  ips: string[]
  attackerAddresses: string[]
  chains: string[]
  findings: string[]
  campaigns: string[]
  gaps: string[]
  lineage: { sessions: Session[]; hops: Hop[]; processes: Process[]; devices?: Device[] }
}
export interface CampaignTarget {
  id: string
  account: string
  how: string[]
  via: string[]
  refs: string[]
}
export interface Campaign {
  id: string
  label: string
  labelKind: string
  artifacts: { kind: string; value: string; stories: string[] }[]
  stories: string[]
  people: string[]
  targets: CampaignTarget[]
  start: number
  end: number
  severity: Severity
}
export interface StoryResult {
  version: number
  stories: Story[]
  campaigns: Campaign[]
  chains: ChainResult
  identities: Identity[]
  hosts: HostCoverage[]
  unstoried: { ref: string; why: string; findings: string[] }[]
  stats: Record<string, unknown> & { truncated?: string[] }
  builtAt?: number
}

/** events read per build and per kind of selection (the server applies the same caps); the page says when one was hit */
export const EVENT_CAP = 50_000
const MAIL_CAP = 5_000
const DAY = 86_400_000
const WINDOW_BEFORE = DAY
const WINDOW_AFTER = 3 * DAY
/** the records lineage reads on a flagged host (mirror of stories.LINEAGE_EVENT_IDS) */
export const LINEAGE_EVENT_IDS = [
  1, 3, 21, 23, 24, 25, 104, 1102, 1116, 1117, 1149, 4624, 4625, 4634, 4647, 4648, 4672, 4688, 4697, 4698, 4702, 4720, 4722, 4724, 4728, 4732, 4738, 4756, 4778, 4779, 4781, 5140, 5145, 7045,
]
const LINEAGE = new Set(LINEAGE_EVENT_IDS)
/**
 * And, by channel, WinRM's session records, WMI's failed calls and the DNS client's answers; the
 * script blocks that name a remote computer; the DNS answers that give a private address (their own
 * cap); the DHCP server's leases (no time, so case-wide). Mirrors of stories.py, compared by a test.
 */
export const LINEAGE_CHANNEL_EVENTS: [string, number[]][] = [
  ['winrm', [6, 91]],
  ['wmi-activity', [5858]],
  ['dns-client', [3008]],
]
export const REMOTE_SCRIPT = '-computername|-cn\\s|enter-pssession|/node:'
export const PRIVATE_ANSWER = '(^|;)\\s*(::ffff:)?(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)'
const REMOTE_SCRIPT_RE = new RegExp(REMOTE_SCRIPT)
const PRIVATE_ANSWER_RE = new RegExp(PRIVATE_ANSWER)
const DNS_CAP = 20_000
const DHCP_CAP = 20_000

/** A record beyond LINEAGE_EVENT_IDS that lineage reads on a flagged host. */
function lineageExtra(row: Record<string, unknown>): boolean {
  const eid = Number(row.eventId)
  const chan = String(row.channel ?? '').toLowerCase()
  if (LINEAGE_CHANNEL_EVENTS.some(([c, ids]) => ids.includes(eid) && chan.includes(c))) return true
  return eid === 4104 && REMOTE_SCRIPT_RE.test(String(row.scriptBlockText ?? '').toLowerCase())
}

/** A Sysmon DNS answer that gives a private address: lineage reads it to know whose an address is. */
function dnsAnswer(row: Record<string, unknown>): boolean {
  return (
    Number(row.eventId) === 22 &&
    String(row.provider ?? '')
      .toLowerCase()
      .includes('sysmon') &&
    PRIVATE_ANSWER_RE.test(String(row.queryResults ?? ''))
  )
}

/** The fields of an event the story engine reads (tests/backend/test_stories.py compares this list with the Python). */
export const STORY_EVENT_FIELDS = [
  'id',
  'ts',
  'eventId',
  'channel',
  'provider',
  'category',
  'operation',
  'computer',
  'recordKey',
  'summary',
  'description',
  'status',
  'targetUser',
  'targetDomain',
  'targetSid',
  'targetLogonId',
  'targetLinkedLogonId',
  'targetServer',
  'subjectUser',
  'subjectDomain',
  'subjectSid',
  'subjectLogonId',
  'user',
  'upn',
  'displayName',
  'memberName',
  'memberSid',
  'userObjectId',
  'logonType',
  'logonTypeName',
  'logonProcess',
  'authPackage',
  'elevatedToken',
  'ipAddress',
  'workstation',
  'processGuid',
  'parentProcessGuid',
  'image',
  'parentImage',
  'commandLine',
  'parentCommandLine',
  'processName',
  'parentProcessName',
  'newProcessId',
  'callerProcessId',
  'parentProcessId',
  'integrityLevel',
  'mandatoryLabel',
  'hashes',
  'sourceIp',
  'destinationIp',
  'destinationPort',
  'destinationHostname',
  'initiated',
  'query',
  'queryResults',
  'artifactType',
  'targetFilename',
  'shareName',
  'relativeTargetName',
  'serviceName',
  'serviceFile',
  'serviceAccount',
  'taskName',
  'objectName',
  'scriptBlockText',
  'data',
] as const

/** The keys of an event's data the story engine reads, beyond the chains' (identity, lineage). */
export const STORY_DATA_KEYS = [
  ...CHAIN_DATA_KEYS,
  'userPrincipalName',
  'userId',
  'userDisplayName',
  'UserDisplayName',
  'DisplayName',
  'OldTargetUserName',
  'NewTargetUserName',
  'TargetDomainName',
  'TargetSid',
  'SubjectLogonId',
  'LogonId',
  'LogonID',
  'AccountName',
  'AccountDomain',
  'TargetServerName',
  'ProcessId',
  // lineage: DNS answers, WinRM's session record, WMI's failed calls, DHCP leases, Entra devices
  'QueryName',
  'QueryResults',
  'connection',
  'Connection',
  'ClientMachine',
  'User',
  'Operation',
  'ID',
  'IP Address',
  'Host Name',
  'deviceName',
  'deviceId',
  'trustType',
] as const

const SKIP = new Set(['', '-', 'system', 'anonymous logon', 'local service', 'network service', 'local system', 'krbtgt'])

/** The account name a value writes: alice for alice@contoso.com and CONTOSO\alice; null for machines and Windows' own. */
export function accountName(v: unknown): string | null {
  if (v == null) return null
  let s = String(v)
    .trim()
    .replace(/^["']|["']$/g, '')
    .toLowerCase()
  if (s.includes('\\')) s = s.slice(s.lastIndexOf('\\') + 1)
  if (s.includes('@')) s = s.slice(0, s.indexOf('@'))
  s = s.trim()
  if (!s || s.endsWith('$') || SKIP.has(s) || s.startsWith('dwm-') || s.startsWith('umfd-') || s.startsWith('s-1-') || s.length < 2) return null
  return s
}

const PRIVATE = [/^10\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./, /^127\./, /^169\.254\./, /^::1$/, /^f[cd][0-9a-f]{2}:/i, /^fe80:/i]
const DOC = [/^192\.0\.2\./, /^198\.51\.100\./, /^203\.0\.113\./, /^2001:db8:/i]
/** a private address (the documentation ranges stand for internet addresses in the samples and labs) */
export function isInternalIp(ip: string): boolean {
  return PRIVATE.some((r) => r.test(ip)) && !DOC.some((r) => r.test(ip))
}
function ipOf(v: unknown): string {
  let s = String(v ?? '')
    .trim()
    .toLowerCase()
  if (s.startsWith('::ffff:')) s = s.slice(7)
  if (!s || ['-', '::1', '127.0.0.1', '0.0.0.0', '::', 'localhost'].includes(s)) return ''
  return /^[\d.]+$/.test(s) || s.includes(':') ? s : ''
}

/** the flags' times widened and merged; too many windows become one from the first to the last (mirror of stories.windows) */
export function windows(times: number[], before = WINDOW_BEFORE, after = WINDOW_AFTER, most = 40): [number, number][] {
  const spans: [number, number][] = []
  for (const t of times.filter((t) => t).sort((a, b) => a - b)) {
    const last = spans[spans.length - 1]
    if (last && t - before <= last[1]) last[1] = Math.max(last[1], t + after)
    else spans.push([t - before, t + after])
  }
  return spans.length > most ? [[spans[0][0], spans[spans.length - 1][1]]] : spans
}

function storyData(data: unknown): Record<string, unknown> | undefined {
  if (!data || typeof data !== 'object') return undefined
  const src = data as Record<string, unknown>
  const out: Record<string, unknown> = {}
  for (const k of STORY_DATA_KEYS) if (src[k] !== undefined && src[k] !== null && src[k] !== '') out[k] = src[k]
  for (const k of Object.keys(src)) if (k.startsWith('StrongAuthentication')) out[k] = true
  return Object.keys(out).length ? out : undefined
}

function slimEvent(row: Record<string, unknown>): Record<string, unknown> {
  const slim: Record<string, unknown> = {}
  for (const k of STORY_EVENT_FIELDS) if (row[k] !== undefined && row[k] !== null) slim[k] = row[k]
  if (typeof slim.scriptBlockText === 'string' && slim.scriptBlockText.length > 4000) slim.scriptBlockText = slim.scriptBlockText.slice(0, 4000)
  const kept = storyData(row.data)
  if (kept) slim.data = kept
  else delete slim.data
  return slim
}

function slimMail(m: MailRow) {
  return {
    id: m.id,
    date: m.date,
    subject: m.subject,
    fromAddr: m.fromAddr,
    fromName: m.fromName,
    fromRegistrable: m.fromRegistrable,
    to: m.to,
    cc: m.cc,
    bcc: m.bcc,
    replyTo: m.replyTo,
    risk: m.risk,
    flags: m.flags,
    urls: (m.urls ?? []).map((u) => ({ url: u.url, host: u.host, domain: u.domain })),
    attachments: (m.attachments ?? []).map((a) => ({ name: a.name, sha256: a.sha256 })),
    messageId: m.messageId,
    inReplyTo: m.inReplyTo,
  }
}

/** What the story engine reads of a finding: its tactic tags and techniques give the phase, its entities the attacker's addresses. */
export function slimFinding(f: Finding) {
  return {
    ruleId: f.ruleId,
    title: f.title,
    severity: effectiveSeverity(f),
    source: f.source,
    refs: f.refs.slice(0, 2000),
    ts: f.ts,
    key: f.key,
    tags: f.tags ?? [],
    attack: f.attack ?? [],
    entities: f.entities ?? {},
  }
}

const rank: Record<string, number> = { critical: 5, high: 4, medium: 2, low: 1, info: 0 }

/** Build the stories of a case, keep the snapshot the Stories page reads, and keep the chains in step. */
export async function buildStories(kase: Case): Promise<StoryResult> {
  const db = getDb()
  const caseId = kase.id!
  const settings = settingsForRules(kase)
  // findings marked false positive neither start a story nor weigh in one; the chains' own mirror findings are not flags
  const findings = (await db.findings.where('caseId').equals(caseId).toArray()).filter((f) => f.ruleId !== 'chain' && f.status !== 'false_positive').map(slimFinding)
  let result: StoryResult
  if (kase.storage === 'server' && kase.serverKey) {
    result = await apiPost<StoryResult>('/api/stories/build', { storeKey: kase.serverKey, settings, findings })
  } else {
    const { events, mails, truncated } = await selectRows(caseId, findings)
    result = await apiPost<StoryResult>('/api/stories/build', { events, mails, findings, settings })
    result.stats.truncated = [...new Set([...(result.stats.truncated ?? []), ...truncated])].sort()
  }
  result.builtAt = Date.now()
  await db.kv.put({ key: `stories-${caseId}`, value: result })
  if (result.chains) await persistChainResult(caseId, result.chains)
  return result
}

/** The rows of a browser case around its flags: what stories_for_store selects by SQL, read from IndexedDB. */
export async function selectRows(
  caseId: number,
  findings: ReturnType<typeof slimFinding>[],
): Promise<{ events: Record<string, unknown>[]; mails: ReturnType<typeof slimMail>[]; truncated: string[] }> {
  const db = getDb()
  const truncated = new Set<string>()
  const evIds = new Set<number>()
  const mailIds = new Set<number>()
  for (const f of findings) for (const r of f.refs) (f.source === 'mails' ? mailIds : evIds).add(r)
  const ids = [...evIds].sort((a, b) => a - b)
  if (ids.length > EVENT_CAP) truncated.add('flagged')
  const flagged = (await db.events.bulkGet(ids.slice(0, EVENT_CAP))).filter((e): e is NonNullable<typeof e> => !!e && e.caseId === caseId)
  const allMails = await db.mails.where('caseId').equals(caseId).toArray()
  const mails = allMails.filter((m) => m.date != null && (m.risk >= 45 || (m.id != null && mailIds.has(m.id))))
  // what to read around the flags: the names they name, the outside addresses the findings name, the flagged hosts
  const names = new Set<string>()
  const hosts = new Set<string>()
  const ips = new Set<string>()
  for (const e of flagged) {
    const row = e as unknown as Record<string, unknown>
    const data = (row.data ?? {}) as Record<string, unknown>
    for (const v of [row.targetUser, row.subjectUser, row.user, row.upn, data.UserId, data.MailboxOwnerUPN]) {
      const n = accountName(v)
      if (n) names.add(n)
    }
    if (row.computer) hosts.add(String(row.computer).toLowerCase())
    const ip = ipOf(row.ipAddress)
    if (ip && !isInternalIp(ip)) ips.add(ip)
  }
  for (const m of mails)
    for (const a of [...m.to, ...m.cc, ...m.bcc].map((r) => r.addr).concat([m.fromAddr ?? ''])) {
      const n = accountName(a)
      if (n) names.add(n)
    }
  for (const f of findings)
    if ((rank[f.severity] ?? 0) >= 2) {
      const ip = ipOf(f.entities.ipAddress)
      if (ip && !isInternalIp(ip)) ips.add(ip)
    }
  const events = new Map<number, Record<string, unknown>>()
  for (const e of flagged) events.set(e.id!, slimEvent(e as unknown as Record<string, unknown>))
  const spans = windows([...flagged.map((e) => e.ts ?? 0), ...mails.map((m) => m.date ?? 0)])
  let picked = 0
  let dnsPicked = 0
  for (const [lo, hi] of spans) {
    await db.events
      .where('[caseId+ts]')
      .between([caseId, lo], [caseId, hi], true, true)
      .each((e) => {
        if (events.has(e.id!)) return
        const row = e as unknown as Record<string, unknown>
        const data = (row.data ?? {}) as Record<string, unknown>
        const named = [row.targetUser, row.subjectUser, row.user, row.upn, data.UserId].some((v) => {
          const n = accountName(v)
          return !!n && names.has(n)
        })
        const fromIp = ips.has(ipOf(row.ipAddress))
        const flaggedHost = hosts.has(String(row.computer ?? '').toLowerCase())
        const onHost = flaggedHost && (LINEAGE.has(Number(row.eventId)) || lineageExtra(row))
        if (!named && !fromIp && !onHost) {
          if (flaggedHost && dnsAnswer(row)) {
            if (++dnsPicked > DNS_CAP) truncated.add('dns')
            else events.set(e.id!, slimEvent(row))
          }
          return
        }
        if (++picked > EVENT_CAP) {
          truncated.add(named ? 'identities' : fromIp ? 'addresses' : 'hosts')
          return
        }
        events.set(e.id!, slimEvent(row))
      })
  }
  // the DHCP server's leases: they have no time, so they are read whatever the windows
  let dhcpPicked = 0
  await db.events
    .where('[caseId+artifactType]')
    .equals([caseId, 'dhcp'])
    .each((e) => {
      const row = e as unknown as Record<string, unknown>
      if (!row.ipAddress || events.has(e.id!)) return
      if (++dhcpPicked > DHCP_CAP) truncated.add('dhcp')
      else events.set(e.id!, slimEvent(row))
    })
  const inWindow = (t: number | null) => t != null && spans.some(([lo, hi]) => t >= lo && t <= hi)
  const replies = allMails.filter((m) => !mails.includes(m) && inWindow(m.date) && names.has(accountName(m.fromAddr) ?? ''))
  if (replies.length > MAIL_CAP) truncated.add('replies')
  return { events: [...events.values()], mails: [...mails, ...replies.slice(0, MAIL_CAP)].map(slimMail), truncated: [...truncated] }
}

export async function loadStories(caseId: number): Promise<StoryResult | null> {
  const k = await getDb().kv.get(`stories-${caseId}`)
  return (k?.value as StoryResult) ?? null
}

/** What a build could not read, in words: the selections that hit their cap. */
export function storyCoverageWarnings(stats: StoryResult['stats'] | undefined): string[] {
  const labels: Record<string, string> = {
    flagged: `More than ${EVENT_CAP.toLocaleString('en')} records carry findings: the stories read the first ${EVENT_CAP.toLocaleString('en')}.`,
    identities: `The records naming the flagged people passed ${EVENT_CAP.toLocaleString('en')}: the stories read the first ones in time.`,
    addresses: `The records from the flagged addresses passed ${EVENT_CAP.toLocaleString('en')}: the stories read the first ones in time.`,
    hosts: `The logons, processes and services on the flagged hosts passed ${EVENT_CAP.toLocaleString('en')}: the stories read the first ones in time.`,
    replies: `Only the first ${MAIL_CAP.toLocaleString('en')} mails the flagged people sent were read.`,
    dns: `The DNS answers on the flagged hosts passed ${DNS_CAP.toLocaleString('en')}: the addresses they give to hosts come from the first ones in time.`,
    dhcp: `The DHCP leases passed ${DHCP_CAP.toLocaleString('en')}: the addresses they give to hosts come from the first ones.`,
  }
  const out = (stats?.truncated ?? []).map((k) => labels[k]).filter(Boolean)
  if (stats?.storiesTruncated) out.push('Only the highest-scoring 200 stories are kept.')
  return out
}

/** What the evidence cannot show for a story: its hosts' coverage, the phase no record reaches, the build's limits. */
export function storyGaps(story: Story, stats: StoryResult['stats'] | undefined): string[] {
  const out = [...story.gaps]
  const have = new Set(story.phases.map((p) => p.phase))
  if (!have.has('initial-access') && story.phases.length >= 2) out.push('No record of the story shows how it started: initial access is not in the evidence it reads.')
  out.push(...storyCoverageWarnings(stats))
  return out
}

/** The key of an analyst's note on a story: what the story is about and the UTC day it starts, so a note outlives a rebuild and an export (row ids do not). */
export const noteKey = (s: Pick<Story, 'kind' | 'title' | 'start'>) => `${s.kind}|${s.title.toLowerCase()}|${new Date(s.start).toISOString().slice(0, 10)}`

/** event:12 -> {source: 'events', id: 12} */
export function refRow(ref: string): { source: 'events' | 'mails'; id: number } | null {
  const m = /^(event|mail):(\d+)$/.exec(ref)
  return m ? { source: m[1] === 'mail' ? 'mails' : 'events', id: Number(m[2]) } : null
}

/** The rows of a story a note is checked against: its steps' records, the first 2,000 events and 500 mails. */
export function storyRowIds(story: Story, maxEvents = 2000, maxMails = 500): { events: number[]; mails: number[] } {
  const out = { events: [] as number[], mails: [] as number[] }
  for (const ref of story.steps.flatMap((s) => s.refs)) {
    const r = refRow(ref)
    if (r && out[r.source].length < (r.source === 'events' ? maxEvents : maxMails)) out[r.source].push(r.id)
  }
  return out
}

export type StoryNotes = Record<string, { text: string; updatedAt: number }>
export const STORY_NOTES_KEY = (caseId: number) => `story-notes-${caseId}`

export async function loadStoryNotes(caseId: number): Promise<StoryNotes> {
  const k = await getDb().kv.get(STORY_NOTES_KEY(caseId))
  return (k?.value as StoryNotes) ?? {}
}

const SEV_RANK: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

/** A story as the report prints it, with the analyst's note on it. */
export interface ReportStory {
  story: Story
  /** the note's key (noteKey), which is also the key of its claim check: story:<key> */
  key: string
  note?: string
}

/**
 * The stories a report prints: those at or above its severity floor (with a note, when it prints
 * reviewed items only: a story's note is the analyst's reading of it), the highest-scoring first,
 * at most `max`; `left` counts the others.
 */
export function reportStories(stories: Story[], notes: StoryNotes, floor: Severity, onlyReviewed = false, max = 20): { stories: ReportStory[]; left: number } {
  const picked = stories
    .map((story) => ({ story, key: noteKey(story), note: notes[noteKey(story)]?.text.trim() || undefined }))
    .filter((s) => (SEV_RANK[s.story.severity] ?? 0) >= (SEV_RANK[floor] ?? 0) && (!onlyReviewed || s.note))
    .sort((a, b) => b.story.score - a.story.score || a.story.start - b.story.start)
    .slice(0, max)
  return { stories: picked, left: stories.length - picked.length }
}
