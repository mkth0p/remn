import { apiPost } from '../api/client'
import { getDb, type Case, type Finding, type Severity } from '../db/schema'
import { settingsForRules } from './rules'
import { replaceFindings } from './findingReviews'

export interface ChainStep {
  kind: 'mail' | 'event'
  source: 'mails' | 'events'
  id: number | null
  refs?: number[]
  ts: number
  tsEnd: number
  count: number
  title: string
  weight: number
  artifacts: string[]
  findings: { ruleId: string; title: string; severity: string }[]
  offsetMin: number
  ipAddress?: string | null
  computer?: string | null
  origin?: 'm365' | 'host'
  operation?: string | number | null
}
export interface ChainSeed {
  source?: 'mails' | 'events'
  id: number
  ts: number
  subject: string
  fromAddr: string | null
  risk: number
  flags: string[]
  findings: { ruleId: string; title: string; severity: string }[]
  urlDomains: string[]
  attachments: string[]
}
export interface Chain {
  kind?: 'authentication'
  id: string
  identity: string
  identityLabel: string
  seed: ChainSeed
  relatedSeeds?: ChainSeed[]
  steps: ChainStep[]
  start: number
  end: number
  score: number
  severity: Severity
  artifactLinks: number
  /** contribution of each part of the score (seed, links, steps, findings, sources) and the cap applied, if any */
  scoreBreakdown?: { seed: number; links: number; steps: number; findings: number; sources: number; cap: number | null; linkSteps: number }
  entities: { user: string; ips: string[]; hosts: string[]; attackerAddresses: string[]; domains: string[] }
  summary: string
}
export interface ChainResult {
  chains: Chain[]
  stats: Record<string, number>
  builtAt?: number
}
export interface ChainOptions {
  seedMinRisk?: number
  windowHours?: number
}

/** events considered per build (the server applies the same cap); the Chains page says when it was hit */
export const EVENT_CAP = 50_000

const SKIP = new Set(['', '-', 'system', 'anonymous logon', 'local service', 'network service', 'local system'])

/** alice@contoso.com | CONTOSO\alice | alice -> "alice" (mirror of services/analysis/chains.identity_key). */
export function identityKey(v: unknown): string | null {
  if (v == null) return null
  let s = String(v)
    .trim()
    .replace(/^["']|["']$/g, '')
    .toLowerCase()
  if (!s || s.endsWith('$')) return null
  if (s.includes('\\')) s = s.slice(s.lastIndexOf('\\') + 1)
  if (s.includes('@')) s = s.slice(0, s.indexOf('@'))
  s = s.trim()
  if (SKIP.has(s) || s.startsWith('dwm-') || s.startsWith('umfd-') || s.startsWith('s-1-') || s.length < 2) return null
  return s
}

const EVENT_FIELDS = [
  'id',
  'ts',
  'eventId',
  'channel',
  'provider',
  'category',
  'operation',
  'computer',
  'targetUser',
  'targetDomain',
  'subjectDomain',
  'subjectUser',
  'user',
  'upn',
  'ipAddress',
  'logonType',
  'logonTypeName',
  'image',
  'processName',
  'commandLine',
  'parentImage',
  'parentProcessName',
  'query',
  'destinationHostname',
  'destinationIp',
  'destinationPort',
  'targetFilename',
  'objectName',
  'summary',
  'status',
  'taskName',
  'serviceName',
  'scriptBlockText',
  'data',
] as const

function slimFinding(f: Finding) {
  return { ruleId: f.ruleId, title: f.title, severity: f.severity, source: f.source, refs: f.refs.slice(0, 2000), ts: f.ts }
}

/** Build the chains for a case (server store: the API reads DuckDB; browser store: the relevant rows are posted). */
export async function buildChains(kase: Case, opts: ChainOptions = {}): Promise<ChainResult> {
  const db = getDb()
  const caseId = kase.id!
  const settings = settingsForRules(kase)
  // findings marked false positive neither seed a chain nor weight its steps
  const findings = (await db.findings.where('caseId').equals(caseId).toArray()).filter((f) => f.ruleId !== 'chain' && f.status !== 'false_positive').map(slimFinding)
  const seedMinRisk = opts.seedMinRisk ?? 45
  const windowHours = opts.windowHours ?? 72
  let result: ChainResult
  if (kase.storage === 'server' && kase.serverKey) {
    result = await apiPost<ChainResult>('/api/chains/build', { storeKey: kase.serverKey, settings, findings, seedMinRisk, windowHours })
  } else {
    const refIds = new Set<number>()
    for (const f of findings) if (f.source === 'mails') for (const r of f.refs) refIds.add(r)
    const allMails = await db.mails.where('caseId').equals(caseId).toArray()
    const seeds = allMails.filter((m) => m.date != null && (m.risk >= seedMinRisk || (m.id != null && refIds.has(m.id))))
    // no seed left (evidence removed, threshold raised): the empty result must still replace the stored snapshot
    if (!seeds.length && !(await db.events.where('caseId').equals(caseId).count()))
      return persistChainResult(caseId, { chains: [], stats: { seeds: 0, identities: 0, events: 0, mails: 0, chains: 0 } })
    const idents = new Set<string>()
    for (const m of seeds)
      for (const r of [...m.to, ...m.cc, ...m.bcc]) {
        const k = identityKey(r.addr)
        if (k) idents.add(k)
      }
    const tMin = seeds.reduce((v, m) => Math.min(v, m.date!), Number.MAX_SAFE_INTEGER) - 5 * 60_000
    const tMax = seeds.reduce((v, m) => Math.max(v, m.date!), 0) + windowHours * 3_600_000
    const events: Record<string, unknown>[] = []
    let eventsTruncated = false
    let authEventsTruncated = false
    let authCount = 0
    let mailCount = 0
    await db.events
      .where('[caseId+ts]')
      .between([caseId, 0], [caseId, Number.MAX_SAFE_INTEGER], true, true)
      .each((e) => {
        const row = e as unknown as Record<string, unknown>
        const data = (row.data ?? {}) as Record<string, unknown>
        const hit = [row.upn, data.UserId, row.targetUser, row.subjectUser, row.user, data.MailboxOwnerUPN].some((v) => {
          const k = identityKey(v)
          return !!k && idents.has(k)
        })
        const auth = [4624, 4625].includes(Number(row.eventId)) || ['signin', 'sign-in', 'userloginfailed', 'userloggedin'].includes(String(row.operation ?? '').toLowerCase())
        const mailHit = hit && e.ts != null && e.ts >= tMin && e.ts <= tMax
        if (auth && ++authCount > EVENT_CAP) authEventsTruncated = true
        if (mailHit && ++mailCount > EVENT_CAP) eventsTruncated = true
        if (!(auth && authCount <= EVENT_CAP) && !(mailHit && mailCount <= EVENT_CAP)) return
        const slim: Record<string, unknown> = {}
        for (const k of EVENT_FIELDS) if (row[k] !== undefined) slim[k] = row[k]
        events.push(slim)
      })
    const replies = allMails.filter((m) => m.date != null && m.date >= tMin && m.date <= tMax && !seeds.includes(m) && idents.has(identityKey(m.fromAddr) ?? ''))
    const mails = [...seeds, ...replies].map((m) => ({
      id: m.id,
      date: m.date,
      subject: m.subject,
      fromAddr: m.fromAddr,
      fromRegistrable: m.fromRegistrable,
      to: m.to,
      cc: m.cc,
      bcc: m.bcc,
      replyTo: m.replyTo,
      risk: m.risk,
      flags: m.flags,
      urls: (m.urls ?? []).map((u) => ({ url: u.url, host: u.host, domain: u.domain })),
      attachments: (m.attachments ?? []).map((a) => ({ name: a.name })),
      messageId: m.messageId,
      inReplyTo: m.inReplyTo,
    }))
    result = await apiPost<ChainResult>('/api/chains/build', { mails, events, findings, settings, seedMinRisk, windowHours })
    if (eventsTruncated) result.stats.eventsTruncated = 1
    if (authEventsTruncated) result.stats.authEventsTruncated = 1
  }
  return persistChainResult(caseId, result)
}

/** Store the snapshot the Chains view reads on load and mirror the chains as findings. */
async function persistChainResult(caseId: number, result: ChainResult): Promise<ChainResult> {
  const db = getDb()
  const previous = await loadChains(caseId)
  // Preserve decisions when upgrading old bare-username chain keys to qualified ones.
  if (previous?.chains.length) {
    const reviewKey = `chain-reviews-${caseId}`
    const reviews = ((await db.kv.get(reviewKey))?.value ?? {}) as Record<string, unknown>
    const archiveKey = `finding-reviews-${caseId}`
    const archive = ((await db.kv.get(archiveKey))?.value ?? {}) as Record<string, unknown>
    for (const old of previous.chains) {
      const next = result.chains.find(
        (c) => old.seed && c.seed.id === old.seed.id && (c.seed.source ?? 'mails') === (old.seed.source ?? 'mails') && c.identityLabel.toLowerCase() === old.identityLabel?.toLowerCase(),
      )
      if (!next || next.id === old.id) continue
      if (reviews[old.id] && !reviews[next.id]) reviews[next.id] = reviews[old.id]
      const oldKey = `chain|${old.identity}|${old.seed.id}`
      const nextKey = `chain|${next.identity}|${next.seed.id}`
      await db.findings
        .where('caseId')
        .equals(caseId)
        .and((f) => f.key === oldKey)
        .modify({ key: nextKey })
      if (archive[oldKey] && !archive[nextKey]) archive[nextKey] = archive[oldKey]
    }
    await db.kv.bulkPut([
      { key: reviewKey, value: reviews },
      { key: archiveKey, value: archive },
    ])
  }
  result.builtAt = Date.now()
  await getDb().kv.put({ key: `chains-${caseId}`, value: result })
  await persistChainFindings(caseId, result.chains)
  return result
}

/** Chains are also findings (ruleId "chain") so they show in Findings, the report and the AI summary. */
async function persistChainFindings(caseId: number, chains: Chain[]): Promise<void> {
  const now = Date.now()
  const rows: Finding[] = chains.map((c) => ({
    caseId,
    ruleId: 'chain',
    key: `chain|${c.identity}|${c.seed.id}`,
    title: `Attack chain: ${c.identityLabel} — ${c.steps.length} step(s) after "${c.seed.subject.slice(0, 60)}"`,
    description: c.summary,
    severity: c.severity,
    source: c.seed.source ?? 'mails',
    ts: c.start,
    tsEnd: c.end,
    entities: { user: c.entities.user, ip: c.entities.ips.slice(0, 3).join(', '), host: c.entities.hosts.slice(0, 3).join(', '), attacker: c.entities.attackerAddresses.slice(0, 3).join(', ') },
    count: c.steps.length,
    refs: [c.seed.id],
    attack: c.kind === 'authentication' ? ['T1110', ...(c.severity === 'high' ? ['T1078'] : [])] : ['T1566', 'T1114', 'T1078'],
    tags: ['chain', c.kind === 'authentication' ? 'authentication' : 'mail-led'],
    status: 'new',
    createdAt: now,
  }))
  await replaceFindings(caseId, ['chain'], rows as unknown as Record<string, unknown>[]) // analyst status / notes survive a rebuild
}

export async function loadChains(caseId: number): Promise<ChainResult | null> {
  const k = await getDb().kv.get(`chains-${caseId}`)
  return (k?.value as ChainResult) ?? null
}

export function chainCoverageWarnings(stats: Record<string, number> = {}): string[] {
  const labels: Record<string, string> = {
    eventsTruncated: 'Mail correlation: only the first 50,000 matching events were considered.',
    authEventsTruncated: 'Authentication campaigns: only the first 50,000 authentication events were considered.',
    seedsTruncated: 'Mail seed selection reached its limit (300 seeds or 500 finding references).',
    repliesTruncated: 'Only the first 5,000 matching replies were considered.',
    chainsTruncated: 'Only the highest-scoring chains are displayed.',
  }
  return Object.entries(labels)
    .filter(([key]) => stats[key])
    .map(([, label]) => label)
}
