import { getDb, type Finding, type Severity } from '../db/schema'
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
  /** authentication campaigns against the same person, in the chain's window, folded into its steps */
  authCampaigns?: { account: string; summary: string; severity: string }[]
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
/**
 * The keys of an event's `data` that services/analysis/chains.py reads. The rest of EventData
 * stays in the browser: a 4624 carries about a kilobyte of it, and sending all of it for 50,000
 * logons took the request past what the server accepts. tests/backend/test_chains.py checks this
 * list against the Python.
 */
export const CHAIN_DATA_KEYS = [
  'UserId',
  'MailboxOwnerUPN',
  'country',
  'clientAppUsed',
  'riskLevelDuringSignIn',
  'riskLevelAggregated',
  'riskState',
  'appDisplayName',
  'ForwardTo',
  'ForwardAsAttachmentTo',
  'RedirectTo',
  'DeleteMessage',
  'MoveToFolder',
  'SubjectContainsWords',
  'ForwardingSmtpAddress',
  'ForwardingAddress',
  'AuditEnabled',
  'MailAccessType',
  'Role.DisplayName',
  'Target',
  'ConsentAction.Permissions',
] as const
/** Store the snapshot the review and the report read and mirror the chains as findings (a story build keeps them too). */
export async function persistChainResult(caseId: number, result: ChainResult): Promise<ChainResult> {
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

const INBOX_RULE_OPS = new Set(['new-inboxrule', 'set-inboxrule', 'updateinboxrules'])
const SIGN_IN_OPS = new Set(['signin', 'userloggedin', '4624'])
// what services/analysis/chains.py notes on a sign-in that does not look like the person's own
const SIGN_IN_RISK = /^(unexpected country|legacy authentication|identity protection risk)/

/**
 * The ATT&CK techniques a chain's own steps show. A mail-led chain starts from a phishing mail
 * (T1566); it is email collection (T1114) when a step forwards the mailbox or sets an inbox rule,
 * or reads the mailbox with a finding on it; valid accounts (T1078) when a sign-in or logon that
 * worked carries a finding or a sign that it was not the person (an unexpected country, legacy
 * authentication, an identity protection risk). An authentication chain is brute force (T1110), and
 * valid accounts when a guessed password worked (its severity high).
 */
export function chainAttack(c: Chain): string[] {
  if (c.kind === 'authentication') return ['T1110', ...(c.severity === 'high' ? ['T1078'] : [])]
  const out = ['T1566']
  const op = (s: ChainStep) => String(s.operation ?? '').toLowerCase()
  const collects = c.steps.some(
    (s) => INBOX_RULE_OPS.has(op(s)) || s.artifacts.some((a) => a === 'mailbox forwarding' || a === 'forwarding rule') || (op(s) === 'mailitemsaccessed' && s.findings.length > 0),
  )
  if (collects) out.push('T1114')
  const signedIn = c.steps.some((s) => SIGN_IN_OPS.has(op(s)) && !s.title.startsWith('failed') && (s.findings.length > 0 || s.artifacts.some((a) => SIGN_IN_RISK.test(a))))
  if (signedIn) out.push('T1078')
  return out
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
    attack: chainAttack(c),
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
