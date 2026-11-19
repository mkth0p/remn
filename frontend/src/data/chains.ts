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
