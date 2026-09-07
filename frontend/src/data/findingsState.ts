import { getDb, type Case } from '../db/schema'
import { sevCounts } from '../rules/incidents'
import { log, toast, useStore } from '../state/store'
import { pruneOrphanFindings } from './findingReviews'
import { loadRules, runRulesFor } from './rules'

/**
 * Are the findings current? Findings are only as fresh as the last rule run: evidence added
 * afterwards, a rescore that did not finish, or a baseline pass all leave the Mails and Events
 * pages ahead of the Findings page. This is what the banner on the Findings page reads.
 */
export interface Staleness {
  lastRun: number | null
  /** evidence files finished after the last run (all of them when rules never ran) */
  evidenceAfter: number
  /** a rescore updated mail scores but its findings refresh did not complete */
  rescoreIncomplete: boolean
  /** sender baseline ran after the last run (rules reading sender history are behind) */
  baselineAfter: boolean
  /** rule errors of the last run ("<ruleId>: message") */
  errors: string[]
}

export async function findingsStaleness(caseId: number): Promise<Staleness> {
  const db = getDb()
  const diags = (await db.kv.get(`ruleDiags-${caseId}`))?.value as { ts?: number; errors?: string[] } | undefined
  const lastRun = diags?.ts ?? null
  const evidence = await db.evidence.where('caseId').equals(caseId).toArray()
  const done = evidence.filter((e) => e.status === 'done')
  const evidenceAfter = lastRun == null ? done.length : done.filter((e) => (e.addedAt ?? 0) > lastRun).length
  const cal = (await db.kv.get(`mail-calibration-${caseId}`))?.value as { at?: number; state?: string } | undefined
  const base = (await db.kv.get(`baseline-${caseId}`))?.value as { at?: number } | undefined
  return {
    lastRun,
    evidenceAfter,
    rescoreIncomplete: !!cal?.state && cal.state !== 'done',
    baselineAfter: !!(lastRun && base?.at && base.at > lastRun),
    errors: diags?.errors ?? [],
  }
}

export interface RulesRun {
  done: number
  total: number
  rule: string
  reason: 'manual' | 'ingest'
}

let running = false

/** Run every enabled rule of the case, prune orphans, keep the previous counts for the deltas. One run at a time. */
export async function runEnabledRules(kase: Case, reason: RulesRun['reason'] = 'manual'): Promise<boolean> {
  if (running) {
    if (reason === 'manual') toast('info', 'rules are already running')
    return false
  }
  const caseId = kase.id!
  const rules = await loadRules(caseId)
  const enabled = rules.filter((r) => r.enabled && !r.error).map((r) => r.rule)
  if (!enabled.length) {
    if (reason === 'manual') toast('warn', 'no enabled rules')
    return false
  }
  running = true
  const db = getDb()
  const before = sevCounts((await db.findings.where('caseId').equals(caseId).toArray()).filter((f) => f.status !== 'false_positive'))
  useStore.getState().setRulesRun({ done: 0, total: enabled.length, rule: '', reason })
  try {
    const res = await runRulesFor(kase, enabled, (done, total, rule) => useStore.getState().setRulesRun({ done, total, rule, reason }))
    const pruned = await pruneOrphanFindings(
      caseId,
      rules.map((r) => r.rule.id),
    )
    if (pruned) toast('info', `${pruned} finding(s) of rules that no longer exist were removed`)
    await db.kv.put({ key: `findingCounts-${caseId}`, value: { previous: before, at: Date.now() } })
    // a rescore whose findings refresh did not finish is complete once a full run succeeds
    const cal = (await db.kv.get(`mail-calibration-${caseId}`))?.value as { state?: string } | undefined
    if (cal?.state === 'scores_done' && !res.errors.length) await db.kv.put({ key: `mail-calibration-${caseId}`, value: { ...cal, state: 'done', at: Date.now() } })
    return true
  } catch (e) {
    toast('err', `rules failed: ${(e as Error).message}`, 0)
    return false
  } finally {
    running = false
    useStore.getState().setRulesRun(null)
    useStore.getState().bumpRules()
    const { refreshCounts } = await import('./ingest')
    refreshCounts(kase).catch(() => undefined)
  }
}

export const rulesRunning = () => running

let pending: ReturnType<typeof setTimeout> | null = null

/**
 * Called when an ingest job finishes. Once every job of the case is done (files dropped together
 * finish at different times) and the case allows it, the findings are refreshed so the Findings
 * page never lags behind the evidence.
 */
export function autoRunAfterIngest(kase: Case): void {
  if (kase.settings.autoRunRules === false) return
  if (pending) clearTimeout(pending)
  pending = setTimeout(() => {
    pending = null
    const s = useStore.getState()
    const current = s.currentCase
    if (!current || current.id !== kase.id) return
    if (s.jobs.some((j) => j.phase !== 'done' && j.phase !== 'error')) return
    if (running) return
    log('info', 'evidence changed: refreshing the findings')
    runEnabledRules(current, 'ingest').catch(() => undefined)
  }, 1500)
}
