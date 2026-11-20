/** The Review page's vocabularies: an incident's status as this page names it, a chain's verdict, and how the triage log counts them. */
import type { ChainReview, ReviewItem, Verdict } from '../../data/review'
import { groupByRule } from '../../data/reportHtml'
import type { useStore } from '../../state/store'
import { fmtNum } from '../../util/format'

export type Status = 'new' | 'reviewed' | 'escalated' | 'false_positive'
export const STATUS_LABEL: Record<Status, string> = { new: 'not reviewed', reviewed: 'reviewed', escalated: 'confirmed', false_positive: 'false positive' }
export const STATUS_SEV: Record<Status, string> = { new: 'accent', reviewed: 'ok', escalated: 'critical', false_positive: 'info' }
export const DECISIONS: { id: Exclude<Status, 'new'>; label: string; key: string; tone: string }[] = [
  { id: 'escalated', label: 'confirmed', key: 'e', tone: 'confirm' },
  { id: 'reviewed', label: 'reviewed', key: 'r', tone: 'review' },
  { id: 'false_positive', label: 'false positive', key: 'f', tone: 'dismiss' },
]
export const VERDICTS: { id: Verdict; label: string; key: string; tone: string }[] = [
  { id: 'confirmed', label: 'confirmed', key: 'e', tone: 'confirm' },
  { id: 'unsure', label: 'unsure', key: 'r', tone: 'review' },
  { id: 'benign', label: 'benign', key: 'f', tone: 'dismiss' },
]
export const DECISION_LABEL: Record<string, string> = { ...STATUS_LABEL, confirmed: 'confirmed', benign: 'benign', unsure: 'unsure' }
export const DECISION_SEV: Record<string, string> = { ...STATUS_SEV, confirmed: 'critical', benign: 'ok', unsure: 'medium' }
/** the log's summary counts chains and incidents apart, since both have a "confirmed" */
export const SUMMARY_LABEL: Record<string, string> = {
  confirmed: 'chains confirmed',
  escalated: 'incidents confirmed',
  unsure: 'chains unsure',
  reviewed: 'incidents reviewed',
  benign: 'chains benign',
  false_positive: 'false positives',
}
export const chainDecision = (r?: ChainReview) => (r?.verdict === 'confirmed' ? 'critical' : r?.verdict === 'benign' ? 'ok' : 'medium')
export const trim = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + '…' : s)

/** What the rail says under an item: the rules and the first values they matched. */
export function factsLine(it: ReviewItem): string {
  if (it.kind === 'chain' || !it.incident) return it.sub
  const gs = groupByRule(it.incident.findings, it.incident.entities)
  const values = gs.flatMap((g) => g.values).slice(0, 2)
  return `${gs.length} rule${gs.length === 1 ? '' : 's'} · ${fmtNum(it.incident.refs.length)} rows${values.length ? ' · ' + values.map((v) => trim(v, 40)).join(' · ') : ''}`
}

export type AiConfig = ReturnType<typeof useStore.getState>['aiConfig']
/** The model the triage asks, as the page names it. */
export const modelNameOf = (aiCfg: AiConfig) => (aiCfg.transport === 'claude' ? `Claude (${aiCfg.claudeModel})` : aiCfg.model || 'the default model')
