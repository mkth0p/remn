import { runAgent } from '../ai/chat'
import { getDb, type Case } from '../db/schema'
import { buildIncidents } from '../rules/incidents'
import { loadChains } from './chains'
import { chainSeverity, loadChainReviews, loadReportSettings, selectForReport } from './review'
import { getSource } from './source'

/**
 * The executive summary drafted by the model from what the report will carry: reviewed chains
 * (with their narratives), incidents (with their notes) and flagged indicators. Used by the Report
 * page's button and at the end of an AI triage pass. Stored in kv `report-summary-<case>`.
 */
export async function draftExecutiveSummary(kase: Case, opts: { signal?: AbortSignal; model?: string } = {}): Promise<string> {
  const caseId = kase.id!
  const db = getDb()
  const [findings, chainRes, reviews, settings, iocRes] = await Promise.all([
    db.findings.where('caseId').equals(caseId).toArray(),
    loadChains(caseId),
    loadChainReviews(caseId),
    loadReportSettings(caseId),
    getSource(kase)
      .listIocs({ onlyBad: true, limit: 500 })
      .catch(() => ({ rows: [] })),
  ])
  const chains = chainRes?.chains ?? []
  const selection = selectForReport(findings, chains, reviews, settings)
  const incidents = buildIncidents(selection.findings, { chains: selection.chains, severityOf: (c) => chainSeverity(c, reviews[c.id]) }).filter((i) => i.kind !== 'chain')
  const data = {
    case: { name: kase.name, analyst: kase.analyst, settings: { internalDomains: kase.settings.internalDomains } },
    summary: await getSource(kase).summary(),
    chains: selection.chains
      .slice(0, 10)
      .map((c) => ({ recipient: c.identityLabel, severity: chainSeverity(c, reviews[c.id]), verdict: reviews[c.id]?.verdict, narrative: reviews[c.id]?.narrative || c.summary })),
    incidents: incidents.slice(0, 40).map((i) => ({ title: i.title, severity: i.severity, status: i.status, findings: i.findings.map((f) => f.title), entities: i.entities, note: i.lead.notes })),
    iocs: iocRes.rows.slice(0, 40).map((i) => ({ kind: i.kind, value: i.value, verdict: i.verdict, tags: i.tags })),
  }
  const msgs = await runAgent([{ role: 'user', content: `Write the executive summary for this investigation:\n\`\`\`json\n${JSON.stringify(data).slice(0, 60000)}\n\`\`\`` }], kase, {
    mode: 'report',
    tools: false,
    think: false,
    maxIterations: 1,
    signal: opts.signal,
    model: opts.model,
  })
  const last = [...msgs].reverse().find((m) => m.role === 'assistant')
  const text = (last?.content ?? '').trim()
  if (!text || text.startsWith('⚠')) throw new Error(text.replace(/^⚠\s*/, '') || 'the model returned nothing')
  await db.kv.put({ key: `report-summary-${caseId}`, value: text })
  return text
}
