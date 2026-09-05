/**
 * DataSource: one interface, two backends.
 *  - BrowserSource: rows live in IndexedDB (portable cases, small evidence).
 *  - ServerSource: rows live in a DuckDB case store on the local server (GB-scale).
 * Analyst state (cases, evidence list, findings, notes, AI sessions) always stays in IndexedDB.
 */
import { apiGet, apiPost, API_HEADERS } from '../api/client'
import { getDb, type Case, type EventRow, type Ioc, type MailBody, type MailRow } from '../db/schema'
import type { Filter, SettingsLike } from '../rules/filter'
import type { Rule, RuleDiag } from '../rules/engine'
import * as local from './queries'
import { settingsForRules, runRules as runLocalRules } from './rules'

export interface AggGroup {
  value: string
  count: number
  first: number | null
  last: number | null
}
export interface Aggregation {
  groups: AggGroup[]
  total: number
  distinct: number
}
export interface SearchResult<T> {
  rows: T[]
  truncated: boolean
}
export interface FacetItem {
  value: string
  count: number
}
export interface IocListOptions {
  kind?: string
  q?: string
  onlyBad?: boolean
  unchecked?: boolean
  limit?: number
  offset?: number
  sort?: string
}
export interface IocList {
  rows: Ioc[]
  total: number
  kinds: Record<string, number>
}
export interface RuleRunResult {
  findings: Record<string, unknown>[]
  byRule: Record<string, number>
  errors: string[]
  diagnostics?: RuleDiag[]
}

export interface DataSource {
  readonly kind: 'browser' | 'server'
  searchEvents(filter: Filter, limit: number): Promise<SearchResult<EventRow>>
  countEvents(filter: Filter): Promise<number>
  aggregateEvents(filter: Filter, field: string, limit: number): Promise<Aggregation>
  timelineEvents(filter: Filter, bucket: local.Bucket): Promise<{ t: number; count: number }[]>
  searchMails(filter: Filter, limit: number): Promise<SearchResult<MailRow>>
  countMails(filter: Filter): Promise<number>
  aggregateMails(filter: Filter, field: string, limit: number): Promise<Aggregation>
  timelineMails(filter: Filter, bucket: local.Bucket): Promise<{ t: number; count: number }[]>
  facets(source: 'events' | 'mails', field: string, limit: number): Promise<FacetItem[]>
  getEvent(id: number): Promise<EventRow | null>
  getMail(id: number): Promise<{ row: MailRow; body: MailBody | null } | null>
  pivot(value: string): Promise<local.PivotResult>
  summary(): Promise<Record<string, unknown>>
  listIocs(opts: IocListOptions): Promise<IocList>
  setIocReputation(items: { kind: string; value: string; verdict: string; tags: string[]; summary: unknown; verdicts: unknown; checkedAt: number }[]): Promise<void>
  runRules(rules: Rule[], onProgress?: (done: number, total: number, ruleId: string, findings: number) => void): Promise<RuleRunResult>
  /** Removes the rows and the derived state they fed (findings, chain snapshot, diagnostics). */
  deleteEvidence(evidenceId: number): Promise<{ findings: number; chains: number }>
  sql?(sql: string, limit?: number): Promise<{ rows: Record<string, unknown>[]; columns: string[]; truncated: boolean }>
}

// ---------------------------------------------------------------------------
class BrowserSource implements DataSource {
  readonly kind = 'browser' as const
  constructor(private kase: Case) {}
  private get id(): number {
    return this.kase.id!
  }
  private get settings(): SettingsLike {
    return settingsForRules(this.kase)
  }
  searchEvents(filter: Filter, limit: number) {
    return local.searchEvents(this.id, filter, { limit, settings: this.settings })
  }
  countEvents(filter: Filter) {
    return local.countEvents(this.id, filter, this.settings)
  }
  aggregateEvents(filter: Filter, field: string, limit: number) {
    return local.aggregateEvents(this.id, filter, field, limit, this.settings)
  }
  timelineEvents(filter: Filter, bucket: local.Bucket) {
    return local.timelineEvents(this.id, filter, bucket, this.settings)
  }
  searchMails(filter: Filter, limit: number) {
    return local.searchMails(this.id, filter, { limit, settings: this.settings })
  }
  countMails(filter: Filter) {
    return local.countMails(this.id, filter, this.settings)
  }
  aggregateMails(filter: Filter, field: string, limit: number) {
    return local.aggregateMails(this.id, filter, field, limit, this.settings)
  }
  timelineMails(filter: Filter, bucket: local.Bucket) {
    return local.timelineMails(this.id, filter, bucket, this.settings)
  }
  async facets(source: 'events' | 'mails', field: string, limit: number) {
    return (await local.getFacets(this.id, source, field, limit)).map((f) => ({ value: f.value, count: f.count }))
  }
  async getEvent(id: number) {
    const r = await getDb().events.get(id)
    return r && r.caseId === this.id ? r : null
  }
  async getMail(id: number) {
    const row = await getDb().mails.get(id)
    if (!row || row.caseId !== this.id) return null
    const body = (await getDb().mailBodies.get(id)) ?? null
    return { row, body }
  }
  pivot(value: string) {
    return local.pivot(this.id, value)
  }
  summary() {
    return local.caseSummary(this.id)
  }
  async listIocs(opts: IocListOptions) {
    const db = getDb()
    let rows = await db.iocs.where('caseId').equals(this.id).toArray()
    const kinds: Record<string, number> = {}
    for (const r of rows) kinds[r.kind] = (kinds[r.kind] ?? 0) + 1
    const rank = (v: string | null | undefined) => ({ malicious: 3, suspicious: 2, clean: 1 })[v ?? ''] ?? 0
    rows = rows.filter((i) => (!opts.kind || i.kind === opts.kind) && (!opts.q || i.value.includes(opts.q.toLowerCase())) && (!opts.onlyBad || rank(i.verdict) >= 2) && (!opts.unchecked || !i.checkedAt))
    rows.sort((a, b) => rank(b.verdict) - rank(a.verdict) || b.count - a.count)
    const total = rows.length
    const offset = opts.offset ?? 0
    return { rows: rows.slice(offset, offset + (opts.limit ?? 500)), total, kinds }
  }
  async setIocReputation(items: { kind: string; value: string; verdict: string; tags: string[]; summary: unknown; verdicts: unknown; checkedAt: number }[]) {
    const db = getDb()
    for (const it of items) {
      const row = await db.iocs.where('[caseId+kind+value]').equals([this.id, it.kind, it.value]).first()
      if (row) await db.iocs.update(row.id!, { reputation: { summary: it.summary, verdicts: it.verdicts }, verdict: it.verdict, tags: it.tags, checkedAt: it.checkedAt })
    }
    const { mirrorToMails } = await import('./iocs')
    await mirrorToMails(this.id)
  }
  async runRules(rules: Rule[], onProgress?: (done: number, total: number, ruleId: string, findings: number) => void) {
    const res = await runLocalRules(this.kase, rules, onProgress)
    return { findings: [], byRule: res.byRule, errors: res.errors, diagnostics: res.diagnostics }
  }
  async deleteEvidence(evidenceId: number) {
    const db = getDb()
    const ev = await db.evidence.get(evidenceId)
    const { deleteEvidenceData } = await import('../db/schema')
    const { clearDerivedState } = await import('./caseState')
    const { rebuildDerived } = await import('./ingest')
    const { forgetUpload } = await import('./upload')
    await deleteEvidenceData(db, this.id, evidenceId)  // events, mails, bodies, attachments, urls, evidence row
    const cleared = await clearDerivedState(this.id)  // findings, chain snapshot, diagnostics (reviews archived)
    if (ev) await forgetUpload(ev)  // resume record + server-side partial, if any
    await rebuildDerived(this.id)  // facets and indicators from the rows that remain
    return cleared
  }
}

// ---------------------------------------------------------------------------
class ServerSource implements DataSource {
  readonly kind = 'server' as const
  constructor(private kase: Case) {}
  private get key(): string {
    return this.kase.serverKey!
  }
  private get settings(): SettingsLike {
    return settingsForRules(this.kase)
  }
  private post<T>(path: string, body: unknown) {
    return apiPost<T>(`/api/store/${this.key}/${path}`, body)
  }
  private async search<T>(source: 'events' | 'mails', filter: Filter, limit: number): Promise<SearchResult<T>> {
    const r = await this.post<{ rows: T[]; truncated: boolean }>('search', { source, filter, limit, sort: filter.sort, settings: this.settings })
    return { rows: r.rows, truncated: r.truncated }
  }
  searchEvents(filter: Filter, limit: number) {
    return this.search<EventRow>('events', filter, limit)
  }
  async countEvents(filter: Filter) {
    return (await this.post<{ count: number }>('count', { source: 'events', filter, settings: this.settings })).count
  }
  aggregateEvents(filter: Filter, field: string, limit: number) {
    return this.post<Aggregation>('aggregate', { source: 'events', filter, field, limit, settings: this.settings })
  }
  timelineEvents(filter: Filter, bucket: local.Bucket) {
    return this.post<{ t: number; count: number }[]>('timeline', { source: 'events', filter, bucket, settings: this.settings })
  }
  searchMails(filter: Filter, limit: number) {
    return this.search<MailRow>('mails', filter, limit)
  }
  async countMails(filter: Filter) {
    return (await this.post<{ count: number }>('count', { source: 'mails', filter, settings: this.settings })).count
  }
  aggregateMails(filter: Filter, field: string, limit: number) {
    return this.post<Aggregation>('aggregate', { source: 'mails', filter, field, limit, settings: this.settings })
  }
  timelineMails(filter: Filter, bucket: local.Bucket) {
    return this.post<{ t: number; count: number }[]>('timeline', { source: 'mails', filter, bucket, settings: this.settings })
  }
  facets(source: 'events' | 'mails', field: string, limit: number) {
    return apiGet<FacetItem[]>(`/api/store/${this.key}/facets?source=${source}&field=${encodeURIComponent(field)}&limit=${limit}`)
  }
  async getEvent(id: number) {
    try {
      return await apiGet<EventRow>(`/api/store/${this.key}/row?source=events&id=${id}`)
    } catch {
      return null
    }
  }
  async getMail(id: number) {
    try {
      const r = await apiGet<MailRow & { body: MailBody | null }>(`/api/store/${this.key}/row?source=mails&id=${id}`)
      const { body, ...row } = r
      return { row: row as MailRow, body: body ? { ...body, caseId: this.kase.id!, mailId: id } : null }
    } catch {
      return null
    }
  }
  pivot(value: string) {
    return this.post<local.PivotResult>('pivot', { value })
  }
  summary() {
    return apiGet<Record<string, unknown>>(`/api/store/${this.key}`)
  }
  async listIocs(opts: IocListOptions) {
    const params = new URLSearchParams()
    if (opts.kind) params.set('kind', opts.kind)
    if (opts.q) params.set('q', opts.q)
    if (opts.onlyBad) params.set('bad', '1')
    if (opts.unchecked) params.set('unchecked', '1')
    params.set('limit', String(opts.limit ?? 500))
    params.set('offset', String(opts.offset ?? 0))
    if (opts.sort) params.set('sort', opts.sort)
    const r = await apiGet<{ rows: Record<string, unknown>[]; total: number; kinds: Record<string, number> }>(`/api/store/${this.key}/iocs?${params}`)
    const rows: Ioc[] = r.rows.map((x, i) => ({
      id: (opts.offset ?? 0) + i + 1,
      caseId: this.kase.id!,
      kind: x.kind as Ioc['kind'],
      value: String(x.value),
      sources: (x.sources as string[]) ?? [],
      firstSeen: (x.firstSeen as number) ?? null,
      lastSeen: (x.lastSeen as number) ?? null,
      count: Number(x.count) || 0,
      verdict: (x.verdict as string) ?? null,
      tags: (x.tags as string[]) ?? [],
      checkedAt: (x.checkedAt as number) ?? null,
      reputation: x.verdicts || x.summary ? { summary: x.summary, verdicts: x.verdicts } : null,
    }))
    return { rows, total: r.total, kinds: r.kinds }
  }
  async setIocReputation(items: { kind: string; value: string; verdict: string; tags: string[]; summary: unknown; verdicts: unknown; checkedAt: number }[]) {
    await this.post('reputation', { items })
  }
  async runRules(rules: Rule[], onProgress?: (done: number, total: number, ruleId: string, findings: number) => void) {
    const { waitForJob } = await import('./jobs')
    const { jobId } = await this.post<{ jobId: string }>('rules/run', { rules, settings: this.settings })
    const job = await waitForJob(jobId, (j) => {
      const p = j.progress as { index?: number; total?: number; ruleId?: string; findings?: number }
      if (p.index != null) onProgress?.(p.index, p.total ?? rules.length, p.ruleId ?? '', p.findings ?? 0)
    })
    const res = (job.result ?? {}) as { findings?: Record<string, unknown>[]; byRule?: Record<string, number>; errors?: { ruleId: string; error: string }[]; diagnostics?: RuleDiag[] }
    return { findings: res.findings ?? [], byRule: res.byRule ?? {}, errors: (res.errors ?? []).map((e) => `${e.ruleId}: ${e.error}`), diagnostics: res.diagnostics ?? [] }
  }
  async deleteEvidence(evidenceId: number) {
    const db = getDb()
    const ev = await db.evidence.get(evidenceId)
    // rows, bodies, attachments, urls and indicators leave the DuckDB store and the file is checkpointed
    const res = await fetch(`/api/store/${this.key}/evidence/${evidenceId}`, { method: 'DELETE', headers: API_HEADERS })
    if (!res.ok) throw new Error(`server refused the deletion (HTTP ${res.status})`)
    await db.evidence.delete(evidenceId)
    const { clearDerivedState } = await import('./caseState')
    const { forgetUpload } = await import('./upload')
    if (ev) await forgetUpload(ev)
    return clearDerivedState(this.kase.id!)
  }
  sql(sql: string, limit = 200) {
    return this.post<{ rows: Record<string, unknown>[]; columns: string[]; truncated: boolean }>('sql', { sql, limit })
  }
}

export function getSource(kase: Case): DataSource {
  return kase.storage === 'server' && kase.serverKey ? new ServerSource(kase) : new BrowserSource(kase)
}
