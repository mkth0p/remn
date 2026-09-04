/**
 * Executes the AI tool calls locally against the case data source (IndexedDB
 * or the server store). Only what these functions return is sent to the model.
 */
import { getDb, type Case } from '../db/schema'
import { lookupReputation } from '../api/client'
import { getSource } from '../data/source'
import { compileRegex, type Filter } from '../rules/filter'
import type { Bucket } from '../data/queries'

const EVENT_COLS = ['id', 'tsIso', 'eventId', 'provider', 'channel', 'computer', 'sourceFile', 'summary', 'targetUser', 'targetDomain', 'subjectUser', 'logonType', 'ipAddress', 'workstation', 'statusText', 'processName', 'commandLine', 'parentProcessName', 'serviceName', 'serviceFile', 'taskName', 'memberName', 'groupName', 'shareName', 'relativeTargetName', 'image', 'destinationIp', 'destinationPort', 'query', 'targetFilename', 'targetObject', 'threatName', 'path']
const MAIL_COLS = ['id', 'dateIso', 'subject', 'folder', 'fromName', 'fromAddr', 'fromDomain', 'replyTo', 'returnPath', 'originIp', 'risk', 'flags', 'urlCount', 'attachmentCount', 'maxAttachmentRisk', 'textPreview']

const MAX_ROWS = 100
const MAX_CHARS = 60_000

function project(row: Record<string, unknown>, cols: string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const c of cols) {
    const v = row[c]
    if (v == null || v === '' || (Array.isArray(v) && !v.length)) continue
    out[c] = typeof v === 'string' && v.length > 400 ? v.slice(0, 400) + '…' : v
  }
  return out
}

function clampFilter(f: unknown): Filter {
  if (!f || typeof f !== 'object') return {}
  const x = f as Filter
  return { ...x, limit: undefined }
}

function cap(obj: unknown): string {
  let s = JSON.stringify(obj)
  if (s.length > MAX_CHARS) s = s.slice(0, MAX_CHARS) + `…[truncated ${s.length - MAX_CHARS} chars]`
  return s
}

const iso = (t: number | null | undefined) => (t ? new Date(t).toISOString() : null)

export async function executeTool(name: string, args: Record<string, unknown>, kase: Case): Promise<string> {
  const caseId = kase.id!
  const ds = getSource(kase)
  const db = getDb()
  try {
    switch (name) {
      case 'get_case_summary': {
        const sum = (await ds.summary()) as Record<string, unknown>
        const findings = await db.findings.where('caseId').equals(caseId).toArray()
        const bySeverity: Record<string, number> = {}
        for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1
        const order = ['critical', 'high', 'medium', 'low', 'info']
        return cap({
          storage: ds.kind,
          ...sum,
          findingsBySeverity: bySeverity,
          topFindings: findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity)).slice(0, 15).map((f) => ({ id: f.id, ruleId: f.ruleId, title: f.title, severity: f.severity, count: f.count, entities: f.entities, tsIso: iso(f.ts) })),
        })
      }
      case 'search_events': {
        const limit = Math.min(Number(args.limit) || 30, MAX_ROWS)
        const res = await ds.searchEvents(clampFilter(args.filter), limit)
        const cols = Array.isArray(args.fields) && args.fields.length ? ['id', 'tsIso', 'eventId', ...(args.fields as string[])] : EVENT_COLS
        return cap({ count: res.rows.length, truncated: res.truncated, rows: res.rows.map((r) => project(r as Record<string, unknown>, cols)) })
      }
      case 'aggregate_events': {
        const res = await ds.aggregateEvents(clampFilter(args.filter), String(args.field || 'eventId'), Math.min(Number(args.limit) || 25, 100))
        return cap({ field: args.field, total: res.total, distinct: res.distinct, groups: res.groups.map((g) => ({ ...g, firstIso: iso(g.first), lastIso: iso(g.last) })) })
      }
      case 'timeline_events': {
        const bucket = (['minute', 'hour', 'day'].includes(String(args.bucket)) ? args.bucket : 'hour') as Bucket
        const res = await ds.timelineEvents(clampFilter(args.filter), bucket)
        const limit = Math.min(Number(args.limit) || 200, 500)
        const top = res.length > limit ? [...res].sort((a, b) => b.count - a.count).slice(0, limit).sort((a, b) => a.t - b.t) : res
        return cap({ bucket, buckets: res.length, shown: top.length, series: top.map((b) => ({ tIso: iso(b.t), count: b.count })) })
      }
      case 'get_event': {
        const row = await ds.getEvent(Number(args.id))
        if (!row) return JSON.stringify({ error: 'not found' })
        const { raw, ...rest } = row
        void raw
        return cap(rest)
      }
      case 'search_mails': {
        const limit = Math.min(Number(args.limit) || 30, MAX_ROWS)
        const res = await ds.searchMails(clampFilter(args.filter), limit)
        return cap({ count: res.rows.length, truncated: res.truncated, rows: res.rows.map((r) => ({ ...project(r as Record<string, unknown>, MAIL_COLS), attachments: (r.attachments ?? []).map((a) => ({ name: a.name, realExt: a.realExt, size: a.size, risk: a.risk, flags: a.flags })), urls: (r.urls ?? []).slice(0, 10).map((u) => ({ url: u.defanged, flags: u.flags })) })) })
      }
      case 'aggregate_mails': {
        const res = await ds.aggregateMails(clampFilter(args.filter), String(args.field || 'fromDomain'), Math.min(Number(args.limit) || 25, 100))
        return cap({ field: args.field, total: res.total, distinct: res.distinct, groups: res.groups.map((g) => ({ ...g, firstIso: iso(g.first), lastIso: iso(g.last) })) })
      }
      case 'timeline_mails': {
        const bucket = (['minute', 'hour', 'day'].includes(String(args.bucket)) ? args.bucket : 'day') as Bucket
        const res = await ds.timelineMails(clampFilter(args.filter), bucket)
        return cap({ bucket, series: res.slice(0, 500).map((b) => ({ tIso: iso(b.t), count: b.count })) })
      }
      case 'get_mail': {
        const r = await ds.getMail(Number(args.id))
        if (!r) return JSON.stringify({ error: 'not found' })
        const row = r.row
        const out: Record<string, unknown> = { ...row, attachments: (row.attachments ?? []).map((a) => ({ ...a, details: undefined })), urls: (row.urls ?? []).slice(0, 40).map((u) => ({ url: u.defanged, host: u.host, flags: u.flags, text: u.text })) }
        if (args.includeBody && r.body) {
          out.bodyText = (r.body.bodyText || r.body.visibleText || '').slice(0, 6000)
          if (r.body.headersText) out.headersText = r.body.headersText.slice(0, 6000)
        }
        delete out.bodyHtml
        return cap(out)
      }
      case 'list_findings': {
        const sev = args.severity ? String(args.severity) : null
        const src = args.source ? String(args.source) : null
        const rows = await db.findings.where('caseId').equals(caseId).filter((f) => (!sev || f.severity === sev) && (!src || f.source === src)).toArray()
        const order = ['critical', 'high', 'medium', 'low', 'info']
        rows.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity))
        const limit = Math.min(Number(args.limit) || 50, 200)
        return cap({ count: rows.length, findings: rows.slice(0, limit).map((f) => ({ id: f.id, ruleId: f.ruleId, title: f.title, severity: f.severity, source: f.source, tsIso: iso(f.ts), count: f.count, entities: f.entities, attack: f.attack, status: f.status, refs: f.refs.slice(0, 10) })) })
      }
      case 'regex_test': {
        const re = compileRegex(String(args.pattern || ''), String(args.flags || 'i'))
        if (!re) return JSON.stringify({ error: 'invalid regular expression' })
        if (args.sample != null) {
          const s = String(args.sample)
          const m = s.match(new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g'))
          return JSON.stringify({ matches: m ? m.slice(0, 50) : [], count: m ? m.length : 0 })
        }
        const source = args.source === 'mails' ? 'mails' : 'events'
        const field = String(args.field || (source === 'mails' ? 'subject' : 'summary'))
        const limit = Math.min(Number(args.limit) || 20, MAX_ROWS)
        const filter: Filter = { regex: { field, pattern: String(args.pattern), flags: String(args.flags || 'i') } }
        if (source === 'mails') {
          const res = await ds.searchMails(filter, limit)
          return cap({ count: res.rows.length, truncated: res.truncated, rows: res.rows.map((r) => ({ id: r.id, value: (r as Record<string, unknown>)[field] })) })
        }
        const res = await ds.searchEvents(filter, limit)
        return cap({ count: res.rows.length, truncated: res.truncated, rows: res.rows.map((r) => ({ id: r.id, tsIso: r.tsIso, eventId: r.eventId, value: (r as Record<string, unknown>)[field] })) })
      }
      case 'lookup_ioc': {
        if (!kase.settings.networkAllowed) return JSON.stringify({ notice: 'External reputation lookups are disabled for this case. Ask the analyst to enable them in Settings.' })
        const kind = String(args.kind)
        const value = String(args.value || '').trim()
        if (!['ip', 'domain', 'url', 'hash'].includes(kind) || !value) return JSON.stringify({ error: 'kind must be ip|domain|url|hash and value non-empty' })
        const resp = await lookupReputation([{ kind, value }], kase.settings.providers?.length ? kase.settings.providers : undefined)
        const sum = resp.summary[`${kind}:${value}`]
        return cap({ summary: sum ?? null, verdicts: resp.results.map((r) => ({ provider: r.provider, verdict: r.verdict, score: r.score, tags: r.tags, details: r.details })) })
      }
      case 'pivot':
        return cap(await ds.pivot(String(args.value || '')))
      case 'sql': {
        if (!ds.sql) return JSON.stringify({ notice: 'This case is stored in the browser; the sql tool is only available for server-stored cases. Use search_events / aggregate_events instead.' })
        const res = await ds.sql(String(args.sql || ''), Math.min(Number(args.limit) || 200, 500))
        return cap(res)
      }
      default:
        return JSON.stringify({ error: `unknown tool ${name}` })
    }
  } catch (e) {
    return JSON.stringify({ error: (e as Error).message || String(e) })
  }
}
