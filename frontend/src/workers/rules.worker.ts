/// <reference lib="webworker" />
/**
 * Rule worker: runs the YAML rules against IndexedDB and stores findings.
 */
import { getDb, type Finding, type MailRow } from '../db/schema'
import { compileCond, ruleEventIds, ruleFields, runRule, type Rule, type RuleDiag } from '../rules/engine'
import type { Row, SettingsLike } from '../rules/filter'

export interface RunRequest {
  cmd: 'run'
  caseId: number
  rules: Rule[]
  settings: SettingsLike
}

const ctx = self as unknown as DedicatedWorkerGlobalScope
const post = (msg: Record<string, unknown>) => ctx.postMessage(msg)

const BODY_FIELDS = new Set(['bodyText', 'bodyHtml', 'headersText', 'visibleText'])

async function fetchEvents(caseId: number, ids: number[] | null, pred: (r: Row) => boolean, keepHeavy: boolean): Promise<Row[]> {
  const db = getDb()
  const out: Row[] = []
  const strip = (r: Row) => {
    if (!keepHeavy) {
      delete r.raw
      delete r.data
    }
    return r
  }
  if (ids && ids.length) {
    const keys = ids.map((id) => [caseId, id] as [number, number])
    await db.events
      .where('[caseId+eventId]')
      .anyOf(keys)
      .each((r) => {
        if (pred(r as Row)) out.push(strip(r as Row))
      })
  } else {
    await db.events
      .where('caseId')
      .equals(caseId)
      .each((r) => {
        if (pred(r as Row)) out.push(strip(r as Row))
      })
  }
  return out
}

let mailCache: { caseId: number; rows: MailRow[] } | null = null
async function allMails(caseId: number): Promise<MailRow[]> {
  if (mailCache && mailCache.caseId === caseId) return mailCache.rows
  const db = getDb()
  const rows = await db.mails.where('caseId').equals(caseId).toArray()
  mailCache = { caseId, rows }
  return rows
}
async function mailsWithBodies(caseId: number): Promise<Row[]> {
  const db = getDb()
  const rows = await allMails(caseId)
  const bodies = await db.mailBodies.where('caseId').equals(caseId).toArray()
  const byId = new Map(bodies.map((b) => [b.mailId, b]))
  return rows.map((m) => {
    const b = byId.get(m.id as number)
    return { ...m, bodyText: b?.bodyText ?? null, bodyHtml: b?.bodyHtml ?? null, headersText: b?.headersText ?? null, visibleText: b?.visibleText ?? null }
  })
}

async function run(req: RunRequest): Promise<void> {
  const db = getDb()
  const { caseId, rules, settings } = req
  mailCache = null
  const ruleIds = rules.map((r) => r.id)
  // preserve analyst decisions on findings that still exist after the re-run
  const old = await db.findings.where('caseId').equals(caseId).filter((f) => ruleIds.includes(f.ruleId)).toArray()
  const oldByKey = new Map(old.map((f) => [f.key, f]))
  await db.findings.where('caseId').equals(caseId).filter((f) => ruleIds.includes(f.ruleId)).delete()
  let total = 0
  const byRule: Record<string, number> = {}
  const diagnostics: RuleDiag[] = []
  const now = Date.now()
  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i]
    if (rule.enabled === false) continue
    const t0 = Date.now()
    try {
      let rows: Row[]
      let thenRows: (() => Row[]) | undefined
      const fields = ruleFields(rule.where)
      const heavy = fields.has('raw') || fields.has('data') || Array.from(fields).some((f) => f.startsWith('data.') || f.startsWith('raw'))
      if (rule.source === 'events') {
        const pred = compileCond(rule.where, settings)
        rows = await fetchEvents(caseId, ruleEventIds(rule.where), pred, heavy)
        if (rule.then?.where) {
          const thenPred = compileCond(rule.then.where, settings)
          const pre = await fetchEvents(caseId, ruleEventIds(rule.then.where), thenPred, false)
          thenRows = () => pre
        }
      } else {
        const needBodies = Array.from(fields).some((f) => BODY_FIELDS.has(f))
        rows = needBodies ? await mailsWithBodies(caseId) : ((await allMails(caseId)) as unknown as Row[])
        if (rule.then?.where) {
          const all = rows
          thenRows = () => all
        }
      }
      const found = runRule(rule, { rows, settings, thenRows: thenRows ? () => thenRows!() : undefined, onDiag: (d) => diagnostics.push(d) })
      const toAdd: Finding[] = found.map((f) => {
        const prev = oldByKey.get(f.key)
        return { ...f, caseId, createdAt: prev?.createdAt ?? now, status: prev?.status ?? 'new', notes: prev?.notes }
      })
      if (toAdd.length) await db.findings.bulkAdd(toAdd)
      byRule[rule.id] = toAdd.length
      total += toAdd.length
      post({ type: 'progress', index: i + 1, total: rules.length, ruleId: rule.id, findings: toAdd.length, ms: Date.now() - t0, rows: rows.length })
    } catch (e) {
      post({ type: 'rule-error', ruleId: rule.id, error: (e as Error).message || String(e), index: i + 1, total: rules.length })
    }
  }
  mailCache = null
  post({ type: 'done', total, byRule, diagnostics })
}

ctx.onmessage = async (ev: MessageEvent<RunRequest>) => {
  try {
    if (ev.data.cmd === 'run') await run(ev.data)
  } catch (e) {
    post({ type: 'error', error: (e as Error).message || String(e) })
  }
}
