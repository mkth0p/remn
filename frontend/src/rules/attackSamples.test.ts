import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { expect, it } from 'vitest'
import { compileCond, ruleApplicable, ruleEventIds, ruleFields, ruleReadFields, runRule, validateRule, type Rule } from './engine'
import type { Row, SettingsLike } from './filter'

/**
 * The browser engine over EVTX-ATTACK-SAMPLES, against the SQL engine's findings: the same finding
 * keys for every rule on every file. Runs when EVTX_ATTACK_OUT points at the output of
 * tools/evtx_attack_samples.py (CI does this); skipped otherwise. Rows are read and their heavy
 * columns dropped as workers/rules.worker.ts does, so a rule the worker would starve of `data`
 * fails here too.
 */
const OUT = process.env.EVTX_ATTACK_OUT ?? ''

const SETTINGS = {
  internal_domains: [],
  expected_countries: [],
  vip_names: [],
  admin_accounts: [],
  service_accounts: [],
  internal_ips: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '::1', 'fe80::/10', 'fc00::/7'],
  brands: [],
  trusted_senders: [],
  businessHours: { start: 8, end: 19, tz: 'UTC' },
  weekendDays: [0, 6],
} as unknown as SettingsLike

function keepFor(fields: Set<string>) {
  let raw = false
  let data = false
  for (const f of fields) {
    if (f === 'raw' || f.startsWith('raw')) raw = true
    if (f === 'data' || f.startsWith('data.') || f === 'dataList') data = true
  }
  return { raw, data }
}

function run(all: Row[], rules: Rule[]): Record<string, string[]> {
  const present = {
    eventIds: new Set(all.map((r) => Number(r.eventId)).filter((n) => Number.isFinite(n))),
    channels: Array.from(new Set(all.map((r) => r.channel).filter((c) => c != null))).map((c) => String(c).toLowerCase()),
  }
  const fetch = (ids: number[] | null, pred: (r: Row) => boolean, keep: { raw: boolean; data: boolean }) => {
    const out: Row[] = []
    for (const r0 of all) {
      if (ids && ids.length && !ids.includes(Number(r0.eventId))) continue
      if (!pred(r0)) continue
      const r = { ...r0 }
      if (!keep.raw) delete r.raw
      if (!keep.data) delete r.data
      out.push(r)
    }
    return out
  }
  const got: Record<string, string[]> = {}
  for (const rule of rules) {
    if (rule.enabled === false || rule.source !== 'events' || !ruleApplicable(rule, present).ok) continue
    const rows = fetch(ruleEventIds(rule.where), () => true, keepFor(ruleReadFields(rule)))
    let thenRows: (() => Row[]) | undefined
    if (rule.then?.where) {
      const thenFields = ruleFields(rule.then.where)
      for (const f of rule.then.join ?? []) thenFields.add(f)
      const pre = fetch(ruleEventIds(rule.then.where), compileCond(rule.then.where, SETTINGS), keepFor(thenFields))
      thenRows = () => pre
    }
    const keys = runRule(rule, { rows, settings: SETTINGS, thenRows }).map((f) => String(f.key))
    if (keys.length) got[rule.id] = keys.sort()
  }
  return got
}

it.skipIf(!OUT || !existsSync(join(OUT, 'sql.json')))(
  'finds on every attack sample exactly what the SQL engine finds',
  () => {
    const sets = JSON.parse(readFileSync(join(OUT, 'rules.json'), 'utf-8')) as Record<'default' | 'hunting', unknown[]>
    const valid = (list: unknown[]) =>
      list.map((r) => {
        const v = validateRule(r)
        if (!v.ok) throw new Error(`invalid rule ${(r as { id?: string }).id}: ${v.error}`)
        return v.rule
      })
    const rules = { default: valid(sets.default), hunting: valid(sets.hunting) }
    const sql = JSON.parse(readFileSync(join(OUT, 'sql.json'), 'utf-8')) as Record<string, Record<'default' | 'hunting', Record<string, string[]>>>
    const index = JSON.parse(readFileSync(join(OUT, 'index.json'), 'utf-8')) as { i: number; file: string }[]
    const diffs: string[] = []
    for (const { i, file } of index) {
      const rows = readFileSync(join(OUT, 'rows', `${i}.ndjson`), 'utf-8')
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as Row)
      for (const set of ['default', 'hunting'] as const) {
        const got = run(rows, rules[set])
        const want = sql[file][set]
        for (const id of new Set([...Object.keys(got), ...Object.keys(want)])) {
          if (JSON.stringify(got[id] ?? []) !== JSON.stringify(want[id] ?? [])) diffs.push(`${file} ${id}: browser ${(got[id] ?? []).length}, sql ${(want[id] ?? []).length}`)
        }
      }
    }
    expect(diffs, diffs.slice(0, 50).join('\n')).toEqual([])
  },
  1_800_000,
)
