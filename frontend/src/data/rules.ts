import yaml from 'js-yaml'
import { getDb, type Case } from '../db/schema'
import { validateRule, type Rule, type RuleDiag } from '../rules/engine'
import { log, toast, useStore } from '../state/store'
import type { RunRequest } from '../workers/rules.worker'
import type { SettingsLike } from '../rules/filter'
import { enabledPackIds, getPackRules } from './packs'
import { replaceFindings } from './findingReviews'

export interface LoadedRule {
  rule: Rule
  yaml: string
  file: string
  origin: 'bundled' | 'pack' | 'custom'
  /** community pack id for origin 'pack' */
  pack?: string
  error?: string
  enabled: boolean
}

export function parseRuleYaml(text: string): { rules: Rule[]; errors: string[] } {
  const rules: Rule[] = []
  const errors: string[] = []
  let docs: unknown[] = []
  try {
    docs = yaml.loadAll(text)
  } catch (e) {
    return { rules, errors: [(e as Error).message] }
  }
  for (const d of docs) {
    if (!d || typeof d !== 'object') continue
    const v = validateRule(d)
    if (v.ok) rules.push(v.rule)
    else errors.push(v.error)
  }
  return { rules, errors }
}

export async function loadRules(caseId: number | null, strict = false): Promise<LoadedRule[]> {
  const meta = useStore.getState().meta
  if (strict && !meta) throw new Error('Rule metadata is unavailable; reconnect to the backend and retry')
  const out: LoadedRule[] = []
  const db = getDb()
  const disabled = new Set<string>(((await db.kv.get('disabledRules'))?.value as string[]) ?? [])
  for (const r of meta?.rules ?? []) {
    if (r.error) {
      out.push({ rule: { id: r.file, title: r.file, severity: 'info', source: 'events' }, yaml: r.yaml, file: r.file, origin: 'bundled', error: r.error, enabled: false })
      continue
    }
    const v = validateRule(r.rule)
    if (v.ok) out.push({ rule: v.rule, yaml: r.yaml, file: r.file, origin: 'bundled', enabled: !disabled.has(v.rule.id) })
    else out.push({ rule: { id: r.file, title: r.file, severity: 'info', source: 'events' }, yaml: r.yaml, file: r.file, origin: 'bundled', error: v.error, enabled: false })
  }
  // community packs (SigmaHQ, Sublime): fetched on demand, only the enabled ones
  const packs = meta?.packs ?? []
  const enabledPacks = await enabledPackIds(packs)
  for (const p of packs) {
    if (!enabledPacks.has(p.id)) continue
    let pr
    try {
      pr = await getPackRules(p.id)
    } catch (e) {
      log('err', `rule pack ${p.id}: ${(e as Error).message}`)
      if (strict) throw new Error(`Could not load enabled rule pack ${p.id}: ${(e as Error).message}`)
      continue
    }
    for (const r of pr.rules) {
      if (r.error || !r.rule) {
        out.push({ rule: { id: r.file, title: r.file, severity: 'info', source: p.source }, yaml: r.yaml ?? '', file: r.file, origin: 'pack', pack: p.id, error: r.error ?? 'empty rule', enabled: false })
        continue
      }
      const v = validateRule(r.rule)
      if (v.ok) out.push({ rule: v.rule, yaml: '', file: r.file, origin: 'pack', pack: p.id, enabled: !disabled.has(v.rule.id) })
      else out.push({ rule: { id: r.file, title: r.file, severity: 'info', source: p.source }, yaml: '', file: r.file, origin: 'pack', pack: p.id, error: v.error, enabled: false })
    }
  }
  const custom = await db.customRules.filter((c) => c.caseId === null || c.caseId === caseId).toArray()
  for (const c of custom) {
    const { rules, errors } = parseRuleYaml(c.yaml)
    if (rules.length) {
      // custom rules override bundled rules with the same id
      const idx = out.findIndex((x) => x.rule.id === rules[0].id)
      const entry: LoadedRule = { rule: rules[0], yaml: c.yaml, file: `custom:${c.id}`, origin: 'custom', enabled: c.enabled && !disabled.has(rules[0].id) }
      if (idx >= 0) out[idx] = entry
      else out.push(entry)
    } else out.push({ rule: { id: c.ruleId, title: c.ruleId, severity: 'info', source: 'events' }, yaml: c.yaml, file: `custom:${c.id}`, origin: 'custom', error: errors.join('; '), enabled: false })
  }
  if (strict && out.some((r) => r.error)) throw new Error('Some rules could not be loaded. See Rules diagnostics, correct them, and retry.')
  return out
}

export function settingsForRules(kase: Case): SettingsLike {
  const s = kase.settings
  return {
    internal_domains: s.internalDomains,
    expected_countries: (s.expectedCountries ?? []).map((c) => c.trim().toUpperCase()).filter(Boolean),
    vip_names: s.vipNames,
    admin_accounts: s.adminAccounts,
    service_accounts: s.serviceAccounts,
    internal_ips: s.internalIps,
    brands: s.brands,
    trusted_senders: s.trustedSenders ?? [],
    businessHours: s.businessHours,
    weekendDays: s.weekendDays,
  }
}

/** Replace the findings of the given rules, preserving analyst status/notes on findings whose key still exists. */
export async function persistFindings(caseId: number, ruleIds: string[], findings: Record<string, unknown>[]): Promise<number> {
  return replaceFindings(caseId, ruleIds, findings)
}

export interface RuleRunSummary {
  total: number
  byRule: Record<string, number>
  errors: string[]
  diagnostics: RuleDiag[]
}

/** Store the last run's per-rule outcome so the Rules view can explain silent rules. */
async function saveDiagnostics(caseId: number, res: RuleRunSummary): Promise<void> {
  await getDb().kv.put({ key: `ruleDiags-${caseId}`, value: { ts: Date.now(), byRule: res.byRule, diagnostics: res.diagnostics, errors: res.errors } })
  for (const d of res.diagnostics) {
    if (d.reason === 'missing_setting') log('warn', `${d.ruleId}: disarmed — ${d.detail}`)
  }
  const noData = res.diagnostics.filter((d) => d.reason === 'no_selector_match').length
  const needSettings = res.diagnostics.filter((d) => d.reason === 'missing_setting').length
  const notApplicable = res.diagnostics.filter((d) => d.reason === 'not_applicable').length
  if (noData || needSettings || notApplicable) {
    toast('info', `${res.total} finding(s) · ${notApplicable ? `${notApplicable} rule(s) not applicable to this evidence · ` : ''}${noData} rule(s) had no matching events${needSettings ? ` · ${needSettings} need Settings (internal domains, VIPs…)` : ''} — see the Rules view`, 9000)
  }
}

/** Run rules on whichever store the case uses and persist the findings in IndexedDB. */
export async function runRulesFor(kase: Case, rules: Rule[], onProgress?: (done: number, total: number, ruleId: string, findings: number) => void): Promise<RuleRunSummary> {
  let res: RuleRunSummary
  if (kase.storage === 'server' && kase.serverKey) {
    const { getSource } = await import('./source')
    log('info', `running ${rules.length} rule(s) on the server store…`)
    const r = await getSource(kase).runRules(rules, onProgress)
    const completed = rules.map((x) => x.id).filter((id) => !r.errors.some((e) => e.startsWith(`${id}:`)))
    const n = await persistFindings(kase.id!, completed, r.findings.filter((f) => completed.includes(String(f.ruleId))))
    for (const e of r.errors) log('err', e)
    log('ok', `rules done: ${n} finding(s)`)
    toast('ok', `${n} finding(s) from ${rules.length} rule(s)`)
    useStore.getState().bumpRules()
    res = { total: n, byRule: r.byRule, errors: r.errors, diagnostics: r.diagnostics ?? [] }
  } else {
    res = await runRules(kase, rules, onProgress)
  }
  await saveDiagnostics(kase.id!, res)
  return res
}

export async function runRules(kase: Case, rules: Rule[], onProgress?: (done: number, total: number, ruleId: string, findings: number) => void): Promise<RuleRunSummary> {
  const worker = new Worker(new URL('../workers/rules.worker.ts', import.meta.url), { type: 'module' })
  const req: RunRequest = { cmd: 'run', caseId: kase.id!, rules, settings: settingsForRules(kase) }
  const errors: string[] = []
  log('info', `running ${rules.length} rule(s)…`)
  return new Promise((resolve) => {
    worker.onmessage = (ev: MessageEvent<Record<string, unknown>>) => {
      const m = ev.data
      if (m.type === 'progress') {
        onProgress?.(Number(m.index), Number(m.total), String(m.ruleId), Number(m.findings))
        if (Number(m.findings) > 0) log('ok', `${m.ruleId}: ${m.findings} finding(s) (${m.rows} rows, ${m.ms} ms)`)
      } else if (m.type === 'rule-error') {
        errors.push(`${m.ruleId}: ${m.error}`)
        log('err', `${m.ruleId}: ${m.error}`)
        onProgress?.(Number(m.index), Number(m.total), String(m.ruleId), 0)
      } else if (m.type === 'done') {
        log('ok', `rules done: ${m.total} finding(s)`)
        toast('ok', `${m.total} finding(s) from ${rules.length} rule(s)`)
        worker.terminate()
        useStore.getState().bumpRules()
        resolve({ total: Number(m.total), byRule: m.byRule as Record<string, number>, errors, diagnostics: (m.diagnostics as RuleDiag[]) ?? [] })
      } else if (m.type === 'error') {
        log('err', `rule worker: ${m.error}`)
        toast('err', `rule engine error: ${m.error}`, 0)
        worker.terminate()
        resolve({ total: 0, byRule: {}, errors: [String(m.error)], diagnostics: [] })
      }
    }
    worker.onerror = (e) => {
      log('err', `rule worker crashed: ${e.message}`)
      worker.terminate()
      resolve({ total: 0, byRule: {}, errors: [e.message], diagnostics: [] })
    }
    worker.postMessage(req)
  })
}
