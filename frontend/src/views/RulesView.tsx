import { useEffect, useState } from 'react'
import { runAgent } from '../ai/chat'
import type { PackInfo } from '../api/client'
import { loadRules, parseRuleYaml, type LoadedRule } from '../data/rules'
import { enabledPackIds, ruleYaml, setPackEnabled, shortSha } from '../data/packs'
import { getDb } from '../db/schema'
import { toast, useStore } from '../state/store'
import { Badge, Modal, Spinner, Toggle } from '../components/ui'
import { RuleImport } from '../components/RuleImport'
import { IconAi, IconEdit, IconPlus, IconTrash } from '../components/Icons'
import type { RuleDiag } from '../rules/engine'
import { fmtNum, fmtTs } from '../util/format'
import { safeHref } from '../util/safe'

interface LastRun {
  ts: number
  byRule: Record<string, number>
  diagnostics: RuleDiag[]
  errors?: string[]
}

const DIAG_LABEL: Record<RuleDiag['reason'], { label: string; sev: string }> = {
  missing_setting: { label: 'needs settings', sev: 'medium' },
  no_selector_match: { label: 'no matching data', sev: 'info' },
  all_excluded: { label: 'all excluded', sev: 'info' },
  outside_time_window: { label: 'time filter', sev: 'info' },
  below_threshold: { label: 'below threshold', sev: 'info' },
  not_applicable: { label: 'not applicable', sev: 'info' },
}

/** Rows rendered at once; the search box narrows the rest (the packs bring ~3,000 rules). */
const MAX_ROWS = 400

const TEMPLATE = `id: custom-my-rule
title: My rule
description: What it detects and why it matters
severity: medium          # info | low | medium | high | critical
source: events            # events | mails
attack: [T1078]
where:
  eventId: 4624
  logonType|in: [10]
  ipAddress|nin_setting: internal_ips
# group_by: [ipAddress]
# window: 10m
# threshold: ">= 5"
# distinct: targetUser
# time: { outside_business_hours: true }
# exclude: { targetUser|in_setting: service_accounts }
`

function PackCard({ pack, on, busy, selected, onToggle, onShow }: { pack: PackInfo; on: boolean; busy: boolean; selected: boolean; onToggle: (v: boolean) => void; onShow: () => void }) {
  const sha = shortSha(pack.upstream?.sha)
  return (
    <div className="card" style={{ padding: '8px 12px', minWidth: 260, flex: '1 1 260px', outline: selected ? '1px solid var(--accent)' : undefined }} data-pack={pack.id}>
      <div className="row" style={{ gap: 8, alignItems: 'center' }}>
        <Toggle on={on} onChange={onToggle} />
        <strong style={{ flex: 1 }}>{pack.name}</strong>
        <Badge sev="info">{pack.source}</Badge>
      </div>
      <div className="small muted" style={{ marginTop: 4 }}>{pack.description}</div>
      <div className="small" style={{ marginTop: 6 }}>
        <span className="mono">{fmtNum(pack.counts.converted)}</span> rules converted from {fmtNum(pack.counts.upstream)} upstream
        {pack.counts.skipped ? <span className="muted"> · {fmtNum(pack.counts.skipped)} skipped (listed in skipped.json)</span> : null}
      </div>
      <div className="small muted row" style={{ gap: 8, marginTop: 4, flexWrap: 'wrap' }}>
        <a href={safeHref(pack.upstream?.url)} target="_blank" rel="noreferrer noopener">{pack.upstream?.repo}{sha ? `@${sha}` : ''}</a>
        <span>· {pack.upstream?.fetched}</span>
        <span>· {safeHref(pack.license?.url) ? <a href={safeHref(pack.license?.url)} target="_blank" rel="noreferrer noopener">{pack.license?.name}</a> : pack.license?.name}</span>
        {pack.licenseText && <a href={`/api/rules/packs/${encodeURIComponent(pack.id)}/license`} target="_blank" rel="noreferrer">licence text</a>}
        <span className="spacer" />
        {on && <button className={`btn xs${selected ? ' primary' : ''}`} onClick={onShow} disabled={busy}>{busy ? <Spinner /> : selected ? 'showing' : 'show rules'}</button>}
      </div>
    </div>
  )
}

export function RulesView() {
  const kase = useStore((s) => s.currentCase)
  const meta = useStore((s) => s.meta)
  const rulesVersion = useStore((s) => s.rulesVersion)
  const bump = useStore((s) => s.bumpRules)
  const [rules, setRules] = useState<LoadedRule[]>([])
  const [loading, setLoading] = useState(false)
  const [q, setQ] = useState('')
  const [source, setSource] = useState('')
  const [packFilter, setPackFilter] = useState('')
  const [packsOn, setPacksOn] = useState<Set<string>>(new Set())
  const [edit, setEdit] = useState<{ id?: number; yaml: string; error?: string } | null>(null)
  const [aiAsk, setAiAsk] = useState('')
  const [aiBusy, setAiBusy] = useState(false)
  const [lastRun, setLastRun] = useState<LastRun | null>(null)
  const packs = meta?.packs ?? []
  useEffect(() => {
    if (!kase) return
    let alive = true
    setLoading(true)
    Promise.all([loadRules(kase.id!), enabledPackIds(packs), getDb().kv.get(`ruleDiags-${kase.id}`)])
      .then(([rs, on, k]) => {
        if (!alive) return
        setRules(rs)
        setPacksOn(on)
        setLastRun((k?.value as LastRun) ?? null)
      })
      .finally(() => alive && setLoading(false))
    return () => {
      alive = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kase, rulesVersion, meta])
  if (!kase) return null
  const needle = q.toLowerCase()
  const shown = rules.filter(
    (r) =>
      (!source || r.rule.source === source) &&
      (!packFilter || (packFilter === 'core' ? r.origin !== 'pack' : r.pack === packFilter)) &&
      (!needle || `${r.rule.id} ${r.rule.title} ${(r.rule.tags ?? []).join(' ')} ${(r.rule.attack ?? []).join(' ')}`.toLowerCase().includes(needle)),
  )
  const toggle = async (r: LoadedRule, on: boolean) => {
    const db = getDb()
    const disabled = new Set<string>(((await db.kv.get('disabledRules'))?.value as string[]) ?? [])
    if (on) disabled.delete(r.rule.id)
    else disabled.add(r.rule.id)
    await db.kv.put({ key: 'disabledRules', value: Array.from(disabled) })
    bump()
  }
  const togglePack = async (p: PackInfo, on: boolean) => {
    await setPackEnabled(p.id, on)
    if (!on && packFilter === p.id) setPackFilter('')
    toast('ok', on ? `${p.name}: ${fmtNum(p.counts.converted)} rules enabled` : `${p.name} disabled`)
    bump()
  }
  const save = async () => {
    if (!edit) return
    const { rules: parsed, errors } = parseRuleYaml(edit.yaml)
    if (errors.length || !parsed.length) return setEdit({ ...edit, error: errors.join('; ') || 'no rule found in the YAML' })
    const db = getDb()
    if (edit.id) await db.customRules.update(edit.id, { yaml: edit.yaml, ruleId: parsed[0].id, updatedAt: Date.now() })
    else await db.customRules.add({ caseId: null, ruleId: parsed[0].id, yaml: edit.yaml, enabled: true, updatedAt: Date.now() })
    toast('ok', `rule ${parsed[0].id} saved`)
    setEdit(null)
    bump()
  }
  const remove = async (r: LoadedRule) => {
    const id = Number(r.file.split(':')[1])
    if (!confirm(`Delete custom rule ${r.rule.id}?`)) return
    await getDb().customRules.delete(id)
    bump()
  }
  const askAi = async () => {
    if (!aiAsk.trim()) return
    if (useStore.getState().aiStatus.reachable !== true) return toast('err', 'the analyst model is not reachable (see the AI section in Settings)')
    setAiBusy(true)
    try {
      const msgs = await runAgent([{ role: 'user', content: `Write one rule for: ${aiAsk}` }], kase, { mode: 'rule', tools: false, think: false, maxIterations: 1 })
      const text = msgs.filter((m) => m.role === 'assistant').map((m) => m.content).join('\n')
      const y = text.replace(/^```(?:yaml)?\s*/m, '').replace(/```\s*$/m, '').trim()
      setEdit({ yaml: y })
    } catch (e) {
      toast('err', (e as Error).message)
    } finally {
      setAiBusy(false)
    }
  }
  const yamlOf = (r: LoadedRule) => r.yaml || ruleYaml(r.rule as unknown as Record<string, unknown>)
  const originLabel = (r: LoadedRule) => (r.origin === 'pack' ? (r.pack ?? 'pack') : r.origin)
  return (
    <div className="view">
      <div className="view-header">
        <h1>Rules</h1>
        <span className="sub">
          {loading ? 'loading… ' : null}
          {fmtNum(rules.filter((r) => r.enabled).length)}/{fmtNum(rules.length)} enabled
          {lastRun && (() => {
            const fired = Object.values(lastRun.byRule ?? {}).filter((n) => n > 0).length
            const noData = lastRun.diagnostics.filter((d) => d.reason === 'no_selector_match').length
            const needSet = lastRun.diagnostics.filter((d) => d.reason === 'missing_setting').length
            const notApp = lastRun.diagnostics.filter((d) => d.reason === 'not_applicable').length
            return ` · last run ${fmtTs(lastRun.ts)}: ${fired} fired, ${noData} without matching data${notApp ? `, ${notApp} not applicable to this evidence (their event ids or channels are absent)` : ''}${needSet ? `, ${needSet} need Settings` : ''}`
          })()}
        </span>
        <span className="spacer" />
        {lastRun && lastRun.diagnostics.some((d) => d.reason === 'missing_setting') && (
          <button className="btn sm" onClick={() => useStore.getState().setView('settings')} title="rules referencing empty settings lists are disarmed">⚠ configure Settings to arm {lastRun.diagnostics.filter((d) => d.reason === 'missing_setting').length} rule(s)</button>
        )}
        <RuleImport kind="sigma" />
        <RuleImport kind="sublime" />
        <button className="btn sm primary" onClick={() => setEdit({ yaml: TEMPLATE })}><IconPlus /> new rule</button>
      </div>
      {packs.length > 0 && (
        <div style={{ padding: '10px 16px', borderBottom: '1px solid var(--line)' }}>
          <div className="row" style={{ gap: 8, alignItems: 'baseline', marginBottom: 6 }}>
            <strong>Community packs</strong>
            <span className="small muted">converted one to one from the public collections; a pack is fetched once when it is on. Toggle a pack here, or single rules in the table below.</span>
          </div>
          <div className="row" style={{ gap: 10, flexWrap: 'wrap', alignItems: 'stretch' }}>
            {packs.map((p) => (
              <PackCard key={p.id} pack={p} on={packsOn.has(p.id)} busy={loading} selected={packFilter === p.id} onToggle={(v) => togglePack(p, v)} onShow={() => setPackFilter(packFilter === p.id ? '' : p.id)} />
            ))}
          </div>
        </div>
      )}
      <div className="row" style={{ padding: '8px 16px', borderBottom: '1px solid var(--line)', gap: 8 }}>
        <input className="input mono" placeholder="search id / title / tag / technique…" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 300 }} />
        <select className="select" value={source} onChange={(e) => setSource(e.target.value)}><option value="">events + mails</option><option value="events">events</option><option value="mails">mails</option></select>
        <select className="select" value={packFilter} onChange={(e) => setPackFilter(e.target.value)} title="origin">
          <option value="">all origins</option>
          <option value="core">built-in + custom</option>
          {packs.filter((p) => packsOn.has(p.id)).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
        <span className="small muted">{fmtNum(shown.length)} shown</span>
        <span className="spacer" />
        <input className="input" style={{ width: 380 }} placeholder="describe a detection and let the local model draft the YAML…" value={aiAsk} onChange={(e) => setAiAsk(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && askAi()} />
        <button className="btn sm" onClick={askAi} disabled={aiBusy}>{aiBusy ? <Spinner /> : <IconAi />} draft</button>
      </div>
      <div className="view-body">
        <table className="table">
          <thead><tr><th></th><th>id</th><th>title</th><th>src</th><th>severity</th><th>type</th><th>last run</th><th>att&amp;ck</th><th>origin</th><th></th></tr></thead>
          <tbody>
            {shown.slice(0, MAX_ROWS).map((r) => (
              <tr key={r.file + r.rule.id}>
                <td><Toggle on={r.enabled} onChange={(v) => toggle(r, v)} /></td>
                <td className="mono small">{r.rule.id}</td>
                <td>{r.rule.title}{r.error && <div className="small" style={{ color: 'var(--danger)' }}>{r.error}</div>}<div className="small muted">{r.rule.description}</div></td>
                <td>{r.rule.source}</td>
                <td><Badge sev={r.rule.severity}>{r.rule.severity}</Badge></td>
                <td className="small">{r.rule.group_by?.length ? `group ${r.rule.group_by.join('+')}${r.rule.window ? ` / ${r.rule.window}` : ''}${r.rule.threshold ? ` ${r.rule.threshold}` : ''}` : r.rule.time ? 'temporal' : 'match'}{r.rule.then ? ' → follow-up' : ''}</td>
                <td>{(() => {
                  if (!lastRun) return <span className="muted small">—</span>
                  const n = lastRun.byRule?.[r.rule.id]
                  if (n && n > 0) return <Badge sev="ok" title={`${n} finding(s) in the last run`}>{n}</Badge>
                  const d = lastRun.diagnostics.find((x) => x.ruleId === r.rule.id)
                  if (d) return <Badge sev={DIAG_LABEL[d.reason].sev} title={d.detail || `${d.matched} matched · ${d.afterExclude} after exclude · ${d.afterTime} after time filter`}>{DIAG_LABEL[d.reason].label}</Badge>
                  if (n === 0) return <span className="muted small">0</span>
                  return <span className="muted small">not run</span>
                })()}</td>
                <td className="small">{(r.rule.attack ?? []).join(' ')}</td>
                <td><Badge sev={r.origin === 'custom' ? 'accent' : 'info'} title={r.file}>{originLabel(r)}</Badge></td>
                <td className="row">
                  <button className="btn xs" onClick={() => setEdit({ id: r.origin === 'custom' ? Number(r.file.split(':')[1]) : undefined, yaml: yamlOf(r) })} title={r.origin === 'custom' ? 'edit' : 'copy as custom rule'}><IconEdit /></button>
                  {r.origin === 'custom' && <button className="btn xs danger" onClick={() => remove(r)}><IconTrash /></button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {shown.length > MAX_ROWS && <div className="hint" style={{ padding: 12 }}>showing the first {MAX_ROWS} of {fmtNum(shown.length)} rules — narrow with the search box, the source or the origin filter.</div>}
        {!loading && shown.length === 0 && <div className="hint" style={{ padding: 12 }}>no rule matches.</div>}
      </div>
      {edit && (
        <Modal title={edit.id ? 'Edit custom rule' : 'New custom rule'} onClose={() => setEdit(null)} wide footer={<><button className="btn" onClick={() => setEdit(null)}>cancel</button><button className="btn primary" onClick={save}>save</button></>}>
          <textarea className="textarea mono" style={{ minHeight: 360 }} value={edit.yaml} onChange={(e) => setEdit({ ...edit, yaml: e.target.value })} spellCheck={false} />
          {edit.error && <div className="small" style={{ color: 'var(--danger)' }}>{edit.error}</div>}
          <div className="hint">Operators: field|eq (default), ne, in, nin, contains, not_contains, contains_any, contains_all, startswith, not_startswith, endswith, not_endswith, re, not_re, gt, gte, lt, lte, exists, empty, in_setting, nin_setting, levenshtein, length ("&lt; 500"), contains_cs / startswith_cs / endswith_cs (case-sensitive). Groups: any_of / all_of / not. Aggregation: group_by, window, threshold, distinct, then, time, exclude. Custom rules with the same id override bundled and pack rules.</div>
        </Modal>
      )}
    </div>
  )
}
