import { useEffect, useState } from 'react'
import { getTransport } from '../ai/transport'
import { getDb } from '../db/schema'
import type { Condition, Filter, Op } from '../rules/filter'
import { toast, useStore } from '../state/store'
import { Chip, Modal, Spinner } from './ui'
import { IconAi, IconClose, IconSave, IconSearch } from './Icons'

const OPS: Op[] = ['eq', 'ne', 'in', 'nin', 'contains', 'not_contains', 'startswith', 'endswith', 're', 'gt', 'gte', 'lt', 'lte', 'exists', 'empty']

interface Props {
  source: 'events' | 'mails'
  filter: Filter
  onChange: (f: Filter) => void
  fields: string[]
  total?: number | null
  loading?: boolean
  facetsHint?: Record<string, string[]>
}

function toLocalInput(v: string | number | null | undefined): string {
  if (v == null || v === '') return ''
  const d = new Date(v)
  if (Number.isNaN(d.getTime())) return ''
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`
}
function fromLocalInput(s: string): string | undefined {
  if (!s) return undefined
  return s.length === 16 ? s + ':00Z' : s + 'Z'
}

export function FilterBar({ source, filter, onChange, fields, total, loading, facetsHint }: Props) {
  const kase = useStore((s) => s.currentCase)
  const [text, setText] = useState(filter.text ?? '')
  const [regex, setRegex] = useState(filter.regex?.pattern ?? '')
  const [regexField, setRegexField] = useState(filter.regex?.field ?? '*')
  const [showAdd, setShowAdd] = useState(false)
  const [cond, setCond] = useState<Condition>({ field: fields[0] ?? '', op: 'eq', value: '' })
  const [ai, setAi] = useState(false)
  const [aiQ, setAiQ] = useState('')
  const [aiBusy, setAiBusy] = useState(false)
  const [aiExpl, setAiExpl] = useState<string | null>(null)
  const [saveName, setSaveName] = useState<string | null>(null)
  const [saved, setSaved] = useState<{ id: number; name: string; filter: Filter }[]>([])
  useEffect(() => setText(filter.text ?? ''), [filter.text])
  useEffect(() => {
    setRegex(filter.regex?.pattern ?? '')
    setRegexField(filter.regex?.field ?? '*')
  }, [filter.regex])
  useEffect(() => {
    if (!kase?.id) return
    getDb()
      .savedSearches.where('caseId')
      .equals(kase.id)
      .filter((s) => s.source === source)
      .toArray()
      .then((s) => setSaved(s.map((x) => ({ id: x.id!, name: x.name, filter: x.filter as Filter }))))
  }, [kase?.id, source, saveName])

  const conds = filter.conditions ?? []
  const setConds = (c: Condition[]) => onChange({ ...filter, conditions: c })
  const applyText = () => onChange({ ...filter, text: text.trim() || undefined })
  const applyRegex = () => {
    if (!regex.trim()) return onChange({ ...filter, regex: undefined })
    try {
      new RegExp(regex, 'i')
    } catch (e) {
      toast('err', `invalid regex: ${(e as Error).message}`)
      return
    }
    onChange({ ...filter, regex: { field: regexField, pattern: regex, flags: 'i' } })
  }
  const preset = (hours: number) => {
    const to = Date.now()
    onChange({ ...filter, timeRange: { from: new Date(to - hours * 3600_000).toISOString(), to: new Date(to).toISOString() } })
  }
  const runAi = async () => {
    if (!aiQ.trim()) return
    setAiBusy(true)
    setAiExpl(null)
    try {
      const facets = facetsHint ?? {}
      const res = await getTransport().queryJson(aiQ, { now: new Date().toISOString(), source, businessHours: kase?.settings.businessHours, facets })
      const q = res.query as { source?: string; filter?: Filter; explanation?: string } | null
      if (!q?.filter) {
        toast('err', 'the model did not return a usable filter')
        setAiExpl(res.raw?.slice(0, 500) ?? null)
        return
      }
      setAiExpl(q.explanation ?? null)
      const f = q.filter
      onChange({ conditions: (f.conditions ?? []).filter((c) => c.field && c.op), logic: f.logic, timeRange: f.timeRange, hourRange: f.hourRange, regex: f.regex?.pattern ? f.regex : undefined, text: f.text || undefined, sort: filter.sort })
      if (q.source && q.source !== source) toast('warn', `the model suggested the "${q.source}" view for this question`)
    } catch (e) {
      toast('err', `AI query failed: ${(e as Error).message}`)
    } finally {
      setAiBusy(false)
    }
  }
  const save = async () => {
    if (!kase?.id || !saveName?.trim()) return
    await getDb().savedSearches.add({ caseId: kase.id, name: saveName.trim(), source, filter: filter as Record<string, unknown>, createdAt: Date.now() })
    toast('ok', 'search saved')
    setSaveName(null)
  }
  const hasAny = conds.length || filter.timeRange?.from || filter.timeRange?.to || filter.regex?.pattern || filter.text || filter.hourRange

  return (
    <div className="col" style={{ padding: '10px 14px', borderBottom: '1px solid var(--line)', background: 'var(--bg-1)', gap: 8 }}>
      <div className="row wrap">
        <div className="row" style={{ flex: 1, minWidth: 220 }}>
          <IconSearch style={{ color: 'var(--fg-3)' }} />
          <input className="input mono" style={{ flex: 1 }} placeholder="full-text search (summary, users, IPs, command lines, raw…)" value={text} onChange={(e) => setText(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && applyText()} onBlur={applyText} />
        </div>
        <div className="row" style={{ minWidth: 300 }}>
          <select className="select mono" value={regexField} onChange={(e) => setRegexField(e.target.value)} title="regex target field">
            <option value="*">/ any (raw) /</option>
            {fields.map((f) => (
              <option key={f} value={f}>
                {f}
              </option>
            ))}
          </select>
          <input className="input mono" style={{ flex: 1 }} placeholder="regex (JS syntax, case-insensitive)" value={regex} onChange={(e) => setRegex(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && applyRegex()} onBlur={applyRegex} />
        </div>
        <div className="row">
          <input type="datetime-local" className="input mono" value={toLocalInput(filter.timeRange?.from)} onChange={(e) => onChange({ ...filter, timeRange: { ...filter.timeRange, from: fromLocalInput(e.target.value) } })} title="from (UTC)" />
          <span className="muted">→</span>
          <input type="datetime-local" className="input mono" value={toLocalInput(filter.timeRange?.to)} onChange={(e) => onChange({ ...filter, timeRange: { ...filter.timeRange, to: fromLocalInput(e.target.value) } })} title="to (UTC)" />
          <button className="btn sm ghost" onClick={() => preset(24)}>24h</button>
          <button className="btn sm ghost" onClick={() => preset(24 * 7)}>7d</button>
          <button className="btn sm ghost" onClick={() => preset(24 * 30)}>30d</button>
        </div>
        <button className="btn sm" onClick={() => setShowAdd(true)}>+ condition</button>
        <button className="btn sm" onClick={() => onChange({ ...filter, hourRange: filter.hourRange ? undefined : { from: kase?.settings.businessHours.start ?? 8, to: kase?.settings.businessHours.end ?? 19, outside: true, tz: kase?.settings.businessHours.tz } })} title="only rows outside business hours (Settings)">
          {filter.hourRange ? '✓ ' : ''}outside hours
        </button>
        <button className="btn sm primary" onClick={() => setAi(!ai)} title="describe what you want in plain language; the local model builds the filter">
          <IconAi /> ask
        </button>
        {saved.length > 0 && (
          <select className="select" value="" onChange={(e) => { const s = saved.find((x) => String(x.id) === e.target.value); if (s) onChange(s.filter) }}>
            <option value="">saved searches…</option>
            {saved.map((s) => (
              <option key={s.id} value={s.id}>{s.name}</option>
            ))}
          </select>
        )}
        {hasAny && (
          <>
            <button className="btn sm ghost" onClick={() => setSaveName('')} title="save this search"><IconSave /></button>
            <button className="btn sm ghost" onClick={() => onChange({ sort: filter.sort })} title="clear all"><IconClose /> clear</button>
          </>
        )}
        <span className="mono small dim nowrap">{loading ? <Spinner /> : total != null ? `${total.toLocaleString('en-US')} match${total === 1 ? '' : 'es'}` : ''}</span>
      </div>
      {ai && (
        <div className="row" style={{ gap: 8 }}>
          <input className="input" style={{ flex: 1 }} placeholder={source === 'events' ? 'e.g. failed logons on the admin account last night from outside the LAN' : 'e.g. mails with macro attachments from lookalike domains this week'} value={aiQ} onChange={(e) => setAiQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && runAi()} autoFocus />
          <button className="btn primary sm" disabled={aiBusy} onClick={runAi}>{aiBusy ? <Spinner /> : 'build filter'}</button>
          {aiExpl && <span className="small dim" style={{ maxWidth: 480 }}>{aiExpl}</span>}
        </div>
      )}
      {hasAny && (
        <div className="row wrap" style={{ gap: 6 }}>
          {filter.logic === 'or' && conds.length > 1 && <span className="badge accent">OR</span>}
          {conds.map((c, i) => (
            <Chip key={i} neg={c.op.startsWith('n') || c.op === 'not_contains'} onRemove={() => setConds(conds.filter((_, j) => j !== i))} title="click × to remove">
              {c.field} <b>{c.op}</b> {c.value !== undefined && (Array.isArray(c.value) ? c.value.join(', ') : String(c.value))}
            </Chip>
          ))}
          {(filter.timeRange?.from || filter.timeRange?.to) && (
            <Chip onRemove={() => onChange({ ...filter, timeRange: undefined })}>
              time {filter.timeRange?.from ? toLocalInput(filter.timeRange.from) : '…'} → {filter.timeRange?.to ? toLocalInput(filter.timeRange.to) : '…'}
            </Chip>
          )}
          {filter.hourRange && <Chip onRemove={() => onChange({ ...filter, hourRange: undefined })}>{filter.hourRange.outside ? 'outside' : 'within'} {filter.hourRange.from}h–{filter.hourRange.to}h</Chip>}
          {filter.regex?.pattern && <Chip onRemove={() => onChange({ ...filter, regex: undefined })}>/{filter.regex.pattern}/ on {filter.regex.field || '*'}</Chip>}
          {filter.text && <Chip onRemove={() => onChange({ ...filter, text: undefined })}>"{filter.text}"</Chip>}
          {conds.length > 1 && (
            <button className="btn xs ghost" onClick={() => onChange({ ...filter, logic: filter.logic === 'or' ? 'and' : 'or' })}>
              logic: {filter.logic === 'or' ? 'OR' : 'AND'}
            </button>
          )}
        </div>
      )}
      {showAdd && (
        <Modal title="Add condition" onClose={() => setShowAdd(false)} footer={<><button className="btn" onClick={() => setShowAdd(false)}>cancel</button><button className="btn primary" onClick={() => { if (!cond.field) return; let v: unknown = cond.value; if (cond.op === 'in' || cond.op === 'nin') v = String(v).split(',').map((s) => s.trim()).filter(Boolean); else if (typeof v === 'string' && /^-?\d+$/.test(v) && ['eq', 'ne', 'gt', 'gte', 'lt', 'lte'].includes(cond.op)) v = Number(v); if (cond.op === 'exists' || cond.op === 'empty') v = undefined; setConds([...conds, { ...cond, value: v }]); setShowAdd(false) }}>add</button></>}>
          <div className="row">
            <select className="select mono" value={cond.field} onChange={(e) => setCond({ ...cond, field: e.target.value })}>
              {fields.map((f) => (
                <option key={f} value={f}>{f}</option>
              ))}
            </select>
            <select className="select mono" value={cond.op} onChange={(e) => setCond({ ...cond, op: e.target.value as Op })}>
              {OPS.map((o) => (
                <option key={o} value={o}>{o}</option>
              ))}
            </select>
            <input className="input mono" style={{ flex: 1 }} placeholder={cond.op === 'in' || cond.op === 'nin' ? 'comma-separated values' : 'value'} value={String(cond.value ?? '')} onChange={(e) => setCond({ ...cond, value: e.target.value })} disabled={cond.op === 'exists' || cond.op === 'empty'} />
          </div>
          <div className="hint">Strings compare case-insensitively. Dotted paths reach nested values (attachments.flags, data.LogonType). "re" takes a JavaScript regular expression.</div>
        </Modal>
      )}
      {saveName !== null && (
        <Modal title="Save search" onClose={() => setSaveName(null)} footer={<button className="btn primary" onClick={save}>save</button>}>
          <input className="input" autoFocus placeholder="name" value={saveName} onChange={(e) => setSaveName(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && save()} />
        </Modal>
      )}
    </div>
  )
}
