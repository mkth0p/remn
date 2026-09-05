import { useEffect, useState } from 'react'
import { getTransport } from '../ai/transport'
import { getDb } from '../db/schema'
import type { Condition, Filter, Op } from '../rules/filter'
import { toast, useStore } from '../state/store'
import { Chip, Modal, Spinner } from './ui'
import { IconAi, IconClock, IconClose, IconFilter, IconSave, IconSearch } from './Icons'

const OPS: Op[] = ['eq', 'ne', 'in', 'nin', 'contains', 'not_contains', 'startswith', 'endswith', 're', 'gt', 'gte', 'lt', 'lte', 'exists', 'empty']

interface Props {
  source: 'events' | 'mails'
  filter: Filter
  onChange: (f: Filter) => void
  fields: string[]
  total?: number | null
  loading?: boolean
  facetsHint?: Record<string, string[]>
  /** extra controls rendered at the right end of the first row */
  extra?: React.ReactNode
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
function shortTs(v: string | number | null | undefined): string {
  const s = toLocalInput(v)
  return s ? s.replace('T', ' ') : '…'
}

/**
 * Query bar: one search field, then pills for the time range, conditions, business hours,
 * regex, saved searches and the plain-language query. Active pills carry their value;
 * the full state is also listed as removable chips below the bar.
 */
export function FilterBar({ source, filter, onChange, fields, total, loading, facetsHint, extra }: Props) {
  const kase = useStore((s) => s.currentCase)
  const [text, setText] = useState(filter.text ?? '')
  const [regex, setRegex] = useState(filter.regex?.pattern ?? '')
  const [regexField, setRegexField] = useState(filter.regex?.field ?? '*')
  const [showAdd, setShowAdd] = useState(false)
  const [showTime, setShowTime] = useState(false)
  const [showRegex, setShowRegex] = useState(Boolean(filter.regex?.pattern))
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
    if (filter.regex?.pattern) setShowRegex(true)
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
  const applyText = () => {
    const t = text.trim() || undefined
    if (t !== (filter.text || undefined)) onChange({ ...filter, text: t })
  }
  const applyRegex = () => {
    if (!regex.trim()) return filter.regex ? onChange({ ...filter, regex: undefined }) : undefined
    try {
      new RegExp(regex, 'i')
    } catch (e) {
      toast('err', `invalid regex: ${(e as Error).message}`)
      return
    }
    if (filter.regex?.pattern !== regex || filter.regex?.field !== regexField) onChange({ ...filter, regex: { field: regexField, pattern: regex, flags: 'i' } })
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
  const hasTime = Boolean(filter.timeRange?.from || filter.timeRange?.to)
  const hasAny = conds.length || hasTime || filter.regex?.pattern || filter.text || filter.hourRange
  const cls = (on: unknown) => 'pill' + (on ? ' active' : '')

  return (
    <div className="querybar">
      <div className="row wrap" style={{ gap: 6 }}>
        <div className="search">
          <IconSearch />
          <input data-query-search placeholder={source === 'events' ? 'search summary, users, IPs, command lines, raw…  (Enter)' : 'search subject, sender, recipients, body…  (Enter)'} value={text} onChange={(e) => setText(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && applyText()} onBlur={applyText} />
          {text && <button className="btn icon ghost xs" title="clear search" onClick={() => { setText(''); onChange({ ...filter, text: undefined }) }}><IconClose /></button>}
        </div>
        <button className={cls(hasTime)} onClick={() => setShowTime(!showTime)} title="time range (UTC)"><IconClock /> {hasTime ? `${shortTs(filter.timeRange?.from)} → ${shortTs(filter.timeRange?.to)}` : 'any time'}</button>
        <button className={cls(conds.length)} onClick={() => setShowAdd(true)} title="add a field condition"><IconFilter /> {conds.length ? `${conds.length} condition${conds.length === 1 ? '' : 's'}` : 'condition'}</button>
        <button className={cls(filter.hourRange)} onClick={() => onChange({ ...filter, hourRange: filter.hourRange ? undefined : { from: kase?.settings.businessHours.start ?? 8, to: kase?.settings.businessHours.end ?? 19, outside: true, tz: kase?.settings.businessHours.tz } })} title="only rows outside business hours (Settings)">outside hours</button>
        <button className={cls(filter.regex?.pattern)} onClick={() => setShowRegex(!showRegex)} title="regular expression on a field">regex</button>
        <button className={cls(ai)} onClick={() => setAi(!ai)} title="describe what you want in plain language; the local model builds the filter"><IconAi /> ask</button>
        {saved.length > 0 && (
          <label className="pill" title="saved searches">
            <select value="" onChange={(e) => { const s = saved.find((x) => String(x.id) === e.target.value); if (s) onChange(s.filter) }}>
              <option value="">saved ({saved.length})</option>
              {saved.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
          </label>
        )}
        {hasAny ? (
          <>
            <button className="btn icon ghost sm" onClick={() => setSaveName('')} title="save this search"><IconSave /></button>
            <button className="btn ghost sm" onClick={() => onChange({ sort: filter.sort })} title="clear every filter">clear</button>
          </>
        ) : null}
        <span className="spacer" />
        {extra}
        <span className="mono small dim nowrap" style={{ minWidth: 80, textAlign: 'right' }}>{loading ? <Spinner /> : total != null ? `${total.toLocaleString('en-US')} match${total === 1 ? '' : 'es'}` : ''}</span>
      </div>
      {showTime && (
        <div className="row wrap" style={{ gap: 6 }}>
          <input type="datetime-local" className="input mono" value={toLocalInput(filter.timeRange?.from)} onChange={(e) => onChange({ ...filter, timeRange: { ...filter.timeRange, from: fromLocalInput(e.target.value) } })} title="from (UTC)" />
          <span className="muted">to</span>
          <input type="datetime-local" className="input mono" value={toLocalInput(filter.timeRange?.to)} onChange={(e) => onChange({ ...filter, timeRange: { ...filter.timeRange, to: fromLocalInput(e.target.value) } })} title="to (UTC)" />
          <div className="segmented">
            <button onClick={() => preset(24)}>24h</button>
            <button onClick={() => preset(24 * 7)}>7d</button>
            <button onClick={() => preset(24 * 30)}>30d</button>
            <button onClick={() => onChange({ ...filter, timeRange: undefined })}>any</button>
          </div>
          <span className="hint">times are UTC · click a histogram bar to narrow to that bucket</span>
        </div>
      )}
      {showRegex && (
        <div className="row wrap" style={{ gap: 6 }}>
          <select className="select mono" value={regexField} onChange={(e) => setRegexField(e.target.value)} title="regex target field">
            <option value="*">any field (raw)</option>
            {fields.map((f) => <option key={f} value={f}>{f}</option>)}
          </select>
          <input className="input mono" style={{ flex: 1, minWidth: 240 }} placeholder="JavaScript regular expression, case-insensitive (Enter)" value={regex} onChange={(e) => setRegex(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && applyRegex()} onBlur={applyRegex} />
        </div>
      )}
      {ai && (
        <div className="row" style={{ gap: 8 }}>
          <input className="input" style={{ flex: 1 }} placeholder={source === 'events' ? 'e.g. failed logons on the admin account last night from outside the LAN' : 'e.g. mails with macro attachments from lookalike domains this week'} value={aiQ} onChange={(e) => setAiQ(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && runAi()} autoFocus />
          <button className="btn primary sm" disabled={aiBusy} onClick={runAi}>{aiBusy ? <Spinner /> : 'build filter'}</button>
          {aiExpl && <span className="small dim" style={{ maxWidth: 480 }}>{aiExpl}</span>}
        </div>
      )}
      {hasAny ? (
        <div className="row wrap" style={{ gap: 6 }}>
          {filter.logic === 'or' && conds.length > 1 && <span className="badge accent">OR</span>}
          {conds.map((c, i) => (
            <Chip key={i} neg={c.op.startsWith('n') || c.op === 'not_contains'} onRemove={() => setConds(conds.filter((_, j) => j !== i))} title="click × to remove">
              {c.field} <b>{c.op}</b> {c.value !== undefined && (Array.isArray(c.value) ? c.value.join(', ') : String(c.value))}
            </Chip>
          ))}
          {hasTime && (
            <Chip onRemove={() => onChange({ ...filter, timeRange: undefined })}>
              time {shortTs(filter.timeRange?.from)} → {shortTs(filter.timeRange?.to)}
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
      ) : null}
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
            <input className="input mono" style={{ flex: 1 }} placeholder={cond.op === 'in' || cond.op === 'nin' ? 'comma-separated values' : 'value'} value={String(cond.value ?? '')} onChange={(e) => setCond({ ...cond, value: e.target.value })} disabled={cond.op === 'exists' || cond.op === 'empty'} autoFocus={false} onKeyDown={(e) => { if (e.key === 'Enter') (e.currentTarget.closest('.modal')?.querySelector('.btn.primary') as HTMLButtonElement | null)?.click() }} />
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
