import { useCallback, useEffect, useMemo, useState } from 'react'
import { Facets, type FacetDef } from '../components/Facets'
import { FilterBar } from '../components/FilterBar'
import { VirtualTable, type Column } from '../components/VirtualTable'
import { MailDetail } from '../components/Detail'
import { getSource } from '../data/source'
import type { MailRow } from '../db/schema'
import type { Condition, Filter } from '../rules/filter'
import { useStore } from '../state/store'
import { fmtTs } from '../util/format'
import { exportCsv, exportJson } from '../util/export'
import { BaselineButton } from '../components/BaselineButton'
import { Flag, Risk } from '../components/ui'

const FACETS: FacetDef[] = [
  { field: 'riskBand', label: 'Risk', open: true },
  { field: 'flags', label: 'Flags', open: true },
  { field: 'fromDomain', label: 'Sender domain' },
  { field: 'fromAddr', label: 'Sender address' },
  { field: 'fromNameNorm', label: 'Display name' },
  { field: 'originIp', label: 'Origin IP' },
  { field: 'folder', label: 'Folder' },
  { field: 'attExt', label: 'Attachment type' },
  { field: 'sourceFormat', label: 'Source format' },
  { field: 'sourceName', label: 'Source file' },
]
const FIELDS = ['subject', 'fromName', 'fromNameNorm', 'fromAddr', 'fromDomain', 'fromRegistrable', 'replyTo.addr', 'returnPath', 'to.addr', 'originIp', 'originHelo', 'hopCount', 'messageId', 'xMailer', 'risk', 'flags', 'folder', 'sourceName', 'urlCount', 'attachmentCount', 'maxAttachmentRisk', 'attachments.name', 'attachments.realExt', 'attachments.sha256', 'attachments.flags', 'urls.host', 'urls.domain', 'urls.flags', 'auth.spf', 'auth.dkim', 'auth.dmarc', 'textPreview', 'bodyText', 'sourceFormat', 'reputation.worst']
const LIMIT = 3000

export function MailsView() {
  const kase = useStore((s) => s.currentCase)
  const filter = useStore((s) => s.mailsFilter)
  const setFilter = useStore((s) => s.setMailsFilter)
  const focus = useStore((s) => s.focusId)
  const setFocus = useStore((s) => s.setFocus)
  const jobs = useStore((s) => s.jobs)
  const [rows, setRows] = useState<MailRow[]>([])
  const [truncated, setTruncated] = useState(false)
  const [total, setTotal] = useState<number | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<MailRow | null>(null)
  const [version, setVersion] = useState(0)
  const ds = useMemo(() => (kase ? getSource(kase) : null), [kase])
  useEffect(() => {
    if (jobs.every((j) => j.phase === 'done' || j.phase === 'error')) setVersion((v) => v + 1)
  }, [jobs])
  useEffect(() => {
    if (!ds) return
    let alive = true
    setLoading(true)
    setError(null)
    ds.searchMails(filter, LIMIT)
      .then((r) => {
        if (!alive) return
        setRows(r.rows)
        setTruncated(r.truncated)
      })
      .catch((e) => alive && setError((e as Error).message))
      .finally(() => alive && setLoading(false))
    setTotal(null)
    ds.countMails(filter).then((n) => alive && setTotal(n)).catch(() => undefined)
    return () => {
      alive = false
    }
  }, [ds, filter, version])
  useEffect(() => {
    if (focus?.source === 'mails' && ds) {
      ds.getMail(focus.id).then((r) => r && setSelected(r.row))
      setFocus(null)
    }
  }, [focus, setFocus, ds])
  const toggleFacet = useCallback(
    (field: string, value: string, negate?: boolean) => {
      setFilter((prev: Filter) => {
        const conds = prev.conditions ?? []
        const f = field === 'riskBand' ? 'risk' : field === 'attExt' ? 'attachments.realExt' : field
        let cond: Condition
        if (field === 'riskBand') {
          const ranges: Record<string, [number, number]> = { critical: [80, 101], high: [60, 80], medium: [40, 60], low: [20, 40], clean: [0, 20] }
          const [lo] = ranges[value] ?? [0, 101]
          cond = { field: 'risk', op: negate ? 'lt' : 'gte', value: lo }
          const hiCond: Condition | null = ranges[value] && ranges[value][1] <= 100 ? { field: 'risk', op: 'lt', value: ranges[value][1] } : null
          const exists = conds.some((c) => c.field === 'risk' && c.op === cond.op && c.value === cond.value)
          if (exists) return { ...prev, conditions: conds.filter((c) => c.field !== 'risk') }
          return { ...prev, conditions: [...conds.filter((c) => c.field !== 'risk'), cond, ...(hiCond && !negate ? [hiCond] : [])] }
        }
        const op = field === 'flags' ? (negate ? 'not_contains' : 'contains') : negate ? 'ne' : 'eq'
        cond = { field: f, op, value }
        const idx = conds.findIndex((c) => c.field === f && c.op === op && String(c.value).toLowerCase() === value.toLowerCase())
        if (idx >= 0) return { ...prev, conditions: conds.filter((_, i) => i !== idx) }
        return { ...prev, conditions: [...conds, cond] }
      })
    },
    [setFilter],
  )
  const columns: Column<MailRow>[] = useMemo(
    () => [
      { key: 'date', label: 'date (UTC)', width: 150, render: (r) => fmtTs(r.date) },
      { key: 'risk', label: 'risk', width: 60, render: (r) => <Risk value={r.risk} /> },
      { key: 'fromAddr', label: 'from', width: 260, click: (r) => toggleFacet('fromAddr', r.fromAddr), render: (r) => (r.fromName ? `${r.fromName} <${r.fromAddr}>` : r.fromAddr), title: (r) => `${r.fromName} <${r.fromAddr}>` },
      { key: 'subject', label: 'subject', width: 'minmax(240px, 1fr)' },
      { key: 'flags', label: 'flags', width: 'minmax(220px, 1.2fr)', render: (r) => <span className="row" style={{ gap: 3, overflow: 'hidden' }}>{(r.flags ?? []).filter((f) => !/^(spf_none|dkim_none|dmarc_none|html_only|from_webmail|single_hop|no_origin_ip)$/.test(f)).slice(0, 6).map((f) => <Flag key={f} name={f} />)}{(r.flags ?? []).length > 6 ? <span className="muted">+{r.flags.length - 6}</span> : null}</span> },
      { key: 'attachmentCount', label: 'att', width: 50, render: (r) => (r.attachmentCount ? `${r.attachmentCount}${r.maxAttachmentRisk >= 60 ? ' ⚠' : ''}` : '') },
      { key: 'originIp', label: 'origin ip', width: 120, click: (r) => toggleFacet('originIp', String(r.originIp)) },
      { key: 'folder', label: 'folder', width: 120 },
    ],
    [toggleFacet],
  )
  if (!kase || !ds) return null
  const sort = filter.sort ?? { field: 'date', dir: 'desc' as const }
  return (
    <div className="view">
      <div className="split">
        <div className="left">
          <div className="panel-h">facets <span className="muted">({ds.kind === 'server' ? 'server store' : 'global'})</span></div>
          <Facets ds={ds} source="mails" fields={FACETS} conditions={filter.conditions ?? []} onToggle={toggleFacet} version={version} />
        </div>
        <div className="right relative">
          <FilterBar source="mails" filter={filter} onChange={setFilter} fields={FIELDS} total={total} loading={loading} />
          <div className="row small dim" style={{ padding: '4px 14px', gap: 12 }}>
            <span className="mono">{rows.length.toLocaleString('en-US')} row(s) loaded{truncated ? ` (first ${LIMIT})` : ''}</span>
            {error && <span style={{ color: 'var(--danger)' }}>{error}</span>}
            <span className="spacer" />
            <button className="btn xs ghost" onClick={() => exportCsv('mails.csv', rows.map((r) => ({ id: r.id, date: r.dateIso, risk: r.risk, from: r.fromAddr, fromName: r.fromName, subject: r.subject, to: (r.to ?? []).map((t) => t.addr).join(';'), replyTo: (r.replyTo ?? []).map((t) => t.addr).join(';'), originIp: r.originIp, spf: r.auth?.spf, dkim: r.auth?.dkim, dmarc: r.auth?.dmarc, flags: (r.flags ?? []).join(' '), attachments: (r.attachments ?? []).map((a) => `${a.name}(${a.risk})`).join(';'), hashes: (r.attachments ?? []).map((a) => a.sha256).join(';'), urls: (r.urls ?? []).map((u) => u.defanged).join(' '), folder: r.folder, source: r.sourceName })))}>csv</button>
            <button className="btn xs ghost" onClick={() => exportJson('mails.json', rows)}>json</button>
            <BaselineButton />
            <span className="hint">alt+click a facet to exclude · click a sender to filter</span>
          </div>
          <VirtualTable
            rows={rows}
            columns={columns}
            rowKey={(r) => r.id!}
            onRowClick={setSelected}
            selectedKey={selected?.id ?? null}
            sort={sort}
            onSort={(field) => setFilter({ ...filter, sort: { field, dir: sort.field === field && sort.dir === 'desc' ? 'asc' : 'desc' } })}
            rowClass={(r) => (r.risk >= 80 ? 'sev-critical' : r.risk >= 60 ? 'sev-high' : r.risk >= 40 ? 'sev-medium' : undefined)}
            empty={loading ? 'loading…' : 'no mails match - load a mailbox in Evidence or relax the filter'}
          />
          {selected && <MailDetail row={selected} onClose={() => setSelected(null)} />}
        </div>
      </div>
    </div>
  )
}
