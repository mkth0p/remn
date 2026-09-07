import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Facets, type FacetDef } from '../components/Facets'
import { FilterBar } from '../components/FilterBar'
import { TimeHistogram } from '../components/TimeHistogram'
import { VirtualTable, type Column } from '../components/VirtualTable'
import { MailDetail } from '../components/Detail'
import { getSource } from '../data/source'
import type { MailRow } from '../db/schema'
import type { Condition, Filter } from '../rules/filter'
import { useStore } from '../state/store'
import { fmtTs } from '../util/format'
import { exportCsv, exportJson } from '../util/export'
import { BaselineButton } from '../components/BaselineButton'
import { RescoreButton } from '../components/RescoreButton'
import { Dot, Flag } from '../components/ui'
import { IconMore, IconPaperclip } from '../components/Icons'

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
const FIELDS = [
  'subject',
  'fromName',
  'fromNameNorm',
  'fromAddr',
  'fromDomain',
  'fromRegistrable',
  'replyTo.addr',
  'returnPath',
  'to.addr',
  'originIp',
  'originHelo',
  'hopCount',
  'messageId',
  'xMailer',
  'risk',
  'flags',
  'folder',
  'sourceName',
  'urlCount',
  'attachmentCount',
  'maxAttachmentRisk',
  'attachments.name',
  'attachments.realExt',
  'attachments.sha256',
  'attachments.flags',
  'urls.host',
  'urls.domain',
  'urls.flags',
  'auth.spf',
  'auth.dkim',
  'auth.dmarc',
  'textPreview',
  'bodyText',
  'sourceFormat',
  'reputation.worst',
]
const LIMIT = 3000
const QUIET_FLAGS = /^(spf_none|dkim_none|dmarc_none|html_only|from_webmail|single_hop|no_origin_ip)$/

export const riskSev = (risk: number) => (risk >= 80 ? 'critical' : risk >= 60 ? 'high' : risk >= 40 ? 'medium' : risk >= 20 ? 'low' : 'info')

/**
 * Mails: query bar, histogram of the result set, dense table, and a bottom preview pane
 * (message on the left, evidence context on the right). j / k move the selection.
 */
export function MailsView() {
  const kase = useStore((s) => s.currentCase)
  const filter = useStore((s) => s.mailsFilter)
  const setFilter = useStore((s) => s.setMailsFilter)
  const focus = useStore((s) => s.focusId)
  const setFocus = useStore((s) => s.setFocus)
  const jobs = useStore((s) => s.jobs)
  const rulesVersion = useStore((s) => s.rulesVersion)
  const [rows, setRows] = useState<MailRow[]>([])
  const [truncated, setTruncated] = useState(false)
  const [total, setTotal] = useState<number | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [selected, setSelected] = useState<MailRow | null>(null)
  const [version, setVersion] = useState(0)
  const [menu, setMenu] = useState(false)
  // bottom pane height (% of the page), remembered per browser; the grip above the pane drags it
  const [paneH, setPaneH] = useState(() => {
    try {
      return Number(localStorage.getItem('remn-mail-pane')) || 55
    } catch {
      return 55
    }
  })
  const [paneMax, setPaneMax] = useState(false)
  const rightRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    try {
      localStorage.setItem('remn-mail-pane', String(paneH))
    } catch {
      /* private mode */
    }
  }, [paneH])
  const startDrag = (e: React.PointerEvent) => {
    const el = rightRef.current
    if (!el) return
    e.preventDefault()
    const rect = el.getBoundingClientRect()
    const move = (ev: PointerEvent) => setPaneH(Math.min(92, Math.max(20, Math.round(((rect.bottom - ev.clientY) / rect.height) * 100))))
    const up = () => {
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', up)
    }
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
    setPaneMax(false)
  }
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
    ds.countMails(filter)
      .then((n) => alive && setTotal(n))
      .catch(() => undefined)
    return () => {
      alive = false
    }
  }, [ds, filter, version, rulesVersion])
  const selectedId = selected?.id
  useEffect(() => {
    let alive = true
    if (selectedId != null && ds)
      ds.getMail(selectedId)
        .then((r) => {
          if (alive) setSelected(r?.row ?? null)
        })
        .catch(() => {
          if (alive) setSelected(null)
        })
    return () => {
      alive = false
    }
  }, [ds, selectedId, version, rulesVersion])
  useEffect(() => {
    setSelected(null)
  }, [kase?.id])
  useEffect(() => {
    if (focus?.source === 'mails' && ds) {
      ds.getMail(focus.id).then((r) => r && setSelected(r.row))
      setFocus(null)
    }
  }, [focus, setFocus, ds])
  // keyboard: j / k move the selection, Escape closes the pane, / focuses the search
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null
      if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable)) return
      if (e.key === '/') {
        e.preventDefault()
        ;(document.querySelector('[data-query-search]') as HTMLInputElement | null)?.focus()
        return
      }
      if (e.key === 'Escape') return useStore.getState().entity ? undefined : setSelected(null)
      if ((e.key === 'j' || e.key === 'k') && rows.length) {
        const i = selected ? rows.findIndex((r) => r.id === selected.id) : -1
        const next = e.key === 'j' ? Math.min(rows.length - 1, i + 1) : Math.max(0, i - 1)
        setSelected(rows[next])
      }
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [rows, selected])
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
      { key: 'date', label: 'date (UTC)', width: 138, render: (r) => fmtTs(r.date) },
      {
        key: 'risk',
        label: 'risk',
        width: 62,
        render: (r) => (
          <span className="row" style={{ gap: 6 }}>
            <Dot sev={riskSev(r.risk)} />
            <span className="mono">{r.risk}</span>
          </span>
        ),
      },
      {
        key: 'fromAddr',
        label: 'from',
        width: 'minmax(180px, 0.9fr)',
        click: (r) => toggleFacet('fromAddr', r.fromAddr),
        title: (r) => `${r.fromName} <${r.fromAddr}>`,
        render: (r) =>
          r.fromName ? (
            <span>
              <span style={{ color: 'var(--fg-1)' }}>{r.fromName}</span> <span className="muted">{r.fromAddr}</span>
            </span>
          ) : (
            r.fromAddr
          ),
      },
      {
        key: 'to',
        label: 'to',
        width: 'minmax(120px, 0.6fr)',
        render: (r) => {
          const t = r.to ?? []
          return t.length ? (
            <span title={t.map((x) => x.addr).join(', ')}>
              {t[0].addr || t[0].name}
              {t.length > 1 ? <span className="muted"> +{t.length - 1}</span> : null}
            </span>
          ) : (
            <span className="muted">(undisclosed)</span>
          )
        },
      },
      { key: 'subject', label: 'subject', width: 'minmax(220px, 1.4fr)', render: (r) => <span style={{ color: 'var(--fg-1)' }}>{r.subject || <span className="muted">(no subject)</span>}</span> },
      {
        key: 'attachmentCount',
        label: '',
        width: 44,
        render: (r) =>
          r.attachmentCount ? (
            <span
              className="row"
              style={{ gap: 3, color: r.maxAttachmentRisk >= 60 ? 'var(--sev-high)' : 'var(--fg-2)' }}
              title={`${r.attachmentCount} attachment(s), max risk ${r.maxAttachmentRisk}`}
            >
              <IconPaperclip />
              {r.attachmentCount}
            </span>
          ) : null,
      },
      {
        key: 'flags',
        label: 'flags',
        width: 'minmax(180px, 1fr)',
        render: (r) => {
          const fl = (r.flags ?? []).filter((f) => !QUIET_FLAGS.test(f))
          return (
            <span className="row" style={{ gap: 3, overflow: 'hidden' }}>
              {fl.slice(0, 4).map((f) => (
                <Flag key={f} name={f} />
              ))}
              {fl.length > 4 ? <span className="muted">+{fl.length - 4}</span> : null}
            </span>
          )
        },
      },
      {
        key: 'sourceName',
        label: 'source',
        width: 130,
        title: (r) => `${r.sourceName ?? ''} · ${r.folder ?? ''}`,
        render: (r) => (
          <span className="muted">
            {(r.sourceName ?? '').replace(/^.*[\\/]/, '') || r.sourceFormat}
            {r.folder ? ` / ${r.folder}` : ''}
          </span>
        ),
      },
    ],
    [toggleFacet],
  )
  if (!kase || !ds) return null
  const sort = filter.sort ?? { field: 'date', dir: 'desc' as const }
  const exportCsvRows = () =>
    exportCsv(
      'mails.csv',
      rows.map((r) => ({
        id: r.id,
        date: r.dateIso,
        risk: r.risk,
        from: r.fromAddr,
        fromName: r.fromName,
        subject: r.subject,
        to: (r.to ?? []).map((t) => t.addr).join(';'),
        replyTo: (r.replyTo ?? []).map((t) => t.addr).join(';'),
        originIp: r.originIp,
        spf: r.auth?.spf,
        dkim: r.auth?.dkim,
        dmarc: r.auth?.dmarc,
        flags: (r.flags ?? []).join(' '),
        attachments: (r.attachments ?? []).map((a) => `${a.name}(${a.risk})`).join(';'),
        hashes: (r.attachments ?? []).map((a) => a.sha256).join(';'),
        urls: (r.urls ?? []).map((u) => u.defanged).join(' '),
        folder: r.folder,
        source: r.sourceName,
      })),
    )
  return (
    <div className="view">
      <div className="split">
        <div className="left">
          <div className="panel-h">
            Filters <span className="muted">({ds.kind === 'server' ? 'server store' : 'browser store'})</span>
          </div>
          <Facets ds={ds} source="mails" fields={FACETS} conditions={filter.conditions ?? []} onToggle={toggleFacet} version={version + rulesVersion} />
        </div>
        <div className="right relative" ref={rightRef}>
          <FilterBar
            source="mails"
            filter={filter}
            onChange={setFilter}
            fields={FIELDS}
            total={total}
            loading={loading}
            extra={
              <span className="row relative" style={{ gap: 4 }}>
                <BaselineButton />
                <RescoreButton key={kase?.id} />
                <button className="btn icon ghost sm" title="export" onClick={() => setMenu(!menu)}>
                  <IconMore />
                </button>
                {menu && (
                  <div className="menu" style={{ position: 'absolute', right: 0, top: '100%', zIndex: 25 }} onMouseLeave={() => setMenu(false)}>
                    <button
                      className="btn ghost sm"
                      onClick={() => {
                        exportCsvRows()
                        setMenu(false)
                      }}
                    >
                      export CSV ({rows.length})
                    </button>
                    <button
                      className="btn ghost sm"
                      onClick={() => {
                        exportJson('mails.json', rows)
                        setMenu(false)
                      }}
                    >
                      export JSON ({rows.length})
                    </button>
                  </div>
                )}
              </span>
            }
          />
          {!paneMax && (
            <TimeHistogram
              ds={ds}
              source="mails"
              filter={filter}
              version={version + rulesVersion}
              onRange={(from, to) => setFilter({ ...filter, timeRange: { from: new Date(from).toISOString(), to: new Date(to).toISOString() } })}
            />
          )}
          {!paneMax && (truncated || error) && (
            <div className="row small dim" style={{ padding: '3px 16px', gap: 12, borderBottom: '1px solid var(--line)' }}>
              {truncated && <span className="mono">showing the first {LIMIT.toLocaleString('en-US')} rows - narrow the filter or change the sort</span>}
              {error && <span style={{ color: 'var(--danger)' }}>{error}</span>}
            </div>
          )}
          {!paneMax && (
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
          )}
          {selected && !paneMax && (
            <div
              className="pane-grip"
              onPointerDown={startDrag}
              onDoubleClick={() => {
                setPaneH(55)
                setPaneMax(false)
              }}
              title="drag to resize the message pane · double-click to reset"
            />
          )}
          {selected && <MailDetail row={selected} onClose={() => setSelected(null)} layout="pane" paneHeight={`${paneMax ? 94 : paneH}%`} paneMax={paneMax} onPaneMax={setPaneMax} />}
        </div>
      </div>
    </div>
  )
}
