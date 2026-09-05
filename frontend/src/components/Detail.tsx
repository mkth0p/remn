import DOMPurify from 'dompurify'
import { Fragment, useEffect, useMemo, useState } from 'react'
import { getDb, type EventRow, type Finding, type MailBody, type MailRow } from '../db/schema'
import { getSource } from '../data/source'
import type { Condition, Filter } from '../rules/filter'
import { useStore } from '../state/store'
import { fmtBytes, fmtTs } from '../util/format'
import { IconAi, IconClose, IconPivot } from './Icons'
import { Badge, CopyButton, Dot, Flag, JsonView, KV, Risk, Sev, Tabs } from './ui'
import { AddToTimeline } from './AddToTimeline'

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']

const HIDE = new Set(['id', 'caseId', 'evidenceId', 'data', 'raw', 'summary', 'type'])

export function Drawer({ title, onClose, children, actions }: { title: React.ReactNode; onClose: () => void; children: React.ReactNode; actions?: React.ReactNode }) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [onClose])
  return (
    <div className="drawer">
      <div className="drawer-h">
        <div style={{ flex: 1, minWidth: 0 }} className="ellipsis">{title}</div>
        {actions}
        <button className="btn ghost sm" onClick={onClose} aria-label="close"><IconClose /></button>
      </div>
      <div className="drawer-b">{children}</div>
    </div>
  )
}

export function usePivot() {
  const setView = useStore((s) => s.setView)
  const setEventsFilter = useStore((s) => s.setEventsFilter)
  const setMailsFilter = useStore((s) => s.setMailsFilter)
  return (value: string, field?: string, target?: 'events' | 'mails') => {
    const v = value.trim()
    if (!v) return
    if (target === 'mails' || (!target && field && ['fromAddr', 'fromDomain', 'originIp', 'subject', 'fromName'].includes(field))) {
      setMailsFilter(field && !['summary'].includes(field) ? { conditions: [{ field, op: 'eq', value: v }] } : { text: v })
      setView('mails')
    } else {
      setEventsFilter(field && !['summary', 'raw', 'message', 'commandLine', 'scriptBlockText'].includes(field) ? { conditions: [{ field, op: 'eq', value: v }] } : { text: v })
      setView('events')
    }
  }
}

export function EventDetail({ row: initial, onClose }: { row: EventRow; onClose: () => void }) {
  const [tab, setTab] = useState<'fields' | 'data' | 'raw'>('fields')
  const [row, setRow] = useState<EventRow>(initial)
  const meta = useStore((s) => s.meta)
  const kase = useStore((s) => s.currentCase)
  const setAiPrompt = useStore((s) => s.setAiPrompt)
  const setView = useStore((s) => s.setView)
  const pivot = usePivot()
  useEffect(() => {
    setRow(initial)
    // server-stored rows arrive without data/raw: fetch the full record
    if (kase && initial.id != null && initial.data === undefined && initial.raw === undefined) {
      let alive = true
      getSource(kase)
        .getEvent(initial.id)
        .then((full) => alive && full && setRow(full))
        .catch(() => undefined)
      return () => {
        alive = false
      }
    }
  }, [initial, kase])
  const note = meta?.notes[String(row.eventId)]
  const scalars = Object.entries(row).filter(([k, v]) => !HIDE.has(k) && v != null && v !== '' && typeof v !== 'object') as [string, unknown][]
  const raw = useMemo(() => {
    try {
      return row.raw ? JSON.parse(row.raw) : null
    } catch {
      return row.raw
    }
  }, [row.raw])
  const explain = () => {
    const { raw: _r, data, ...rest } = row
    void _r
    setAiPrompt(`Explain this Windows event and suggest pivots:\n\`\`\`json\n${JSON.stringify({ ...rest, data }, null, 1).slice(0, 6000)}\n\`\`\``)
    setView('ai')
  }
  return (
    <Drawer
      title={<span className="mono"><Badge sev="accent">{row.eventId}</Badge> {row.description || row.provider} · {fmtTs(row.ts)}</span>}
      onClose={onClose}
      actions={<><AddToTimeline ts={initial.ts} text={String(initial.summary ?? `event ${initial.eventId ?? initial.operation ?? ''}`)} link={{ source: 'events', id: initial.id!, label: `#${initial.id}` }} /><button className="btn sm primary" onClick={explain}><IconAi /> explain</button></>}
    >
      <div className="card glow">
        <div className="mono" style={{ color: 'var(--fg-1)' }}>{row.summary}</div>
        {note && <div className="hint" style={{ marginTop: 6 }}>{note}</div>}
        <div className="row wrap" style={{ marginTop: 8, gap: 6 }}>
          {['ipAddress', 'targetUser', 'subjectUser', 'computer', 'workstation', 'processName', 'serviceName', 'destinationIp'].map((f) => {
            const v = row[f]
            return v ? (
              <button key={f} className="btn xs" onClick={() => pivot(String(v), f)} title={`pivot on ${f}`}>
                <IconPivot /> {f}: {String(v)}
              </button>
            ) : null
          })}
          {row.ipAddress && <button className="btn xs" onClick={() => pivot(String(row.ipAddress), 'originIp', 'mails')}>mails from {String(row.ipAddress)}</button>}
        </div>
      </div>
      <Tabs tabs={[{ id: 'fields', label: 'Fields' }, { id: 'data', label: 'EventData' }, { id: 'raw', label: 'Raw JSON' }]} active={tab} onChange={setTab} />
      {tab === 'fields' && <KV items={scalars} onPivot={(v, k) => pivot(v, k)} />}
      {tab === 'data' && (row.data ? <KV items={Object.entries(row.data)} onPivot={(v) => pivot(v)} /> : <div className="muted">no EventData</div>)}
      {tab === 'raw' && (
        <div>
          <div className="row" style={{ justifyContent: 'flex-end' }}><CopyButton text={typeof raw === 'string' ? raw : JSON.stringify(raw, null, 2)} label="copy" /></div>
          {raw ? <JsonView value={raw} /> : <div className="muted">raw JSON was not stored for this evidence (lite mode)</div>}
        </div>
      )}
    </Drawer>
  )
}

function sanitizeMailHtml(html: string): string {
  const clean = DOMPurify.sanitize(html, {
    FORBID_TAGS: ['script', 'iframe', 'object', 'embed', 'form', 'input', 'button', 'video', 'audio', 'link', 'meta', 'base', 'svg', 'math', 'style'],
    FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'style', 'srcset', 'background', 'action', 'formaction', 'poster'],
    ALLOW_UNKNOWN_PROTOCOLS: false,
  })
  const doc = new DOMParser().parseFromString(clean, 'text/html')
  doc.querySelectorAll('img').forEach((img) => {
    const src = img.getAttribute('src') || ''
    img.setAttribute('alt', `[image blocked: ${src.slice(0, 80)}]`)
    img.removeAttribute('src')
    img.setAttribute('style', 'border:1px dashed #999;padding:4px;font:11px monospace;color:#666')
  })
  doc.querySelectorAll('a').forEach((a) => {
    const href = a.getAttribute('href') || ''
    a.setAttribute('title', href)
    a.setAttribute('href', '#')
    a.setAttribute('style', 'color:#0645ad;text-decoration:underline dotted;cursor:not-allowed')
  })
  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;"><style>body{font:13px/1.5 Arial,sans-serif;color:#111;background:#fff;padding:12px;margin:0;word-break:break-word}</style></head><body>${doc.body.innerHTML}</body></html>`
}

function normalizeMail(m: MailRow): MailRow {
  return { ...m, hops: m.hops ?? [], to: m.to ?? [], cc: m.cc ?? [], bcc: m.bcc ?? [], replyTo: m.replyTo ?? [], urls: m.urls ?? [], attachments: m.attachments ?? [], flags: m.flags ?? [], keywordHits: m.keywordHits ?? {}, auth: m.auth ?? {}, lookalike: m.lookalike ?? {} }
}

type MailTab = 'message' | 'headers' | 'hops' | 'urls' | 'attachments' | 'related' | 'json'

/** Local part used by identity_key on the parser side; matches events' targetUser / subjectUser. */
function localPart(addr: string): string {
  return (addr.split('@')[0] ?? addr).toLowerCase()
}

/**
 * Mail detail. `layout="pane"` renders the bottom split pane used by the Mails view
 * (message left, evidence context right); the default is the right-hand drawer used from
 * other views (findings, chains, IOCs) where the context block sits on top of the tabs.
 */
export function MailDetail({ row: initialRaw, onClose, layout = 'drawer' }: { row: MailRow; onClose: () => void; layout?: 'drawer' | 'pane' }) {
  const initial = useMemo(() => normalizeMail(initialRaw), [initialRaw])
  const [tab, setTab] = useState<MailTab>('message')
  const [bodyMode, setBodyMode] = useState<'text' | 'html'>('text')
  const [body, setBody] = useState<MailBody | null>(null)
  const [row, setRow] = useState<MailRow>(initial)
  const [findings, setFindings] = useState<Finding[]>([])
  const [related, setRelated] = useState<{ events: EventRow[]; busy: boolean; loaded: boolean }>({ events: [], busy: false, loaded: false })
  const meta = useStore((s) => s.meta)
  const kase = useStore((s) => s.currentCase)
  const setAiPrompt = useStore((s) => s.setAiPrompt)
  const setView = useStore((s) => s.setView)
  const setEntity = useStore((s) => s.setEntity)
  const setFocus = useStore((s) => s.setFocus)
  const pivot = usePivot()
  useEffect(() => {
    let alive = true
    setRow(initial)
    setBody(null)
    setRelated({ events: [], busy: false, loaded: false })
    if (kase && initial.id != null) {
      getSource(kase)
        .getMail(initial.id)
        .then((r) => {
          if (!alive || !r) return
          setBody(r.body)
          // server rows: the detail carries attachments (with analysis details), urls and hops
          setRow(normalizeMail({ ...initial, ...r.row }))
        })
        .catch(() => undefined)
      getDb()
        .findings.where('caseId')
        .equals(kase.id!)
        .filter((f) => f.source === 'mails' && f.refs.includes(initial.id!))
        .toArray()
        .then((fs) => alive && setFindings(fs.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))))
        .catch(() => undefined)
    } else setFindings([])
    return () => {
      alive = false
    }
  }, [initial, kase])
  // events for the recipients around delivery time, fetched when the Related tab opens
  useEffect(() => {
    if (tab !== 'related' || related.loaded || !kase) return
    const rcpts = row.to.map((t) => t.addr).filter(Boolean).slice(0, 3)
    if (!rcpts.length || !row.date) return setRelated({ events: [], busy: false, loaded: true })
    let alive = true
    setRelated({ events: [], busy: true, loaded: false })
    const conditions: Condition[] = rcpts.flatMap((a) => [{ field: 'targetUser', op: 'eq', value: localPart(a) }, { field: 'subjectUser', op: 'eq', value: localPart(a) }, { field: 'upn', op: 'eq', value: a }] as Condition[])
    const f: Filter = { conditions, logic: 'or', timeRange: { from: new Date(row.date - 15 * 60_000).toISOString(), to: new Date(row.date + 72 * 3_600_000).toISOString() }, sort: { field: 'ts', dir: 'asc' } }
    getSource(kase)
      .searchEvents(f, 300)
      .then((r) => alive && setRelated({ events: r.rows, busy: false, loaded: true }))
      .catch(() => alive && setRelated({ events: [], busy: false, loaded: true }))
    return () => {
      alive = false
    }
  }, [tab, related.loaded, kase, row])
  const auth = row.auth as Record<string, unknown>
  const authBadge = (k: string) => {
    const v = String(auth?.[k] ?? 'n/a')
    const sev = v === 'pass' ? 'ok' : /fail|error/.test(v) ? 'critical' : v === 'n/a' || v === 'none' ? 'info' : 'medium'
    return <Badge key={k} sev={sev} title={String((auth?.raw as string[] | undefined)?.join('\n') ?? '')}>{k} {v}</Badge>
  }
  const explain = () => {
    setAiPrompt(`Analyse this e-mail (mail id ${row.id}) for phishing / BEC indicators and tell me what to check next. Use get_mail with includeBody if needed. Summary: subject "${row.subject}", from ${row.fromName} <${row.fromAddr}>, origin IP ${row.originIp}, risk ${row.risk}, flags: ${row.flags.join(', ')}`)
    setView('ai')
  }
  const srcdoc = useMemo(() => (bodyMode === 'html' && body?.bodyHtml ? sanitizeMailHtml(body.bodyHtml) : ''), [bodyMode, body])
  const lookalike = (row.lookalike as { matches?: { reference: string; method: string; kind: string }[] }).matches ?? []
  const worstFinding = findings[0]?.severity
  const senderDomain = row.fromRegistrable || row.fromDomain
  const visibleFlags = row.flags.filter((f) => !/^(spf_none|dkim_none|dmarc_none)$/.test(f))

  const context = (
    <div className="col" style={{ gap: 14 }}>
      <div className="section">
        <h3>Entities</h3>
        <div className="kv">
          <div className="k">sender</div>
          <div className="v click" onClick={() => setEntity({ kind: 'address', value: row.fromAddr })} title="open the sender page">{row.fromAddr}</div>
          {senderDomain && (<><div className="k">domain</div><div className="v click" onClick={() => setEntity({ kind: 'domain', value: senderDomain })} title="open the domain page">{senderDomain}</div></>)}
          {row.replyTo.filter((r) => r.addr && r.addr.toLowerCase() !== row.fromAddr.toLowerCase()).map((r) => (<Fragment key={r.addr}><div className="k" style={{ color: 'var(--warn)' }}>reply-to</div><div className="v click" onClick={() => setEntity({ kind: 'address', value: r.addr })}>{r.addr}</div></Fragment>))}
          {row.to.slice(0, 4).map((t, i) => (<Fragment key={'to' + i}><div className="k">{i === 0 ? 'recipient' : ''}</div><div className="v click" onClick={() => setEntity({ kind: 'user', value: t.addr || t.name })} title="open the user page">{t.addr || t.name}</div></Fragment>))}
          {row.to.length > 4 && (<><div className="k" /><div className="v muted">+{row.to.length - 4} more</div></>)}
          {row.originIp && (<><div className="k">origin ip</div><div className="v click" onClick={() => setEntity({ kind: 'ip', value: String(row.originIp) })} title="open the IP page">{row.originIp}</div></>)}
        </div>
      </div>
      <div className="section">
        <h3>Sender history</h3>
        {row.senderPrevalence ? (
          <div className="kv">
            <div className="k">prevalence</div><div className="v"><Badge sev={row.senderPrevalence === 'new' ? 'high' : row.senderPrevalence === 'rare' ? 'medium' : 'ok'}>{row.senderPrevalence}</Badge></div>
            <div className="k">prior mails</div><div className="v">{row.senderPriorCount ?? 0}{row.senderDaysKnown != null ? ` · known ${row.senderDaysKnown} day(s)` : ''}</div>
            <div className="k">first seen</div><div className="v">{row.senderFirstSeen ? fmtTs(row.senderFirstSeen) : '—'}</div>
            <div className="k">solicited</div><div className="v">{row.senderSolicited === true ? 'yes - the recipient wrote to this sender before' : row.senderSolicited === false ? 'no - first contact' : 'unknown (inbox-only export)'}</div>
            {row.senderAuthRegression && (<><div className="k">auth</div><div className="v" style={{ color: 'var(--danger)' }}>authentication regressed vs earlier mails from this sender</div></>)}
            {row.campaignId && (<><div className="k">campaign</div><div className="v click" onClick={() => pivot(row.campaignId!, 'campaignId', 'mails')}>{row.campaignSize ?? '?'} mail(s) · {row.campaignSenders ?? '?'} sender(s)</div></>)}
          </div>
        ) : <div className="muted small">run "baseline senders" on the Mails page to compare this sender with the rest of the mailbox</div>}
      </div>
      <div className="section">
        <h3>Findings {findings.length ? <span className="muted">({findings.length})</span> : null}</h3>
        {!findings.length && <div className="muted small">no rule fired on this mail</div>}
        {findings.slice(0, 8).map((f) => (
          <div key={f.id} className="row click" style={{ gap: 8, cursor: 'pointer' }} onClick={() => setView('findings')} title={f.description}>
            <Dot sev={f.severity} /><span className="ellipsis" style={{ flex: 1 }}>{f.title}</span><Badge className="small">{f.status}</Badge>
          </div>
        ))}
      </div>
      <div className="section">
        <h3>Score</h3>
        {row.assessment ? (
          <div className="small dim">
            <div>Attack evidence <strong>{row.assessment.confidence}</strong>{row.assessment.expectedSender ? ' · expected correspondent' : ''}</div>
            <div>{Object.entries(row.assessment.groups).filter(([, w]) => w > 0).map(([g, w]) => `${g} (${w})`).join(' · ') || 'no signal family'} · attachments {row.assessment.attachmentRisk}</div>
            {row.assessment.limitations.map((s) => <div key={s} style={{ color: 'var(--warn)' }}>{s}</div>)}
            <div className="muted">calibration {row.assessment.version} · the score is a review priority, not a probability of compromise</div>
          </div>
        ) : meta?.mailWeights && row.flags.length > 0 ? (
          <div className="small dim">
            legacy score - use "rescore" to apply the current calibration. Drivers: {row.flags.map((f) => ({ f, w: meta.mailWeights![f] ?? 5, s: meta.mailStrongFlags?.includes(f) })).sort((a, b) => b.w - a.w).slice(0, 5).map((x) => `${x.f}${x.s ? '*' : ''} (${x.w})`).join(' · ')}
          </div>
        ) : <div className="muted small">no flags</div>}
        {row.reputation?.worst && <div className="small">reputation <Badge sev={row.reputation.worst === 'malicious' ? 'critical' : 'medium'}>{row.reputation.worst}</Badge></div>}
      </div>
      <div className="section">
        <h3>Evidence</h3>
        <div className="kv">
          <div className="k">file</div><div className="v">{(row.sourceName ?? '').replace(/^.*[\\/]/, '') || '—'} <span className="muted">({row.sourceFormat})</span></div>
          <div className="k">folder</div><div className="v">{row.folder || '—'}</div>
          <div className="k">message-id</div><div className="v">{row.messageId ?? '—'}</div>
          {row.xMailer && (<><div className="k">mailer</div><div className="v">{row.xMailer}</div></>)}
          <div className="k">row</div><div className="v">#{row.id}</div>
        </div>
      </div>
    </div>
  )

  const head = (
    <div className="col" style={{ gap: 6 }}>
      <div className="row" style={{ gap: 10, alignItems: 'flex-start' }}>
        <Risk value={row.risk} />
        <div className="col" style={{ gap: 2, flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 600, color: 'var(--fg-1)', fontSize: 13.5 }}>{row.subject || '(no subject)'}</div>
          <div className="small mono" style={{ color: 'var(--fg-2)' }}>
            <span className="click" onClick={() => setEntity({ kind: 'address', value: row.fromAddr })}>{row.fromName ? `"${row.fromName}" ` : ''}&lt;{row.fromAddr}&gt;</span>
            {' → '}{row.to.map((t) => t.addr || t.name).slice(0, 3).join(', ') || '(undisclosed)'}{row.to.length > 3 ? ` +${row.to.length - 3}` : ''}
            {row.cc.length ? <span className="muted"> · cc {row.cc.length}</span> : null}
            {' · '}{fmtTs(row.date)}
          </div>
        </div>
        {worstFinding && <Sev sev={worstFinding}>{findings.length} finding{findings.length === 1 ? '' : 's'}</Sev>}
        <AddToTimeline ts={row.date} text={`Mail "${row.subject || '(no subject)'}" from ${row.fromAddr} to ${row.to.map((t) => t.addr).slice(0, 2).join(', ')}`} link={{ source: 'mails', id: row.id!, label: row.subject || `#${row.id}` }} severity={row.risk >= 80 ? 'critical' : row.risk >= 60 ? 'high' : row.risk >= 40 ? 'medium' : 'info'} />
        <button className="btn sm" onClick={explain} title="ask the local model"><IconAi /> analyse</button>
        <button className="btn icon ghost sm" onClick={onClose} title="close (Esc)"><IconClose /></button>
      </div>
      <div className="row wrap" style={{ gap: 4 }}>
        {['spf', 'dkim', 'dmarc'].map(authBadge)}{auth?.compauth ? authBadge('compauth') : null}{auth?.arc ? authBadge('arc') : null}
        {row.replyTo.some((r) => r.addr && r.addr.toLowerCase() !== row.fromAddr.toLowerCase()) && <Badge sev="medium" title={row.replyTo.map((r) => r.addr).join(', ')}>reply-to differs</Badge>}
        {lookalike.length > 0 && <Badge sev="critical" title={lookalike.map((m) => `${m.reference} (${m.method}, ${m.kind})`).join('; ')}>lookalike of {lookalike[0].reference}</Badge>}
        {visibleFlags.map((f) => <Flag key={f} name={f} />)}
      </div>
    </div>
  )

  const tabs = (
    <Tabs
      tabs={[
        { id: 'message' as MailTab, label: 'Message' },
        { id: 'headers' as MailTab, label: 'Headers' },
        { id: 'hops' as MailTab, label: <span>Hops <span className="n">{row.hopCount}</span></span> },
        { id: 'urls' as MailTab, label: <span>URLs <span className="n">{row.urlCount}</span></span> },
        { id: 'attachments' as MailTab, label: <span>Attachments <span className="n">{row.attachmentCount}</span></span> },
        { id: 'related' as MailTab, label: <span>Related{related.loaded ? <span className="n">{related.events.length}</span> : null}</span> },
        { id: 'json' as MailTab, label: 'JSON' },
      ]}
      active={tab}
      onChange={setTab}
    />
  )

  const content = (
    <>
      {tab === 'message' && (
        <div className="col" style={{ gap: 8 }}>
          <div className="row" style={{ gap: 8 }}>
            <div className="segmented">
              <button className={bodyMode === 'text' ? 'active' : ''} onClick={() => setBodyMode('text')}>text</button>
              <button className={bodyMode === 'html' ? 'active' : ''} onClick={() => setBodyMode('html')} disabled={!body?.bodyHtml} title={body?.bodyHtml ? 'sandboxed: images blocked, links disabled' : 'no HTML body'}>html</button>
            </div>
            {Object.keys(row.keywordHits ?? {}).length > 0 && <span className="small dim">lexicon: {Object.entries(row.keywordHits).map(([k, v]) => `${k} → ${v.slice(0, 4).join(', ')}`).join(' · ')}</span>}
            {body?.visibleText && body.bodyText && body.visibleText.length < body.bodyText.length * 0.6 && <Badge sev="medium" title="a large part of the text is not visible when rendered">hidden text</Badge>}
          </div>
          {bodyMode === 'text' ? <pre className="codeblock" style={{ fontFamily: 'var(--sans)', fontSize: 12.5, lineHeight: 1.5 }}>{body?.bodyText || body?.visibleText || row.textPreview || '(empty)'}</pre> : <iframe className="mailframe" sandbox="" srcDoc={srcdoc} title="mail html (sandboxed, images blocked, links disabled)" />}
        </div>
      )}
      {tab === 'headers' && <pre className="codeblock">{body?.headersText || '(headers not stored)'}</pre>}
      {tab === 'hops' && (
        <table className="table compact">
          <thead><tr><th>#</th><th>from</th><th>ip</th><th>by</th><th>with</th><th>time</th><th>delay</th></tr></thead>
          <tbody>
            {(row.hops as { index: number; from?: string; fromIp?: string; by?: string; with?: string; ts?: number; delayS?: number | null }[]).map((h) => (
              <tr key={h.index}>
                <td>{h.index}</td>
                <td className="ellipsis" style={{ maxWidth: 220 }} title={h.from}>{h.from}</td>
                <td className="click" onClick={() => h.fromIp && setEntity({ kind: 'ip', value: h.fromIp })}>{h.fromIp}</td>
                <td className="ellipsis" style={{ maxWidth: 160 }}>{h.by}</td>
                <td>{h.with}</td>
                <td>{h.ts ? fmtTs(h.ts) : ''}</td>
                <td style={h.delayS != null && h.delayS < 0 ? { color: 'var(--danger)' } : undefined}>{h.delayS != null ? `${h.delayS}s` : ''}</td>
              </tr>
            ))}
            {!row.hops.length && <tr><td colSpan={7} className="muted sans">no Received headers</td></tr>}
          </tbody>
        </table>
      )}
      {tab === 'urls' && (
        <table className="table compact">
          <thead><tr><th>url (defanged)</th><th>text</th><th>flags</th></tr></thead>
          <tbody>
            {row.urls.map((u, i) => (
              <tr key={i}>
                <td className="click" style={{ maxWidth: 420, wordBreak: 'break-all' }} onClick={() => setEntity({ kind: 'domain', value: u.domain || u.host })} title="open the domain page">{u.defanged}</td>
                <td className="ellipsis sans" style={{ maxWidth: 160 }}>{u.text}</td>
                <td><div className="row wrap" style={{ gap: 3 }}>{u.flags.map((f) => <Flag key={f} name={'url_' + f} />)}</div></td>
              </tr>
            ))}
            {!row.urls.length && <tr><td colSpan={3} className="muted sans">no URLs</td></tr>}
          </tbody>
        </table>
      )}
      {tab === 'attachments' && (
        <div className="col">
          {row.attachments.map((a, i) => (
            <div key={i} className="card">
              <div className="row">
                <Risk value={a.risk} />
                <b className="mono">{a.name}</b>
                <span className="muted small">{fmtBytes(a.size)} · declared .{a.ext || '?'} · real {a.realExt || '?'} ({a.realMime})</span>
                <span className="spacer" />
                {a.sha256 && <CopyButton text={a.sha256} label="sha256" />}
              </div>
              <div className="mono small dim" style={{ wordBreak: 'break-all' }}>sha256 {a.sha256} · md5 {a.md5}</div>
              <div className="row wrap" style={{ gap: 4, marginTop: 6 }}>{a.flags.map((f) => <Flag key={f} name={f} />)}</div>
              {a.details && Object.keys(a.details).length > 0 && (
                <details style={{ marginTop: 6 }}>
                  <summary className="small dim" style={{ cursor: 'pointer' }}>analysis details</summary>
                  <JsonView value={a.details} />
                </details>
              )}
            </div>
          ))}
          {!row.attachments.length && <div className="muted">no attachments</div>}
        </div>
      )}
      {tab === 'related' && (
        <div className="col" style={{ gap: 12 }}>
          <div className="section">
            <h3>Findings on this mail</h3>
            {!findings.length && <div className="muted small">none</div>}
            {findings.map((f) => <div key={f.id} className="row" style={{ gap: 8 }}><Sev sev={f.severity} /><span style={{ flex: 1 }}>{f.title}</span><span className="mono small muted">{f.ruleId}</span></div>)}
          </div>
          <div className="section">
            <h3>Recipient activity after delivery <span className="muted">(15 min before to 72 h after, first 300)</span></h3>
            {related.busy && <div className="muted small">loading…</div>}
            {!related.busy && related.loaded && !related.events.length && <div className="muted small">no host or cloud events for {row.to.slice(0, 3).map((t) => localPart(t.addr || t.name)).join(', ') || 'the recipients'} in that window</div>}
            {related.events.length > 0 && (
              <table className="table compact">
                <thead><tr><th>time (UTC)</th><th>Δ</th><th>id</th><th>computer / ip</th><th>summary</th></tr></thead>
                <tbody>
                  {related.events.map((e) => (
                    <tr key={e.id} onClick={() => { setFocus({ source: 'events', id: e.id! }); setView('events') }} style={{ cursor: 'pointer' }}>
                      <td className="nowrap">{fmtTs(e.ts)}</td>
                      <td className="muted nowrap">{e.ts && row.date ? (() => { const d = Math.round((e.ts - row.date) / 60_000); return `${d >= 0 ? '+' : ''}${d}m` })() : ''}</td>
                      <td>{String(e.eventId ?? e.operation ?? '')}</td>
                      <td>{[e.computer, e.ipAddress].filter(Boolean).join(' · ')}</td>
                      <td className="sans">{String(e.summary ?? '')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
      {tab === 'json' && <JsonView value={row} />}
    </>
  )

  if (layout === 'pane') {
    return (
      <div className="pane">
        <div className="pane-main">
          <div style={{ padding: '10px 16px 8px', borderBottom: '1px solid var(--line)' }}>{head}</div>
          {tabs}
          <div className="pane-b">{content}</div>
        </div>
        <div className="pane-side">{context}</div>
      </div>
    )
  }
  return (
    <Drawer title={<span className="mono"><Risk value={row.risk} /> {row.subject || '(no subject)'}</span>} onClose={onClose} actions={<button className="btn sm primary" onClick={explain}><IconAi /> analyse</button>}>
      <div className="card col">{head}</div>
      <div className="card">{context}</div>
      {tabs}
      {content}
    </Drawer>
  )
}
