import DOMPurify from 'dompurify'
import { useEffect, useMemo, useState } from 'react'
import type { EventRow, MailBody, MailRow } from '../db/schema'
import { getSource } from '../data/source'
import { useStore } from '../state/store'
import { classNames, fmtBytes, fmtTs } from '../util/format'
import { IconAi, IconClose, IconPivot } from './Icons'
import { Badge, CopyButton, Flag, JsonView, KV, Risk, Tabs } from './ui'

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
      actions={<button className="btn sm primary" onClick={explain}><IconAi /> explain</button>}
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

export function MailDetail({ row: initialRaw, onClose }: { row: MailRow; onClose: () => void }) {
  const initial = useMemo(() => normalizeMail(initialRaw), [initialRaw])
  const [tab, setTab] = useState<'overview' | 'text' | 'html' | 'headers' | 'urls' | 'attachments' | 'json'>('overview')
  const [body, setBody] = useState<MailBody | null>(null)
  const [row, setRow] = useState<MailRow>(initial)
  const meta = useStore((s) => s.meta)
  const kase = useStore((s) => s.currentCase)
  const setAiPrompt = useStore((s) => s.setAiPrompt)
  const setView = useStore((s) => s.setView)
  const pivot = usePivot()
  useEffect(() => {
    let alive = true
    setRow(initial)
    setBody(null)
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
    }
    return () => {
      alive = false
    }
  }, [initial, kase])
  const auth = row.auth as Record<string, unknown>
  const authBadge = (k: string) => {
    const v = String(auth?.[k] ?? 'n/a')
    const sev = v === 'pass' ? 'ok' : /fail|error/.test(v) ? 'critical' : v === 'n/a' || v === 'none' ? 'info' : 'medium'
    return <Badge sev={sev} title={String((auth?.raw as string[] | undefined)?.join('\n') ?? '')}>{k} {v}</Badge>
  }
  const explain = () => {
    setAiPrompt(`Analyse this e-mail (mail id ${row.id}) for phishing / BEC indicators and tell me what to check next. Use get_mail with includeBody if needed. Summary: subject "${row.subject}", from ${row.fromName} <${row.fromAddr}>, origin IP ${row.originIp}, risk ${row.risk}, flags: ${row.flags.join(', ')}`)
    setView('ai')
  }
  const srcdoc = useMemo(() => (tab === 'html' && body?.bodyHtml ? sanitizeMailHtml(body.bodyHtml) : ''), [tab, body])
  return (
    <Drawer
      title={<span className="mono"><Risk value={row.risk} /> {row.subject || '(no subject)'}</span>}
      onClose={onClose}
      actions={<button className="btn sm primary" onClick={explain}><IconAi /> analyse</button>}
    >
      <div className="card glow col">
        <div className="kv">
          <div className="k">from</div>
          <div className="v click" onClick={() => pivot(row.fromAddr, 'fromAddr')}>{row.fromName ? `"${row.fromName}" ` : ''}&lt;{row.fromAddr}&gt;</div>
          <div className="k">to</div>
          <div className="v">{row.to.map((t) => t.addr || t.name).join(', ') || '(undisclosed)'}{row.cc.length ? ` · cc ${row.cc.map((t) => t.addr).join(', ')}` : ''}</div>
          {row.replyTo.length > 0 && (<><div className="k">reply-to</div><div className="v" style={{ color: 'var(--warn)' }}>{row.replyTo.map((t) => t.addr).join(', ')}</div></>)}
          {row.returnPath && (<><div className="k">return-path</div><div className="v">{row.returnPath}</div></>)}
          <div className="k">date</div>
          <div className="v">{fmtTs(row.date)} {row.dateRaw ? <span className="muted">({String(row.dateRaw)})</span> : null}</div>
          <div className="k">origin</div>
          <div className="v click" onClick={() => row.originIp && pivot(row.originIp, 'ipAddress', 'events')} title="pivot: events with this IP">{row.originIp ?? '—'} {row.originHelo ? <span className="muted">helo {row.originHelo}</span> : null} {row.originRdns ? <span className="muted">rdns {row.originRdns}</span> : null} · {row.hopCount} hop{row.hopCount === 1 ? '' : 's'}</div>
          <div className="k">message-id</div>
          <div className="v">{row.messageId ?? '—'}</div>
          {row.xMailer && (<><div className="k">mailer</div><div className="v">{row.xMailer}</div></>)}
          <div className="k">folder</div>
          <div className="v">{row.folder || '—'} · {row.sourceFormat}</div>
        </div>
        <div className="row wrap" style={{ gap: 6 }}>{authBadge('spf')}{authBadge('dkim')}{authBadge('dmarc')}{auth?.compauth ? authBadge('compauth') : null}{auth?.arc ? authBadge('arc') : null}</div>
        <div className="row wrap" style={{ gap: 4 }}>{row.flags.map((f) => <Flag key={f} name={f} />)}</div>
        {row.lookalike && (row.lookalike as { matches?: { reference: string; method: string; kind: string }[] }).matches?.length ? (
          <div className="small" style={{ color: 'var(--danger)' }}>
            lookalike of {(row.lookalike as { matches: { reference: string; method: string; kind: string }[] }).matches.map((m) => `${m.reference} (${m.method}, ${m.kind})`).join('; ')}
          </div>
        ) : null}
        {Object.keys(row.keywordHits ?? {}).length > 0 && (
          <div className="small dim">lexicon: {Object.entries(row.keywordHits).map(([k, v]) => `${k} → ${v.slice(0, 4).join(', ')}`).join(' · ')}</div>
        )}
        {meta?.mailWeights && (row.flags ?? []).length > 0 && (
          <div className="small dim" title="flag weights driving the risk score; * marks strong indicators that carry the score on their own">
            score drivers: {(row.flags ?? [])
              .map((f) => ({ f, w: meta.mailWeights![f] ?? 5, s: meta.mailStrongFlags?.includes(f) }))
              .sort((a, b) => b.w - a.w)
              .slice(0, 6)
              .map((x) => `${x.f}${x.s ? '*' : ''} (${x.w})`)
              .join(' · ')}
          </div>
        )}
        {row.reputation?.worst && <div className="small">reputation: <Badge sev={row.reputation.worst === 'malicious' ? 'critical' : 'medium'}>{row.reputation.worst}</Badge></div>}
      </div>
      <Tabs tabs={[{ id: 'overview', label: 'Hops' }, { id: 'text', label: 'Text' }, { id: 'html', label: 'HTML (sandbox)' }, { id: 'headers', label: 'Headers' }, { id: 'urls', label: `URLs (${row.urlCount})` }, { id: 'attachments', label: `Attachments (${row.attachmentCount})` }, { id: 'json', label: 'JSON' }]} active={tab} onChange={setTab} />
      {tab === 'overview' && (
        <table className="table">
          <thead><tr><th>#</th><th>from</th><th>ip</th><th>by</th><th>with</th><th>time</th><th>delay</th></tr></thead>
          <tbody>
            {(row.hops as { index: number; from?: string; fromIp?: string; by?: string; with?: string; ts?: number; delayS?: number | null }[]).map((h) => (
              <tr key={h.index}>
                <td>{h.index}</td>
                <td className="ellipsis" style={{ maxWidth: 220 }} title={h.from}>{h.from}</td>
                <td className="click" onClick={() => h.fromIp && pivot(h.fromIp, 'ipAddress', 'events')}>{h.fromIp}</td>
                <td className="ellipsis" style={{ maxWidth: 160 }}>{h.by}</td>
                <td>{h.with}</td>
                <td>{h.ts ? fmtTs(h.ts) : ''}</td>
                <td className={classNames(h.delayS != null && h.delayS < 0 && 'danger')} style={h.delayS != null && h.delayS < 0 ? { color: 'var(--danger)' } : undefined}>{h.delayS != null ? `${h.delayS}s` : ''}</td>
              </tr>
            ))}
            {!row.hops.length && <tr><td colSpan={7} className="muted">no Received headers</td></tr>}
          </tbody>
        </table>
      )}
      {tab === 'text' && <pre className="mono" style={{ background: '#05070a', padding: 10, borderRadius: 4, border: '1px solid var(--line)' }}>{body?.bodyText || body?.visibleText || row.textPreview || '(empty)'}</pre>}
      {tab === 'html' && (body?.bodyHtml ? <iframe className="mailframe" sandbox="" srcDoc={srcdoc} title="mail html (sandboxed, images blocked, links disabled)" /> : <div className="muted">no HTML body</div>)}
      {tab === 'headers' && <pre className="mono small" style={{ background: '#05070a', padding: 10, borderRadius: 4, border: '1px solid var(--line)' }}>{body?.headersText || '(headers not stored)'}</pre>}
      {tab === 'urls' && (
        <table className="table">
          <thead><tr><th>url (defanged)</th><th>text</th><th>flags</th></tr></thead>
          <tbody>
            {row.urls.map((u, i) => (
              <tr key={i}>
                <td className="click" style={{ maxWidth: 360, wordBreak: 'break-all' }} onClick={() => pivot(u.domain || u.host, undefined, 'events')} title="pivot on the domain">{u.defanged}</td>
                <td className="ellipsis" style={{ maxWidth: 160 }}>{u.text}</td>
                <td><div className="row wrap" style={{ gap: 3 }}>{u.flags.map((f) => <Flag key={f} name={'url_' + f} />)}</div></td>
              </tr>
            ))}
            {!row.urls.length && <tr><td colSpan={3} className="muted">no URLs</td></tr>}
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
      {tab === 'json' && <JsonView value={row} />}
    </Drawer>
  )
}
