import { useEffect, useState } from 'react'
import { Badge, Spinner } from '../components/ui'
import { IconLink, IconPlay } from '../components/Icons'
import { buildChains, loadChains, type Chain, type ChainResult, type ChainStep } from '../data/chains'
import { toast, useStore } from '../state/store'
import { fmtTs } from '../util/format'

function stepBadge(s: ChainStep) {
  if (s.kind === 'mail') return <Badge sev="accent">mail</Badge>
  if (s.origin === 'm365') return <Badge sev="info">m365</Badge>
  return <Badge sev="medium">host</Badge>
}

function offset(min: number): string {
  const a = Math.abs(min)
  const txt = a < 90 ? `${Math.round(a)} min` : a < 48 * 60 ? `${(a / 60).toFixed(1)} h` : `${(a / 1440).toFixed(1)} d`
  return (min < 0 ? '-' : '+') + txt
}

export function ChainsView() {
  const kase = useStore((s) => s.currentCase)
  const setFocus = useStore((s) => s.setFocus)
  const setView = useStore((s) => s.setView)
  const setEventsFilter = useStore((s) => s.setEventsFilter)
  const bump = useStore((s) => s.bumpRules)
  const [res, setRes] = useState<ChainResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [minRisk, setMinRisk] = useState(45)
  const [hours, setHours] = useState(72)
  const [open, setOpen] = useState<string | null>(null)
  useEffect(() => {
    if (kase?.id) loadChains(kase.id).then((r) => { setRes(r); setOpen(r?.chains[0]?.id ?? null) })
  }, [kase?.id])
  if (!kase) return null
  const build = async () => {
    setBusy(true)
    try {
      const r = await buildChains(kase, { seedMinRisk: minRisk, windowHours: hours })
      setRes(r)
      setOpen(r.chains[0]?.id ?? null)
      bump()
      toast(r.chains.length ? 'ok' : 'warn', `${r.chains.length} chain(s) from ${r.stats.seeds} seed mail(s), ${r.stats.events} event(s) of ${r.stats.identities} identit${r.stats.identities === 1 ? 'y' : 'ies'}`)
    } catch (e) {
      toast('err', `chains: ${(e as Error).message}`, 0)
    } finally {
      setBusy(false)
    }
  }
  const openStep = (s: ChainStep) => {
    if (s.kind === 'mail' && s.id != null) { setFocus({ source: 'mails', id: s.id }); setView('mails'); return }
    const ids = (s.refs?.length ? s.refs : s.id != null ? [s.id] : []).slice(0, 500)
    if (!ids.length) return
    if (ids.length === 1) { setFocus({ source: 'events', id: ids[0] }); setView('events'); return }
    setEventsFilter({ conditions: [{ field: 'id', op: 'in', value: ids }], sort: { field: 'ts', dir: 'asc' } })
    setView('events')
  }
  return (
    <div className="view">
      <div className="view-header">
        <h1>Attack chains</h1>
        <span className="sub">
          {res ? `${res.chains.length} chain(s) · built ${res.builtAt ? fmtTs(res.builtAt) : ''}` : 'not built yet'}
        </span>
        <span className="spacer" />
        <label className="row" style={{ gap: 6 }}><span className="muted">seed risk ≥</span><input className="input" type="number" style={{ width: 64 }} value={minRisk} min={0} max={100} onChange={(e) => setMinRisk(Number(e.target.value))} /></label>
        <label className="row" style={{ gap: 6 }}><span className="muted">window</span><input className="input" type="number" style={{ width: 64 }} value={hours} min={1} max={720} onChange={(e) => setHours(Number(e.target.value))} /><span className="muted">h</span></label>
        <button className="btn sm primary" onClick={build} disabled={busy}>{busy ? <Spinner /> : <IconPlay />} build chains</button>
      </div>
      <div className="view-body" style={{ padding: 16, overflow: 'auto' }}>
        <p className="muted" style={{ marginTop: 0 }}>
          A chain starts from a suspicious mail (risk above the threshold, or carrying a medium+ finding) and follows what its recipient did next across the mailbox,
          Microsoft 365 / Entra audit rows and Windows events: replies to the sender, sign-ins, mailbox rules, consent grants, role changes, processes spawned by Outlook or a browser,
          DNS queries and files that name the mail's links or attachments. Run the rules first so their findings attach to the steps.
        </p>
        {res && res.chains.length === 0 && <div className="muted">No chain: no recipient of a seed mail has correlated activity in the window.</div>}
        {res?.chains.map((c: Chain) => (
          <div key={c.id} className="card" style={{ marginBottom: 12, padding: 12 }}>
            <div className="row" style={{ gap: 10, cursor: 'pointer', alignItems: 'center' }} onClick={() => setOpen(open === c.id ? null : c.id)}>
              <Badge sev={c.severity}>{c.severity}</Badge>
              <IconLink />
              <strong>{c.identityLabel}</strong>
              <span className="muted">score {c.score} · {c.steps.length} step(s) · {c.artifactLinks} artifact link(s) · {fmtTs(c.start)} → {fmtTs(c.end)}</span>
              <span className="spacer" />
              <span className="muted mono" style={{ fontSize: 12 }}>seed: {c.seed.fromAddr} · risk {c.seed.risk}</span>
            </div>
            <div style={{ marginTop: 6 }}>{c.summary}</div>
            {open === c.id && (
              <div style={{ marginTop: 10 }}>
                <div className="row" style={{ gap: 8, alignItems: 'baseline', marginBottom: 6 }}>
                  <Badge sev="accent">seed</Badge>
                  <span className="mono" style={{ fontSize: 12 }}>{fmtTs(c.seed.ts)}</span>
                  <button className="btn link" onClick={() => { setFocus({ source: 'mails', id: c.seed.id }); setView('mails') }}>{c.seed.subject || '(no subject)'}</button>
                  <span className="muted">from {c.seed.fromAddr}</span>
                  {c.seed.findings.map((f) => <Badge key={f.ruleId} sev={f.severity}>{f.ruleId}</Badge>)}
                  {c.seed.urlDomains.length > 0 && <span className="muted mono" style={{ fontSize: 12 }}>links: {c.seed.urlDomains.join(', ')}</span>}
                  {c.seed.attachments.length > 0 && <span className="muted mono" style={{ fontSize: 12 }}>attachments: {c.seed.attachments.join(', ')}</span>}
                </div>
                <table className="table compact">
                  <tbody>
                    {c.steps.map((s, i) => (
                      <tr key={i}>
                        <td style={{ width: 90 }} className="mono muted">{offset(s.offsetMin)}</td>
                        <td style={{ width: 70 }}>{stepBadge(s)}</td>
                        <td>
                          <button className="btn link" onClick={() => openStep(s)}>{s.title}</button>
                          {s.artifacts.map((a, j) => <Badge key={j} sev={a.startsWith('mail ') || a.includes('thread') || a.includes('engaged') ? 'critical' : 'high'}>{a}</Badge>)}
                          {s.findings.map((f) => <Badge key={f.ruleId} sev={f.severity}>{f.ruleId}</Badge>)}
                        </td>
                        <td className="mono muted" style={{ width: 160, fontSize: 12 }}>{s.ipAddress || ''}{s.computer ? ` ${s.computer}` : ''}</td>
                        <td className="muted" style={{ width: 50, textAlign: 'right' }}>+{s.weight}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                <div className="row" style={{ gap: 12, marginTop: 8, fontSize: 12 }} >
                  {c.entities.ips.length > 0 && <span className="mono muted">IPs: {c.entities.ips.join(', ')}</span>}
                  {c.entities.hosts.length > 0 && <span className="mono muted">hosts: {c.entities.hosts.join(', ')}</span>}
                  {c.entities.attackerAddresses.length > 0 && <span className="mono muted">attacker: {c.entities.attackerAddresses.join(', ')}</span>}
                  {(c.relatedSeeds?.length ?? 0) > 0 && <span className="muted">+{c.relatedSeeds!.length} related mail(s) to the same identity</span>}
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
