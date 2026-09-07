import { useCallback, useEffect, useMemo, useState } from 'react'
import { Badge, Dot, Sev, Spinner, Tabs } from '../components/ui'
import { IconAi, IconCloud, IconHost, IconMail, IconPlay } from '../components/Icons'
import { buildChains, EVENT_CAP, loadChains, type Chain, type ChainResult, type ChainStep } from '../data/chains'
import { toast, useStore } from '../state/store'
import { AddToTimeline } from '../components/AddToTimeline'
import { ChainGraph } from '../components/ChainGraph'
import { fmtNum, fmtTs } from '../util/format'

type StepKind = 'mail' | 'm365' | 'host'
const stepKind = (s: ChainStep): StepKind => (s.kind === 'mail' ? 'mail' : s.origin === 'm365' ? 'm365' : 'host')
const KIND_ICON: Record<StepKind, React.ComponentType> = { mail: IconMail, m365: IconCloud, host: IconHost }
const KIND_LABEL: Record<StepKind, string> = { mail: 'mailbox', m365: 'Microsoft 365 / Entra', host: 'Windows host' }

function offset(min: number): string {
  const a = Math.abs(min)
  const txt = a < 90 ? `${Math.round(a)} min` : a < 48 * 60 ? `${(a / 60).toFixed(1)} h` : `${(a / 1440).toFixed(1)} d`
  return (min < 0 ? '-' : '+') + txt
}
function span(ms: number): string {
  const m = ms / 60_000
  return m < 90 ? `${Math.round(m)} min` : m < 48 * 60 ? `${(m / 60).toFixed(1)} h` : `${(m / 1440).toFixed(1)} d`
}
const strongArtifact = (a: string) => a.startsWith('mail ') || a.includes('thread') || a.includes('engaged')

/**
 * Attack chains as stories: the left list ranks the chains, the middle column is the
 * ordered narrative (time gutter, source icon, what happened, what tied it to the seed
 * mail), the right column details the selected step and opens the underlying rows.
 */
export function ChainsView() {
  const kase = useStore((s) => s.currentCase)
  const setFocus = useStore((s) => s.setFocus)
  const setView = useStore((s) => s.setView)
  const setEventsFilter = useStore((s) => s.setEventsFilter)
  const setEntity = useStore((s) => s.setEntity)
  const setAiPrompt = useStore((s) => s.setAiPrompt)
  const bump = useStore((s) => s.bumpRules)
  const [res, setRes] = useState<ChainResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [minRisk, setMinRisk] = useState(45)
  const [hours, setHours] = useState(72)
  const [open, setOpen] = useState<string | null>(null)
  const [stepIdx, setStepIdx] = useState<number | null>(null)
  const [tab, setTab] = useState<'story' | 'graph' | 'entities' | 'json'>('story')
  const [graphMode, setGraphMode] = useState<'chain' | 'campaign'>('chain')
  useEffect(() => {
    if (kase?.id)
      loadChains(kase.id).then((r) => {
        const want = useStore.getState().focusChain
        useStore.getState().setFocusChain(null)
        setRes(r)
        setOpen(want && r?.chains.some((c) => c.id === want) ? want : (r?.chains[0]?.id ?? null))
        setStepIdx(null)
      })
  }, [kase?.id])
  const chain = useMemo(() => res?.chains.find((c) => c.id === open) ?? null, [res, open])
  const step = chain && stepIdx != null ? chain.steps[stepIdx] : null
  // keyboard: j / k move between steps of the open chain
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null
      if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable)) return
      if (!chain || (e.key !== 'j' && e.key !== 'k')) return
      const i = stepIdx ?? -1
      setStepIdx(e.key === 'j' ? Math.min(chain.steps.length - 1, i + 1) : Math.max(0, i - 1))
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [chain, stepIdx])
  const openChainFromGraph = useCallback((id: string) => {
    setOpen(id)
    setStepIdx(null)
    setGraphMode('chain')
  }, [])
  if (!kase) return null
  const build = async () => {
    setBusy(true)
    try {
      const r = await buildChains(kase, { seedMinRisk: minRisk, windowHours: hours })
      setRes(r)
      setOpen(r.chains[0]?.id ?? null)
      setStepIdx(null)
      bump()
      toast(
        r.chains.length ? 'ok' : 'warn',
        `${r.chains.length} chain(s) from ${r.stats.seeds} seed mail(s), ${r.stats.events} event(s) of ${r.stats.identities} identit${r.stats.identities === 1 ? 'y' : 'ies'}${r.stats.eventsTruncated ? ` · only the first ${EVENT_CAP.toLocaleString()} events of the window were considered: narrow the window or the seed threshold` : ''}`,
      )
    } catch (e) {
      toast('err', `chains: ${(e as Error).message}`, 0)
    } finally {
      setBusy(false)
    }
  }
  const openRows = (s: ChainStep) => {
    if (s.kind === 'mail' && s.id != null) {
      setFocus({ source: 'mails', id: s.id })
      setView('mails')
      return
    }
    const ids = (s.refs?.length ? s.refs : s.id != null ? [s.id] : []).slice(0, 500)
    if (!ids.length) return
    if (ids.length === 1) {
      setFocus({ source: 'events', id: ids[0] })
      setView('events')
      return
    }
    setEventsFilter({ conditions: [{ field: 'id', op: 'in', value: ids }], sort: { field: 'ts', dir: 'asc' } })
    setView('events')
  }
  const ask = (c: Chain) => {
    setAiPrompt(
      `Walk me through attack chain ${c.id} for ${c.identityLabel} (score ${c.score}, ${c.steps.length} steps from ${new Date(c.start).toISOString()} to ${new Date(c.end).toISOString()}). Seed mail id ${c.seed.id} "${c.seed.subject}" from ${c.seed.fromAddr}. Steps: ${c.steps
        .slice(0, 25)
        .map((s) => `${offset(s.offsetMin)} ${s.title}${s.artifacts.length ? ' [' + s.artifacts.join('; ') + ']' : ''}`)
        .join(' | ')}. Which steps confirm compromise, which are routine, and what should be checked or contained next?`,
    )
    setView('ai')
  }
  const stepPane = chain && step && (
    <div className="pane-side">
      <div className="col" style={{ gap: 14 }}>
        <div className="section">
          <h3>
            Step {stepIdx! + 1} of {chain.steps.length}
          </h3>
          <div style={{ fontWeight: 500, color: 'var(--fg-1)' }}>{step.title}</div>
          <div className="kv">
            <div className="k">source</div>
            <div className="v">{KIND_LABEL[stepKind(step)]}</div>
            <div className="k">time</div>
            <div className="v">
              {fmtTs(step.ts)}
              {step.tsEnd && step.tsEnd > step.ts ? ` → ${fmtTs(step.tsEnd)}` : ''}
            </div>
            <div className="k">offset</div>
            <div className="v">{offset(step.offsetMin)} from the seed mail</div>
            <div className="k">rows</div>
            <div className="v">{fmtNum(step.count)}</div>
            {step.operation != null && (
              <>
                <div className="k">operation</div>
                <div className="v">{String(step.operation)}</div>
              </>
            )}
            {step.computer && (
              <>
                <div className="k">computer</div>
                <div className="v click" onClick={() => setEntity({ kind: 'host', value: step.computer! })}>
                  {step.computer}
                </div>
              </>
            )}
            {step.ipAddress && (
              <>
                <div className="k">ip</div>
                <div className="v click" onClick={() => setEntity({ kind: 'ip', value: step.ipAddress! })}>
                  {step.ipAddress}
                </div>
              </>
            )}
            <div className="k">weight</div>
            <div className="v">+{step.weight} to the chain score</div>
          </div>
        </div>
        <div className="section">
          <h3>Why it is in the chain</h3>
          {!step.artifacts.length && !step.findings.length && <div className="muted small">same identity inside the window, no artifact link and no finding (routine step, low weight)</div>}
          {step.artifacts.map((a, j) => (
            <div key={j} className="row" style={{ gap: 6 }}>
              <Dot sev={strongArtifact(a) ? 'critical' : 'high'} />
              <span className="small">{a}</span>
            </div>
          ))}
          {step.findings.map((f) => (
            <div key={f.ruleId} className="row" style={{ gap: 6 }}>
              <Dot sev={f.severity} />
              <span className="small">{f.title}</span>
              <span className="mono small muted">{f.ruleId}</span>
            </div>
          ))}
        </div>
        <div className="row" style={{ gap: 6 }}>
          <button className="btn sm" onClick={() => openRows(step)}>
            open {step.kind === 'mail' ? 'the mail' : `${fmtNum(Math.min(step.count, 500))} row(s)`}
          </button>
          <AddToTimeline
            ts={step.ts}
            text={`${chain.identityLabel}: ${step.title}${step.artifacts.length ? ' (' + step.artifacts.join('; ') + ')' : ''}`}
            link={{
              source: step.kind === 'mail' && step.id != null ? 'mails' : 'chains',
              id: step.kind === 'mail' && step.id != null ? step.id : `${chain.id}#${stepIdx}`,
              label: step.kind === 'mail' ? step.title : `${chain.identityLabel} step ${stepIdx! + 1}`,
            }}
            severity={step.findings[0]?.severity ?? (step.artifacts.length ? 'high' : 'info')}
          />
          <button className="btn sm ghost" onClick={() => setStepIdx(null)}>
            close
          </button>
        </div>
        <div className="hint">j / k move between steps</div>
      </div>
    </div>
  )
  const sevCounts = (res?.chains ?? []).reduce<Record<string, number>>((m, c) => ((m[c.severity] = (m[c.severity] ?? 0) + 1), m), {})
  return (
    <div className="view">
      <div className="view-header">
        <div className="desc">
          <h1>Attack chains</h1>
          <span className="sub">
            {res
              ? `${res.chains.length} chain(s) · ${
                  Object.entries(sevCounts)
                    .map(([k, v]) => `${v} ${k}`)
                    .join(', ') || 'none'
                } · built ${res.builtAt ? fmtTs(res.builtAt) : ''}`
              : 'not built yet - run the rules first so their findings attach to the steps'}
          </span>
        </div>
        <span className="spacer" />
        <label className="row" style={{ gap: 6 }}>
          <span className="muted small">seed risk ≥</span>
          <input className="input" type="number" style={{ width: 60 }} value={minRisk} min={0} max={100} onChange={(e) => setMinRisk(Number(e.target.value))} />
        </label>
        <label className="row" style={{ gap: 6 }}>
          <span className="muted small">window</span>
          <input className="input" type="number" style={{ width: 60 }} value={hours} min={1} max={720} onChange={(e) => setHours(Number(e.target.value))} />
          <span className="muted small">h</span>
        </label>
        <button className="btn sm primary" onClick={build} disabled={busy}>
          {busy ? <Spinner /> : <IconPlay />} build chains
        </button>
      </div>
      <div className="split" style={{ gridTemplateColumns: '320px 1fr' }}>
        <div className="left">
          {!res && (
            <div className="muted small" style={{ padding: 14, lineHeight: 1.5 }}>
              A chain starts from a suspicious mail (risk above the threshold, or carrying a medium+ finding) and follows what its recipient did next across the mailbox, Microsoft 365 / Entra audit
              rows and Windows events: replies to the sender, sign-ins, mailbox rules, consent grants, role changes, processes spawned by Outlook or a browser, DNS queries and files that name the
              mail's links or attachments.
            </div>
          )}
          {res && res.chains.length === 0 && (
            <div className="muted small" style={{ padding: 14 }}>
              No chain: no recipient of a seed mail has correlated activity in the window.
            </div>
          )}
          {res?.chains.map((c) => (
            <div
              key={c.id}
              className={'group-row' + (open === c.id ? ' active' : '')}
              style={{ display: 'grid', gridTemplateColumns: '14px 1fr auto', gap: '2px 10px', padding: '10px 14px', cursor: 'pointer', alignItems: 'start' }}
              onClick={() => {
                setOpen(c.id)
                setStepIdx(null)
              }}
            >
              <Dot sev={c.severity} />
              <div style={{ minWidth: 0 }}>
                <div className="ellipsis" style={{ fontWeight: 600, color: 'var(--fg-1)' }}>
                  {c.identityLabel}
                </div>
                <div className="ellipsis small" style={{ color: 'var(--fg-2)' }}>
                  {c.seed.subject || '(no subject)'}
                </div>
                <div className="small mono" style={{ color: 'var(--fg-3)' }}>
                  {fmtTs(c.start)} · {span(c.end - c.start)}
                </div>
              </div>
              <div className="col" style={{ alignItems: 'flex-end', gap: 2 }}>
                <span className="mono" style={{ fontWeight: 600, color: 'var(--fg-1)' }}>
                  {c.score}
                </span>
                <span className="small mono" style={{ color: 'var(--fg-3)' }}>
                  {c.steps.length} steps
                </span>
                <span className="small mono" style={{ color: c.artifactLinks ? 'var(--accent)' : 'var(--fg-3)' }}>
                  {c.artifactLinks} links
                </span>
              </div>
            </div>
          ))}
        </div>
        <div className="right">
          {!chain && (
            <div className="muted" style={{ padding: 24 }}>
              {res?.chains.length ? 'select a chain' : ''}
            </div>
          )}
          {chain && (
            <>
              <div style={{ padding: '12px 16px 8px', borderBottom: '1px solid var(--line)', background: 'var(--surface)' }}>
                <div className="row" style={{ gap: 10, alignItems: 'flex-start' }}>
                  <Sev sev={chain.severity} />
                  <div className="col" style={{ gap: 3, flex: 1, minWidth: 0 }}>
                    <div style={{ fontWeight: 600, color: 'var(--fg-1)', fontSize: 14 }}>
                      <span className="click" style={{ cursor: 'pointer' }} onClick={() => setEntity({ kind: 'user', value: chain.entities.user || chain.identityLabel })} title="open the user page">
                        {chain.identityLabel}
                      </span>
                      <span
                        className="muted"
                        style={{ fontWeight: 400 }}
                        title={
                          chain.scoreBreakdown
                            ? `seed ${chain.scoreBreakdown.seed} + links ${chain.scoreBreakdown.links} + steps ${chain.scoreBreakdown.steps} + findings ${chain.scoreBreakdown.findings} + sources ${chain.scoreBreakdown.sources}${chain.scoreBreakdown.cap ? ` · capped at ${chain.scoreBreakdown.cap}: no artifact ties the activity to the mail` : ''}`
                            : undefined
                        }
                      >
                        {' '}
                        · score {chain.score} · {chain.steps.length} steps over {span(chain.end - chain.start)} · {chain.artifactLinks} artifact link(s)
                      </span>
                    </div>
                    <div className="small" style={{ color: 'var(--fg-2)' }}>
                      {chain.summary}
                    </div>
                  </div>
                  <AddToTimeline
                    ts={chain.start}
                    text={`Attack chain ${chain.identityLabel}: ${chain.summary}`}
                    link={{ source: 'chains', id: chain.id, label: chain.identityLabel }}
                    severity={chain.severity}
                  />
                  <button className="btn sm" onClick={() => ask(chain)}>
                    <IconAi /> ask the analyst
                  </button>
                </div>
                {chain.scoreBreakdown && (
                  <div
                    className="row wrap small mono"
                    style={{ gap: 10, marginTop: 6, color: 'var(--fg-3)' }}
                    title="how the score is built: each part is bounded, so long windows of routine activity do not saturate it"
                  >
                    <span>score {chain.score} =</span>
                    <span>seed {chain.scoreBreakdown.seed}/30</span>
                    <span>links {chain.scoreBreakdown.links}/30</span>
                    <span>steps {chain.scoreBreakdown.steps}/20</span>
                    <span>findings {chain.scoreBreakdown.findings}/15</span>
                    <span>sources {chain.scoreBreakdown.sources}/5</span>
                    {chain.scoreBreakdown.cap ? <span style={{ color: 'var(--sev-medium)' }}>capped at {chain.scoreBreakdown.cap}: nothing ties the activity to the mail</span> : null}
                  </div>
                )}
                <div className="row wrap small" style={{ gap: 6, marginTop: 8 }}>
                  {chain.seed.fromAddr && (
                    <span className="pill" onClick={() => setEntity({ kind: 'address', value: chain.seed.fromAddr! })} title="seed sender">
                      <IconMail /> {chain.seed.fromAddr}
                    </span>
                  )}
                  {chain.entities.attackerAddresses
                    .filter((a) => a !== chain.seed.fromAddr)
                    .map((a) => (
                      <span key={a} className="pill" onClick={() => setEntity({ kind: 'address', value: a })} title="attacker address">
                        <IconMail /> {a}
                      </span>
                    ))}
                  {chain.entities.ips.map((ip) => (
                    <span key={ip} className="pill" onClick={() => setEntity({ kind: 'ip', value: ip })} title="IP seen in the chain">
                      {ip}
                    </span>
                  ))}
                  {chain.entities.hosts.map((h) => (
                    <span key={h} className="pill" onClick={() => setEntity({ kind: 'host', value: h })} title="host seen in the chain">
                      <IconHost /> {h}
                    </span>
                  ))}
                  {chain.entities.domains.slice(0, 6).map((d) => (
                    <span key={d} className="pill" onClick={() => setEntity({ kind: 'domain', value: d })} title="domain from the seed mail">
                      {d}
                    </span>
                  ))}
                  {(chain.relatedSeeds?.length ?? 0) > 0 && <span className="muted">+{chain.relatedSeeds!.length} related mail(s) to the same identity</span>}
                </div>
              </div>
              <Tabs
                tabs={[
                  { id: 'story' as const, label: 'Story' },
                  { id: 'graph' as const, label: 'Graph' },
                  { id: 'entities' as const, label: 'Seed' },
                  { id: 'json' as const, label: 'JSON' },
                ]}
                active={tab}
                onChange={setTab}
              />
              {tab === 'story' && (
                <div className="pane" style={{ flex: 1, height: 'auto', borderTop: 0, gridTemplateColumns: step ? '1fr 340px' : '1fr' }}>
                  <div className="pane-main" style={{ overflow: 'auto' }}>
                    <div className="story">
                      <div
                        className="step"
                        onClick={() => {
                          setFocus({ source: 'mails', id: chain.seed.id })
                          setView('mails')
                        }}
                        title="open the seed mail"
                      >
                        <span className="t">
                          {fmtTs(chain.seed.ts)}
                          <br />
                          <span style={{ color: 'var(--accent)' }}>seed</span>
                        </span>
                        <span className="n mail" title="mailbox">
                          <IconMail />
                        </span>
                        <span>
                          <div className="title">
                            {chain.seed.subject || '(no subject)'} <Badge sev={chain.seed.risk >= 80 ? 'critical' : chain.seed.risk >= 60 ? 'high' : 'medium'}>risk {chain.seed.risk}</Badge>
                          </div>
                          <div className="sub">
                            from {chain.seed.fromAddr}
                            {chain.seed.urlDomains.length ? ` · links ${chain.seed.urlDomains.join(', ')}` : ''}
                            {chain.seed.attachments.length ? ` · attachments ${chain.seed.attachments.join(', ')}` : ''}
                          </div>
                          <div className="row wrap" style={{ gap: 4, marginTop: 3 }}>
                            {chain.seed.findings.map((f) => (
                              <Badge key={f.ruleId} sev={f.severity} title={f.title}>
                                {f.ruleId}
                              </Badge>
                            ))}
                          </div>
                        </span>
                      </div>
                      {chain.steps.map((s, i) => {
                        const k = stepKind(s)
                        const Icon = KIND_ICON[k]
                        return (
                          <div key={i} className={'step' + (stepIdx === i ? ' active' : '')} onClick={() => setStepIdx(i)}>
                            <span className="t">
                              {fmtTs(s.ts)}
                              <br />
                              <span>{offset(s.offsetMin)}</span>
                            </span>
                            <span className={'n ' + k} title={KIND_LABEL[k]}>
                              <Icon />
                            </span>
                            <span>
                              <div className="title">
                                {s.title}
                                {s.count > 1 && (
                                  <span className="muted" style={{ fontWeight: 400 }}>
                                    {' '}
                                    ×{fmtNum(s.count)}
                                  </span>
                                )}
                              </div>
                              <div className="sub">
                                {[s.computer, s.ipAddress].filter(Boolean).join(' · ')}
                                {s.tsEnd && s.tsEnd > s.ts ? ` · until ${fmtTs(s.tsEnd)}` : ''}
                              </div>
                              {(s.artifacts.length > 0 || s.findings.length > 0) && (
                                <div className="row wrap" style={{ gap: 4, marginTop: 3 }}>
                                  {s.artifacts.map((a, j) => (
                                    <Badge key={j} sev={strongArtifact(a) ? 'critical' : 'high'} title="what ties this step to the seed mail">
                                      {a}
                                    </Badge>
                                  ))}
                                  {s.findings.map((f) => (
                                    <Badge key={f.ruleId} sev={f.severity} title={f.title}>
                                      {f.ruleId}
                                    </Badge>
                                  ))}
                                </div>
                              )}
                            </span>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                  {stepPane}
                </div>
              )}
              {tab === 'graph' && (
                <div className="pane" style={{ flex: 1, height: 'auto', borderTop: 0, gridTemplateColumns: step && graphMode === 'chain' ? '1fr 340px' : '1fr' }}>
                  <div className="pane-main" style={{ overflow: 'hidden' }}>
                    <div className="row" style={{ padding: '6px 12px', gap: 10, borderBottom: '1px solid var(--line)' }}>
                      <div className="segmented">
                        <button className={graphMode === 'chain' ? 'active' : ''} onClick={() => setGraphMode('chain')}>
                          this chain
                        </button>
                        <button className={graphMode === 'campaign' ? 'active' : ''} onClick={() => setGraphMode('campaign')}>
                          all chains
                        </button>
                      </div>
                      <span className="small muted">
                        {graphMode === 'chain'
                          ? 'time runs left to right, one lane per source; routine runs are folded into one node'
                          : `${res?.chains.length ?? 0} chains against the sender addresses, link domains, IPs and hosts they share`}
                      </span>
                    </div>
                    <ChainGraph mode={graphMode} chain={chain} chains={res?.chains ?? []} selectedStep={stepIdx} onStep={setStepIdx} onEntity={setEntity} onChain={openChainFromGraph} />
                  </div>
                  {graphMode === 'chain' && stepPane}
                </div>
              )}
              {tab === 'entities' && (
                <div className="view-body">
                  <div className="section">
                    <h3>Seed mail</h3>
                    <div className="kv">
                      <div className="k">subject</div>
                      <div
                        className="v click"
                        onClick={() => {
                          setFocus({ source: 'mails', id: chain.seed.id })
                          setView('mails')
                        }}
                      >
                        {chain.seed.subject || '(no subject)'}
                      </div>
                      <div className="k">from</div>
                      <div className="v click" onClick={() => chain.seed.fromAddr && setEntity({ kind: 'address', value: chain.seed.fromAddr })}>
                        {chain.seed.fromAddr}
                      </div>
                      <div className="k">date</div>
                      <div className="v">{fmtTs(chain.seed.ts)}</div>
                      <div className="k">risk</div>
                      <div className="v">{chain.seed.risk}</div>
                      <div className="k">flags</div>
                      <div className="v">{chain.seed.flags.join(', ') || '—'}</div>
                      <div className="k">links</div>
                      <div className="v">{chain.seed.urlDomains.join(', ') || '—'}</div>
                      <div className="k">attachments</div>
                      <div className="v">{chain.seed.attachments.join(', ') || '—'}</div>
                      <div className="k">findings</div>
                      <div className="v">{chain.seed.findings.map((f) => `${f.ruleId} (${f.severity})`).join(', ') || '—'}</div>
                    </div>
                  </div>
                  {(chain.relatedSeeds?.length ?? 0) > 0 && (
                    <div className="section" style={{ marginTop: 16 }}>
                      <h3>Related mails to the same identity</h3>
                      <table className="table compact">
                        <thead>
                          <tr>
                            <th>date (UTC)</th>
                            <th>risk</th>
                            <th>from</th>
                            <th>subject</th>
                          </tr>
                        </thead>
                        <tbody>
                          {chain.relatedSeeds!.map((s) => (
                            <tr
                              key={s.id}
                              style={{ cursor: 'pointer' }}
                              onClick={() => {
                                setFocus({ source: 'mails', id: s.id })
                                setView('mails')
                              }}
                            >
                              <td className="nowrap">{fmtTs(s.ts)}</td>
                              <td>{s.risk}</td>
                              <td>{s.fromAddr}</td>
                              <td className="sans">{s.subject}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
              {tab === 'json' && (
                <div className="view-body">
                  <pre className="codeblock">{JSON.stringify(chain, null, 2)}</pre>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
