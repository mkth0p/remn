import { useCallback, useEffect, useMemo, useState } from 'react'
import { Badge, Dot, Empty, Sev } from '../components/ui'
import { ChainGraph } from '../components/ChainGraph'
import { loadChains, type ChainResult, type ChainStep } from '../data/chains'
import { useStore } from '../state/store'
import { fmtNum, fmtTs } from '../util/format'

type Mode = 'chain' | 'campaign'

const stepSource = (s: ChainStep): string => (s.kind === 'mail' ? 'mailbox' : s.origin === 'm365' ? 'Microsoft 365 / Entra' : 'Windows host')
const strongArtifact = (a: string) => a.startsWith('mail ') || a.includes('thread') || a.includes('engaged')

function span(ms: number): string {
  const m = ms / 60_000
  return m < 90 ? `${Math.round(m)} min` : m < 48 * 60 ? `${(m / 60).toFixed(1)} h` : `${(m / 1440).toFixed(1)} d`
}

/**
 * The attack chains the story build keeps, drawn as graphs: one chain as a swimlane of its steps,
 * or all chains against the senders, link domains, IPs and hosts they share. The left rail lists
 * the chains, the right pane details the selected step and opens its rows.
 */
export function GraphView() {
  const kase = useStore((s) => s.currentCase)
  const setView = useStore((s) => s.setView)
  const setFocus = useStore((s) => s.setFocus)
  const setEventsFilter = useStore((s) => s.setEventsFilter)
  const setEntity = useStore((s) => s.setEntity)
  const [res, setRes] = useState<ChainResult | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [open, setOpen] = useState<string | null>(null)
  const [stepIdx, setStepIdx] = useState<number | null>(null)
  const [mode, setMode] = useState<Mode>('chain')

  useEffect(() => {
    if (!kase?.id) return
    let alive = true
    loadChains(kase.id).then((r) => {
      if (!alive) return
      const want = useStore.getState().focusChain
      const hit = want && r?.chains.some((c) => c.id === want) ? want : null
      if (hit) useStore.getState().setFocusChain(null)
      setRes(r)
      setOpen(hit ?? r?.chains[0]?.id ?? null)
      setStepIdx(null)
      setLoaded(true)
    })
    return () => {
      alive = false
    }
  }, [kase?.id])

  const chains = useMemo(() => res?.chains ?? [], [res])
  const chain = useMemo(() => chains.find((c) => c.id === open) ?? null, [chains, open])
  const step = chain && stepIdx != null ? (chain.steps[stepIdx] ?? null) : null

  // keyboard: j / k move between steps of the open chain
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null
      if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable)) return
      if (!chain || mode !== 'chain' || (e.key !== 'j' && e.key !== 'k')) return
      const i = stepIdx ?? -1
      setStepIdx(e.key === 'j' ? Math.min(chain.steps.length - 1, i + 1) : Math.max(0, i - 1))
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [chain, stepIdx, mode])

  const selectChain = useCallback((id: string) => {
    setOpen(id)
    setStepIdx(null)
  }, [])
  const openChainFromGraph = useCallback((id: string) => {
    setOpen(id)
    setStepIdx(null)
    setMode('chain')
  }, [])

  if (!kase) return null

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

  const stepPane = chain && step && (
    <div className="pane-side" aria-label="Selected step">
      <div className="col" style={{ gap: 14 }}>
        <div className="section">
          <h3>
            Step {stepIdx! + 1} of {chain.steps.length}
          </h3>
          <div style={{ fontWeight: 500, color: 'var(--fg-1)' }}>{step.title}</div>
          <div className="kv">
            <div className="k">source</div>
            <div className="v">{stepSource(step)}</div>
            <div className="k">time</div>
            <div className="v">
              {fmtTs(step.ts)}
              {step.tsEnd && step.tsEnd > step.ts ? ` → ${fmtTs(step.tsEnd)}` : ''}
            </div>
            <div className="k">rows</div>
            <div className="v">{fmtNum(step.count)}</div>
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
          </div>
        </div>
        <div className="section">
          <h3>Why it is in the chain</h3>
          {!step.artifacts.length && !step.findings.length && <div className="muted small">same identity inside the window, no artifact link and no finding (routine step)</div>}
          {step.artifacts.length > 0 && (
            <div className="row wrap" style={{ gap: 4 }}>
              {step.artifacts.map((a, j) => (
                <Badge key={j} sev={strongArtifact(a) ? 'critical' : 'high'} title="what ties this step to the seed">
                  {a}
                </Badge>
              ))}
            </div>
          )}
          {step.findings.map((f) => (
            <div key={f.ruleId} className="row" style={{ gap: 6, marginTop: 4 }}>
              <Badge sev={f.severity} title={f.title}>
                {f.ruleId}
              </Badge>
              <span className="small">{f.title}</span>
            </div>
          ))}
        </div>
        <div className="row" style={{ gap: 6 }}>
          <button className="btn sm" onClick={() => openRows(step)}>
            Open {step.kind === 'mail' ? 'the mail' : `${fmtNum(Math.min(step.count, 500))} row(s)`}
          </button>
          <button className="btn sm ghost" onClick={() => setStepIdx(null)}>
            close
          </button>
        </div>
        <div className="hint">j / k move between steps</div>
      </div>
    </div>
  )

  return (
    <div className="view">
      <div className="view-header">
        <div className="desc">
          <h1>Graph</h1>
          <span className="sub">{res ? `${chains.length} chain(s) · built ${res.builtAt ? fmtTs(res.builtAt) : ''}` : loaded ? 'no chains yet' : ''}</span>
        </div>
      </div>
      {loaded && !chains.length ? (
        <Empty title="No chains to draw" hint="The graphs are drawn from the attack chains that building the stories keeps. Build the stories first, then come back here.">
          <button className="btn sm primary" onClick={() => setView('stories')}>
            Go to Stories
          </button>
        </Empty>
      ) : (
        <div className="split" style={{ gridTemplateColumns: '300px 1fr' }}>
          <div className="left">
            {chains.map((c) => (
              <div key={c.id} className={'story-row' + (open === c.id ? ' active' : '')} onClick={() => selectChain(c.id)} role="button" aria-label={`Chain ${c.identityLabel}`}>
                <Dot sev={c.severity} />
                <div style={{ minWidth: 0 }}>
                  <div className="ellipsis name">{c.identityLabel}</div>
                  <div className="ellipsis small" style={{ color: 'var(--fg-2)' }} title={c.summary}>
                    {c.seed.subject || c.summary || '(no subject)'}
                  </div>
                  <div className="small mono" style={{ color: 'var(--fg-3)' }}>
                    {fmtTs(c.start)} · {span(c.end - c.start)}
                  </div>
                </div>
                <div className="meta">
                  <span className="score">{c.score}</span>
                  <span>{c.steps.length} steps</span>
                </div>
              </div>
            ))}
          </div>
          <div className="right">
            {chain && (
              <div className="row" style={{ padding: '10px 16px', gap: 10, borderBottom: '1px solid var(--line)', background: 'var(--surface)' }}>
                <Sev sev={chain.severity} />
                <span style={{ fontWeight: 600, color: 'var(--fg-1)' }}>{chain.identityLabel}</span>
                <span className="muted small ellipsis">
                  score {chain.score} · {chain.steps.length} steps over {span(chain.end - chain.start)}
                </span>
              </div>
            )}
            <div className="pane" style={{ flex: 1, height: 'auto', borderTop: 0, gridTemplateColumns: step && mode === 'chain' ? '1fr 340px' : '1fr' }}>
              <div className="pane-main" style={{ overflow: 'hidden' }}>
                <div className="row" style={{ padding: '6px 12px', gap: 10, borderBottom: '1px solid var(--line)' }}>
                  <div className="segmented">
                    <button className={mode === 'chain' ? 'active' : ''} onClick={() => setMode('chain')}>
                      this chain
                    </button>
                    <button className={mode === 'campaign' ? 'active' : ''} onClick={() => setMode('campaign')}>
                      all chains
                    </button>
                  </div>
                  <span className="small muted">
                    {mode === 'chain'
                      ? 'time runs left to right, one lane per source; routine runs are folded into one node'
                      : `${chains.length} chains against the sender addresses, link domains, IPs and hosts they share`}
                  </span>
                </div>
                {loaded && <ChainGraph mode={mode} chain={chain} chains={chains} selectedStep={stepIdx} onStep={setStepIdx} onEntity={setEntity} onChain={openChainFromGraph} />}
              </div>
              {mode === 'chain' && stepPane}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
