import { useEffect, useRef } from 'react'
import { useStore } from '../state/store'
import { fmtBytes, fmtNum } from '../util/format'
import { Progress } from './ui'

export function Jobs() {
  const jobs = useStore((s) => s.jobs)
  if (!jobs.length) return null
  return (
    <div className="col" style={{ gap: 6 }}>
      {jobs.map((j) => (
        <div key={j.id} className="card" style={{ padding: '8px 12px' }}>
          <div className="row small">
            <span className="mono ellipsis" style={{ maxWidth: 260 }}>
              {j.name}
            </span>
            <span className="badge">{j.kind}</span>
            <span className="dim">{j.phase}</span>
            <span className="spacer" />
            <span className="mono dim">{j.phase === 'hashing' ? `${Math.round(j.progress * 100)}%` : `${fmtNum(j.rows)} rows${j.bytes ? ` · ${fmtBytes(j.bytes)}` : ''}`}</span>
          </div>
          {j.phase !== 'done' && j.phase !== 'error' && (
            <div style={{ marginTop: 6 }}>
              <Progress value={j.phase === 'hashing' ? j.progress : undefined} indeterminate={j.phase !== 'hashing'} />
            </div>
          )}
          {j.error && (
            <div className="small" style={{ color: 'var(--danger)', marginTop: 4 }}>
              {j.error}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

export function ConsolePanel() {
  const lines = useStore((s) => s.console)
  const clear = useStore((s) => s.clearConsole)
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight
  }, [lines.length])
  return (
    <div className="panel">
      <div className="panel-h">
        console
        <span className="spacer" />
        <button className="btn xs ghost" onClick={clear}>
          clear
        </button>
      </div>
      <div className="console" ref={ref}>
        {!lines.length && <div className="l muted">ready.</div>}
        {lines.map((l) => (
          <div key={l.id} className={`l ${l.level}`}>
            <span className="muted">{new Date(l.ts).toISOString().slice(11, 19)}</span> {l.text}
          </div>
        ))}
      </div>
    </div>
  )
}

export function Toasts() {
  const toasts = useStore((s) => s.toasts)
  const dismiss = useStore((s) => s.dismissToast)
  return (
    <div className="toasts">
      {toasts.map((t) => (
        <div key={t.id} className={`toast ${t.kind}`} onClick={() => dismiss(t.id)}>
          {t.text}
        </div>
      ))}
    </div>
  )
}
