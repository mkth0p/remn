import { Fragment, useEffect, useState, type ReactNode } from 'react'
import type { Severity } from '../db/schema'
import { classNames, highlightJson, riskClass } from '../util/format'
import { IconClose, IconCopy } from './Icons'
import { useStore } from '../state/store'

export function Badge({ sev, children, className, title }: { sev?: Severity | 'ok' | 'accent' | 'flag' | string; children: ReactNode; className?: string; title?: string }) {
  return (
    <span className={classNames('badge', sev, className)} title={title}>
      {children}
    </span>
  )
}

export function Risk({ value }: { value: number | null | undefined }) {
  return <span className={classNames('risk', riskClass(value))}>{value ?? 0}</span>
}

export function Flag({ name }: { name: string }) {
  const meta = useStore((s) => s.meta)
  const base = name.replace(/^(att_|nested_|archive_entry_|sender_|replyto_|url_)/, '')
  const desc = meta?.flags[name] ?? meta?.flags[base] ?? name
  return (
    <span className="badge flag info" title={`Observation: ${desc} Severity depends on the message context; this flag alone is not a verdict.`}>
      {name}
    </span>
  )
}

export function Chip({ children, onRemove, neg, title }: { children: ReactNode; onRemove?: () => void; neg?: boolean; title?: string }) {
  return (
    <span className={classNames('chip', neg && 'neg')} title={title}>
      {children}
      {onRemove && (
        <span className="x" onClick={onRemove} role="button" aria-label="remove">
          ×
        </span>
      )}
    </span>
  )
}

export function Toggle({ on, onChange, label }: { on: boolean; onChange: (v: boolean) => void; label?: ReactNode }) {
  return (
    <label className="row" style={{ cursor: 'pointer', gap: 8 }}>
      <span className={classNames('toggle', on && 'on')} onClick={() => onChange(!on)} role="switch" aria-checked={on} />
      {label && <span className="dim small">{label}</span>}
    </label>
  )
}

export function Spinner() {
  return <span className="spinner" />
}

export function Progress({ value, indeterminate }: { value?: number; indeterminate?: boolean }) {
  return (
    <div className={classNames('progress', indeterminate && 'indeterminate')}>
      <div style={{ width: `${Math.round(Math.max(0, Math.min(1, value ?? 0)) * 100)}%` }} />
    </div>
  )
}

export function Modal({ title, onClose, children, footer, wide }: { title: ReactNode; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [onClose])
  return (
    <div className="modal-bg" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" style={wide ? { width: 'min(1000px, 94vw)' } : undefined}>
        <div className="modal-h">
          <h2 style={{ flex: 1 }}>{title}</h2>
          <button className="btn ghost sm" onClick={onClose} aria-label="close">
            <IconClose />
          </button>
        </div>
        <div className="modal-b">{children}</div>
        {footer && <div className="modal-f">{footer}</div>}
      </div>
    </div>
  )
}

export function Tabs<T extends string>({ tabs, active, onChange }: { tabs: { id: T; label: ReactNode }[]; active: T; onChange: (t: T) => void }) {
  return (
    <div className="tabs">
      {tabs.map((t) => (
        <button key={t.id} className={classNames('tab', active === t.id && 'active')} onClick={() => onChange(t.id)}>
          {t.label}
        </button>
      ))}
    </div>
  )
}

export function KV({ items, onPivot }: { items: [string, unknown][]; onPivot?: (value: string, key: string) => void }) {
  return (
    <div className="kv">
      {items
        .filter(([, v]) => v != null && v !== '' && !(Array.isArray(v) && !v.length))
        .map(([k, v]) => {
          const s = typeof v === 'object' ? JSON.stringify(v) : String(v)
          return (
            <Fragment key={k}>
              <div className="k">{k}</div>
              <div className={classNames('v', onPivot && 'click')} onClick={() => onPivot?.(s, k)} title={onPivot ? 'pivot on this value' : undefined}>
                {s}
              </div>
            </Fragment>
          )
        })}
    </div>
  )
}

export function JsonView({ value }: { value: unknown }) {
  return <pre className="json" dangerouslySetInnerHTML={{ __html: highlightJson(value) }} />
}

export function Empty({ title, hint, children }: { title: string; hint?: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <div className="big">{title}</div>
      {hint && <div>{hint}</div>}
      {children && <div style={{ marginTop: 12 }}>{children}</div>}
    </div>
  )
}

export function CopyButton({ text, label }: { text: string; label?: string }) {
  const [ok, setOk] = useState(false)
  return (
    <button
      className="btn ghost xs"
      title="copy"
      onClick={() => {
        const flash = () => {
          setOk(true)
          setTimeout(() => setOk(false), 1200)
        }
        if (navigator.clipboard?.writeText) {
          navigator.clipboard.writeText(text).then(flash)
        } else {
          // plain-http remote access: no async clipboard - legacy path
          const ta = document.createElement('textarea')
          ta.value = text
          ta.style.position = 'fixed'
          ta.style.opacity = '0'
          document.body.appendChild(ta)
          ta.select()
          try {
            document.execCommand('copy')
            flash()
          } finally {
            ta.remove()
          }
        }
      }}
    >
      <IconCopy /> {ok ? 'copied' : label}
    </button>
  )
}

export function SevBar({ counts }: { counts: Record<string, number> }) {
  const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
  const total = order.reduce((s, k) => s + (counts[k] ?? 0), 0) || 1
  return (
    <div className="severity-bar" title={order.map((k) => `${k}: ${counts[k] ?? 0}`).join(' · ')}>
      {order.map((k) => (
        <div key={k} style={{ width: `${((counts[k] ?? 0) / total) * 100}%`, background: `var(--sev-${k})` }} />
      ))}
    </div>
  )
}

export function ListInput({ value, onChange, placeholder, mono }: { value: string[]; onChange: (v: string[]) => void; placeholder?: string; mono?: boolean }) {
  const [text, setText] = useState(value.join('\n'))
  useEffect(() => setText(value.join('\n')), [value])
  return (
    <textarea
      className={classNames('textarea', mono && 'mono')}
      value={text}
      placeholder={placeholder}
      onChange={(e) => setText(e.target.value)}
      onBlur={() => onChange(text.split(/[\n,;]+/).map((s) => s.trim()).filter(Boolean))}
    />
  )
}
