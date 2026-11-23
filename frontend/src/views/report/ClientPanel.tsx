import { useState } from 'react'
import { type EvidenceScope, initialAccessIsDraft } from '../../data/reportHtml'
import { LOGO_MAX_BYTES, logoImage, REPORT_LANGUAGES, type ReportLanguage } from '../../data/reportText'
import { type AnalyticConfidence, type ClientReport, type ContainmentAction, type ReportBranding, type ReportVersion, type Tlp, TLP_LEVELS } from '../../data/review'
import { fmtNum, fmtUtc } from '../../util/format'

type TextKey = { [K in keyof ClientReport]: ClientReport[K] extends string ? K : never }[keyof ClientReport]
const CONFIDENCES: AnalyticConfidence[] = ['', 'low', 'moderate', 'high']

/**
 * What the analyst writes for a client: the engagement, the handling marking, the scope, the
 * conclusion, the impact, the containment actions and the recommendations. Each part is printed
 * only when filled in; the scope falls back to what the evidence covers, and says so.
 */
export function ClientPanel({
  client,
  onChange,
  language,
  branding,
  onSettings,
  spineDraft,
  scope,
  period,
  impact,
}: {
  client: ClientReport
  onChange: (patch: Partial<ClientReport>) => void
  language: ReportLanguage
  branding: ReportBranding
  onSettings: (patch: { language?: ReportLanguage; branding?: ReportBranding }) => void
  spineDraft: string
  scope: EvidenceScope | undefined
  period: { from: number | null; to: number | null }
  impact: { accounts: unknown[]; hosts: unknown[] }
}) {
  // fields keep what is typed until they lose focus; a value set from outside (the spine's draft) remounts them
  const [round, setRound] = useState(0)
  const set = <K extends keyof ClientReport>(k: K, v: ClientReport[K]) => {
    const patch: Partial<ClientReport> = {}
    patch[k] = v
    onChange(patch)
  }
  const text = (k: TextKey, label: string, opts: { area?: boolean; placeholder?: string; type?: string; rows?: number } = {}) => (
    <label className="col small" style={{ gap: 2 }}>
      <span className="muted">{label}</span>
      {opts.area ? (
        <textarea
          key={`${k}-${round}`}
          className="textarea"
          style={{ minHeight: (opts.rows ?? 3) * 18 }}
          defaultValue={client[k]}
          placeholder={opts.placeholder}
          onBlur={(e) => e.target.value !== client[k] && set(k, e.target.value)}
        />
      ) : (
        <input
          key={`${k}-${round}`}
          className="input small"
          type={opts.type ?? 'text'}
          defaultValue={client[k]}
          placeholder={opts.placeholder}
          onBlur={(e) => e.target.value !== client[k] && set(k, e.target.value)}
        />
      )}
    </label>
  )
  const list = (xs: string[] | undefined, more: boolean | undefined) =>
    xs?.length ? `from the evidence: ${xs.slice(0, 6).join(', ')}${xs.length > 6 || more ? ', …' : ''}` : 'one a line; empty: what the evidence covers'
  const rowsEditor = <T extends ReportVersion | ContainmentAction>(
    key: 'versions' | 'containment',
    rows: T[],
    blank: T,
    cols: { k: keyof T & string; label: string; type?: string; width?: number }[],
  ) => (
    <div className="col" style={{ gap: 4 }}>
      {rows.map((r, i) => (
        <div key={`${key}-${i}-${round}`} className="row" style={{ gap: 4 }}>
          {cols.map((c) => (
            <input
              key={c.k}
              className="input small"
              type={c.type ?? 'text'}
              placeholder={c.label}
              style={{ flex: c.width ? `0 0 ${c.width}px` : 1, minWidth: 0 }}
              defaultValue={String(r[c.k] ?? '')}
              onBlur={(e) => {
                if (e.target.value === String(r[c.k] ?? '')) return
                const next = rows.map((x, j) => (j === i ? { ...x, [c.k]: e.target.value } : x))
                onChange({ [key]: next } as Partial<ClientReport>)
              }}
            />
          ))}
          <button
            className="btn xs"
            title="remove this row"
            onClick={() => {
              onChange({ [key]: rows.filter((_, j) => j !== i) } as Partial<ClientReport>)
              setRound((x) => x + 1)
            }}
          >
            remove
          </button>
        </div>
      ))}
      <div>
        <button className="btn xs" onClick={() => onChange({ [key]: [...rows, blank] } as Partial<ClientReport>)}>
          add a row
        </button>
      </div>
    </div>
  )
  const draftPending = initialAccessIsDraft(client)
  return (
    <div className="panel" data-testid="client-panel">
      <div className="panel-h">
        client report <span className="muted">· printed only where filled in; kept with the case and its bundle</span>
      </div>
      <div className="panel-b" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 14 }}>
        <div className="col" style={{ gap: 6 }}>
          <b className="small">Engagement</b>
          {text('client', 'client')}
          {text('engagementRef', 'engagement reference')}
          <div className="row" style={{ gap: 6 }}>
            {text('engagementStart', 'engagement start', { type: 'date' })}
            {text('engagementEnd', 'engagement end', { type: 'date' })}
          </div>
          {text('requestedBy', 'requested by')}
          {text('distribution', 'distribution', { area: true, placeholder: 'one recipient a line' })}
          <span className="muted small">version history</span>
          {rowsEditor<ReportVersion>('versions', client.versions, { version: '', date: '', author: '', note: '' }, [
            { k: 'version', label: 'version', width: 64 },
            { k: 'date', label: 'date', type: 'date', width: 140 },
            { k: 'author', label: 'author', width: 110 },
            { k: 'note', label: 'changes' },
          ])}
          <b className="small" style={{ marginTop: 8 }}>
            Handling
          </b>
          <label className="col small" style={{ gap: 2 }}>
            <span className="muted">TLP</span>
            <select className="select" value={client.tlp} onChange={(e) => set('tlp', e.target.value as Tlp)}>
              <option value="">none</option>
              {TLP_LEVELS.map((t) => (
                <option key={t} value={t}>
                  TLP:{t.toUpperCase()}
                </option>
              ))}
            </select>
          </label>
          {text('confidentiality', 'confidentiality line', { placeholder: 'printed on the cover and on every page' })}
          <b className="small" style={{ marginTop: 8 }}>
            Language and branding
          </b>
          <label className="col small" style={{ gap: 2 }}>
            <span className="muted">report language (this page stays English)</span>
            <select className="select" value={language} onChange={(e) => onSettings({ language: e.target.value as ReportLanguage })}>
              {REPORT_LANGUAGES.map((l) => (
                <option key={l.id} value={l.id}>
                  {l.label}
                </option>
              ))}
            </select>
          </label>
          <BrandingFields key={round} branding={branding} onChange={(b) => onSettings({ branding: b })} />
        </div>
        <div className="col" style={{ gap: 6 }}>
          <b className="small">Scope</b>
          {text('objectives', 'objectives', { area: true })}
          <div className="row" style={{ gap: 6 }}>
            {text('periodFrom', 'period from', { type: 'date' })}
            {text('periodTo', 'period to', { type: 'date' })}
          </div>
          {period.from != null && !client.periodFrom && !client.periodTo && (
            <span className="hint">
              empty: the evidence's {fmtUtc(period.from, { date: true })} to {fmtUtc(period.to, { date: true })}
            </span>
          )}
          {text('systemsIn', 'systems in scope', { area: true, placeholder: list(scope?.hosts, scope?.hostsCapped) })}
          {text('systemsOut', 'systems out of scope', { area: true, placeholder: 'one a line; empty: none named' })}
          {text('accountsIn', 'accounts in scope', { area: true, placeholder: list(scope?.accounts, scope?.accountsCapped) })}
          {text('accountsOut', 'accounts out of scope', { area: true, placeholder: 'one a line; empty: none named' })}
        </div>
        <div className="col" style={{ gap: 6 }}>
          <b className="small">Conclusion</b>
          {text('initialAccess', 'initial access: how the attacker got in', { area: true, rows: 4 })}
          <div className="row small" style={{ gap: 6 }}>
            <button
              className="btn xs"
              disabled={!spineDraft || !!client.initialAccess.trim()}
              title={!spineDraft ? 'no printed story has a spine' : client.initialAccess.trim() ? 'the field holds text already' : "put the story's spine in the field as a starting point to rewrite"}
              onClick={() => {
                onChange({ initialAccess: spineDraft, initialAccessDraft: spineDraft })
                setRound((x) => x + 1)
              }}
            >
              start from the story spine
            </button>
            {draftPending && <span className="warn">not printed until you rewrite it</span>}
          </div>
          {text('rootCause', 'root cause: why it was possible', { area: true, rows: 4 })}
          <label className="col small" style={{ gap: 2 }}>
            <span className="muted">your confidence in the conclusion (printed as yours)</span>
            <select className="select" value={client.analyticConfidence} onChange={(e) => set('analyticConfidence', e.target.value as AnalyticConfidence)}>
              {CONFIDENCES.map((c) => (
                <option key={c} value={c}>
                  {c || 'not given'}
                </option>
              ))}
            </select>
          </label>
          {client.analyticConfidence && text('confidenceBasis', 'on what it rests')}
          <b className="small" style={{ marginTop: 8 }}>
            Impact
          </b>
          <span className="hint">
            The report lists the {fmtNum(impact.accounts.length)} account(s) and {fmtNum(impact.hosts.length)} host(s) the confirmed items name.
          </span>
          {text('impact', 'what was reached or taken, and the effect on the business', { area: true })}
        </div>
        <div className="col" style={{ gap: 6 }}>
          <b className="small">Containment actions taken</b>
          {rowsEditor<ContainmentAction>('containment', client.containment, { date: '', action: '', by: '' }, [
            { k: 'date', label: 'date', type: 'date', width: 140 },
            { k: 'action', label: 'action' },
            { k: 'by', label: 'by', width: 100 },
          ])}
          <b className="small" style={{ marginTop: 8 }}>
            Recommendations
          </b>
          {text('recShort', 'short term', { area: true })}
          {text('recMedium', 'medium term', { area: true })}
          {text('recLong', 'long term', { area: true })}
        </div>
      </div>
    </div>
  )
}

/** The firm the report goes out under: its name, a line for the cover, and its logo, size-capped and checked before it is kept. */
function BrandingFields({ branding, onChange }: { branding: ReportBranding; onChange: (b: ReportBranding) => void }) {
  const [problem, setProblem] = useState('')
  const field = (k: 'firmName' | 'coverLine', label: string, placeholder: string) => (
    <label className="col small" style={{ gap: 2 }}>
      <span className="muted">{label}</span>
      <input className="input small" defaultValue={branding[k]} placeholder={placeholder} onBlur={(e) => e.target.value !== branding[k] && onChange({ ...branding, [k]: e.target.value })} />
    </label>
  )
  const pick = (file: File | undefined) => {
    setProblem('')
    if (!file) return
    if (file.size > LOGO_MAX_BYTES) return setProblem(`${file.name} is ${fmtNum(Math.ceil(file.size / 1024))} KB; the logo can be ${fmtNum(LOGO_MAX_BYTES / 1024)} KB at most`)
    const reader = new FileReader()
    reader.onload = () => {
      const url = typeof reader.result === 'string' ? reader.result : ''
      if (!logoImage(url)) return setProblem(`${file.name} is not a PNG or JPEG image the report can embed`)
      onChange({ ...branding, logo: url })
    }
    reader.onerror = () => setProblem(`${file.name} could not be read`)
    reader.readAsDataURL(file)
  }
  const logo = logoImage(branding.logo)
  return (
    <>
      {field('firmName', 'firm name', "empty: REMN's own wordmark")}
      {field('coverLine', 'cover line', 'empty: forensic analysis report')}
      <label className="col small" style={{ gap: 2 }}>
        <span className="muted">logo: PNG or JPEG, {fmtNum(LOGO_MAX_BYTES / 1024)} KB at most, embedded in the HTML and Word reports</span>
        <input aria-label="logo" type="file" accept="image/png,image/jpeg" className="small" onChange={(e) => pick(e.target.files?.[0])} />
      </label>
      {problem && <span className="warn small">{problem}</span>}
      {logo && (
        <div className="row small" style={{ gap: 8, alignItems: 'center' }}>
          <img src={logo.dataUrl} alt="the logo the report carries" style={{ maxHeight: 32, maxWidth: 140, background: '#fff' }} />
          <span className="muted">
            {fmtNum(logo.width)} × {fmtNum(logo.height)} px, {fmtNum(Math.ceil(logo.bytes.length / 1024))} KB
          </span>
          <button className="btn xs" onClick={() => onChange({ ...branding, logo: '' })}>
            remove logo
          </button>
        </div>
      )}
    </>
  )
}
