import { useEffect, useMemo, useState } from 'react'
import { estimateStorage, getDb, type Evidence, type Finding } from '../db/schema'
import { useStore } from '../state/store'
import { fmtBytes, fmtNum, fmtTs } from '../util/format'
import { Badge, Kpi, SevBar } from '../components/ui'
import { IconEvents, IconEvidence, IconFindings, IconMail } from '../components/Icons'
import { Dropzone } from '../components/Dropzone'
import { requestIngest, refreshCounts } from '../data/ingest'
import { getSource } from '../data/source'
import { Jobs } from '../components/ConsolePanel'

interface Summary {
  counts?: { events?: number; mails?: number; iocs?: number }
  eventsTimeRange?: { firstIso?: string | null; lastIso?: string | null; first?: number | null; last?: number | null }
  sizeBytes?: number
}

export function Dashboard() {
  const kase = useStore((s) => s.currentCase)
  const counts = useStore((s) => s.counts)
  const setView = useStore((s) => s.setView)
  const health = useStore((s) => s.health)
  const aiCfg = useStore((s) => s.aiConfig)
  const aiStatus = useStore((s) => s.aiStatus)
  const rulesVersion = useStore((s) => s.rulesVersion)
  const jobs = useStore((s) => s.jobs)
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [storage, setStorage] = useState<{ usage: number; quota: number } | null>(null)
  const [summary, setSummary] = useState<Summary | null>(null)
  const ds = useMemo(() => (kase ? getSource(kase) : null), [kase])
  useEffect(() => {
    if (!kase?.id || !ds) return
    const db = getDb()
    db.evidence.where('caseId').equals(kase.id).toArray().then(setEvidence)
    db.findings
      .where('caseId')
      .equals(kase.id)
      .filter((f) => f.status !== 'false_positive')
      .toArray()
      .then((f) => setFindings(f.sort((a, b) => ['info', 'low', 'medium', 'high', 'critical'].indexOf(b.severity) - ['info', 'low', 'medium', 'high', 'critical'].indexOf(a.severity)).slice(0, 12)))
    estimateStorage().then(setStorage)
    ds.summary()
      .then((s) => setSummary(s as Summary))
      .catch(() => setSummary(null))
    refreshCounts(kase)
  }, [kase, ds, rulesVersion, jobs.length])
  if (!kase) return null
  const bySev: Record<string, number> = {}
  for (const f of findings) bySev[f.severity] = (bySev[f.severity] ?? 0) + 1
  const range = summary?.eventsTimeRange
  const isServer = kase.storage === 'server'
  return (
    <div className="view">
      <div className="view-header">
        <h1>Dashboard</h1>
        <span className="sub">
          {kase.name} · created {fmtTs(kase.createdAt, { date: true })}
          {kase.analyst ? ` · ${kase.analyst}` : ''}
        </span>
        <Badge sev={isServer ? 'accent' : 'info'} title={isServer ? `DuckDB case store ${kase.serverKey}` : 'rows stored in this browser (IndexedDB)'}>
          {isServer ? 'server store' : 'browser store'}
        </Badge>
      </div>
      <div className="view-body col" style={{ gap: 14 }}>
        <div className="grid-4">
          <Kpi
            tone="accent"
            icon={<IconEvidence />}
            value={fmtNum(counts.evidence)}
            label={`evidence · ${fmtBytes(evidence.reduce((s, e) => s + e.size, 0))} · ${evidence.filter((e) => e.integrity === 'verified').length} verified`}
            onClick={() => setView('evidence')}
          />
          <Kpi
            tone="accent"
            icon={<IconEvents />}
            value={fmtNum(counts.events)}
            label={range?.firstIso ? `events · ${range.firstIso.slice(0, 10)} → ${range.lastIso?.slice(0, 10)}` : 'events · no EVTX loaded'}
            onClick={() => setView('events')}
          />
          <Kpi tone="accent" icon={<IconMail />} value={fmtNum(counts.mails)} label={`mails · ${evidence.filter((e) => e.kind === 'mail').length} mailbox file(s)`} onClick={() => setView('mails')} />
          <Kpi
            tone={bySev.critical ? 'critical' : bySev.high ? 'high' : 'medium'}
            icon={<IconFindings />}
            value={fmtNum(counts.findings)}
            label={
              <span className="row" style={{ gap: 8 }}>
                <span>findings</span>
                <span style={{ width: 90 }}>
                  <SevBar counts={bySev} />
                </span>
              </span>
            }
            onClick={() => setView('findings')}
          />
        </div>
        <div className="grid-2">
          <div className="panel">
            <div className="panel-h">add evidence</div>
            <div className="panel-b col">
              <Dropzone onFiles={(files) => requestIngest(files, kase)} />
              <Jobs />
              <div className="hint">
                {isServer
                  ? 'Files are hashed in the browser, uploaded in chunks to the local server and parsed into a DuckDB case store on this machine. Nothing leaves the host.'
                  : "Files are hashed (SHA-256) in the browser, parsed by the local server and stored only in this browser's IndexedDB. The server keeps nothing."}
              </div>
            </div>
          </div>
          <div className="panel">
            <div className="panel-h">
              top findings <span className="spacer" />
              <button className="btn xs ghost" onClick={() => setView('findings')}>
                all →
              </button>
            </div>
            <div className="panel-b col" style={{ gap: 6 }}>
              {!findings.length && <div className="muted small">No findings yet. Load evidence, then run the rules from the Findings view.</div>}
              {findings.map((f) => (
                <div key={f.id} className="row small" style={{ gap: 8 }}>
                  <Badge sev={f.severity}>{f.severity}</Badge>
                  <span className="ellipsis" style={{ flex: 2, minWidth: 0 }} title={f.title}>
                    {f.title}
                  </span>
                  <span className="mono dim ellipsis" style={{ flex: 1, minWidth: 0 }}>
                    {Object.values(f.entities).slice(0, 2).join(' · ')}
                  </span>
                  <span className="mono muted nowrap">{fmtTs(f.ts)}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
        <div className="grid-3">
          <div className="card">
            <div className="stat">
              <span className="label">{isServer ? 'server store size' : 'browser storage'}</span>
              <span className="value" style={{ fontSize: 16 }}>
                {isServer ? fmtBytes(summary?.sizeBytes ?? 0) : storage ? `${fmtBytes(storage.usage)} / ${fmtBytes(storage.quota)}` : '—'}
              </span>
            </div>
            {!isServer && storage && (
              <div className="progress" style={{ marginTop: 6 }}>
                <div style={{ width: `${Math.min(100, (storage.usage / Math.max(1, storage.quota)) * 100)}%` }} />
              </div>
            )}
            {isServer && <div className="small muted">DuckDB file on this machine · {kase.serverKey?.slice(0, 8)}…</div>}
          </div>
          <div className="card">
            <div className="stat">
              <span className="label">local AI</span>
              <span className="value" style={{ fontSize: 16 }}>
                {aiStatus.reachable ? aiCfg.model || health?.ollama.defaultModel || 'ready' : aiStatus.reachable === null ? 'checking…' : 'Ollama unreachable'}
              </span>
            </div>
            <div className="small muted">
              {aiCfg.transport === 'browser' ? `browser-direct · ${aiCfg.ollamaUrl}` : 'via REMN server'}
              {aiStatus.reachable ? ` · ${aiStatus.models ?? 0} model(s)` : aiStatus.error ? ` · ${aiStatus.error.slice(0, 120)}` : ''}
            </div>
          </div>
          <div className="card">
            <div className="stat">
              <span className="label">external lookups</span>
              <span className="value" style={{ fontSize: 16, color: kase.settings.networkAllowed ? 'var(--warn)' : 'var(--ok)' }}>
                {kase.settings.networkAllowed ? 'ENABLED' : 'disabled'}
              </span>
            </div>
            <div className="small muted">
              {health?.providers
                .filter((p) => p.configured)
                .map((p) => p.name)
                .join(', ') || 'no provider configured'}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
