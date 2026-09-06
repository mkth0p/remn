import { useEffect, useState } from 'react'
import { ApiError, getHealth, getMeta, onAuthError, setApiToken } from './api/client'
import { defaultSettings, getDb, newServerKey, type Case } from './db/schema'
import { toast, useStore, type View } from './state/store'
import { detectKind, ingestFile, refreshCounts, requestIngest } from './data/ingest'
import { migrateCaseToServer } from './data/migrate'
import { getSource } from './data/source'
import { setLocalTime } from './util/format'
import { getTransport } from './ai/transport'
import { IconAi, IconDashboard, IconEvents, IconEvidence, IconFindings, IconIoc, IconMail, IconReport, IconRules, IconSettings, IconTerminal, IconTimeline, IconPivot, IconLink, IconFile, IconArrowLeft } from './components/Icons'
import { ConsolePanel, Toasts } from './components/ConsolePanel'
import { TokenGate } from './components/TokenGate'
import { EntityPanel } from './components/EntityPanel'
import { Modal, Progress, ThemeToggle } from './components/ui'
import { Dashboard } from './views/Dashboard'
import { EvidenceView } from './views/EvidenceView'
import { EventsView } from './views/EventsView'
import { MailsView } from './views/MailsView'
import { FindingsView } from './views/FindingsView'
import { ChainsView } from './views/ChainsView'
import { TimelineView } from './views/TimelineView'
import { IocsView } from './views/IocsView'
import { AiView } from './views/AiView'
import { ReportView } from './views/ReportView'
import { CaseView } from './views/CaseView'
import { HomeView } from './views/HomeView'
import { RulesView } from './views/RulesView'
import { SettingsView } from './views/SettingsView'
import type { PivotResult } from './data/queries'
import { fmtBytes, fmtNum, fmtTs } from './util/format'

const NAV: { id: View; label: string; icon: React.ComponentType; count?: 'events' | 'mails' | 'findings' | 'iocs' | 'evidence'; section?: string }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: IconDashboard },
  { id: 'evidence', label: 'Evidence', icon: IconEvidence, count: 'evidence' },
  { id: 'events', label: 'Events', icon: IconEvents, count: 'events', section: 'investigate' },
  { id: 'mails', label: 'Mails', icon: IconMail, count: 'mails' },
  { id: 'timeline', label: 'Timeline', icon: IconTimeline },
  { id: 'findings', label: 'Findings', icon: IconFindings, count: 'findings', section: 'detect' },
  { id: 'chains', label: 'Chains', icon: IconLink },
  { id: 'rules', label: 'Rules', icon: IconRules },
  { id: 'iocs', label: 'Indicators', icon: IconIoc, count: 'iocs' },
  { id: 'ai', label: 'AI analyst', icon: IconAi, section: 'assist' },
  { id: 'case', label: 'Case notes', icon: IconFile },
  { id: 'report', label: 'Report', icon: IconReport },
  { id: 'settings', label: 'Settings', icon: IconSettings },
]

export default function App() {
  const view = useStore((s) => s.view)
  const setView = useStore((s) => s.setView)
  const [collapsed, setCollapsed] = useState(() => { try { return localStorage.getItem('remn-sidebar') === 'collapsed' } catch { return false } })
  useEffect(() => { try { localStorage.setItem('remn-sidebar', collapsed ? 'collapsed' : 'open') } catch { /* private mode */ } }, [collapsed])
  const kase = useStore((s) => s.currentCase)
  const setCurrentCase = useStore((s) => s.setCurrentCase)
  const health = useStore((s) => s.health)
  const setHealth = useStore((s) => s.setHealth)
  const setMeta = useStore((s) => s.setMeta)
  const counts = useStore((s) => s.counts)
  const jobs = useStore((s) => s.jobs)
  const threshold = useStore((s) => s.storeThresholdMb)
  const setThreshold = useStore((s) => s.setStoreThresholdMb)
  const aiCfg = useStore((s) => s.aiConfig)
  const aiStatus = useStore((s) => s.aiStatus)
  const authRequired = useStore((s) => s.authRequired)
  const pending = useStore((s) => s.pendingIngest)
  const setPending = useStore((s) => s.setPendingIngest)
  const [cases, setCases] = useState<Case[]>([])
  const [showConsole, setShowConsole] = useState(false)
  const [newCase, setNewCase] = useState<{ name: string; storage: 'browser' | 'server' } | null>(null)
  const [global, setGlobal] = useState('')
  const [pivotRes, setPivotRes] = useState<PivotResult | null>(null)
  const [ready, setReady] = useState(false)
  const [pendingKind, setPendingKind] = useState<'evtx' | 'mail'>('mail')
  const [migrating, setMigrating] = useState<string | null>(null)

  useEffect(() => {
    const db = getDb()
    onAuthError(() => useStore.getState().setAuthRequired(true))
    const tokenReady = db.kv.get('apiToken').then((tok) => {
      if (typeof tok?.value === 'string' && tok.value) setApiToken(tok.value)
    })
    ;(async () => {
      await tokenReady // the first data fetches need the header in place
      const lt = await db.kv.get('localTime')
      if (lt?.value) setLocalTime(true)
      const th = await db.kv.get('storeThresholdMb')
      if (typeof th?.value === 'number') setThreshold(th.value)
      const [tp, ou, om, onc] = await Promise.all([db.kv.get('aiTransport'), db.kv.get('aiOllamaUrl'), db.kv.get('aiModel'), db.kv.get('aiNumCtx')])
      useStore.getState().setAiConfig({
        transport: tp?.value === 'server' ? 'server' : 'browser',
        ollamaUrl: typeof ou?.value === 'string' && ou.value ? ou.value : 'http://localhost:11434',
        model: typeof om?.value === 'string' ? om.value : '',
        numCtx: typeof onc?.value === 'number' ? onc.value : null,
      })
      getTransport()
        .ping()
        .then((r) => useStore.getState().setAiStatus({ reachable: r.reachable, error: r.error, models: r.models, checkedAt: Date.now() }))
      let all = await db.cases.toArray()
      if (!all.length) {
        const id = await db.cases.add({ name: 'Case 1', createdAt: Date.now(), updatedAt: Date.now(), settings: defaultSettings(), storage: 'browser' })
        all = await db.cases.toArray()
        await db.kv.put({ key: 'lastCase', value: id })
      }
      setCases(all)
      const last = (await db.kv.get('lastCase'))?.value as number | undefined
      const current = all.find((c) => c.id === last) ?? all[0]
      setCurrentCase({ ...current, settings: { ...defaultSettings(), ...current.settings } })
      setReady(true)
    })()
    const load = () => {
      getHealth()
        .then((h) => {
          setHealth(h)
          if (h.store?.thresholdMb) db.kv.get('storeThresholdMb').then((k) => { if (typeof k?.value !== 'number') setThreshold(h.store!.thresholdMb) })
        })
        .catch((e) => {
          setHealth(null)
          if (!(e instanceof ApiError && e.status === 401)) useStore.getState().log('err', `server unreachable: ${e.message}`)
        })
    }
    tokenReady.then(() => {
      load()
      getMeta().then(setMeta).catch((e) => {
        if (!(e instanceof ApiError && e.status === 401)) toast('err', `could not load reference data: ${e.message}`, 0)
      })
    })
    const t = setInterval(load, 30000)
    return () => clearInterval(t)
  }, [setCurrentCase, setHealth, setMeta, setThreshold])

  useEffect(() => {
    if (kase?.id) {
      refreshCounts(kase)
      getDb().kv.put({ key: 'lastCase', value: kase.id })
    }
  }, [kase, jobs.length, view])

  useEffect(() => {
    const onDrop = (e: DragEvent) => {
      if (!e.dataTransfer?.files?.length || !kase) return
      e.preventDefault()
      if (view !== 'evidence' && view !== 'dashboard') {
        requestIngest(Array.from(e.dataTransfer.files), kase)
        setView('evidence')
      }
    }
    const onOver = (e: DragEvent) => e.preventDefault()
    window.addEventListener('drop', onDrop)
    window.addEventListener('dragover', onOver)
    return () => {
      window.removeEventListener('drop', onDrop)
      window.removeEventListener('dragover', onOver)
    }
  }, [kase, view, setView])

  useEffect(() => {
    if (pending) setPendingKind(pending.kindOverride ?? (pending.files.every((f) => detectKind(f) === 'evtx') ? 'evtx' : 'mail'))
  }, [pending])

  const switchCase = async (id: number) => {
    const c = await getDb().cases.get(id)
    if (c) setCurrentCase({ ...c, settings: { ...defaultSettings(), ...c.settings } })
  }
  const createCase = async () => {
    if (!newCase) return
    const name = newCase.name.trim() || `Case ${cases.length + 1}`
    const serverKey = newCase.storage === 'server' ? newServerKey() : undefined
    const id = await getDb().cases.add({ name, createdAt: Date.now(), updatedAt: Date.now(), settings: defaultSettings(), storage: newCase.storage, serverKey })
    setCases(await getDb().cases.toArray())
    await switchCase(id)
    setNewCase(null)
    setView('evidence')
  }
  const runPivot = async () => {
    if (!kase?.id || !global.trim()) return
    try {
      setPivotRes(await getSource(kase).pivot(global.trim()))
    } catch (e) {
      toast('err', `pivot failed: ${(e as Error).message}`)
    }
  }
  const goto = (v: View) => {
    setView(v)
    if (v === 'events') useStore.getState().setEventsFilter({ text: global.trim() })
    if (v === 'mails') useStore.getState().setMailsFilter({ text: global.trim() })
    setPivotRes(null)
  }
  const proceedPending = async (convert: boolean) => {
    if (!pending || !kase) return
    let target = kase
    if (convert) {
      setMigrating('preparing…')
      try {
        target = await migrateCaseToServer(kase, setMigrating)
      } catch (e) {
        toast('err', `conversion failed: ${(e as Error).message}`, 0)
        setMigrating(null)
        return
      }
      setMigrating(null)
    }
    const files = pending.files
    setPending(null)
    files.forEach((f) => ingestFile(f, target, pending.kindOverride ?? (/(\.zip|\.tar|\.tgz|\.gz|\.bz2|\.xz)$/i.test(f.name) ? pendingKind : detectKind(f))))
    setView('evidence')
  }

  if (!ready || !kase) return <div className="empty"><div className="big">REMN</div>booting…</div>
  const busy = jobs.some((j) => j.phase !== 'done' && j.phase !== 'error')
  const isServer = kase.storage === 'server'
  const bigTotal = pending ? pending.files.reduce((s, f) => s + f.size, 0) : 0
  return (
    <div className={collapsed ? 'app sidebar-collapsed' : 'app'}>
      <aside className="sidebar">
        <div className="brand click" role="button" tabIndex={0} title="about REMN" onClick={() => setView('home')} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') setView('home') }}><span className="wordmark">REMN</span><span className="mark">R</span></div>
        <nav className="nav">
          {NAV.map((n) => (
            <div key={n.id}>
              {n.section && <div className="nav-section">{n.section}</div>}
              <button className={`nav-item ${view === n.id ? 'active' : ''}`} onClick={() => setView(n.id)} title={n.label}>
                <n.icon />
                <span>{n.label}</span>
                {n.count && counts[n.count] > 0 && <span className="count">{fmtNum(counts[n.count])}</span>}
              </button>
            </div>
          ))}
        </nav>
        <div className="sidebar-footer">
          <div><span className={`status-dot ${health ? 'ok' : 'bad'}`} />server {health ? `v${health.version}` : 'offline'}</div>
          <div title={aiCfg.transport === 'browser' ? `browser-direct: ${aiCfg.ollamaUrl}` : 'via REMN server'}><span className={`status-dot ${aiStatus.reachable ? 'ok' : aiStatus.reachable === null ? '' : 'bad'}`} />ollama {aiStatus.reachable ? 'online' : aiStatus.reachable === null ? '…' : 'offline'} <span className="dim">[{aiCfg.transport}]</span></div>
          <div><span className={`status-dot ${kase.settings.networkAllowed ? 'bad' : 'ok'}`} />egress {kase.settings.networkAllowed ? 'allowed' : 'blocked'}</div>
          <div><span className={`status-dot ${isServer ? 'ok' : ''}`} />store {isServer ? 'server' : 'browser'}</div>
          <button className="btn ghost xs" style={{ justifyContent: 'flex-start' }} onClick={() => setShowConsole(!showConsole)} title="console"><IconTerminal /><span className="label"> console {busy ? '●' : ''}</span></button>
          <button className="btn ghost xs sidebar-toggle" style={{ justifyContent: 'flex-start' }} onClick={() => setCollapsed(!collapsed)} title={collapsed ? 'expand the sidebar' : 'collapse the sidebar'}><IconArrowLeft style={{ transform: collapsed ? 'rotate(180deg)' : undefined }} /><span className="label"> collapse</span></button>
        </div>
      </aside>
      <header className="topbar">
        <select className="select mono" value={kase.id} onChange={(e) => switchCase(Number(e.target.value))} title="case">
          {cases.map((c) => <option key={c.id} value={c.id}>{c.name}{c.storage === 'server' ? ' [server]' : ''}</option>)}
        </select>
        <button className="btn sm ghost" onClick={() => setNewCase({ name: '', storage: 'browser' })}>+ case</button>
        <span className="title">{NAV.find((n) => n.id === view)?.label ?? (view === 'home' ? 'About' : '')}</span>
        <span className="spacer" />
        <ThemeToggle />
        <div className="row" style={{ width: 420 }}>
          <IconPivot style={{ color: 'var(--fg-3)' }} />
          <input className="input mono" style={{ flex: 1 }} placeholder="pivot: IP, user, domain, hash, subject… (Enter)" value={global} onChange={(e) => setGlobal(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && runPivot()} />
        </div>
      </header>
      <main className="main relative">
        {view === 'home' && <HomeView />}
        {view === 'dashboard' && <Dashboard />}
        {view === 'evidence' && <EvidenceView />}
        {view === 'events' && <EventsView />}
        {view === 'mails' && <MailsView />}
        {view === 'timeline' && <TimelineView />}
        {view === 'findings' && <FindingsView />}
        {view === 'chains' && <ChainsView />}
        {view === 'rules' && <RulesView />}
        {view === 'iocs' && <IocsView />}
        {view === 'ai' && <AiView />}
        {view === 'case' && <CaseView />}
        {view === 'report' && <ReportView />}
        {view === 'settings' && <SettingsView />}
        <EntityPanel />
        {showConsole && <div style={{ position: 'absolute', left: 12, right: 12, bottom: 12, zIndex: 30 }}><ConsolePanel /></div>}
      </main>
      <Toasts />
      {authRequired && <TokenGate />}
      {newCase && (
        <Modal title="New case" onClose={() => setNewCase(null)} footer={<button className="btn primary" onClick={createCase}>create</button>}>
          <input className="input" autoFocus placeholder="case name" value={newCase.name} onChange={(e) => setNewCase({ ...newCase, name: e.target.value })} onKeyDown={(e) => e.key === 'Enter' && createCase()} />
          <div className="col" style={{ gap: 6 }}>
            <label className="checkbox"><input type="radio" name="storage" checked={newCase.storage === 'browser'} onChange={() => setNewCase({ ...newCase, storage: 'browser' })} /> <span><b>Browser store</b> <span className="muted small">— everything stays in this browser (IndexedDB). Portable, zero server state, best under ~{threshold} MB per file.</span></span></label>
            <label className="checkbox"><input type="radio" name="storage" checked={newCase.storage === 'server'} onChange={() => setNewCase({ ...newCase, storage: 'server' })} /> <span><b>Server store</b> <span className="muted small">— rows go to a DuckDB file on this machine ({health?.store?.casesDir ?? 'backend/data/cases'}); the browser keeps findings and notes. For gigabytes of EVTX / mailboxes.</span></span></label>
          </div>
          <div className="hint">A browser case can be converted to the server store later from Settings, or when a large file is dropped.</div>
        </Modal>
      )}
      {pending && (
        <Modal title={pending.reason === 'big' ? 'Large evidence' : 'Archive contents'} onClose={() => !migrating && setPending(null)} footer={
          <>
            <button className="btn" disabled={!!migrating} onClick={() => setPending(null)}>cancel</button>
            {pending.reason === 'big' && !isServer && <button className="btn" disabled={!!migrating} onClick={() => proceedPending(false)}>ingest in the browser anyway</button>}
            <button className="btn primary" disabled={!!migrating} onClick={() => proceedPending(pending.reason === 'big' && !isServer)}>{pending.reason === 'big' && !isServer ? 'convert case to server store and ingest' : 'ingest'}</button>
          </>
        }>
          <div className="col" style={{ gap: 6 }}>
            {pending.files.slice(0, 8).map((f) => <div key={f.name} className="row small mono"><span className="ellipsis" style={{ flex: 1 }}>{f.name}</span><span className="dim">{fmtBytes(f.size)}</span></div>)}
            {pending.files.length > 8 && <div className="small muted">…and {pending.files.length - 8} more</div>}
          </div>
          {pending.reason === 'big' && !isServer && <div className="hint">{fmtBytes(bigTotal)} is above the {threshold} MB browser threshold. The browser store gets slow past a few hundred MB; the server store (DuckDB on this machine) handles gigabytes. Converting moves the existing {fmtNum(counts.events + counts.mails)} rows of this case too.</div>}
          {pending.files.some((f) => /(\.zip|\.tar|\.tgz|\.gz|\.bz2|\.xz)$/i.test(f.name)) && !pending.kindOverride && (
            <label className="field"><span>what is inside the archive(s)?</span>
              <select className="select" value={pendingKind} onChange={(e) => setPendingKind(e.target.value as 'evtx' | 'mail')}>
                <option value="evtx">Windows event logs (.evtx files)</option>
                <option value="mail">Mailbox / mail corpus (.eml, .msg, .mbox, .pst, extension-less messages)</option>
              </select>
            </label>
          )}
          {migrating && <><Progress indeterminate /><div className="small dim mono">{migrating}</div></>}
        </Modal>
      )}
      {pivotRes && (
        <Modal title={<span className="mono">pivot: {pivotRes.value}</span>} onClose={() => setPivotRes(null)}>
          <div className="grid-2">
            <div className="card">
              <div className="stat"><span className="label">events</span><span className="value accent">{fmtNum(pivotRes.events.count)}</span></div>
              <div className="small dim">{pivotRes.events.first ? `${fmtTs(pivotRes.events.first)} → ${fmtTs(pivotRes.events.last)}` : ''}</div>
              <div className="small mono" style={{ marginTop: 6 }}>{Object.entries(pivotRes.events.byEventId).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k, v]) => `${k}×${v}`).join(' · ')}</div>
              <div className="small muted">{Object.entries(pivotRes.events.fields).map(([k, v]) => `${k}:${v}`).join(' · ')}</div>
              {pivotRes.events.count > 0 && <button className="btn sm primary" style={{ marginTop: 8 }} onClick={() => goto('events')}>open in Events</button>}
            </div>
            <div className="card">
              <div className="stat"><span className="label">mails</span><span className="value accent">{fmtNum(pivotRes.mails.count)}</span></div>
              <div className="small dim">{pivotRes.mails.first ? `${fmtTs(pivotRes.mails.first)} → ${fmtTs(pivotRes.mails.last)}` : ''}</div>
              <div className="small muted" style={{ marginTop: 6 }}>{Object.entries(pivotRes.mails.fields).map(([k, v]) => `${k}:${v}`).join(' · ')}</div>
              {pivotRes.mails.count > 0 && <button className="btn sm primary" style={{ marginTop: 8 }} onClick={() => goto('mails')}>open in Mails</button>}
            </div>
          </div>
        </Modal>
      )}
    </div>
  )
}
