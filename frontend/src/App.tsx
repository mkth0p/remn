import { lazy, Suspense, useEffect, useRef, useState, type ComponentType } from 'react'
import { ApiError, getHealth, getMeta, onAuthError, setApiToken } from './api/client'
import { defaultSettings, getDb, newServerKey, type Case } from './db/schema'
import { toast, useStore, type View } from './state/store'
import { findCase, focusRouteItem, NOT_HELD, parseRoute, startHistorySync } from './state/route'
import { detectKind, ingestFiles, refreshCounts, requestIngest } from './data/ingest'
import { migrateCaseToServer } from './data/migrate'
import { getSource } from './data/source'
import { setLocalTime } from './util/format'
import { getTransport, transportLabel } from './ai/transport'
import { deployment } from './data/deployment'
import { setCaseInternalDomains } from './rules/incidents'
import { repairInterruptedImports } from './data/interruptedImports'
import { removeInterruptedRestores } from './data/caseBundle'
import { isAbort } from './data/queryClient'
import { casesWithEvidence, FIRST_CASE_NAME } from './data/cases'
import { DEFAULT_DETECTION_LEVEL, type DetectionLevel } from './data/detectionLevel'
import { DetectionLevelPicker } from './components/DetectionLevelPicker'
import {
  IconAi,
  IconDashboard,
  IconEvents,
  IconEvidence,
  IconFindings,
  IconIoc,
  IconMail,
  IconReport,
  IconRules,
  IconSettings,
  IconTerminal,
  IconTimeline,
  IconPivot,
  IconLink,
  IconGraph,
  IconFile,
  IconArrowLeft,
  IconCheck,
  IconQuestion,
} from './components/Icons'
import { ConsolePanel, Toasts } from './components/ConsolePanel'
import { TokenGate } from './components/TokenGate'
import { ConfirmHost } from './components/ConfirmHost'
import { SharedCases } from './components/CaseAccess'
import { signOut, viewerReason } from './data/access'
import { RemnMark } from './components/RemnMark'
import { DataNotice } from './components/DataNotice'
import { EntityPanel } from './components/EntityPanel'
import { ErrorBoundary } from './components/ErrorBoundary'
import { focusPageHeading } from './components/viewFocus'
import { Modal, Progress, ThemeToggle } from './components/ui'
import type { PivotResult } from './data/queries'
import { fmtBytes, fmtNum, fmtTs } from './util/format'
import { safeHref } from './util/safe'

/**
 * Each page is its own script, fetched when it is first opened: the charts, the rule parser, the
 * mail sanitiser and the home page's fonts are not part of the first load.
 */
function page<K extends string>(load: () => Promise<{ [P in K]: ComponentType }>, name: K) {
  return lazy(() => load().then((m) => ({ default: m[name] })))
}
const Dashboard = page(() => import('./views/Dashboard'), 'Dashboard')
const EvidenceView = page(() => import('./views/EvidenceView'), 'EvidenceView')
const EventsView = page(() => import('./views/EventsView'), 'EventsView')
const MailsView = page(() => import('./views/MailsView'), 'MailsView')
const FindingsView = page(() => import('./views/FindingsView'), 'FindingsView')
const StoriesView = page(() => import('./views/StoriesView'), 'StoriesView')
const GraphView = page(() => import('./views/GraphView'), 'GraphView')
const TimelineView = page(() => import('./views/TimelineView'), 'TimelineView')
const IocsView = page(() => import('./views/IocsView'), 'IocsView')
const AiView = page(() => import('./views/AiView'), 'AiView')
const ReportView = page(() => import('./views/ReportView'), 'ReportView')
const CaseView = page(() => import('./views/CaseView'), 'CaseView')
const QuestionsView = page(() => import('./views/QuestionsView'), 'QuestionsView')
const ReviewView = page(() => import('./views/ReviewView'), 'ReviewView')
const HomeView = page(() => import('./views/HomeView'), 'HomeView')
const RulesView = page(() => import('./views/RulesView'), 'RulesView')
const SettingsView = page(() => import('./views/SettingsView'), 'SettingsView')

const loadingPage = <div className="empty">loading the page…</div>

const NAV: { id: View; label: string; icon: React.ComponentType; count?: 'events' | 'mails' | 'findings' | 'iocs' | 'evidence'; section?: string }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: IconDashboard },
  { id: 'evidence', label: 'Evidence', icon: IconEvidence, count: 'evidence' },
  { id: 'events', label: 'Events', icon: IconEvents, count: 'events', section: 'investigate' },
  { id: 'mails', label: 'Mails', icon: IconMail, count: 'mails' },
  { id: 'timeline', label: 'Timeline', icon: IconTimeline },
  { id: 'findings', label: 'Findings', icon: IconFindings, count: 'findings', section: 'detect' },
  { id: 'stories', label: 'Stories', icon: IconLink },
  { id: 'graph', label: 'Graph', icon: IconGraph },
  { id: 'rules', label: 'Rules', icon: IconRules },
  { id: 'iocs', label: 'Indicators', icon: IconIoc, count: 'iocs' },
  { id: 'ai', label: 'AI analyst', icon: IconAi, section: 'assist' },
  { id: 'review', label: 'Review', icon: IconCheck },
  { id: 'case', label: 'Case notes', icon: IconFile },
  { id: 'questions', label: 'Questions', icon: IconQuestion },
  { id: 'report', label: 'Report', icon: IconReport },
  { id: 'settings', label: 'Settings', icon: IconSettings },
]

/** Why the start failed, from the browser's error, and what usually causes it. */
function bootFailure(e: unknown): string {
  const err = e as { name?: string; message?: string; inner?: { name?: string } } | null
  const names = [err?.name, err?.inner?.name]
  const said = `REMN could not open its database in this browser: ${err?.message || String(e)}.`
  if (names.includes('VersionError')) return `${said} It was written by a newer version of REMN than this page; open that version.`
  if (names.includes('QuotaExceededError')) return `${said} The browser's storage for this site is full: free space and reload.`
  return `${said} The browser may refuse this site storage (a private window, or site data turned off in its settings), its storage may be full, or another REMN tab may hold the database while it is upgraded: close other REMN tabs, check the site settings and reload.`
}

// the page's own title (index.html), for the home page
const HOME_TITLE = typeof document === 'undefined' ? 'REMN' : document.title

const BOOT_BLOCKED = 'Another REMN tab holds the database of this browser open in an older version, so this page cannot upgrade it yet: close the other REMN tabs or reload them, and this page starts.'

export default function App() {
  const view = useStore((s) => s.view)
  const setView = useStore((s) => s.setView)
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem('remn-sidebar') === 'collapsed'
    } catch {
      return false
    }
  })
  useEffect(() => {
    try {
      localStorage.setItem('remn-sidebar', collapsed ? 'collapsed' : 'open')
    } catch {
      /* private mode */
    }
  }, [collapsed])
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
  const casesVersion = useStore((s) => s.casesVersion)
  const [showConsole, setShowConsole] = useState(false)
  const [newCase, setNewCase] = useState<{ name: string; storage: 'browser' | 'server'; level: DetectionLevel } | null>(null)
  const [global, setGlobal] = useState('')
  const [pivotRes, setPivotRes] = useState<PivotResult | null>(null)
  const pivotAbort = useRef<AbortController | null>(null)
  const [ready, setReady] = useState(false)
  const [bootError, setBootError] = useState<string | null>(null)
  const [bootWait, setBootWait] = useState<string | null>(null)
  const [pendingKind, setPendingKind] = useState<'evtx' | 'mail' | 'package'>('mail')
  const [migrating, setMigrating] = useState<string | null>(null)

  useEffect(() => {
    const db = getDb()
    // an older REMN tab that keeps the database open holds this one's upgrade back; the start waits, and says for what
    const blocked = () => setBootWait(BOOT_BLOCKED)
    db.on('blocked', blocked)
    // React runs this twice in development: only the start still mounted keeps the address in step
    let alive = true
    let stopHistory: (() => void) | undefined
    onAuthError((accounts) => useStore.getState().setAuthRequired(true, accounts))
    const tokenReady = db.kv.get('apiToken').then((tok) => {
      if (typeof tok?.value === 'string' && tok.value) setApiToken(tok.value)
    })
    ;(async () => {
      await tokenReady // the first data fetches need the header in place
      const lt = await db.kv.get('localTime')
      if (lt?.value) setLocalTime(true)
      const th = await db.kv.get('storeThresholdMb')
      if (typeof th?.value === 'number') setThreshold(th.value)
      const [tp, ou, om, onc, ocm, oau] = await Promise.all([
        db.kv.get('aiTransport'),
        db.kv.get('aiOllamaUrl'),
        db.kv.get('aiModel'),
        db.kv.get('aiNumCtx'),
        db.kv.get('aiClaudeModel'),
        db.kv.get('aiOpenaiUrl'),
      ])
      useStore.getState().setAiConfig({
        transport: tp?.value === 'server' ? 'server' : tp?.value === 'claude' ? 'claude' : tp?.value === 'openai' ? 'openai' : 'browser',
        claudeModel: typeof ocm?.value === 'string' && ocm.value ? ocm.value : 'sonnet',
        ollamaUrl: typeof ou?.value === 'string' && ou.value ? ou.value : 'http://localhost:11434',
        openaiUrl: typeof oau?.value === 'string' && oau.value ? oau.value : 'http://localhost:1234/v1',
        model: typeof om?.value === 'string' ? om.value : '',
        numCtx: typeof onc?.value === 'number' ? onc.value : null,
      })
      // A page served from another host reaches the visitor's own model on localhost. That request is
      // made when the analyst opens the AI analyst, not on every page load of every visitor.
      if (deployment(null).tier === 'this-machine' || !['browser', 'openai'].includes(useStore.getState().aiConfig.transport))
        getTransport()
          .ping()
          .then((r) => useStore.getState().setAiStatus({ reachable: r.reachable, error: r.error, models: r.models, checkedAt: Date.now() }))
      // a case bundle (the demo case) a closed or reloaded tab left half-restored goes before anything counts it
      const unfinished = await removeInterruptedRestores().catch((e: Error) => {
        useStore.getState().log('err', `interrupted restores not checked: ${e.message}`)
        return []
      })
      for (const name of unfinished) toast('warn', `${name}: its restore stopped before it finished (the tab was closed or reloaded), so the partial case was removed.`, 0)
      // one transaction, so two boots in flight (React runs effects twice in development) create one default case
      const all = await db.transaction('rw', db.cases, db.kv, async () => {
        if ((await db.cases.count()) === 0) {
          const id = await db.cases.add({
            name: FIRST_CASE_NAME,
            createdAt: Date.now(),
            updatedAt: Date.now(),
            settings: { ...defaultSettings(), detectionLevel: DEFAULT_DETECTION_LEVEL },
            storage: 'browser',
          })
          await db.kv.put({ key: 'lastCase', value: id })
        }
        return db.cases.toArray()
      })
      setCases(all)
      // the place the address names (a reload, a link, a bookmark), when it is a case this browser holds
      const route = parseRoute(location.pathname, location.search)
      const linked = route.caseRef ? findCase(all, route.caseRef) : undefined
      if (route.caseRef && !linked) toast('warn', NOT_HELD, 0)
      const last = (await db.kv.get('lastCase'))?.value as number | undefined
      const current = linked ?? all.find((c) => c.id === last) ?? all[0]
      const open = { ...current, settings: { ...defaultSettings(), ...current.settings } }
      setCurrentCase(open)
      const item = linked && route.item && (await focusRouteItem(open, route.item)) ? route.item : null
      if (linked && route.item && !item) useStore.getState().log('warn', `the ${route.item.kind} the address names is not in case "${open.name}", so it was not opened`)
      // otherwise the home page first, until some case holds evidence
      useStore.getState().setView(linked ? (route.view ?? 'dashboard') : route.view === 'home' ? 'home' : (await casesWithEvidence()).size ? 'dashboard' : 'home')
      if (!alive) return
      stopHistory = startHistorySync(item)
      setReady(true)
      // an import a closed or crashed tab left half-done: its rows go, and the evidence says it stopped
      repairInterruptedImports((st) => {
        useStore.getState().log('warn', `evidence #${st.evidenceId} ${st.name}: the import stopped before it finished; ${st.rows} partial row(s) removed`)
        toast('warn', `${st.name}: its import stopped before it finished (the tab was closed or reloaded). The partial rows were removed; add the file again.`, 0)
      })
        .then((stopped) => {
          const open = useStore.getState().currentCase
          if (stopped.length && open) refreshCounts(open)
        })
        .catch((e: Error) => useStore.getState().log('err', `interrupted imports not checked: ${e.message}`))
    })().catch((e) => setBootError(bootFailure(e))) // without it the page said "booting…" for ever
    const load = () => {
      getHealth()
        .then((h) => {
          setHealth(h)
          if (h.mode === 'browser-only' && !['browser', 'openai'].includes(useStore.getState().aiConfig.transport)) {
            // the server-side transports do not exist here; the page talks to the analyst's own model
            useStore.getState().setAiConfig({ ...useStore.getState().aiConfig, transport: 'browser' })
            db.kv.put({ key: 'aiTransport', value: 'browser' }).catch(() => undefined)
          }
          if (h.store?.thresholdMb)
            db.kv.get('storeThresholdMb').then((k) => {
              if (typeof k?.value !== 'number') setThreshold(h.store!.thresholdMb)
            })
          const dep = deployment(h)
          if (dep.tier === 'this-machine') useStore.getState().setDataNotice('acknowledged')
          else db.kv.get('dataNotice').then((k) => useStore.getState().setDataNotice(k?.value === `${dep.host}|${dep.tier}` ? 'acknowledged' : 'required'))
          // the model went unreachable (the server was down, Ollama restarted): check again with every poll until it is back,
          // once the analyst has asked for it (an earlier check) or where the model sits next to the page
          if (
            useStore.getState().aiStatus.reachable === false ||
            (useStore.getState().aiStatus.reachable === null && (dep.tier === 'this-machine' || !transportLabel(useStore.getState().aiConfig).local))
          ) {
            getTransport()
              .ping()
              .then((r) => useStore.getState().setAiStatus({ reachable: r.reachable, error: r.error, models: r.models, checkedAt: Date.now() }))
              .catch(() => undefined)
          }
        })
        .catch((e) => {
          setHealth(null)
          if (!(e instanceof ApiError && e.status === 401)) useStore.getState().log('err', `server unreachable: ${e.message}`)
        })
    }
    tokenReady
      .then(() => {
        load()
        getMeta()
          .then(setMeta)
          .catch((e) => {
            if (!(e instanceof ApiError && e.status === 401)) toast('err', `could not load reference data: ${e.message}`, 0)
          })
      })
      .catch(() => undefined) // a database that cannot be read is what the start reports
    const t = setInterval(load, 30000)
    return () => {
      alive = false
      stopHistory?.()
      clearInterval(t)
      db.on('blocked').unsubscribe(blocked)
    }
  }, [setCurrentCase, setHealth, setMeta, setThreshold])

  // leaving while an import runs stops it; the browser asks first
  const importing = jobs.some((j) => j.phase !== 'done' && j.phase !== 'error')
  useEffect(() => {
    if (!importing) return
    const warn = (e: BeforeUnloadEvent) => {
      e.preventDefault()
      e.returnValue = ''
    }
    window.addEventListener('beforeunload', warn)
    return () => window.removeEventListener('beforeunload', warn)
  }, [importing])

  // the tab says which page it shows; the case's name stays out of it, and so out of the browser's history
  useEffect(() => {
    const label = NAV.find((n) => n.id === view)?.label
    document.title = label ? `${label} · REMN` : HOME_TITLE
  }, [view])

  // a page opened from the navigation, a link, or back and forward: the focus goes to its heading,
  // so a screen reader says where the person is; not on the first page the start opens
  const mainRef = useRef<HTMLElement>(null)
  const shownView = useRef<string | null>(null)
  const shell = ready && !!kase && !bootError
  useEffect(() => {
    if (!shell) {
      shownView.current = null
      return
    }
    const before = shownView.current
    shownView.current = view
    if (before === null || before === view) return
    return focusPageHeading(mainRef.current ?? document.body)
  }, [view, shell])

  // incidents group one person's accounts by the case's internal domains (rules/identity.ts)
  useEffect(() => setCaseInternalDomains(kase?.settings.internalDomains), [kase?.settings.internalDomains])

  useEffect(() => {
    if (kase?.id) {
      refreshCounts(kase)
      getDb().kv.put({ key: 'lastCase', value: kase.id })
    }
  }, [kase, jobs.length, view])

  useEffect(() => {
    if (casesVersion > 0) getDb().cases.toArray().then(setCases)
  }, [casesVersion])

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
    if (pending) setPendingKind(pending.kindOverride ?? 'package')
  }, [pending])

  const switchCase = async (id: number) => {
    const c = await getDb().cases.get(id)
    if (c) setCurrentCase({ ...c, settings: { ...defaultSettings(), ...c.settings } })
  }
  const createCase = async () => {
    if (!newCase) return
    const name = newCase.name.trim() || `Case ${cases.length + 1}`
    const serverKey = newCase.storage === 'server' ? newServerKey() : undefined
    const id = await getDb().cases.add({ name, createdAt: Date.now(), updatedAt: Date.now(), settings: { ...defaultSettings(), detectionLevel: newCase.level }, storage: newCase.storage, serverKey })
    setCases(await getDb().cases.toArray())
    await switchCase(id)
    setNewCase(null)
    setView('evidence')
  }
  const runPivot = async () => {
    if (!kase?.id || !global.trim()) return
    // a new pivot replaces the one still counting
    pivotAbort.current?.abort()
    const ac = (pivotAbort.current = new AbortController())
    try {
      setPivotRes(await getSource(kase).pivot(global.trim(), ac.signal))
    } catch (e) {
      if (!isAbort(e)) toast('err', `pivot failed: ${(e as Error).message}`)
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
    void ingestFiles(files, target, (f) => pending.kindOverride ?? (/(\.zip|\.tar|\.tgz|\.gz|\.bz2|\.xz)$/i.test(f.name) ? pendingKind : detectKind(f)))
    setView('evidence')
  }

  if (bootError)
    return (
      <div className="empty" role="alert">
        <div className="big">REMN</div>
        {bootError}
      </div>
    )
  if (!ready || !kase)
    return (
      <div className="empty" role="status">
        <div className="big">REMN</div>
        {bootWait ?? 'booting…'}
      </div>
    )
  if (view === 'home')
    return (
      <>
        <ErrorBoundary what="The home page">
          <Suspense fallback={loadingPage}>
            <HomeView />
          </Suspense>
        </ErrorBoundary>
        <Toasts />
        <ConfirmHost />
        {authRequired && <TokenGate />}
      </>
    )
  const busy = jobs.some((j) => j.phase !== 'done' && j.phase !== 'error')
  const isServer = kase.storage === 'server'
  const browserOnly = health?.mode === 'browser-only'
  const canConvert = !isServer && !browserOnly
  // on a server with accounts, a viewer changes nothing; the server refuses it too
  const viewer = viewerReason(health)
  const dep = deployment(health)
  const acknowledgeNotice = async () => {
    if (!pending) return
    await getDb().kv.put({ key: 'dataNotice', value: `${dep.host}|${dep.tier}` })
    useStore.getState().setDataNotice('acknowledged')
    const { files, kindOverride } = pending
    setPending(null)
    requestIngest(files, kase, kindOverride, true)
  }
  const bigTotal = pending ? pending.files.reduce((s, f) => s + f.size, 0) : 0
  return (
    <div className={collapsed ? 'app sidebar-collapsed' : 'app'}>
      <aside className="sidebar">
        <div
          className="brand click"
          role="button"
          tabIndex={0}
          title="REMN home"
          onClick={() => setView('home')}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') setView('home')
          }}
        >
          <RemnMark size={22} />
          <span className="wordmark">REMN</span>
        </div>
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
          <div title={health ? `server ${dep.build || '?'} · page ${dep.pageBuild || '?'}${dep.mismatch ? ' - built from different commits' : ''}` : undefined}>
            <span className={`status-dot ${health ? (dep.mismatch ? 'warn' : 'ok') : 'bad'}`} />
            server{' '}
            {health ? (
              <a href={safeHref(dep.source)} target="_blank" rel="noreferrer noopener" className="mono">
                {dep.build || 'build unknown'}
              </a>
            ) : (
              'offline'
            )}
          </div>
          {health && dep.tier !== 'this-machine' && (
            <div title={dep.parsing}>
              <span className="status-dot" />
              parsing on {dep.host}
            </div>
          )}
          <div title={transportLabel(aiCfg).where}>
            <span className={`status-dot ${aiStatus.reachable ? 'ok' : aiStatus.reachable === null ? '' : 'bad'}`} />
            {transportLabel(aiCfg).short}{' '}
            {aiStatus.reachable ? (aiCfg.transport === 'claude' ? 'ready' : 'online') : aiStatus.reachable === null ? '…' : aiCfg.transport === 'claude' ? 'unavailable' : 'offline'}{' '}
            <span className="dim">[{aiCfg.transport}]</span>
          </div>
          <div title="reputation lookups for this case (Settings); evidence parsing is shown above">
            <span className={`status-dot ${!browserOnly && kase.settings.networkAllowed ? 'bad' : 'ok'}`} />
            lookups {browserOnly ? 'none on this server' : kase.settings.networkAllowed ? 'on' : 'off'}
          </div>
          <div>
            <span className={`status-dot ${isServer ? 'ok' : ''}`} />
            store {isServer ? 'server' : 'browser'}
          </div>
          {health?.account && (
            <div title={`signed in with a personal token as ${health.account.name}, role ${health.account.role}${viewer ? `. ${viewer}` : ''}`}>
              <span className="status-dot ok" />
              <span className="mono">{health.account.name}</span> · {health.account.role}{' '}
              <button className="btn ghost xs" onClick={() => void signOut()} title="forget this browser's token and ask for one again">
                sign out
              </button>
            </div>
          )}
          <button className="btn ghost xs" style={{ justifyContent: 'flex-start' }} onClick={() => setShowConsole(!showConsole)} title="console">
            <IconTerminal />
            <span className="label"> console {busy ? '●' : ''}</span>
          </button>
          <button
            className="btn ghost xs sidebar-toggle"
            style={{ justifyContent: 'flex-start' }}
            onClick={() => setCollapsed(!collapsed)}
            title={collapsed ? 'expand the sidebar' : 'collapse the sidebar'}
          >
            <IconArrowLeft style={{ transform: collapsed ? 'rotate(180deg)' : undefined }} />
            <span className="label"> collapse</span>
          </button>
        </div>
      </aside>
      <header className="topbar">
        <select className="select mono" value={kase.id} onChange={(e) => switchCase(Number(e.target.value))} title="case">
          {cases.map((c) => (
            <option key={c.id} value={c.id}>
              {c.name}
              {c.storage === 'server' ? ' [server]' : ''}
            </option>
          ))}
        </select>
        <button className="btn sm ghost" onClick={() => setNewCase({ name: '', storage: 'browser', level: DEFAULT_DETECTION_LEVEL })}>
          + case
        </button>
        <span className="title">{NAV.find((n) => n.id === view)?.label ?? ''}</span>
        <span className="spacer" />
        <ThemeToggle />
        <div className="row" style={{ width: 420 }}>
          <IconPivot style={{ color: 'var(--fg-3)' }} />
          <input
            className="input mono"
            style={{ flex: 1 }}
            placeholder="pivot: IP, user, domain, hash, subject… (Enter)"
            value={global}
            onChange={(e) => setGlobal(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && runPivot()}
          />
        </div>
      </header>
      <main className="main relative" ref={mainRef}>
        {/* one view failing to render leaves the shell and the other views usable; a new view starts afresh */}
        <ErrorBoundary key={view} back what={`The ${NAV.find((n) => n.id === view)?.label ?? view} page`}>
          <Suspense fallback={loadingPage}>
            {view === 'dashboard' && <Dashboard />}
            {view === 'evidence' && <EvidenceView />}
            {view === 'events' && <EventsView />}
            {view === 'mails' && <MailsView />}
            {view === 'timeline' && <TimelineView />}
            {view === 'findings' && <FindingsView />}
            {view === 'stories' && <StoriesView key={kase?.id} />}
            {view === 'graph' && <GraphView key={kase?.id} />}
            {view === 'rules' && <RulesView />}
            {view === 'iocs' && <IocsView />}
            {view === 'ai' && <AiView />}
            {view === 'review' && <ReviewView />}
            {view === 'case' && <CaseView />}
            {view === 'questions' && <QuestionsView key={kase?.id} />}
            {view === 'report' && <ReportView />}
            {view === 'settings' && <SettingsView />}
          </Suspense>
        </ErrorBoundary>
        <EntityPanel />
        {showConsole && (
          <div style={{ position: 'absolute', left: 12, right: 12, bottom: 12, zIndex: 30 }}>
            <ConsolePanel />
          </div>
        )}
      </main>
      <Toasts />
      <ConfirmHost />
      {authRequired && <TokenGate />}
      {newCase && (
        <Modal
          title="New case"
          onClose={() => setNewCase(null)}
          footer={
            <button className="btn primary" onClick={createCase}>
              create
            </button>
          }
        >
          <input
            className="input"
            autoFocus
            placeholder="case name"
            value={newCase.name}
            onChange={(e) => setNewCase({ ...newCase, name: e.target.value })}
            onKeyDown={(e) => e.key === 'Enter' && createCase()}
          />
          <div className="col" style={{ gap: 6 }}>
            <label className="checkbox">
              <input type="radio" name="storage" checked={newCase.storage === 'browser'} onChange={() => setNewCase({ ...newCase, storage: 'browser' })} />{' '}
              <span>
                <b>Browser store</b>{' '}
                <span className="muted small">
                  — the case is stored in this browser (IndexedDB); {dep.tier === 'this-machine' ? 'files are parsed on this machine' : `each file is uploaded to ${dep.host} to be parsed`}. Best under
                  ~{threshold} MB per file.
                </span>
              </span>
            </label>
            {!browserOnly && (
              <label className="checkbox" title={viewer ?? undefined}>
                <input type="radio" name="storage" disabled={!!viewer} checked={newCase.storage === 'server'} onChange={() => setNewCase({ ...newCase, storage: 'server' })} />{' '}
                <span>
                  <b>Server store</b>{' '}
                  <span className="muted small">
                    — rows go to a DuckDB file on this machine ({health?.store?.casesDir ?? 'backend/data/cases'}); the browser keeps findings and notes. For gigabytes of EVTX / mailboxes.
                    {health?.accounts ? ' You own the case; add members in Settings.' : ''}
                  </span>
                </span>
              </label>
            )}
          </div>
          {viewer && <div className="hint">{viewer}</div>}
          {health?.accounts && (
            <SharedCases
              onOpen={async (id) => {
                setCases(await getDb().cases.toArray())
                await switchCase(id)
                setNewCase(null)
                setView('evidence')
              }}
            />
          )}
          <div className="col" style={{ gap: 4 }}>
            <b className="small">Detection level</b>
            <DetectionLevelPicker value={newCase.level} onChange={(level) => setNewCase({ ...newCase, level })} />
          </div>
          <div className="hint">
            {browserOnly
              ? 'This server runs in browser-only mode: it parses evidence and returns the rows, and keeps nothing. Every case stays in this browser.'
              : 'A browser case can be converted to the server store later from Settings, or when a large file is dropped.'}
          </div>
        </Modal>
      )}
      {pending && (
        <Modal
          title={pending.reason === 'notice' ? `Before you add evidence to ${dep.host}` : pending.reason === 'big' ? 'Large evidence' : 'Archive contents'}
          onClose={() => !migrating && setPending(null)}
          footer={
            <>
              <button className="btn" disabled={!!migrating} onClick={() => setPending(null)}>
                cancel
              </button>
              {pending.reason === 'notice' && (
                <button className="btn primary" autoFocus onClick={acknowledgeNotice}>
                  I understand, add the evidence
                </button>
              )}
              {pending.reason === 'big' && canConvert && (
                <button className="btn" disabled={!!migrating} onClick={() => proceedPending(false)}>
                  ingest in the browser anyway
                </button>
              )}
              {pending.reason !== 'notice' && (
                <button className="btn primary" disabled={!!migrating} onClick={() => proceedPending(pending.reason === 'big' && canConvert)}>
                  {pending.reason === 'big' && canConvert ? 'convert case to server store and ingest' : 'ingest'}
                </button>
              )}
            </>
          }
        >
          {pending.reason === 'notice' && <DataNotice dep={dep} />}
          <div className="col" style={{ gap: 6 }}>
            {pending.files.slice(0, 8).map((f) => (
              <div key={f.name} className="row small mono">
                <span className="ellipsis" style={{ flex: 1 }}>
                  {f.name}
                </span>
                <span className="dim">{fmtBytes(f.size)}</span>
              </div>
            ))}
            {pending.files.length > 8 && <div className="small muted">…and {pending.files.length - 8} more</div>}
          </div>
          {pending.reason === 'big' && canConvert && (
            <div className="hint">
              {fmtBytes(bigTotal)} is above the {threshold} MB browser threshold. The browser store gets slow past a few hundred MB; the server store (DuckDB on this machine) handles gigabytes.
              Converting moves the existing {fmtNum(counts.events + counts.mails)} rows of this case too.
            </div>
          )}
          {pending.reason === 'big' && browserOnly && (
            <div className="hint">
              {fmtBytes(bigTotal)} is above the {threshold} MB browser threshold. This server keeps nothing, so the rows go into this browser, which gets slow past a few hundred MB.
            </div>
          )}
          {pending.reason !== 'notice' && pending.files.some((f) => /(\.zip|\.tar|\.tgz|\.gz|\.bz2|\.xz)$/i.test(f.name)) && !pending.kindOverride && (
            <label className="field">
              <span>what is inside the archive(s)?</span>
              <select className="select" value={pendingKind} onChange={(e) => setPendingKind(e.target.value as 'evtx' | 'mail' | 'package')}>
                <option value="package">Investigation package (detect every member, including mixed mail and events)</option>
                <option value="evtx">Windows event logs (.evtx files)</option>
                <option value="mail">Mailbox / mail corpus (.eml, .msg, .mbox, .pst, extension-less messages)</option>
              </select>
            </label>
          )}
          {migrating && (
            <>
              <Progress indeterminate />
              <div className="small dim mono">{migrating}</div>
            </>
          )}
        </Modal>
      )}
      {pivotRes && (
        <Modal title={<span className="mono">pivot: {pivotRes.value}</span>} onClose={() => setPivotRes(null)}>
          <div className="grid-2">
            <div className="card">
              <div className="stat">
                <span className="label">events</span>
                <span className="value accent">{fmtNum(pivotRes.events.count)}</span>
              </div>
              <div className="small dim">{pivotRes.events.first ? `${fmtTs(pivotRes.events.first)} → ${fmtTs(pivotRes.events.last)}` : ''}</div>
              {pivotRes.events.scannedOf && (
                <div className="small" style={{ color: 'var(--warn)' }}>
                  counted over the first {fmtNum(pivotRes.events.scannedOf.scanned)} of {fmtNum(pivotRes.events.scannedOf.total)} events: open Events for all of them
                </div>
              )}
              <div className="small mono" style={{ marginTop: 6 }}>
                {Object.entries(pivotRes.events.byEventId)
                  .sort((a, b) => b[1] - a[1])
                  .slice(0, 8)
                  .map(([k, v]) => `${k}×${v}`)
                  .join(' · ')}
              </div>
              <div className="small muted">
                {Object.entries(pivotRes.events.fields)
                  .map(([k, v]) => `${k}:${v}`)
                  .join(' · ')}
              </div>
              {pivotRes.events.count > 0 && (
                <button className="btn sm primary" style={{ marginTop: 8 }} onClick={() => goto('events')}>
                  open in Events
                </button>
              )}
            </div>
            <div className="card">
              <div className="stat">
                <span className="label">mails</span>
                <span className="value accent">{fmtNum(pivotRes.mails.count)}</span>
              </div>
              <div className="small dim">{pivotRes.mails.first ? `${fmtTs(pivotRes.mails.first)} → ${fmtTs(pivotRes.mails.last)}` : ''}</div>
              <div className="small muted" style={{ marginTop: 6 }}>
                {Object.entries(pivotRes.mails.fields)
                  .map(([k, v]) => `${k}:${v}`)
                  .join(' · ')}
              </div>
              {pivotRes.mails.count > 0 && (
                <button className="btn sm primary" style={{ marginTop: 8 }} onClick={() => goto('mails')}>
                  open in Mails
                </button>
              )}
            </div>
          </div>
        </Modal>
      )}
    </div>
  )
}
