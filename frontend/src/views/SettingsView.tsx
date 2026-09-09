import { useEffect, useMemo, useState } from 'react'
import { deleteCaseData, getDb, type CaseSettings } from '../db/schema'
import { toast, useStore } from '../state/store'
import { fmtBytes, getLocalTime, setLocalTime } from '../util/format'
import { Badge, ListInput, Progress, Toggle } from '../components/ui'
import { refreshCounts } from '../data/ingest'
import { removeCase } from '../data/caseState'
import { migrateCaseToServer } from '../data/migrate'
import { getSource } from '../data/source'
import { API_HEADERS } from '../api/client'
import { CLAUDE_MODELS, fetchClaudeStatus, getTransport, type ClaudeStatus, type ModelInfo } from '../ai/transport'
import { suggestTrustedSenders, type TrustedSuggestion } from '../data/trusted'
import { Modal } from '../components/ui'

export function SettingsView() {
  const kase = useStore((s) => s.currentCase)
  const updateSettings = useStore((s) => s.updateSettings)
  const setCurrentCase = useStore((s) => s.setCurrentCase)
  const health = useStore((s) => s.health)
  const counts = useStore((s) => s.counts)
  const threshold = useStore((s) => s.storeThresholdMb)
  const setThreshold = useStore((s) => s.setStoreThresholdMb)
  const [local, setLocal] = useState(getLocalTime())
  const [name, setName] = useState(kase?.name ?? '')
  const [analyst, setAnalyst] = useState(kase?.analyst ?? '')
  const [notes, setNotes] = useState(kase?.notes ?? '')
  const [migrating, setMigrating] = useState<string | null>(null)
  const aiCfg = useStore((st) => st.aiConfig)
  const setAiConfig = useStore((st) => st.setAiConfig)
  const aiStatus = useStore((st) => st.aiStatus)
  const setAiStatus = useStore((st) => st.setAiStatus)
  const meta = useStore((st) => st.meta)
  const [aiModels, setAiModels] = useState<ModelInfo[]>([])
  const [aiTesting, setAiTesting] = useState(false)
  const [urlDraft, setUrlDraft] = useState(aiCfg.ollamaUrl)
  const [suggesting, setSuggesting] = useState(false)
  const [suggestions, setSuggestions] = useState<TrustedSuggestion[] | null>(null)
  const [picked, setPicked] = useState<Set<string>>(new Set())
  const [storeSize, setStoreSize] = useState<number | null>(null)
  const ds = useMemo(() => (kase ? getSource(kase) : null), [kase])
  useEffect(() => setUrlDraft(aiCfg.ollamaUrl), [aiCfg.ollamaUrl])
  const [claudeStatus, setClaudeStatus] = useState<ClaudeStatus | null>(null)
  useEffect(() => {
    if (aiCfg.transport !== 'claude') return
    let dead = false
    fetchClaudeStatus()
      .then((st) => {
        if (!dead) setClaudeStatus(st)
      })
      .catch((e) => {
        if (!dead) setClaudeStatus({ enabled: false, available: false, version: null, loggedIn: false, account: null, method: null, error: (e as Error).message })
      })
    return () => {
      dead = true
    }
  }, [aiCfg.transport, aiStatus.checkedAt])
  useEffect(() => {
    setName(kase?.name ?? '')
    setAnalyst(kase?.analyst ?? '')
    setNotes(kase?.notes ?? '')
  }, [kase?.id, kase?.name, kase?.analyst, kase?.notes])
  useEffect(() => {
    if (ds?.kind === 'server')
      ds.summary()
        .then((s) => setStoreSize((s as { sizeBytes?: number }).sizeBytes ?? null))
        .catch(() => setStoreSize(null))
    else setStoreSize(null)
  }, [ds])
  if (!kase || !ds) return null
  const s = kase.settings
  const isServer = kase.storage === 'server'
  const browserOnly = health?.mode === 'browser-only'
  const patch = async (p: Partial<CaseSettings>) => {
    updateSettings(p)
    await getDb().cases.update(kase.id!, { settings: { ...s, ...p }, updatedAt: Date.now() })
  }
  const saveMeta = async () => {
    await getDb().cases.update(kase.id!, { name: name.trim() || kase.name, analyst: analyst.trim(), notes, updatedAt: Date.now() })
    setCurrentCase({ ...kase, name: name.trim() || kase.name, analyst: analyst.trim(), notes })
    toast('ok', 'case saved')
  }
  const wipe = async () => {
    if (!confirm(`Delete ALL data of case "${kase.name}" (${isServer ? 'server store + ' : ''}browser records: evidence rows, findings, sessions)? The case itself is kept.`)) return
    if (isServer && kase.serverKey) {
      await fetch(`/api/store/${kase.serverKey}`, { method: 'DELETE', headers: API_HEADERS }).catch(() => undefined)
    }
    await deleteCaseData(getDb(), kase.id!)
    await refreshCounts(kase)
    toast('ok', 'case data deleted')
  }
  const destroy = async () => {
    if (
      !confirm(`Delete case "${kase.name}" entirely: ${isServer ? 'server store, ' : ''}evidence rows, findings, notes, sessions, custom rules, settings and the case itself? This cannot be undone.`)
    )
      return
    try {
      const { next, serverCleared } = await removeCase(kase)
      setCurrentCase(next)
      useStore.getState().bumpCases()
      useStore.getState().setView('dashboard')
      toast('ok', `case "${kase.name}" deleted`)
      if (!serverCleared) toast('warn', 'the server store could not be removed (server unreachable); delete its folder under backend/data/cases', 0)
    } catch (e) {
      toast('err', `delete failed: ${(e as Error).message}`, 0)
    }
  }
  const migrate = async () => {
    const total = counts.events + counts.mails
    if (
      !confirm(
        `Move this case to the server store (DuckDB on this machine)? ${total.toLocaleString('en-US')} rows will be transferred and removed from the browser. Findings will be cleared (re-run the rules afterwards).`,
      )
    )
      return
    setMigrating('starting…')
    try {
      await migrateCaseToServer(kase, setMigrating)
      await refreshCounts(kase)
    } catch (e) {
      toast('err', `migration failed: ${(e as Error).message}`, 0)
    } finally {
      setMigrating(null)
    }
  }
  const providers = health?.providers ?? []
  const runSuggest = async () => {
    setSuggesting(true)
    try {
      const found = await suggestTrustedSenders(kase, meta?.mailStrongFlags ?? [])
      if (!found.length) {
        toast('info', 'no candidates: needs senders with 5+ mails, passing auth and no strong indicator')
      } else {
        setSuggestions(found)
        setPicked(new Set(found.map((f) => f.registrable)))
      }
    } catch (e) {
      toast('err', `scan failed: ${(e as Error).message}`)
    } finally {
      setSuggesting(false)
    }
  }
  const applySuggestions = async () => {
    const add = suggestions?.filter((f) => picked.has(f.registrable)).map((f) => f.registrable) ?? []
    await patch({ trustedSenders: Array.from(new Set([...(s.trustedSenders ?? []), ...add])) })
    setSuggestions(null)
    toast('ok', `${add.length} trusted sender(s) added. Use Mails → rescore + refresh findings to apply the changes.`)
  }
  const saveAi = async (patch: Partial<typeof aiCfg>) => {
    setAiConfig(patch)
    const db = getDb()
    if (patch.transport !== undefined) await db.kv.put({ key: 'aiTransport', value: patch.transport })
    if (patch.ollamaUrl !== undefined) await db.kv.put({ key: 'aiOllamaUrl', value: patch.ollamaUrl })
    if (patch.model !== undefined) await db.kv.put({ key: 'aiModel', value: patch.model })
    if (patch.numCtx !== undefined) await db.kv.put({ key: 'aiNumCtx', value: patch.numCtx })
    if (patch.claudeModel !== undefined) await db.kv.put({ key: 'aiClaudeModel', value: patch.claudeModel })
  }
  const testAi = async () => {
    setAiTesting(true)
    try {
      const t = getTransport()
      const r = await t.ping()
      setAiStatus({ reachable: r.reachable, error: r.error, models: r.models, checkedAt: Date.now() })
      if (r.reachable) {
        setAiModels(await t.listModels().catch(() => []))
        toast(
          'ok',
          t.kind === 'claude' ? 'Claude Code is installed and signed in on the server machine' : `Ollama reachable (${t.kind === 'browser' ? t.endpoint : 'via server'}) - ${r.models ?? 0} model(s)`,
        )
      } else {
        toast('err', r.error ?? 'unreachable', 0)
      }
    } finally {
      setAiTesting(false)
    }
  }
  return (
    <div className="view">
      <div className="view-header">
        <h1>Settings</h1>
        <span className="sub">case-level context used by the rules and the AI</span>
      </div>
      <div className="view-body col" style={{ gap: 14, maxWidth: 1100 }}>
        <div className="grid-2">
          <div className="panel">
            <div className="panel-h">case</div>
            <div className="panel-b col">
              <label className="field">
                <span>name</span>
                <input className="input" value={name} onChange={(e) => setName(e.target.value)} />
              </label>
              <label className="field">
                <span>analyst</span>
                <input className="input" value={analyst} onChange={(e) => setAnalyst(e.target.value)} placeholder="recorded in the chain of custody" />
              </label>
              <label className="field">
                <span>notes</span>
                <textarea className="textarea" value={notes} onChange={(e) => setNotes(e.target.value)} />
              </label>
              <div className="row">
                <button className="btn primary sm" onClick={saveMeta}>
                  save
                </button>
              </div>
            </div>
          </div>
          <div className="panel">
            <div className="panel-h">storage</div>
            <div className="panel-b col">
              <div className="row">
                <Badge sev={isServer ? 'accent' : 'info'}>{isServer ? 'server store (DuckDB)' : 'browser store (IndexedDB)'}</Badge>
                {isServer && (
                  <span className="mono small dim">
                    {kase.serverKey} · {storeSize != null ? fmtBytes(storeSize) : '…'}
                  </span>
                )}
              </div>
              <div className="hint">
                {isServer
                  ? 'Rows live in a DuckDB file under the server data folder on this machine; the browser keeps cases, findings, notes and AI sessions. Suited to gigabytes of logs and mailboxes.'
                  : 'Rows live in this browser only (portable, zero server state). Suited to cases under a few hundred MB.'}
              </div>
              {!isServer && !browserOnly && (
                <div className="col">
                  <button className="btn primary sm" onClick={migrate} disabled={!!migrating}>
                    convert this case to the server store
                  </button>
                  {migrating && (
                    <>
                      <Progress indeterminate />
                      <div className="small dim mono">{migrating}</div>
                    </>
                  )}
                </div>
              )}
              <label className="field">
                <span>suggest the server store for files larger than (MB)</span>
                <input
                  type="number"
                  className="input mono"
                  min={10}
                  value={threshold}
                  onChange={(e) => {
                    const v = Number(e.target.value) || 150
                    setThreshold(v)
                    getDb().kv.put({ key: 'storeThresholdMb', value: v })
                  }}
                />
              </label>
              {isServer && (
                <>
                  <Toggle
                    on={s.deepAttachments !== false}
                    onChange={(v) => patch({ deepAttachments: v })}
                    label="deep attachment analysis at ingestion (macros, PDF, archives) - slower on huge mailboxes"
                  />
                  <Toggle on={s.keepBodies !== false} onChange={(v) => patch({ keepBodies: v })} label="keep mail bodies and raw headers (needed for body regex and previews)" />
                </>
              )}
            </div>
          </div>
          <div className="panel">
            <div className="panel-h">AI · analyst model</div>
            <div className="panel-b col">
              <div className="col" style={{ gap: 6 }}>
                <label className="checkbox">
                  <input type="radio" name="aitransport" checked={aiCfg.transport === 'browser'} onChange={() => saveAi({ transport: 'browser' })} />{' '}
                  <span>
                    <b>Browser-direct</b>{' '}
                    <span className="muted small">— this page calls YOUR local Ollama. Prompts and evidence excerpts never reach the REMN server. Each analyst uses their own machine's models.</span>
                  </span>
                </label>
                {browserOnly ? (
                  <div className="hint">This server runs in browser-only mode: it has no model of its own. The page talks to the Ollama on your machine.</div>
                ) : (
                  <>
                    <label className="checkbox">
                      <input type="radio" name="aitransport" checked={aiCfg.transport === 'server'} onChange={() => saveAi({ transport: 'server' })} />{' '}
                      <span>
                        <b>Server proxy</b>{' '}
                        <span className="muted small">— the REMN server relays to the Ollama configured in its .env (nothing persisted). Use when no local Ollama, or on Safari over HTTPS.</span>
                      </span>
                    </label>
                    <label className="checkbox">
                      <input type="radio" name="aitransport" checked={aiCfg.transport === 'claude'} onChange={() => saveAi({ transport: 'claude' })} />{' '}
                      <span>
                        <b>Claude Code</b>{' '}
                        <span className="muted small">
                          — the REMN server runs the <code>claude</code> command line installed on its machine, signed in with that machine's Claude account. Prompts, tool results (evidence excerpts)
                          and answers go to Anthropic; the server keeps nothing. Not for evidence that may not leave your organisation.
                        </span>
                      </span>
                    </label>
                  </>
                )}
              </div>
              {aiCfg.transport === 'claude' && (
                <div className="row" style={{ alignItems: 'flex-start' }}>
                  <label className="field">
                    <span>model</span>
                    <select className="select mono" value={aiCfg.claudeModel} onChange={(e) => saveAi({ claudeModel: e.target.value })}>
                      {CLAUDE_MODELS.map((m) => (
                        <option key={m.name} value={m.name}>
                          {m.name}
                          {m.parameterSize ? ` · ${m.parameterSize}` : ''}
                        </option>
                      ))}
                    </select>
                  </label>
                  <div className="field" style={{ flex: 1 }}>
                    <span>on the server machine</span>
                    <div className="small" style={{ paddingTop: 6 }}>
                      {!claudeStatus
                        ? '…'
                        : claudeStatus.available && claudeStatus.loggedIn
                          ? `${claudeStatus.version ?? 'installed'} · signed in${claudeStatus.method ? ` (${claudeStatus.method})` : ''}${claudeStatus.account ? ` as ${claudeStatus.account}` : ''}`
                          : (claudeStatus.error ?? 'not available')}
                    </div>
                  </div>
                </div>
              )}
              {aiCfg.transport === 'browser' && (
                <label className="field">
                  <span>local Ollama URL (as seen from this browser)</span>
                  <div className="row">
                    <input
                      className="input mono"
                      style={{ flex: 1 }}
                      value={urlDraft}
                      onChange={(e) => setUrlDraft(e.target.value)}
                      onBlur={() => saveAi({ ollamaUrl: urlDraft.trim().replace(/\/+$/, '') || 'http://localhost:11434' })}
                      placeholder="http://localhost:11434"
                    />
                  </div>
                </label>
              )}
              {aiCfg.transport !== 'claude' && (
                <div className="row">
                  <label className="field" style={{ flex: 1 }}>
                    <span>default model (blank = server default)</span>
                    <input className="input mono" list="ai-models" value={aiCfg.model} onChange={(e) => saveAi({ model: e.target.value })} placeholder={health?.ollama.defaultModel ?? 'qwen3:8b'} />
                    <datalist id="ai-models">
                      {aiModels.map((m) => (
                        <option key={m.name} value={m.name} />
                      ))}
                    </datalist>
                  </label>
                  <label className="field">
                    <span>context window (num_ctx)</span>
                    <input
                      type="number"
                      className="input mono"
                      min={2048}
                      step={1024}
                      value={aiCfg.numCtx ?? ''}
                      onChange={(e) => saveAi({ numCtx: e.target.value ? Number(e.target.value) : null })}
                      placeholder={String(health?.ollama.numCtx ?? 32768)}
                    />
                  </label>
                </div>
              )}
              <div className="row">
                <button className="btn primary sm" onClick={testAi} disabled={aiTesting}>
                  {aiTesting ? 'testing…' : 'test connection'}
                </button>
                <span className="small dim">
                  {aiStatus.reachable === true ? (aiCfg.transport === 'claude' ? '✓ ready' : `✓ reachable · ${aiStatus.models ?? 0} model(s)`) : aiStatus.reachable === false ? '✗ unreachable' : ''}
                </span>
              </div>
              {aiCfg.transport === 'claude' && (
                <div className="hint">
                  Install Claude Code on the server machine (<code>npm install -g @anthropic-ai/claude-code</code>), run <code>claude</code> there once to sign in, then restart REMN. The server runs
                  it with its own tools, hooks, plugins and MCP servers off and without saving a session; REMN's tools are still executed in this browser. Operators can switch the connector off with{' '}
                  <code>CLAUDE_CODE_ENABLED=0</code>.
                </div>
              )}
              {aiCfg.transport === 'browser' && (
                <div className="hint">
                  If REMN is NOT served from localhost (e.g. accessed on your home server), your Ollama must allow this origin: run{' '}
                  <code>setx OLLAMA_ORIGINS "{typeof location !== 'undefined' ? location.origin : ''}"</code> (Windows, then restart Ollama) or{' '}
                  <code>OLLAMA_ORIGINS={typeof location !== 'undefined' ? location.origin : ''} ollama serve</code>. HTTPS pages may call http://localhost in Chrome, Edge and Firefox; Safari blocks it
                  — use the server proxy there.
                </div>
              )}
            </div>
          </div>
          <div className="panel">
            <div className="panel-h">organisation context</div>
            <div className="panel-b col">
              <label className="field">
                <span>internal domains (one per line) - drives lookalike / spoof detection</span>
                <ListInput mono value={s.internalDomains} onChange={(v) => patch({ internalDomains: v.map((x) => x.toLowerCase().replace(/^@/, '')) })} placeholder={'company.com\ncompany.fr'} />
              </label>
              <label className="field">
                <span>VIP display names (CEO, CFO, IT admins…) - impersonation rule</span>
                <ListInput value={s.vipNames} onChange={(v) => patch({ vipNames: v })} placeholder={'Marie Lefevre\nJean Dupont'} />
              </label>
              <label className="field">
                <span>organisation display names (all staff, one per line) - employee-impersonation rules; the Sublime pack's $org_display_names</span>
                <ListInput value={s.orgDisplayNames ?? []} onChange={(v) => patch({ orgDisplayNames: v })} placeholder={'one display name per line'} />
              </label>
              <label className="field">
                <span>extra brands to protect (second-level labels)</span>
                <ListInput mono value={s.brands} onChange={(v) => patch({ brands: v.map((x) => x.toLowerCase()) })} placeholder={'mybank\nmysupplier'} />
              </label>
              <label className="field">
                <span>trusted senders (addresses or domains) - lower weak signals; some spoofing rules exempt them</span>
                <ListInput
                  mono
                  value={s.trustedSenders ?? []}
                  onChange={(v) => patch({ trustedSenders: v.map((x) => x.toLowerCase().replace(/^@/, '')) })}
                  placeholder={'notifications.supplier.com\nfacture@partenaire.fr'}
                />
              </label>
              <div className="row">
                <button className="btn sm" onClick={runSuggest} disabled={suggesting}>
                  {suggesting ? 'scanning…' : 'suggest trusted senders'}
                </button>
                <span className="small dim">known relays (Teams, GitHub…) are already built in when auth passes</span>
              </div>
              <div className="hint">
                After changing these settings, use Mails → rescore + refresh findings. Trust reduces weak signals; suspicious payloads retain their risk. Full reanalysis of missing attachment facts
                requires the original evidence.
              </div>
            </div>
          </div>
          <div className="panel">
            <div className="panel-h">windows context</div>
            <div className="panel-b col">
              <label className="field">
                <span>internal IP ranges (CIDR) - RDP/share rules exclude them</span>
                <ListInput mono value={s.internalIps} onChange={(v) => patch({ internalIps: v })} />
              </label>
              <label className="field">
                <span>expected sign-in countries (ISO codes) - Entra / M365 sign-in rules flag the rest</span>
                <ListInput mono value={s.expectedCountries ?? []} onChange={(v) => patch({ expectedCountries: v.map((x) => x.trim().toUpperCase()).filter(Boolean) })} placeholder={'FR\nDE\nUS'} />
              </label>
              <label className="field">
                <span>admin accounts (expected to have special privileges)</span>
                <ListInput mono value={s.adminAccounts} onChange={(v) => patch({ adminAccounts: v })} placeholder={'admin.jdoe\nsvc_backup'} />
              </label>
              <label className="field">
                <span>service accounts (excluded from out-of-hours rules)</span>
                <ListInput mono value={s.serviceAccounts} onChange={(v) => patch({ serviceAccounts: v })} placeholder={'svc_sql\nsvc_scan'} />
              </label>
            </div>
          </div>
          <div className="panel">
            <div className="panel-h">time</div>
            <div className="panel-b col">
              <div className="row">
                <label className="field">
                  <span>business hours start</span>
                  <input
                    type="number"
                    className="input mono"
                    min={0}
                    max={23}
                    value={s.businessHours.start}
                    onChange={(e) => patch({ businessHours: { ...s.businessHours, start: Number(e.target.value) } })}
                  />
                </label>
                <label className="field">
                  <span>end</span>
                  <input
                    type="number"
                    className="input mono"
                    min={0}
                    max={24}
                    value={s.businessHours.end}
                    onChange={(e) => patch({ businessHours: { ...s.businessHours, end: Number(e.target.value) } })}
                  />
                </label>
                <label className="field" style={{ flex: 1 }}>
                  <span>time zone (IANA)</span>
                  <input className="input mono" value={s.businessHours.tz} onChange={(e) => patch({ businessHours: { ...s.businessHours, tz: e.target.value } })} placeholder="Europe/Paris" />
                </label>
              </div>
              <label className="field">
                <span>weekend days</span>
                <div className="row wrap">
                  {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map((d, i) => (
                    <label key={d} className="checkbox small">
                      <input
                        type="checkbox"
                        checked={s.weekendDays.includes(i)}
                        onChange={(e) => patch({ weekendDays: e.target.checked ? [...s.weekendDays, i].sort() : s.weekendDays.filter((x) => x !== i) })}
                      />{' '}
                      {d}
                    </label>
                  ))}
                </div>
              </label>
              <Toggle
                on={local}
                onChange={(v) => {
                  setLocal(v)
                  setLocalTime(v)
                  getDb().kv.put({ key: 'localTime', value: v })
                  toast('info', v ? 'timestamps shown in local time' : 'timestamps shown in UTC')
                }}
                label="display timestamps in local time instead of UTC (display only - data stays UTC)"
              />
            </div>
          </div>
          <div className="panel">
            <div className="panel-h">external lookups (opt-in)</div>
            <div className="panel-b col">
              {browserOnly ? (
                <div className="hint">Reputation lookups are switched off on this server (browser-only mode): it contacts no third party on your behalf.</div>
              ) : (
                <Toggle on={s.networkAllowed} onChange={(v) => patch({ networkAllowed: v })} label="allow reputation lookups - every checked indicator is disclosed to the provider" />
              )}
              <div className="col" style={{ gap: 4 }}>
                {providers.map((p) => (
                  <label key={p.name} className="checkbox small" title={p.description}>
                    <input
                      type="checkbox"
                      disabled={!p.configured}
                      checked={!s.providers.length ? p.configured : s.providers.includes(p.name)}
                      onChange={(e) => {
                        const base = s.providers.length ? s.providers : providers.filter((x) => x.configured).map((x) => x.name)
                        patch({ providers: e.target.checked ? Array.from(new Set([...base, p.name])) : base.filter((x) => x !== p.name) })
                      }}
                    />
                    <span className="mono">{p.name}</span> <Badge sev={p.configured ? 'ok' : 'info'}>{p.configured ? 'configured' : p.needsKey ? `needs ${p.needsKey} key` : 'unavailable'}</Badge>{' '}
                    <span className="muted">{p.kinds.join(', ')}</span>
                  </label>
                ))}
              </div>
              <div className="hint">
                Keys are read by the server from <code>.env</code> (see <code>.env.example</code>). Offline block lists go to <code>backend/data/lists</code>, YARA rules to{' '}
                <code>backend/data/yara</code>, GeoLite2 databases to <code>backend/data/geoip</code>.
              </div>
            </div>
          </div>
          <div className="panel">
            <div className="panel-h">ingestion &amp; storage</div>
            <div className="panel-b col">
              <Toggle on={s.includeRaw !== false} onChange={(v) => patch({ includeRaw: v })} label="store the raw event JSON (enables regex over the whole record; ~2x storage)" />
              <Toggle
                on={s.autoRunRules !== false}
                onChange={(v) => patch({ autoRunRules: v })}
                label="run the enabled rules automatically when an ingest finishes (the Findings page otherwise lags the evidence until you run them)"
              />
              <div className="kv small">
                <div className="k">server</div>
                <div className="v">
                  {health?.name} v{health?.version} · python {health?.python} · multipart limit {health?.limits.maxUploadMb} MB · chunked uploads up to {health?.limits.maxChunkedGb ?? '?'} GB
                </div>
                <div className="k">case stores</div>
                <div className="v">{health?.store?.casesDir ?? '—'}</div>
                <div className="k">ollama</div>
                <div className="v">
                  {health?.ollama.host} · {health?.ollama.reachable ? `${health.ollama.models.length} model(s)` : health?.ollama.error}
                </div>
                <div className="k">optional</div>
                <div className="v">
                  PST/OST {health?.optional.pst ? 'yes' : 'no (pip install libpff-python)'} · YARA {health?.optional.yara ? `yes (${health.optional.yaraRules} rule file(s))` : 'no'}
                </div>
              </div>
              <div className="divider" />
              <div className="row">
                <button className="btn danger sm" onClick={wipe}>
                  delete all case data{isServer ? ' (browser + server store)' : ' from this browser'}
                </button>
                <button className="btn danger sm" onClick={destroy}>
                  delete this case
                </button>
              </div>
              <div className="hint">The first empties the case and keeps it; the second removes the case itself and switches to another one.</div>
            </div>
          </div>
        </div>
      </div>
      {suggestions && (
        <Modal
          title="Suggested trusted senders"
          onClose={() => setSuggestions(null)}
          footer={
            <button className="btn primary" onClick={applySuggestions} disabled={!picked.size}>
              add {picked.size} to trusted senders
            </button>
          }
        >
          <div className="small muted">Domains with 5+ mails, passing authentication and no strong indicator in this case. Untick anything you do not recognise.</div>
          <div className="col" style={{ gap: 4, maxHeight: 320, overflowY: 'auto' }}>
            {suggestions.map((f) => (
              <label key={f.registrable} className="checkbox small mono">
                <input
                  type="checkbox"
                  checked={picked.has(f.registrable)}
                  onChange={(e) => {
                    const next = new Set(picked)
                    if (e.target.checked) next.add(f.registrable)
                    else next.delete(f.registrable)
                    setPicked(next)
                  }}
                />
                <span>{f.registrable}</span>{' '}
                <span className="dim">
                  {f.count} mail(s) · e.g. {f.sample}
                </span>
              </label>
            ))}
          </div>
        </Modal>
      )}
    </div>
  )
}
