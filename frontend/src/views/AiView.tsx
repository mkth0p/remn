import { useEffect, useMemo, useRef, useState } from 'react'
import { bindChatToCase, newChatSession, openChatSession, sendMessage, stopChat, useChat, wrapUpChat } from '../ai/session'
import { getTransport, transportLabel, type ModelInfo } from '../ai/transport'
import { SeenSet } from '../ai/evidence'
import { PLAYBOOKS, playbookFits, playbookStart, type Playbook } from '../ai/playbooks'
import { caseShape, type CaseShape } from '../ai/tools'
import { getDb, type AiSession } from '../db/schema'
import { toast, useStore } from '../state/store'
import { fmtTs, renderMarkdown } from '../util/format'
import { Badge, Spinner, Toggle } from '../components/ui'
import { IconPlus, IconStop, IconTrash } from '../components/Icons'
import { AiMessage } from './ai/AiMessage'
import { AiSidePanel } from './ai/AiSidePanel'

const STARTERS = [
  'Give me an overview of this case and the most suspicious things you see.',
  'Which accounts logged on outside business hours, from where, and is anything unusual?',
  'Which mails look like phishing or BEC? Rank them and explain the indicators.',
  'Are there attachments with macros, scripts or HTML smuggling? List sender, subject and hashes.',
  'Write a rule for PowerShell script blocks that download and execute something, and test it on this case.',
]

const BUDGETS = [8, 16, 24, 40]

export function AiView() {
  const kase = useStore((s) => s.currentCase)
  const health = useStore((s) => s.health)
  const aiCfg = useStore((s) => s.aiConfig)
  const aiStatus = useStore((s) => s.aiStatus)
  const setAiConfig = useStore((s) => s.setAiConfig)
  const setAiStatus = useStore((s) => s.setAiStatus)
  const counts = useStore((s) => s.counts)
  const [models, setModels] = useState<ModelInfo[]>([])
  const [canTools, setCanTools] = useState(true)
  const aiPrompt = useStore((s) => s.aiPrompt)
  const setAiPrompt = useStore((s) => s.setAiPrompt)
  const [sessions, setSessions] = useState<AiSession[]>([])
  const session = useChat((s) => s.session)
  const messages = useChat((s) => s.messages)
  const input = useChat((s) => s.input)
  const busy = useChat((s) => s.busy)
  const live = useChat((s) => s.live)
  const liveThinking = useChat((s) => s.liveThinking)
  const sessionsVersion = useChat((s) => s.sessionsVersion)
  const seenKeys = useChat((s) => s.seen)
  const plan = useChat((s) => s.plan)
  const run = useChat((s) => s.run)
  const wrapUp = useChat((s) => s.wrapUp)
  const seen = useMemo(() => new SeenSet(seenKeys), [seenKeys])
  const setInput = (v: string) => useChat.getState().set({ input: v })
  const [think, setThink] = useState(false)
  const [tools, setTools] = useState(true)
  const [budget, setBudget] = useState(24)
  const [model, setModel] = useState('')
  const [showTools, setShowTools] = useState(false)
  const [shape, setShape] = useState<CaseShape | null>(null)
  const logRef = useRef<HTMLDivElement>(null)
  const label = transportLabel(aiCfg)
  const reloadSessions = () => kase?.id && getDb().aiSessions.where('caseId').equals(kase.id).reverse().sortBy('updatedAt').then(setSessions)
  useEffect(() => {
    if (kase?.id) bindChatToCase(kase.id)
    reloadSessions()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kase?.id, sessionsVersion])
  useEffect(() => {
    if (kase) caseShape(kase).then(setShape)
  }, [kase, counts.events, counts.mails])
  useEffect(() => {
    if (aiPrompt) {
      setInput(aiPrompt)
      setAiPrompt(null)
    }
  }, [aiPrompt, setAiPrompt])
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [messages, live, liveThinking])
  useEffect(() => {
    let dead = false
    getTransport()
      .listModels()
      .then((ms) => {
        if (!dead) setModels(ms)
      })
      .catch(() => {
        if (!dead) setModels([])
      })
    return () => {
      dead = true
    }
  }, [aiCfg.transport, aiCfg.ollamaUrl, aiCfg.openaiUrl, aiStatus.reachable])
  useEffect(() => {
    let dead = false
    const m = model || aiCfg.model || health?.ollama.defaultModel || ''
    if (!m) {
      setCanTools(true)
      return
    }
    getTransport()
      .capabilities(m)
      .then((caps) => {
        if (!dead) setCanTools(!caps.length || caps.includes('tools'))
      })
      .catch(() => {
        if (!dead) setCanTools(true)
      })
    return () => {
      dead = true
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [model, aiCfg.transport, aiCfg.ollamaUrl, aiCfg.openaiUrl, aiCfg.model])
  // the model is checked when the analyst comes here, not by every page load (App skips it for a
  // page served from another host, which would otherwise probe every visitor's localhost)
  useEffect(() => {
    if (useStore.getState().aiStatus.reachable === null)
      getTransport()
        .ping()
        .then((r) => setAiStatus({ reachable: r.reachable, error: r.error, models: r.models, checkedAt: Date.now() }))
        .catch(() => undefined)
  }, [setAiStatus])
  if (!kase) return null
  const reachable = aiStatus.reachable === true
  const retryPing = () =>
    getTransport()
      .ping()
      .then((r) => setAiStatus({ reachable: r.reachable, error: r.error, models: r.models, checkedAt: Date.now() }))
  const agentOn = tools && canTools
  const ready = (): boolean => {
    if (reachable) return true
    toast(
      'err',
      aiCfg.transport === 'claude'
        ? 'Claude Code is not available on the server machine (see Settings).'
        : label.local
          ? `your local model (${label.where}) is not reachable - start it, or change the connection in Settings`
          : 'Ollama is not reachable from the server (see Settings).',
    )
    return false
  }
  const send = (text?: string) => {
    const q = (text ?? input).trim()
    if (!q || busy || !ready()) return
    void sendMessage(kase, q, { mode: agentOn ? 'analyst' : 'free', model: model || undefined, think, tools: agentOn, budget })
  }
  const runPlaybook = (p: Playbook) => {
    if (busy || !ready()) return
    if (!agentOn) return toast('err', 'playbooks need the agent (tools) on, and a model that calls tools')
    const start = playbookStart(p)
    newChatSession()
    void sendMessage(kase, start.question, { mode: 'analyst', model: model || undefined, think, tools: true, budget: Math.max(budget, 24), plan: start.plan, label: `playbook: ${p.title}` })
  }
  const visible = messages.filter((m) => !m.synthetic)
  const playbooks = PLAYBOOKS.filter((p) => !shape || playbookFits(p, shape))
  return (
    <div className="view">
      <div className="split ai-layout">
        <div className="left col" style={{ padding: 8, gap: 6 }}>
          <button className="btn sm" onClick={() => newChatSession()} disabled={busy}>
            <IconPlus /> new investigation
          </button>
          {sessions.map((s) => (
            <div key={s.id} className={`list-item ${session?.id === s.id ? 'active' : ''}`} onClick={() => openChatSession(s)} style={{ padding: '6px 10px' }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="ellipsis small">{s.title}</div>
                <div className="muted" style={{ fontSize: 10 }}>
                  {fmtTs(s.updatedAt)}
                </div>
              </div>
              <button
                className="btn ghost xs"
                onClick={(e) => {
                  e.stopPropagation()
                  getDb()
                    .aiSessions.delete(s.id!)
                    .then(() => {
                      reloadSessions()
                      if (session?.id === s.id) useChat.getState().set({ session: null, messages: [], seen: [], plan: [], run: null })
                    })
                }}
              >
                <IconTrash />
              </button>
            </div>
          ))}
          <div className="divider" />
          <div className="small dim" style={{ padding: '0 4px' }}>
            {aiCfg.transport === 'browser'
              ? `Browser-direct: this page talks straight to YOUR Ollama at ${aiCfg.ollamaUrl}. Prompts and tool results never touch the REMN server.`
              : aiCfg.transport === 'openai'
                ? `Local model server: this page talks straight to ${aiCfg.openaiUrl}. Prompts and tool results never touch the REMN server.`
                : aiCfg.transport === 'claude'
                  ? "Claude Code: the REMN server runs the claude command line on its machine; prompts, tool results (evidence excerpts) and answers go to Anthropic under that machine's Claude account. The server keeps nothing."
                  : 'Server proxy: prompts and tool results transit through the REMN server to its Ollama (nothing is persisted there).'}{' '}
            The agent reads the case and proposes; only you change it, from the inbox.
          </div>
        </div>
        <div className="chat">
          <div className="row" style={{ padding: '8px 14px', borderBottom: '1px solid var(--line)', gap: 10, flexWrap: 'wrap' }}>
            <Badge sev={reachable ? 'ok' : 'critical'}>
              {label.short} {reachable ? (aiCfg.transport === 'claude' ? 'ready' : 'online') : aiStatus.reachable === null ? '…' : aiCfg.transport === 'claude' ? 'unavailable' : 'offline'}
            </Badge>
            <Badge sev="info">{label.where.replace(/https?:\/\//, '')}</Badge>
            <select className="select mono" value={model} onChange={(e) => setModel(e.target.value)} title="model">
              <option value="">{aiCfg.transport === 'claude' ? aiCfg.claudeModel || 'sonnet' : aiCfg.model || health?.ollama.defaultModel || 'default model'}</option>
              {models.map((m) => (
                <option key={m.name} value={m.name}>
                  {m.name}
                  {m.parameterSize ? ` (${m.parameterSize})` : ''}
                </option>
              ))}
            </select>
            <Toggle on={tools} onChange={setTools} label={canTools ? 'agent (tools)' : 'tools unsupported by model'} />
            <label className="small row" style={{ gap: 4 }} title="tool rounds before the agent must answer">
              steps
              <select className="select xs" value={budget} onChange={(e) => setBudget(Number(e.target.value))} disabled={!agentOn}>
                {BUDGETS.map((b) => (
                  <option key={b} value={b}>
                    {b}
                  </option>
                ))}
              </select>
            </label>
            <Toggle on={think} onChange={setThink} label="thinking" />
            <Toggle on={showTools} onChange={setShowTools} label="tool results" />
            <span className="spacer" />
            {busy && agentOn && (
              <button className="btn sm" onClick={wrapUpChat} disabled={wrapUp} title="one more turn, without tools, for the answer from what it has">
                {wrapUp ? 'answering…' : 'answer now'}
              </button>
            )}
            {busy && (
              <button className="btn sm danger" onClick={stopChat}>
                <IconStop /> stop
              </button>
            )}
          </div>
          {!reachable && aiStatus.reachable !== null && (
            <div className="row" style={{ padding: '8px 14px', gap: 10, borderBottom: '1px solid var(--line)', background: 'var(--bg-2)' }}>
              <span className="small" style={{ flex: 1 }}>
                ⚠ {aiStatus.error ?? (aiCfg.transport === 'claude' ? 'Claude Code unavailable.' : 'model unreachable.')}
              </span>
              <button className="btn xs" onClick={retryPing}>
                retry
              </button>
              {aiCfg.transport === 'browser' && health?.ollama.reachable && (
                <button
                  className="btn xs"
                  onClick={async () => {
                    setAiConfig({ transport: 'server' })
                    await getDb().kv.put({ key: 'aiTransport', value: 'server' })
                    getTransport()
                      .ping()
                      .then((r) => setAiStatus({ reachable: r.reachable, error: r.error, models: r.models, checkedAt: Date.now() }))
                  }}
                >
                  use server proxy instead
                </button>
              )}
            </div>
          )}
          <div className="chat-log" ref={logRef}>
            {!visible.length && (
              <div className="col" style={{ maxWidth: 820, gap: 14 }}>
                {agentOn && playbooks.length > 0 && (
                  <div className="col" style={{ gap: 6 }}>
                    <div className="muted small">Playbooks: the agent plans and runs the investigation, records hypotheses, and queues what it finds in your inbox.</div>
                    <div className="ai-playbooks">
                      {playbooks.map((p) => (
                        <button key={p.id} className="ai-playbook" onClick={() => runPlaybook(p)} disabled={busy}>
                          <b>{p.title}</b>
                          <span className="small dim">{p.summary}</span>
                          <span className="mono small dim">{p.attack.join(' ')}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
                <div className="col" style={{ gap: 4 }}>
                  <div className="muted small">Or ask:</div>
                  {STARTERS.map((s) => (
                    <button key={s} className="btn ghost sm" style={{ justifyContent: 'flex-start', whiteSpace: 'normal', textAlign: 'left' }} onClick={() => send(s)}>
                      › {s}
                    </button>
                  ))}
                </div>
              </div>
            )}
            {visible.map((m, i) => (
              <AiMessage key={i} m={m} seen={seen} showTools={showTools} />
            ))}
            {busy && (liveThinking || live) && (
              <div className="col" style={{ gap: 6, alignSelf: 'flex-start', maxWidth: '100%' }}>
                {liveThinking && showTools && (
                  <div className="msg thinking">
                    <div className="role">thinking…</div>
                    {liveThinking.slice(-1500)}
                  </div>
                )}
                {live && (
                  <div className="msg assistant md">
                    <div className="role">remn</div>
                    <div dangerouslySetInnerHTML={{ __html: renderMarkdown(live) }} />
                  </div>
                )}
              </div>
            )}
            {busy && !live && !liveThinking && (
              <div className="msg assistant">
                <Spinner /> <span className="dim small">{run ? `step ${run.step + 1} of ${run.budget}…` : 'working…'}</span>
              </div>
            )}
          </div>
          <div className="chat-input">
            <textarea
              className="textarea mono"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="ask about the evidence, or give the agent a task… (Enter to send, Shift+Enter for a new line)"
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault()
                  send()
                }
              }}
            />
            <button className="btn primary" disabled={busy || !input.trim()} onClick={() => send()}>
              send
            </button>
          </div>
        </div>
        <AiSidePanel kase={kase} run={run} plan={plan} seenCount={seenKeys.length} busy={busy} />
      </div>
    </div>
  )
}
