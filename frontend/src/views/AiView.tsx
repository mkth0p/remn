import { useEffect, useRef, useState } from 'react'
import { bindChatToCase, newChatSession, openChatSession, sendMessage, stopChat, useChat } from '../ai/session'
import { getTransport, type ModelInfo } from '../ai/transport'
import { getDb, type AiSession } from '../db/schema'
import { toast, useStore } from '../state/store'
import { fmtTs, renderMarkdown } from '../util/format'
import { Badge, Spinner, Toggle } from '../components/ui'
import { IconPlus, IconStop, IconTrash } from '../components/Icons'

const STARTERS = [
  'Give me an overview of this case and the most suspicious things you see.',
  'Look for brute-force or password-spraying activity and tell me which accounts were targeted.',
  'Which accounts logged on outside business hours, from where, and is anything unusual?',
  'Find evidence of lateral movement (RDP, PsExec, admin shares, WinRM) and build a short timeline.',
  'Which mails look like phishing or BEC? Rank them and explain the indicators.',
  'Are there attachments with macros, scripts or HTML smuggling? List sender, subject and hashes.',
  'Write a regex to find PowerShell script blocks that download and execute something, then test it.',
]

export function AiView() {
  const kase = useStore((s) => s.currentCase)
  const health = useStore((s) => s.health)
  const aiCfg = useStore((s) => s.aiConfig)
  const aiStatus = useStore((s) => s.aiStatus)
  const setAiConfig = useStore((s) => s.setAiConfig)
  const setAiStatus = useStore((s) => s.setAiStatus)
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
  const setInput = (v: string) => useChat.getState().set({ input: v })
  const [think, setThink] = useState(false)
  const [tools, setTools] = useState(true)
  const [model, setModel] = useState('')
  const [showTools, setShowTools] = useState(true)
  const logRef = useRef<HTMLDivElement>(null)
  const reloadSessions = () => kase?.id && getDb().aiSessions.where('caseId').equals(kase.id).reverse().sortBy('updatedAt').then(setSessions)
  useEffect(() => {
    if (kase?.id) bindChatToCase(kase.id)
    reloadSessions()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kase?.id, sessionsVersion])
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
  }, [aiCfg.transport, aiCfg.ollamaUrl, aiStatus.reachable])
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
  }, [model, aiCfg.transport, aiCfg.ollamaUrl, aiCfg.model])
  if (!kase) return null
  const reachable = aiStatus.reachable === true
  const retryPing = () =>
    getTransport()
      .ping()
      .then((r) => setAiStatus({ reachable: r.reachable, error: r.error, models: r.models, checkedAt: Date.now() }))
  const newSession = () => newChatSession()
  const openSession = (s: AiSession) => openChatSession(s)
  const send = (text?: string) => {
    const q = (text ?? input).trim()
    if (!q || busy) return
    if (!reachable)
      return toast(
        'err',
        aiCfg.transport === 'browser'
          ? `your local Ollama (${aiCfg.ollamaUrl}) is not reachable - start it, or switch the transport in Settings`
          : aiCfg.transport === 'claude'
            ? 'Claude Code is not available on the server machine (see Settings).'
            : 'Ollama is not reachable from the server (see Settings).',
      )
    void sendMessage(kase, q, { mode: tools ? 'analyst' : 'free', model: model || undefined, think, tools: tools && canTools })
  }
  return (
    <div className="view">
      <div className="split" style={{ gridTemplateColumns: '240px 1fr' }}>
        <div className="left col" style={{ padding: 8, gap: 6 }}>
          <button className="btn sm" onClick={newSession}>
            <IconPlus /> new session
          </button>
          {sessions.map((s) => (
            <div key={s.id} className={`list-item ${session?.id === s.id ? 'active' : ''}`} onClick={() => openSession(s)} style={{ padding: '6px 10px' }}>
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
                      if (session?.id === s.id) useChat.getState().set({ session: null, messages: [] })
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
              : aiCfg.transport === 'claude'
                ? "Claude Code: the REMN server runs the claude command line on its machine; prompts, tool results (evidence excerpts) and answers go to Anthropic under that machine's Claude account. The server keeps nothing."
                : 'Server proxy: prompts and tool results transit through the REMN server to its Ollama (nothing is persisted there).'}{' '}
            Nothing else leaves the machine except opt-in reputation lookups.
          </div>
        </div>
        <div className="right chat">
          <div className="row" style={{ padding: '8px 14px', borderBottom: '1px solid var(--line)', gap: 10 }}>
            <Badge sev={reachable ? 'ok' : 'critical'}>
              {aiCfg.transport === 'claude'
                ? reachable
                  ? 'claude ready'
                  : aiStatus.reachable === null
                    ? 'claude …'
                    : 'claude unavailable'
                : reachable
                  ? 'ollama online'
                  : aiStatus.reachable === null
                    ? 'ollama …'
                    : 'ollama offline'}
            </Badge>
            <Badge sev="info">
              {aiCfg.transport === 'browser' ? `local · ${aiCfg.ollamaUrl.replace(/^https?:\/\//, '')}` : aiCfg.transport === 'claude' ? 'Claude Code · server machine' : 'via server'}
            </Badge>
            <select className="select mono" value={model} onChange={(e) => setModel(e.target.value)} title="model">
              <option value="">{aiCfg.transport === 'claude' ? aiCfg.claudeModel || 'sonnet' : aiCfg.model || health?.ollama.defaultModel || 'default model'}</option>
              {models.map((m) => (
                <option key={m.name} value={m.name}>
                  {m.name}
                  {m.parameterSize ? ` (${m.parameterSize})` : ''}
                </option>
              ))}
            </select>
            <Toggle on={tools} onChange={setTools} label={canTools ? 'analyst mode (tools)' : 'tools unsupported by model'} />
            <Toggle on={think} onChange={setThink} label="thinking" />
            <Toggle on={showTools} onChange={setShowTools} label="show tool traffic" />
            <span className="spacer" />
            {busy && (
              <button className="btn sm danger" onClick={stopChat}>
                <IconStop /> stop
              </button>
            )}
          </div>
          {!reachable && aiStatus.reachable !== null && (
            <div className="row" style={{ padding: '8px 14px', gap: 10, borderBottom: '1px solid var(--line)', background: 'var(--bg-2)' }}>
              <span className="small" style={{ flex: 1 }}>
                ⚠ {aiStatus.error ?? (aiCfg.transport === 'claude' ? 'Claude Code unavailable.' : 'Ollama unreachable.')}
              </span>
              <button className="btn xs" onClick={retryPing}>
                retry
              </button>
              {aiCfg.transport === 'browser' && health?.ollama.reachable && (
                <button
                  className="btn xs"
                  onClick={async () => {
                    setAiConfig({ transport: 'server' })
                    const { getDb } = await import('../db/schema')
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
            {!messages.length && (
              <div className="col" style={{ maxWidth: 760 }}>
                <div className="muted small">Ask anything about the loaded evidence. Suggested starters:</div>
                {STARTERS.map((s) => (
                  <button key={s} className="btn ghost sm" style={{ justifyContent: 'flex-start', whiteSpace: 'normal', textAlign: 'left' }} onClick={() => send(s)}>
                    › {s}
                  </button>
                ))}
              </div>
            )}
            {messages.map((m, i) => {
              if (m.role === 'tool')
                return showTools ? (
                  <div key={i} className="msg tool">
                    <div className="role">tool result · {m.tool_name}</div>
                    {m.content.length > 1200 ? m.content.slice(0, 1200) + `… (${m.content.length} chars)` : m.content}
                  </div>
                ) : null
              if (m.role === 'assistant') {
                return (
                  <div key={i} className="col" style={{ gap: 6, alignSelf: 'flex-start', maxWidth: '100%' }}>
                    {m.thinking && showTools && (
                      <div className="msg thinking">
                        <div className="role">thinking</div>
                        {m.thinking.slice(0, 2000)}
                      </div>
                    )}
                    {m.tool_calls?.length ? (
                      <div className="msg tool">
                        <div className="role">tool calls</div>
                        {m.tool_calls.map((c, j) => (
                          <div key={j}>
                            → <b>{c.name}</b>({JSON.stringify(c.arguments)})
                          </div>
                        ))}
                      </div>
                    ) : null}
                    {m.content && (
                      <div className="msg assistant md">
                        <div className="role">remn · {m.stats?.eval_count ? `${m.stats.eval_count} tokens` : ''}</div>
                        <div dangerouslySetInnerHTML={{ __html: renderMarkdown(m.content) }} />
                      </div>
                    )}
                  </div>
                )
              }
              return (
                <div key={i} className="msg user">
                  <div className="role">analyst</div>
                  {m.content}
                </div>
              )
            })}
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
                <Spinner /> <span className="dim small">working…</span>
              </div>
            )}
          </div>
          <div className="chat-input">
            <textarea
              className="textarea mono"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="ask about the evidence… (Enter to send, Shift+Enter for a new line)"
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
      </div>
    </div>
  )
}
