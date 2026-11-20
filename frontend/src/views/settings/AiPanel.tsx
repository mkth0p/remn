import { useEffect, useState } from 'react'
import { CLAUDE_MODELS, fetchClaudeStatus, getTransport, isLocalModelUrl, OPENAI_PRESETS, type ClaudeStatus, type ModelInfo } from '../../ai/transport'
import type { Health } from '../../api/client'
import { getDb } from '../../db/schema'
import { toast, useStore } from '../../state/store'

type AiConfig = ReturnType<typeof useStore.getState>['aiConfig']
type SaveAi = (patch: Partial<AiConfig>) => Promise<void>

/** The analyst model: how this page reaches it, where, which model, and whether it answers. */
export function AiPanel({ health }: { health: Health | null }) {
  const aiCfg = useStore((st) => st.aiConfig)
  const setAiConfig = useStore((st) => st.setAiConfig)
  const aiStatus = useStore((st) => st.aiStatus)
  const setAiStatus = useStore((st) => st.setAiStatus)
  const [aiModels, setAiModels] = useState<ModelInfo[]>([])
  const [aiTesting, setAiTesting] = useState(false)
  const [claudeStatus, setClaudeStatus] = useState<ClaudeStatus | null>(null)
  useEffect(() => {
    if (aiCfg.transport !== 'claude') return
    let dead = false
    fetchClaudeStatus()
      .then((st) => {
        if (!dead) setClaudeStatus(st)
      })
      .catch((e) => {
        if (!dead) setClaudeStatus({ enabled: false, available: false, loggedIn: false, error: (e as Error).message })
      })
    return () => {
      dead = true
    }
  }, [aiCfg.transport, aiStatus.checkedAt])
  const saveAi: SaveAi = async (patch) => {
    setAiConfig(patch)
    const db = getDb()
    if (patch.transport !== undefined) await db.kv.put({ key: 'aiTransport', value: patch.transport })
    if (patch.ollamaUrl !== undefined) await db.kv.put({ key: 'aiOllamaUrl', value: patch.ollamaUrl })
    if (patch.openaiUrl !== undefined) await db.kv.put({ key: 'aiOpenaiUrl', value: patch.openaiUrl })
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
          t.kind === 'claude'
            ? 'Claude Code is installed and signed in on the server machine'
            : `${t.kind === 'openai' ? 'Model server' : 'Ollama'} reachable (${t.kind === 'server' ? 'via server' : t.endpoint}) - ${r.models ?? 0} model(s)`,
        )
      } else {
        toast('err', r.error ?? 'unreachable', 0)
      }
    } finally {
      setAiTesting(false)
    }
  }
  const origin = typeof location !== 'undefined' ? location.origin : ''
  return (
    <div className="panel">
      <div className="panel-h">AI · analyst model</div>
      <div className="panel-b col">
        <TransportChoice aiCfg={aiCfg} saveAi={saveAi} browserOnly={health?.mode === 'browser-only'} />
        <Endpoint aiCfg={aiCfg} saveAi={saveAi} health={health} aiModels={aiModels} claudeStatus={claudeStatus} />
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
            The connector is off unless an operator turns it on: install Claude Code on the server machine (<code>npm install -g @anthropic-ai/claude-code</code>), run <code>claude</code> there once
            to sign in as the account that runs REMN, set <code>CLAUDE_CODE_ENABLED=1</code> and restart REMN. REMN does not check which kind of sign-in that is; whether that account may be used for
            this, and on which terms, is for its holder to settle with Anthropic first. The server runs it with its own tools, hooks, plugins and MCP servers off and without saving a session; REMN's
            tools are still executed in this browser.
          </div>
        )}
        {aiCfg.transport === 'browser' && (
          <div className="hint">
            If REMN is NOT served from localhost (e.g. accessed on your home server), your Ollama must allow this origin. On a Mac, paste once in Terminal{' '}
            <code>
              curl -fsSL {origin}/ollama-mac.sh | bash -s -- {origin}
            </code>{' '}
            (it keeps the setting across restarts and restarts Ollama). Otherwise run <code>setx OLLAMA_ORIGINS "{origin}"</code> (Windows, then restart Ollama) or{' '}
            <code>OLLAMA_ORIGINS={origin} ollama serve</code>. HTTPS pages may call http://localhost in Chrome, Edge and Firefox; Safari blocks it — use the server proxy there.
          </div>
        )}
      </div>
    </div>
  )
}

/** The four ways to reach a model, and what each sends where; a browser-only server has no model of its own. */
function TransportChoice({ aiCfg, saveAi, browserOnly }: { aiCfg: AiConfig; saveAi: SaveAi; browserOnly: boolean }) {
  return (
    <div className="col" style={{ gap: 6 }}>
      <label className="checkbox">
        <input type="radio" name="aitransport" checked={aiCfg.transport === 'browser'} onChange={() => saveAi({ transport: 'browser' })} />{' '}
        <span>
          <b>Browser-direct</b>{' '}
          <span className="muted small">— this page calls YOUR local Ollama. Prompts and evidence excerpts never reach the REMN server. Each analyst uses their own machine's models.</span>
        </span>
      </label>
      <label className="checkbox">
        <input type="radio" name="aitransport" checked={aiCfg.transport === 'openai'} onChange={() => saveAi({ transport: 'openai' })} />{' '}
        <span>
          <b>Local OpenAI-compatible server</b>{' '}
          <span className="muted small">
            — this page calls LM Studio, a llama.cpp server, vLLM or Jan on your machine or local network (<code>/v1/chat/completions</code>). Nothing reaches the REMN server; no API key is sent, and
            cloud endpoints are refused.
          </span>
        </span>
      </label>
      {browserOnly ? (
        <div className="hint">This server runs in browser-only mode: it has no model of its own. The page talks to the model server on your machine.</div>
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
                — off unless the server's operator turns it on. The REMN server then runs the <code>claude</code> command line installed on its machine, with the sign-in of the account that runs REMN:
                every analyst who uses this server and picks Claude Code works through that one sign-in. Prompts, tool results (evidence excerpts) and answers leave the server for Anthropic under that
                account; the server keeps nothing. Not for evidence that may not leave your organisation.
              </span>
            </span>
          </label>
        </>
      )}
    </div>
  )
}

/** Where the chosen transport reaches its model (refused off the local network), which model, and the context window. */
function Endpoint({ aiCfg, saveAi, health, aiModels, claudeStatus }: { aiCfg: AiConfig; saveAi: SaveAi; health: Health | null; aiModels: ModelInfo[]; claudeStatus: ClaudeStatus | null }) {
  const [urlDraft, setUrlDraft] = useState(aiCfg.ollamaUrl)
  const [openaiDraft, setOpenaiDraft] = useState(aiCfg.openaiUrl)
  useEffect(() => setUrlDraft(aiCfg.ollamaUrl), [aiCfg.ollamaUrl])
  return (
    <>
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
              {!claudeStatus ? '…' : claudeStatus.available && claudeStatus.loggedIn ? 'installed and signed in' : (claudeStatus.error ?? 'not available')}
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
          {urlDraft.trim() !== '' && !isLocalModelUrl(urlDraft.trim()) && (
            <div className="hint">✗ not a local address: REMN only sends evidence to an Ollama on this machine or your local network.</div>
          )}
        </label>
      )}
      {aiCfg.transport === 'openai' && (
        <div className="col" style={{ gap: 6 }}>
          <label className="field">
            <span>model server URL, ending in /v1 (as seen from this browser)</span>
            <input
              className="input mono"
              value={openaiDraft}
              onChange={(e) => setOpenaiDraft(e.target.value)}
              onBlur={() => saveAi({ openaiUrl: openaiDraft.trim().replace(/\/+$/, '') || 'http://localhost:1234/v1' })}
              placeholder="http://localhost:1234/v1"
            />
          </label>
          {!isLocalModelUrl(openaiDraft) && <div className="hint">✗ not a local address: REMN only sends evidence to a model server on this machine or your local network.</div>}
          <div className="row" style={{ flexWrap: 'wrap', gap: 6 }}>
            {OPENAI_PRESETS.map((p) => (
              <button
                key={p.name}
                className={`btn xs ${aiCfg.openaiUrl === p.url ? 'primary' : ''}`}
                title={p.hint}
                onClick={() => {
                  setOpenaiDraft(p.url)
                  void saveAi({ openaiUrl: p.url })
                }}
              >
                {p.name}
              </button>
            ))}
          </div>
          <div className="hint">{OPENAI_PRESETS.find((p) => p.url === aiCfg.openaiUrl)?.hint ?? "Start the server with tool calling on, and let it accept this page's origin (CORS)."}</div>
        </div>
      )}
      {aiCfg.transport !== 'claude' && (
        <div className="row">
          <label className="field" style={{ flex: 1 }}>
            <span>default model (blank: the server's OLLAMA_MODEL, else the first model listed)</span>
            <input className="input mono" list="ai-models" value={aiCfg.model} onChange={(e) => saveAi({ model: e.target.value })} placeholder={health?.ollama.defaultModel ?? 'qwen3:8b'} />
            <datalist id="ai-models">
              {aiModels.map((m) => (
                <option key={m.name} value={m.name} />
              ))}
            </datalist>
          </label>
          <label className="field">
            <span>{aiCfg.transport === 'openai' ? 'context window (the size loaded in the server)' : 'context window (num_ctx)'}</span>
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
    </>
  )
}
