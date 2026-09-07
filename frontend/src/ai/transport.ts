/**
 * AI transports. Browser-direct (default): the analyst's browser talks to
 * their OWN Ollama (http://localhost:11434 relative to the browser machine),
 * so prompts and tool results never reach the REMN server. Server proxy:
 * the pre-existing /api/ai/* path, for setups without a local Ollama. Claude Code:
 * the server runs the local `claude` command line (that machine's Claude login);
 * prompts, tool results and answers leave for Anthropic, nothing is kept on the server.
 */
import { apiGet, apiPost, readNdjsonBody, streamSse } from '../api/client'
import { useStore } from '../state/store'
import { composeSystem, fetchAiMeta, type AiMeta } from './meta'
import type { ChatMessage } from './chat'

export type ChatChunk =
  | { type: 'token'; content: string }
  | { type: 'thinking'; content: string }
  | { type: 'tool_calls'; calls: { name: string; arguments: Record<string, unknown> }[] }
  | { type: 'done'; model: string; stats: Record<string, unknown> }
  | { type: 'error'; error: string }

export interface ChatTurnParams {
  messages: ChatMessage[]
  mode: 'analyst' | 'explain' | 'rule' | 'report' | 'triage' | 'free'
  tools: boolean
  think?: boolean
  model?: string
  context: Record<string, unknown>
}

export interface ModelInfo {
  name: string
  parameterSize?: string
  capabilities?: string[]
}

export interface AiTransport {
  kind: 'server' | 'browser' | 'claude'
  /** Human-readable endpoint for status displays. */
  endpoint: string
  chatTurn(p: ChatTurnParams, onChunk: (c: ChatChunk) => void, signal?: AbortSignal): Promise<void>
  queryJson(question: string, context: Record<string, unknown>, model?: string): Promise<{ query: Record<string, unknown> | null; raw: string; model: string }>
  listModels(): Promise<ModelInfo[]>
  capabilities(model: string): Promise<string[]>
  ping(): Promise<{ reachable: boolean; error?: string; models?: number }>
}

// ---------------------------------------------------------------------------
// Server proxy (pre-existing behaviour)
// ---------------------------------------------------------------------------
class ServerProxyTransport implements AiTransport {
  readonly kind = 'server' as const
  readonly endpoint = 'via REMN server'
  private modelsCache: { at: number; models: ModelInfo[] } | null = null

  async chatTurn(p: ChatTurnParams, onChunk: (c: ChatChunk) => void, signal?: AbortSignal): Promise<void> {
    await streamSse(
      '/api/ai/chat',
      {
        messages: p.messages.map((m) => ({ role: m.role, content: m.content, tool_calls: m.tool_calls, tool_name: m.tool_name })),
        mode: p.mode,
        tools: p.tools,
        think: p.think,
        model: p.model || undefined,
        context: p.context,
      },
      (ev) => onChunk(ev as ChatChunk),
      signal,
    )
  }

  queryJson(question: string, context: Record<string, unknown>, model?: string) {
    return apiPost<{ query: Record<string, unknown> | null; raw: string; model: string }>('/api/ai/query', { question, context, model: model || undefined })
  }

  async listModels(): Promise<ModelInfo[]> {
    if (this.modelsCache && Date.now() - this.modelsCache.at < 30_000) return this.modelsCache.models
    const info = await apiGet<{ reachable: boolean; error?: string; models: { name: string; parameterSize?: string; capabilities?: string[] }[] }>('/api/ai/models')
    if (!info.reachable) throw new Error(info.error || 'Ollama unreachable from the server')
    const models = info.models.map((m) => ({ name: m.name, parameterSize: m.parameterSize, capabilities: m.capabilities }))
    this.modelsCache = { at: Date.now(), models }
    return models
  }

  async capabilities(model: string): Promise<string[]> {
    const models = await this.listModels()
    return models.find((m) => m.name === model || m.name.split(':')[0] === model.split(':')[0])?.capabilities ?? []
  }

  async ping() {
    try {
      const models = await this.listModels()
      return { reachable: true, models: models.length }
    } catch (e) {
      return { reachable: false, error: (e as Error).message }
    }
  }
}

// ---------------------------------------------------------------------------
// Browser-direct Ollama
// ---------------------------------------------------------------------------
function corsHint(base: string): string {
  const origin = typeof location !== 'undefined' ? location.origin : ''
  const local = /^https?:\/\/(localhost|127\.0\.0\.1)(:|$)/.test(origin)
  let hint = `Cannot reach Ollama at ${base}. Is it running on THIS machine?`
  if (!local) {
    hint += ` REMN is served from ${origin}, so your local Ollama must allow that origin: run "setx OLLAMA_ORIGINS ${origin}" (Windows) or export OLLAMA_ORIGINS=${origin}, then restart Ollama. Safari blocks HTTPS→localhost entirely - use the server transport there.`
  }
  return hint
}

class BrowserOllamaTransport implements AiTransport {
  readonly kind = 'browser' as const
  readonly endpoint: string
  private base: string
  private caps = new Map<string, string[]>()

  constructor(baseUrl: string) {
    this.base = (baseUrl || 'http://localhost:11434').replace(/\/+$/, '')
    this.endpoint = this.base
  }

  private cfgNumCtx(meta: AiMeta): number {
    const cfg = useStore.getState().aiConfig
    return cfg.numCtx || meta.numCtx || 32768
  }

  private wireMessages(messages: ChatMessage[], meta: AiMeta): Record<string, unknown>[] {
    // mirror backend/api/views/ai.py _clean_messages clamps
    const out: Record<string, unknown>[] = []
    for (const m of messages.slice(0, meta.limits.maxMessages)) {
      if (!['system', 'user', 'assistant', 'tool'].includes(m.role)) continue
      const msg: Record<string, unknown> = { role: m.role, content: (m.content || '').slice(0, meta.limits.maxMessageChars) }
      if (m.role === 'assistant' && m.tool_calls?.length) {
        msg.tool_calls = m.tool_calls.map((c) => ({ function: { name: c.name, arguments: c.arguments ?? {} } }))
      }
      if (m.role === 'tool' && m.tool_name) msg.tool_name = m.tool_name
      out.push(msg)
    }
    return out
  }

  async chatTurn(p: ChatTurnParams, onChunk: (c: ChatChunk) => void, signal?: AbortSignal): Promise<void> {
    let meta: AiMeta
    try {
      meta = await fetchAiMeta()
    } catch (e) {
      onChunk({ type: 'error', error: `could not load AI prompts from the server: ${(e as Error).message}` })
      onChunk({ type: 'done', model: p.model || '', stats: {} })
      return
    }
    const cfg = useStore.getState().aiConfig
    const model = p.model || cfg.model || meta.defaultModel
    const wire = this.wireMessages(p.messages, meta)
    const system = composeSystem(p.mode, p.context, meta)
    if (system) {
      if (wire.length && wire[0].role === 'system') wire[0].content = (system + '\n\n' + wire[0].content).trim()
      else wire.unshift({ role: 'system', content: system })
    }
    const body: Record<string, unknown> = {
      model,
      messages: wire,
      stream: true,
      options: { num_ctx: this.cfgNumCtx(meta), temperature: 0.2 },
    }
    if (p.tools) body.tools = meta.tools
    if (p.think === true) body.think = true
    await this.send(body, model, onChunk, signal, true)
  }

  private async send(body: Record<string, unknown>, model: string, onChunk: (c: ChatChunk) => void, signal: AbortSignal | undefined, allowThinkRetry: boolean): Promise<void> {
    let resp: Response
    try {
      resp = await fetch(`${this.base}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal,
      })
    } catch (e) {
      if ((e as Error).name === 'AbortError') throw e
      onChunk({ type: 'error', error: corsHint(this.base) })
      onChunk({ type: 'done', model, stats: {} })
      return
    }
    if (!resp.ok) {
      const text = (await resp.text().catch(() => '')).slice(0, 400)
      if (resp.status === 400 && 'think' in body && /think/i.test(text) && allowThinkRetry) {
        const retry = { ...body }
        delete retry.think
        return this.send(retry, model, onChunk, signal, false)
      }
      let msg = `Ollama error ${resp.status}: ${text || resp.statusText}`
      if (resp.status === 404 && /not found/i.test(text)) msg = `model "${model}" is not installed - run: ollama pull ${model}`
      if (resp.status === 403) msg = `Ollama refused the request (403). ${corsHint(this.base)}`
      onChunk({ type: 'error', error: msg })
      onChunk({ type: 'done', model, stats: {} })
      return
    }
    // NDJSON stream, mirroring services/ai/client.py chat_stream accumulation
    const pending: { name: string; arguments: Record<string, unknown> }[] = []
    let doneSeen = false
    await readNdjsonBody(resp, (row) => {
      const msg = row.message as { content?: string; thinking?: string; tool_calls?: { function?: { name?: string; arguments?: unknown } }[] } | undefined
      if (msg) {
        if (msg.thinking) onChunk({ type: 'thinking', content: String(msg.thinking) })
        if (msg.content) onChunk({ type: 'token', content: String(msg.content) })
        for (const c of msg.tool_calls ?? []) {
          const fn = c.function ?? {}
          let args = fn.arguments ?? {}
          if (typeof args === 'string') {
            try {
              args = JSON.parse(args)
            } catch {
              args = { _raw: args }
            }
          }
          pending.push({ name: String(fn.name ?? ''), arguments: args as Record<string, unknown> })
        }
      }
      if (row.done) {
        doneSeen = true
        if (pending.length) {
          onChunk({ type: 'tool_calls', calls: pending.splice(0) })
        }
        const stats: Record<string, unknown> = {}
        for (const k of ['total_duration', 'load_duration', 'prompt_eval_count', 'eval_count', 'eval_duration', 'done_reason']) {
          if (row[k] !== undefined && row[k] !== null) stats[k] = row[k]
        }
        onChunk({ type: 'done', model: String(row.model ?? model), stats })
      }
    })
    if (!doneSeen) {
      if (pending.length) onChunk({ type: 'tool_calls', calls: pending.splice(0) })
      onChunk({ type: 'done', model, stats: {} })
    }
  }

  async queryJson(question: string, context: Record<string, unknown>, model?: string) {
    const meta = await fetchAiMeta()
    const cfg = useStore.getState().aiConfig
    const useModel = model || cfg.model || meta.defaultModel
    // mirror backend/api/views/ai.py query() context lines
    const lines = [`Reference time (now, UTC): ${context.now ?? 'unknown'}`]
    if (context.businessHours) lines.push(`Business hours: ${pyLike(context.businessHours)}`)
    if (context.timeRange) lines.push(`Data time range: ${pyLike(context.timeRange)}`)
    if (context.facets) lines.push('Known values (facets): ' + JSON.stringify(context.facets).slice(0, 4000))
    if (context.source) lines.push(`Preferred source: ${context.source}`)
    const resp = await fetch(`${this.base}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: useModel,
        messages: [
          { role: 'system', content: meta.prompts.query },
          { role: 'user', content: lines.join('\n') + `\n\nRequest: ${question}` },
        ],
        stream: false,
        format: meta.querySchema,
        options: { num_ctx: this.cfgNumCtx(meta), temperature: 0 },
      }),
    }).catch((e) => {
      throw new Error(corsHint(this.base) + ` (${(e as Error).message})`)
    })
    if (!resp.ok) throw new Error(`Ollama error ${resp.status}: ${(await resp.text().catch(() => '')).slice(0, 200)}`)
    const data = (await resp.json()) as { message?: { content?: string } }
    const raw = data.message?.content ?? ''
    let parsed: Record<string, unknown> | null = null
    try {
      parsed = JSON.parse(raw)
    } catch {
      const start = raw.indexOf('{')
      const end = raw.lastIndexOf('}')
      if (start !== -1 && end > start) {
        try {
          parsed = JSON.parse(raw.slice(start, end + 1))
        } catch {
          parsed = null
        }
      }
    }
    return { query: parsed, raw, model: useModel }
  }

  async listModels(): Promise<ModelInfo[]> {
    const resp = await fetch(`${this.base}/api/tags`, { signal: AbortSignal.timeout(6000) }).catch((e) => {
      throw new Error(corsHint(this.base) + ` (${(e as Error).message})`)
    })
    if (!resp.ok) throw new Error(`Ollama error ${resp.status}`)
    const data = (await resp.json()) as { models?: { name?: string; model?: string; details?: { parameter_size?: string } }[] }
    return (data.models ?? []).map((m) => ({ name: String(m.name ?? m.model ?? ''), parameterSize: m.details?.parameter_size }))
  }

  async capabilities(model: string): Promise<string[]> {
    if (this.caps.has(model)) return this.caps.get(model)!
    try {
      const resp = await fetch(`${this.base}/api/show`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model }),
        signal: AbortSignal.timeout(8000),
      })
      if (!resp.ok) return []
      const data = (await resp.json()) as { capabilities?: string[] }
      const caps = data.capabilities ?? []
      this.caps.set(model, caps)
      return caps
    } catch {
      return []
    }
  }

  async ping() {
    try {
      const models = await this.listModels()
      return { reachable: true, models: models.length }
    } catch (e) {
      return { reachable: false, error: (e as Error).message }
    }
  }
}

// ---------------------------------------------------------------------------
// Claude Code (the server runs the local claude command line)
// ---------------------------------------------------------------------------
export const CLAUDE_MODELS: ModelInfo[] = [
  { name: 'sonnet', parameterSize: 'default', capabilities: ['tools', 'thinking'] },
  { name: 'opus', capabilities: ['tools', 'thinking'] },
  { name: 'fable', parameterSize: 'most capable', capabilities: ['tools', 'thinking'] },
  { name: 'haiku', parameterSize: 'fast', capabilities: ['tools', 'thinking'] },
]

const isClaudeName = (m: string) => CLAUDE_MODELS.some((x) => x.name === m) || m.startsWith('claude-')

/** The AI page's model box may still hold an Ollama name; only Claude aliases or full Claude ids go to the command line. */
export function pickClaudeModel(requested: string | undefined, configured: string | undefined): string {
  const r = (requested || '').trim().toLowerCase()
  if (r && isClaudeName(r)) return r
  const c = (configured || '').trim().toLowerCase()
  return c && isClaudeName(c) ? c : 'sonnet'
}

export interface ClaudeStatus {
  enabled: boolean
  available: boolean
  version: string | null
  loggedIn: boolean
  account: string | null
  method: string | null
  error: string | null
}

export function fetchClaudeStatus(refresh = false): Promise<ClaudeStatus> {
  return apiGet<ClaudeStatus>(`/api/ai/claude/status${refresh ? '?refresh=1' : ''}`)
}

class ClaudeCodeTransport implements AiTransport {
  readonly kind = 'claude' as const
  readonly endpoint = 'Claude Code on the server machine'

  async chatTurn(p: ChatTurnParams, onChunk: (c: ChatChunk) => void, signal?: AbortSignal): Promise<void> {
    await streamSse(
      '/api/ai/claude/chat',
      {
        messages: p.messages.map((m) => ({ role: m.role, content: m.content, tool_calls: m.tool_calls, tool_name: m.tool_name })),
        mode: p.mode,
        tools: p.tools,
        model: pickClaudeModel(p.model, useStore.getState().aiConfig.claudeModel),
        context: p.context,
      },
      (ev) => onChunk(ev as ChatChunk),
      signal,
    )
  }

  queryJson(question: string, context: Record<string, unknown>, model?: string) {
    return apiPost<{ query: Record<string, unknown> | null; raw: string; model: string }>('/api/ai/claude/query', {
      question,
      context,
      model: pickClaudeModel(model, useStore.getState().aiConfig.claudeModel),
    })
  }

  async listModels(): Promise<ModelInfo[]> {
    return CLAUDE_MODELS
  }

  async capabilities(): Promise<string[]> {
    return ['tools', 'thinking']
  }

  async ping() {
    try {
      const s = await fetchClaudeStatus(true)
      if (!s.available || !s.loggedIn) return { reachable: false, error: s.error ?? 'Claude Code is not available on the server machine' }
      return { reachable: true, models: CLAUDE_MODELS.length }
    } catch (e) {
      return { reachable: false, error: (e as Error).message }
    }
  }
}

function pyLike(v: unknown): string {
  // f-string interpolation of a dict in Python prints {'key': value}; close enough for prompt context
  return typeof v === 'object' ? JSON.stringify(v) : String(v)
}

// ---------------------------------------------------------------------------
const instances = new Map<string, AiTransport>()

export function getTransport(): AiTransport {
  const cfg = useStore.getState().aiConfig
  const key = cfg.transport === 'server' ? 'server' : cfg.transport === 'claude' ? 'claude' : `browser:${cfg.ollamaUrl}`
  let t = instances.get(key)
  if (!t) {
    t = cfg.transport === 'server' ? new ServerProxyTransport() : cfg.transport === 'claude' ? new ClaudeCodeTransport() : new BrowserOllamaTransport(cfg.ollamaUrl)
    instances.set(key, t)
  }
  return t
}
