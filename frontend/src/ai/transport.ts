/**
 * AI transports. Browser-direct (default): the analyst's browser talks to
 * their OWN Ollama (http://localhost:11434 relative to the browser machine),
 * so prompts and tool results never reach the REMN server. Local OpenAI-compatible:
 * the same, to a local LM Studio, llama.cpp server, vLLM or Jan (/v1/chat/completions);
 * only addresses on this machine or the local network are accepted, and no key is sent.
 * Server proxy: the pre-existing /api/ai/* path, for setups without a local model.
 * Claude Code: the server runs the local `claude` command line (that machine's Claude
 * login); prompts, tool results and answers leave for Anthropic, nothing is kept on the server.
 */
import { apiGet, apiPost, readNdjsonBody, streamSse } from '../api/client'
import { useStore } from '../state/store'
import { composeSystem, fetchAiMeta, type AiMeta } from './meta'
import type { AgentMode, ChatMessage } from './chat'

export type ChatChunk =
  | { type: 'token'; content: string }
  | { type: 'thinking'; content: string }
  | { type: 'tool_calls'; calls: { id?: string; name: string; arguments: Record<string, unknown> }[] }
  | { type: 'done'; model: string; stats: Record<string, unknown> }
  | { type: 'error'; error: string }

export interface ChatTurnParams {
  messages: ChatMessage[]
  mode: AgentMode
  tools: boolean
  /** the tools this case can use (all of the server's when left out) */
  toolNames?: string[]
  think?: boolean
  model?: string
  context: Record<string, unknown>
}

type AiConfig = ReturnType<typeof useStore.getState>['aiConfig']

/** The model's context window in tokens, for the context engine (ai/context.ts). */
export function contextWindow(cfg: AiConfig, meta: AiMeta | null): number {
  if (cfg.transport === 'claude') return 160_000
  if (cfg.numCtx) return cfg.numCtx
  if (cfg.transport === 'openai') return 32768
  return meta?.numCtx || 32768
}

/** How the page names the model connection: a short word for badges and where the model runs. */
export function transportLabel(cfg: AiConfig): { short: string; where: string; local: boolean } {
  if (cfg.transport === 'openai') return { short: 'local model', where: `local server · ${cfg.openaiUrl}`, local: true }
  if (cfg.transport === 'claude') return { short: 'claude', where: 'Claude Code on the server machine', local: false }
  if (cfg.transport === 'server') return { short: 'ollama', where: 'via REMN server', local: false }
  return { short: 'ollama', where: `browser-direct · ${cfg.ollamaUrl}`, local: true }
}

/** The tool schemas of the tools a turn offers. */
function toolsFor(meta: AiMeta, names: string[] | undefined): Record<string, unknown>[] {
  if (!names) return meta.tools
  const wanted = new Set(names)
  return meta.tools.filter((t) => wanted.has(String((t as { function?: { name?: string } }).function?.name)))
}

/** A conversation longer than the cap keeps its first message (the question) and the newest ones. */
export function capMessages<T>(messages: T[], max: number): T[] {
  return messages.length > max ? [messages[0], ...messages.slice(-(max - 1))] : messages
}

export interface ModelInfo {
  name: string
  parameterSize?: string
  capabilities?: string[]
}

export interface AiTransport {
  kind: 'server' | 'browser' | 'claude' | 'openai'
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
        toolNames: p.toolNames,
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
    const serverTransport = useStore.getState().health?.mode !== 'browser-only'
    hint +=
      ` REMN is served from ${origin}, so your local Ollama must allow that origin, then be restarted:` +
      ` Windows: setx OLLAMA_ORIGINS "${origin}";` +
      ` macOS app: launchctl setenv OLLAMA_ORIGINS "${origin}" (the menu-bar app does not read shell exports);` +
      ` Linux service: add Environment="OLLAMA_ORIGINS=${origin}" with systemctl edit ollama.` +
      ` Allow the browser's local-network prompt if it shows one, and turn off shields or ad blockers that block localhost for this site.` +
      ` Only localhost addresses are reachable from this page.` +
      (serverTransport
        ? ' Safari blocks HTTPS→localhost entirely - use the server transport there.'
        : ' Safari blocks HTTPS→localhost entirely - use Chrome, Edge or Firefox, or run REMN on your own machine.')
  }
  return hint
}

class BrowserOllamaTransport implements AiTransport {
  /** With no model chosen and none offered by the server, the first one this Ollama has installed. */
  private async firstInstalledModel(): Promise<string> {
    try {
      const models = await this.listModels()
      return models[0]?.name ?? ''
    } catch {
      return ''
    }
  }

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
    for (const m of capMessages(messages, meta.limits.maxMessages)) {
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
    const model = p.model || cfg.model || meta.defaultModel || (await this.firstInstalledModel())
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
    if (p.tools) body.tools = toolsFor(meta, p.toolNames)
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
    const useModel = model || cfg.model || meta.defaultModel || (await this.firstInstalledModel())
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
// Local OpenAI-compatible servers (LM Studio, llama.cpp, vLLM, Jan)
// ---------------------------------------------------------------------------
export const OPENAI_PRESETS: { name: string; url: string; hint: string }[] = [
  { name: 'LM Studio', url: 'http://localhost:1234/v1', hint: 'Developer tab → start the server, and switch on "Enable CORS"' },
  { name: 'llama.cpp', url: 'http://localhost:8080/v1', hint: 'llama-server -m model.gguf --jinja (tool calls need --jinja)' },
  { name: 'vLLM', url: 'http://localhost:8000/v1', hint: 'vllm serve <model> --enable-auto-tool-choice --tool-call-parser <parser> --allowed-origins \'["<this page>"]\'' },
  { name: 'Jan', url: 'http://localhost:1337/v1', hint: 'Settings → Local API Server: start it and allow this origin under CORS' },
  { name: 'Ollama (OpenAI API)', url: 'http://localhost:11434/v1', hint: 'the same Ollama through its OpenAI-compatible endpoint' },
]

/**
 * Only a server on this machine or the local network: this transport sends evidence excerpts
 * and no key, so a cloud endpoint is refused rather than sent the case.
 */
export function isLocalModelUrl(url: string): boolean {
  let u: URL
  try {
    u = new URL(url)
  } catch {
    return false
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return false
  const h = u.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (h === 'localhost' || h.endsWith('.localhost') || h === '::1') return true
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h)
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])]
    return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127)
  }
  if (/^f[cd][0-9a-f]{2}:/.test(h) || h.startsWith('fe80:')) return true
  // a single-label name, or one of the names reserved for local networks
  return !h.includes('.') || /\.(local|lan|home|internal|intranet|home\.arpa)$/.test(h)
}

/** Splits <think>…</think> out of streamed text (servers that put the reasoning in the content). */
export class ThinkSplitter {
  private buf = ''
  private inThink = false
  push(text: string): { content: string; thinking: string } {
    this.buf += text
    let content = ''
    let thinking = ''
    for (;;) {
      const tag = this.inThink ? '</think>' : '<think>'
      const i = this.buf.indexOf(tag)
      if (i === -1) {
        let keep = 0
        for (let n = Math.min(tag.length - 1, this.buf.length); n > 0; n--)
          if (tag.startsWith(this.buf.slice(-n))) {
            keep = n
            break
          }
        const out = this.buf.slice(0, this.buf.length - keep)
        this.buf = this.buf.slice(this.buf.length - keep)
        if (this.inThink) thinking += out
        else content += out
        return { content, thinking }
      }
      if (this.inThink) thinking += this.buf.slice(0, i)
      else content += this.buf.slice(0, i)
      this.buf = this.buf.slice(i + tag.length)
      this.inThink = !this.inThink
    }
  }
  flush(): { content: string; thinking: string } {
    const out = this.buf
    this.buf = ''
    return this.inThink ? { content: '', thinking: out } : { content: out, thinking: '' }
  }
}

const rid = () => 'c' + Math.random().toString(36).slice(2, 10).padEnd(8, '0')

/** The conversation in the chat-completions shape: tool calls with ids, tool results answering them. */
export function openAiMessages(system: string, messages: ChatMessage[]): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = []
  let sys = system
  const pending: string[] = []
  for (const m of messages) {
    if (m.role === 'system') {
      sys = (sys + '\n\n' + m.content).trim()
      continue
    }
    if (m.role === 'assistant') {
      pending.length = 0
      const msg: Record<string, unknown> = { role: 'assistant', content: m.content || '' }
      if (m.tool_calls?.length) {
        msg.tool_calls = m.tool_calls.map((c) => {
          const id = c.id || rid()
          pending.push(id)
          return { id, type: 'function', function: { name: c.name, arguments: JSON.stringify(c.arguments ?? {}) } }
        })
      }
      out.push(msg)
    } else if (m.role === 'tool') {
      const id = m.tool_call_id && pending.includes(m.tool_call_id) ? m.tool_call_id : (pending[0] ?? rid())
      const at = pending.indexOf(id)
      if (at >= 0) pending.splice(at, 1)
      out.push({ role: 'tool', tool_call_id: id, content: m.content || '' })
    } else out.push({ role: 'user', content: m.content || '' })
  }
  if (sys) out.unshift({ role: 'system', content: sys })
  return out
}

async function readSse(resp: Response, onData: (data: string) => void): Promise<void> {
  const reader = resp.body!.getReader()
  const dec = new TextDecoder()
  let buf = ''
  for (;;) {
    const { value, done } = await reader.read()
    if (done) break
    buf += dec.decode(value, { stream: true })
    let nl: number
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl).replace(/\r$/, '')
      buf = buf.slice(nl + 1)
      if (line.startsWith('data:')) onData(line.slice(5).trim())
    }
  }
  if (buf.startsWith('data:')) onData(buf.slice(5).trim())
}

function openAiHint(base: string): string {
  const origin = typeof location !== 'undefined' ? location.origin : ''
  return (
    `Cannot reach the model server at ${base}. Is it running on this machine, with its API server started?` +
    ` It must also allow this page's origin (${origin}): LM Studio "Enable CORS", vLLM --allowed-origins, Jan CORS settings; llama.cpp allows it by default.` +
    ` Allow the browser's local-network prompt if it shows one.`
  )
}

class OpenAiCompatTransport implements AiTransport {
  readonly kind = 'openai' as const
  readonly endpoint: string
  private base: string
  private refused: string | null

  constructor(baseUrl: string) {
    this.base = (baseUrl || 'http://localhost:1234/v1').replace(/\/+$/, '')
    this.endpoint = this.base
    this.refused = isLocalModelUrl(this.base) ? null : `REMN only talks to a model server on this machine or your local network, not to ${this.base}. Cloud APIs are not supported.`
  }

  private async pickModel(requested: string | undefined): Promise<string> {
    const cfg = useStore.getState().aiConfig
    if (requested || cfg.model) return String(requested || cfg.model)
    const models = await this.listModels().catch(() => [])
    return models[0]?.name ?? ''
  }

  async chatTurn(p: ChatTurnParams, onChunk: (c: ChatChunk) => void, signal?: AbortSignal): Promise<void> {
    const finish = (model: string, error?: string) => {
      if (error) onChunk({ type: 'error', error })
      onChunk({ type: 'done', model, stats: {} })
    }
    if (this.refused) return finish(p.model || '', this.refused)
    let meta: AiMeta
    try {
      meta = await fetchAiMeta()
    } catch (e) {
      return finish(p.model || '', `could not load AI prompts from the server: ${(e as Error).message}`)
    }
    const model = await this.pickModel(p.model)
    const system = composeSystem(p.mode, p.context, meta)
    const body: Record<string, unknown> = {
      model,
      messages: openAiMessages(system, capMessages(p.messages, meta.limits.maxMessages)),
      stream: true,
      temperature: 0.2,
      stream_options: { include_usage: true },
    }
    if (p.tools) {
      body.tools = toolsFor(meta, p.toolNames)
      body.tool_choice = 'auto'
    }
    let resp: Response
    try {
      resp = await fetch(`${this.base}/chat/completions`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal })
    } catch (e) {
      if ((e as Error).name === 'AbortError') throw e
      return finish(model, openAiHint(this.base))
    }
    if (!resp.ok) {
      const text = (await resp.text().catch(() => '')).slice(0, 400)
      // a server whose chat template has no tools: the same turn without them, once
      if (p.tools && resp.status >= 400 && resp.status < 500 && /tool/i.test(text)) return this.chatTurn({ ...p, tools: false }, onChunk, signal)
      return finish(model, `model server error ${resp.status}: ${text || resp.statusText}`)
    }
    const calls = new Map<number, { id?: string; name: string; args: string }>()
    const split = new ThinkSplitter()
    const stats: Record<string, unknown> = {}
    let modelSeen = model
    await readSse(resp, (data) => {
      if (!data || data === '[DONE]') return
      let row: Record<string, unknown>
      try {
        row = JSON.parse(data)
      } catch {
        return
      }
      if (row.model) modelSeen = String(row.model)
      const usage = row.usage as { prompt_tokens?: number; completion_tokens?: number } | undefined
      if (usage) {
        if (usage.prompt_tokens != null) stats.prompt_eval_count = usage.prompt_tokens
        if (usage.completion_tokens != null) stats.eval_count = usage.completion_tokens
      }
      const choice = (row.choices as Record<string, unknown>[] | undefined)?.[0]
      if (!choice) return
      const delta = (choice.delta ?? {}) as {
        content?: string
        reasoning_content?: string
        reasoning?: string
        tool_calls?: { index?: number; id?: string; function?: { name?: string; arguments?: string } }[]
      }
      const reasoning = delta.reasoning_content ?? delta.reasoning
      if (reasoning) onChunk({ type: 'thinking', content: String(reasoning) })
      if (delta.content) {
        const part = split.push(String(delta.content))
        if (part.thinking) onChunk({ type: 'thinking', content: part.thinking })
        if (part.content) onChunk({ type: 'token', content: part.content })
      }
      for (const tc of delta.tool_calls ?? []) {
        const i = tc.index ?? calls.size
        const cur = calls.get(i) ?? { name: '', args: '' }
        if (tc.id) cur.id = tc.id
        if (tc.function?.name) cur.name += tc.function.name
        if (tc.function?.arguments) cur.args += tc.function.arguments
        calls.set(i, cur)
      }
      if (choice.finish_reason) stats.done_reason = choice.finish_reason
    })
    const rest = split.flush()
    if (rest.thinking) onChunk({ type: 'thinking', content: rest.thinking })
    if (rest.content) onChunk({ type: 'token', content: rest.content })
    if (calls.size) {
      onChunk({
        type: 'tool_calls',
        calls: [...calls.entries()]
          .sort((a, b) => a[0] - b[0])
          .map(([, c]) => {
            let args: Record<string, unknown>
            try {
              args = c.args.trim() ? JSON.parse(c.args) : {}
            } catch {
              args = { _raw: c.args }
            }
            return { id: c.id, name: c.name, arguments: args }
          }),
      })
    }
    onChunk({ type: 'done', model: modelSeen, stats })
  }

  async queryJson(question: string, context: Record<string, unknown>, model?: string) {
    if (this.refused) throw new Error(this.refused)
    const meta = await fetchAiMeta()
    const useModel = await this.pickModel(model)
    const lines = [`Reference time (now, UTC): ${context.now ?? 'unknown'}`]
    if (context.businessHours) lines.push(`Business hours: ${pyLike(context.businessHours)}`)
    if (context.timeRange) lines.push(`Data time range: ${pyLike(context.timeRange)}`)
    if (context.facets) lines.push('Known values (facets): ' + JSON.stringify(context.facets).slice(0, 4000))
    if (context.source) lines.push(`Preferred source: ${context.source}`)
    const messages = [
      { role: 'system', content: meta.prompts.query },
      { role: 'user', content: lines.join('\n') + `\n\nRequest: ${question}` },
    ]
    // the strictest structured output the server takes, then looser
    const formats: (Record<string, unknown> | null)[] = [{ type: 'json_schema', json_schema: { name: 'remn_filter', schema: meta.querySchema } }, { type: 'json_object' }, null]
    let raw = ''
    for (const format of formats) {
      const resp = await fetch(`${this.base}/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: useModel, messages, temperature: 0, stream: false, ...(format ? { response_format: format } : {}) }),
      }).catch((e) => {
        throw new Error(openAiHint(this.base) + ` (${(e as Error).message})`)
      })
      if (resp.status === 400 && format) continue
      if (!resp.ok) throw new Error(`model server error ${resp.status}: ${(await resp.text().catch(() => '')).slice(0, 200)}`)
      const data = (await resp.json()) as { choices?: { message?: { content?: string } }[] }
      raw = new ThinkSplitter().push((data.choices?.[0]?.message?.content ?? '') + '\n').content
      break
    }
    let parsed: Record<string, unknown> | null = null
    const start = raw.indexOf('{')
    const end = raw.lastIndexOf('}')
    if (start !== -1 && end > start) {
      try {
        parsed = JSON.parse(raw.slice(start, end + 1))
      } catch {
        parsed = null
      }
    }
    return { query: parsed, raw, model: useModel }
  }

  async listModels(): Promise<ModelInfo[]> {
    if (this.refused) throw new Error(this.refused)
    const resp = await fetch(`${this.base}/models`, { signal: AbortSignal.timeout(6000) }).catch((e) => {
      throw new Error(openAiHint(this.base) + ` (${(e as Error).message})`)
    })
    if (!resp.ok) throw new Error(`model server error ${resp.status}`)
    const data = (await resp.json()) as { data?: { id?: string }[] }
    return (data.data ?? []).map((m) => ({ name: String(m.id ?? '') })).filter((m) => m.name)
  }

  async capabilities(): Promise<string[]> {
    // the API does not say; a model without tool support gets the turn again without tools
    return []
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
        toolNames: p.toolNames,
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
  const key = cfg.transport === 'server' ? 'server' : cfg.transport === 'claude' ? 'claude' : cfg.transport === 'openai' ? `openai:${cfg.openaiUrl}` : `browser:${cfg.ollamaUrl}`
  let t = instances.get(key)
  if (!t) {
    t =
      cfg.transport === 'server'
        ? new ServerProxyTransport()
        : cfg.transport === 'claude'
          ? new ClaudeCodeTransport()
          : cfg.transport === 'openai'
            ? new OpenAiCompatTransport(cfg.openaiUrl)
            : new BrowserOllamaTransport(cfg.ollamaUrl)
    instances.set(key, t)
  }
  return t
}
