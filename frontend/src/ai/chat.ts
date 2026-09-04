import { getTransport, type ChatChunk } from './transport'
import type { Case } from '../db/schema'
import { executeTool } from './tools'

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant' | 'tool'
  content: string
  thinking?: string
  tool_calls?: { name: string; arguments: Record<string, unknown> }[]
  tool_name?: string
  ts?: number
  stats?: Record<string, unknown>
}

export interface AgentOptions {
  mode: 'analyst' | 'explain' | 'rule' | 'report' | 'free'
  model?: string
  think?: boolean
  tools?: boolean
  maxIterations?: number
  signal?: AbortSignal
  onToken?: (text: string) => void
  onThinking?: (text: string) => void
  onToolCall?: (name: string, args: Record<string, unknown>) => void
  onToolResult?: (name: string, result: string, ms: number) => void
  onMessage?: (m: ChatMessage) => void
}

/** Run the model until it answers without tool calls (or the iteration cap). Mutates and returns `messages`. */
export async function runAgent(messages: ChatMessage[], kase: Case, opts: AgentOptions): Promise<ChatMessage[]> {
  const max = opts.maxIterations ?? 8
  let emptyRetries = 0
  const context = {
    now: new Date().toISOString(),
    networkAllowed: !!kase.settings.networkAllowed,
    storage: kase.storage === 'server' && kase.serverKey ? 'server' : 'browser',
    caseSettings: {
      internalDomains: kase.settings.internalDomains,
      vipNames: kase.settings.vipNames,
      businessHours: kase.settings.businessHours,
      weekendDays: kase.settings.weekendDays,
      internalIps: kase.settings.internalIps,
    },
  }
  for (let iter = 0; iter < max; iter++) {
    let content = ''
    let thinking = ''
    let calls: { name: string; arguments: Record<string, unknown> }[] = []
    let stats: Record<string, unknown> = {}
    let error: string | null = null
    await getTransport().chatTurn(
      {
        messages,
        mode: opts.mode,
        tools: opts.tools ?? opts.mode === 'analyst',
        think: opts.think,
        model: opts.model,
        context,
      },
      (ev: ChatChunk) => {
        switch (ev.type) {
          case 'token':
            content += ev.content
            opts.onToken?.(ev.content)
            break
          case 'thinking':
            thinking += ev.content
            opts.onThinking?.(ev.content)
            break
          case 'tool_calls':
            calls = ev.calls ?? []
            break
          case 'done':
            stats = ev.stats ?? {}
            break
          case 'error':
            error = ev.error
            break
        }
      },
      opts.signal,
    )
    if (error) {
      const m: ChatMessage = { role: 'assistant', content: `⚠ ${error}`, ts: Date.now() }
      messages.push(m)
      opts.onMessage?.(m)
      return messages
    }
    if (!content.trim() && !calls.length) {
      // Small models sometimes end a turn without text (e.g. an unparsable tool call). Nudge once.
      if (emptyRetries++ < 1) {
        messages.push({ role: 'user', content: 'Your previous message was empty. Answer now in plain text, using the tool results above; do not call more tools unless strictly needed.', ts: Date.now() })
        continue
      }
      content = '(the model returned an empty message twice - try a smaller question, disable thinking, or pick another model)'
    }
    const assistant: ChatMessage = { role: 'assistant', content, thinking: thinking || undefined, tool_calls: calls.length ? calls : undefined, ts: Date.now(), stats }
    messages.push(assistant)
    opts.onMessage?.(assistant)
    if (!calls.length) return messages
    for (const c of calls) {
      if (opts.signal?.aborted) return messages
      opts.onToolCall?.(c.name, c.arguments)
      const t0 = Date.now()
      const result = await executeTool(c.name, c.arguments ?? {}, kase)
      const ms = Date.now() - t0
      opts.onToolResult?.(c.name, result, ms)
      const tm: ChatMessage = { role: 'tool', content: result, tool_name: c.name, ts: Date.now() }
      messages.push(tm)
      opts.onMessage?.(tm)
    }
  }
  const m: ChatMessage = { role: 'assistant', content: '(stopped: tool-call iteration limit reached - ask a narrower question or continue)', ts: Date.now() }
  messages.push(m)
  opts.onMessage?.(m)
  return messages
}
