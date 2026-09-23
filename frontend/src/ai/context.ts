/**
 * The context engine: what of a conversation fits the model's window.
 *
 * A long investigation outgrows any local model's context. Instead of cutting the newest turns
 * (what the old transport did), the conversation is fitted to a token budget: tool results older
 * than the last rounds are compacted to their first lines and the refs they returned (which stay
 * citable), then the oldest rounds after the question are left out whole, a tool call never
 * without its result. The plan and the hypotheses travel in the system message as working memory,
 * so what the dropped rounds established is not lost.
 */
import type { ChatMessage } from './chat'

/** A rough count that errs high: JSON and log text run near 3.3 characters per token. */
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 3.3)
}

export function messageTokens(m: ChatMessage): number {
  let n = 6 + estimateTokens(m.content || '')
  if (m.tool_calls?.length) n += estimateTokens(JSON.stringify(m.tool_calls))
  return n
}

/** Keep this many of the newest tool rounds whole; older tool results are compacted first. */
const KEEP_ROUNDS = 3
const COMPACT_HEAD = 700

export function compactToolResult(m: ChatMessage): ChatMessage {
  if (m.role !== 'tool' || m.compacted || (m.content || '').length <= COMPACT_HEAD + 200) return m
  const refs = m.refs ?? []
  const head = m.content.slice(0, COMPACT_HEAD)
  const tail =
    `\n…[REMN compacted this older result (${m.content.length} characters) to fit the context.` +
    (refs.length ? ` Refs it returned, still citable: ${refs.slice(0, 60).join(' ')}${refs.length > 60 ? ` and ${refs.length - 60} more` : ''}.` : '') +
    ' Call the tool again for the full rows.]'
  return { ...m, content: head + tail, compacted: true }
}

/** Rounds: a user message, or an assistant turn with the tool results that answer it. */
function rounds(msgs: ChatMessage[]): ChatMessage[][] {
  const out: ChatMessage[][] = []
  for (const m of msgs) {
    if (m.role === 'tool' && out.length && out[out.length - 1][0].role === 'assistant') out[out.length - 1].push(m)
    else out.push([m])
  }
  return out
}

export interface FitResult {
  messages: ChatMessage[]
  /** messages left out whole */
  omitted: number
  /** tool results shortened */
  compacted: number
  /** estimate of what is sent, the system message and tools excluded */
  tokens: number
}

/**
 * Fit a conversation into `budget` tokens. The first message (the question) and the newest round
 * are always kept; the conversation passed in is not changed.
 */
export function fitToBudget(msgs: ChatMessage[], budget: number): FitResult {
  const convo = msgs.filter((m) => m.role !== 'system')
  const groups = rounds(convo)
  const total = (gs: ChatMessage[][]) => gs.reduce((n, g) => n + g.reduce((k, m) => k + messageTokens(m), 0), 0)
  let compacted = 0
  // 1. compact the tool results of all but the newest rounds
  const toolRounds = groups.map((g, i) => (g[0].role === 'assistant' && g.length > 1 ? i : -1)).filter((i) => i >= 0)
  const keepWhole = new Set(toolRounds.slice(-KEEP_ROUNDS))
  let shaped = groups.map((g, i) =>
    keepWhole.has(i)
      ? g
      : g.map((m) => {
          const c = compactToolResult(m)
          if (c !== m) compacted++
          return c
        }),
  )
  if (total(shaped) > budget) {
    // 2. still too big: compact the kept rounds too, except the newest
    const newest = toolRounds[toolRounds.length - 1]
    shaped = shaped.map((g, i) =>
      i === newest
        ? g
        : g.map((m) => {
            const c = compactToolResult(m)
            if (c !== m) compacted++
            return c
          }),
    )
  }
  // 3. leave out the oldest rounds after the first message until it fits
  let omitted = 0
  while (shaped.length > 2 && total(shaped) > budget) {
    omitted += shaped[1].length
    shaped.splice(1, 1)
  }
  const messages = shaped.flat()
  return { messages, omitted, compacted, tokens: total(shaped) }
}

/** The budget for the conversation: the window, less the system message, the tool schemas and room to answer. */
export function conversationBudget(numCtx: number, systemText: string, tools: unknown[] | null): number {
  const reserveAnswer = Math.min(4096, Math.floor(numCtx / 6))
  const fixed = estimateTokens(systemText) + (tools?.length ? estimateTokens(JSON.stringify(tools)) : 0)
  return Math.max(1024, numCtx - reserveAnswer - fixed)
}
