import { contextWindow, getTransport, type ChatChunk } from './transport'
import type { Case } from '../db/schema'
import { useStore } from '../state/store'
import { sha256Hex } from '../util/export'
import { composeSystem, fetchAiMeta } from './meta'
import { conversationBudget, fitToBudget } from './context'
import { citationsIn, SeenSet, type Suspect } from './evidence'
import { boardMemory, loadBoard } from './hypotheses'
import { appendLedger } from './ledger'
import { caseShape, runTool, toolNamesFor, type PlanStep } from './tools'

export interface ChatMessage {
  role: 'system' | 'user' | 'assistant' | 'tool'
  content: string
  thinking?: string
  tool_calls?: { id?: string; name: string; arguments: Record<string, unknown> }[]
  tool_name?: string
  tool_call_id?: string
  ts?: number
  stats?: Record<string, unknown>
  /** the model that wrote an assistant message, as the transport reported it */
  model?: string
  /** tool: the refs this result returned (they stay citable when the result is compacted) */
  refs?: string[]
  /** tool: text in the result addressed to a model */
  suspects?: Suspect[]
  /** tool: shortened to fit the context */
  compacted?: boolean
  /** tool: milliseconds it took */
  ms?: number
  /** tool: the proposal it queued */
  proposal?: string
  /** a nudge REMN sent the model; not shown and not saved */
  synthetic?: boolean
  /** assistant: the run's answer */
  final?: boolean
  /** assistant: an answer sent back to the model because it cited no rows */
  draft?: boolean
  confidence?: string
  openQuestions?: string[]
  /** assistant: citations in the answer, checked against what the tools returned */
  cites?: { verified: number; unverified: string[] }
}

export type AgentMode = 'analyst' | 'explain' | 'rule' | 'report' | 'triage' | 'narrative' | 'json' | 'free'

/** The live state of an investigation, for the page. */
export interface AgentRun {
  plan: PlanStep[]
  step: number
  budget: number
  toolCalls: number
  proposals: string[]
  suspects: number
  /** prompt tokens of the last turn, as the model counted them (or REMN's estimate) */
  contextTokens?: number
  contextWindow?: number
  omitted?: number
  wrappingUp?: boolean
}

export interface AgentOptions {
  mode: AgentMode
  model?: string
  think?: boolean
  tools?: boolean
  /** tool rounds before the model must answer (the step budget) */
  maxIterations?: number
  signal?: AbortSignal
  onToken?: (text: string) => void
  onThinking?: (text: string) => void
  onToolCall?: (name: string, args: Record<string, unknown>) => void
  onToolResult?: (name: string, result: string, ms: number) => void
  onMessage?: (m: ChatMessage) => void
  /**
   * An investigation: the plan, hypothesis and propose_* tools are offered, citations are checked,
   * and every step goes to the case's AI ledger.
   */
  agent?: {
    seen: SeenSet
    session?: number
    plan?: PlanStep[]
    /** the analyst asked for the answer now */
    wrapUp?: () => boolean
    onRun?: (r: AgentRun) => void
    /** what started it, for the ledger (a question, a playbook) */
    label?: string
  }
}

const WRAP_UP =
  'REMN: the step budget is used up (or the analyst asked for your answer now). Write your final answer from the results above, with citations; say what you could not check. Do not call tools.'
const EMPTY = 'REMN: your previous message was empty. Answer now in plain text, using the tool results above; do not call more tools unless strictly needed.'
const LEAKED = 'REMN: your last message had a tool call written as text, which was not run. Call tools through the tool-calling interface, or write your final answer without it.'
const UNCITED =
  'REMN: your answer cites no rows. Write it again citing the refs of the rows each claim rests on, e.g. [ev:123] or [mail:4], taken from the results above. A claim with no row behind it is a hypothesis or an open question: say so.'

/** A tool call a model wrote into its text (a template the server did not parse): it was not run. */
const LEAKED_CALL = /<\/?tool_call>|<function=|<\|tool_call(s)?_begin\|>/i

function planMemory(plan: PlanStep[]): string {
  return plan.length ? 'Plan:\n' + plan.map((s) => `- [${s.status}] ${s.title}`).join('\n') : ''
}

/** A stable key for a tool call, so the same call twice in a run is answered from the first result. */
function callKey(name: string, args: Record<string, unknown>): string {
  const norm = (v: unknown): unknown =>
    Array.isArray(v)
      ? v.map(norm)
      : v && typeof v === 'object'
        ? Object.fromEntries(
            Object.keys(v as object)
              .sort()
              .map((k) => [k, norm((v as Record<string, unknown>)[k])]),
          )
        : v
  return name + JSON.stringify(norm(args ?? {}))
}

const REPEATABLE = new Set(['update_plan', 'record_hypothesis', 'finish'])

/**
 * Run the model until it answers (or calls finish, or the step budget runs out, when it is asked
 * for its answer without tools). Mutates and returns `messages`.
 */
export async function runAgent(messages: ChatMessage[], kase: Case, opts: AgentOptions): Promise<ChatMessage[]> {
  const agent = opts.agent
  const budget = Math.max(1, opts.maxIterations ?? (agent ? 24 : 8))
  const caseId = kase.id!
  const transport = getTransport()
  const cfg = useStore.getState().aiConfig
  const useTools = opts.tools ?? opts.mode === 'analyst'
  const toolNames = useTools ? toolNamesFor(kase, await caseShape(kase).catch(() => ({ events: 1, mails: 1, chains: 1 })), !!agent) : undefined
  const seen = agent?.seen ?? new SeenSet()
  const run: AgentRun = { plan: agent?.plan ?? [], step: 0, budget, toolCalls: 0, proposals: [], suspects: 0 }
  let exposed = messages.some((m) => m.suspects?.length)
  const cache = new Map<string, { content: string; step: number }>()
  const base = {
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
  const meta = await fetchAiMeta().catch(() => null)
  const window = contextWindow(cfg, meta)
  run.contextWindow = window
  const toolSchemas = meta && toolNames ? meta.tools.filter((t) => toolNames.includes(String((t as { function?: { name?: string } }).function?.name))) : null
  const push = (m: ChatMessage) => {
    messages.push(m)
    opts.onMessage?.(m)
  }
  const report = () => agent?.onRun?.({ ...run, plan: [...run.plan], proposals: [...run.proposals] })
  if (agent) {
    const question = [...messages].reverse().find((m) => m.role === 'user' && !m.synthetic)?.content ?? ''
    await appendLedger(caseId, 'run', (agent.label ?? question).slice(0, 300), {
      model: opts.model || (cfg.transport === 'claude' ? cfg.claudeModel : cfg.model) || undefined,
      transport: cfg.transport,
      mode: opts.mode,
      budget,
      tools: toolNames?.length ?? 0,
      question: await sha256Hex(question),
    }).catch(() => undefined)
  }
  let emptyRetries = 0
  let leakRetries = 0
  let citeRetries = 0
  let wrapping = false
  // an investigation gets one more turn after its budget, without tools, for its answer
  const turns = agent ? budget + 1 : budget
  /** an answer that cites nothing although the tools returned rows goes back once, while a turn is left for it */
  const sendBack = (answer: string, iter: number) => !!agent && seen.size > 0 && iter < turns - 1 && !citationsIn(answer, seen).some((c) => c.verified) && citeRetries++ < 1
  for (let iter = 0; iter < turns; iter++) {
    if (agent && !wrapping && (iter >= budget || agent.wrapUp?.())) {
      wrapping = true
      run.wrappingUp = true
      push({ role: 'user', content: WRAP_UP, ts: Date.now(), synthetic: true })
    }
    const context: Record<string, unknown> = { ...base }
    if (agent) {
      context.steps = { used: iter, budget }
      const memory = [planMemory(run.plan), boardMemory(await loadBoard(caseId).catch(() => []))].filter(Boolean).join('\n')
      if (memory) context.memory = memory
    }
    const systemText = meta ? composeSystem(opts.mode, context, meta) : ''
    const fitted = fitToBudget(messages, conversationBudget(window, systemText, wrapping ? null : toolSchemas))
    if (fitted.omitted) context.omitted = fitted.omitted
    run.omitted = fitted.omitted
    let content = ''
    let thinking = ''
    let calls: { id?: string; name: string; arguments: Record<string, unknown> }[] = []
    let stats: Record<string, unknown> = {}
    let model = ''
    let error: string | null = null
    await transport.chatTurn(
      { messages: fitted.messages, mode: opts.mode, tools: useTools && !wrapping, toolNames, think: opts.think, model: opts.model, context },
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
            model = ev.model || model
            break
          case 'error':
            error = ev.error
            break
        }
      },
      opts.signal,
    )
    run.contextTokens = Number(stats.prompt_eval_count) || fitted.tokens + Math.ceil(systemText.length / 3.3)
    if (error) {
      push({ role: 'assistant', content: `⚠ ${error}`, ts: Date.now() })
      return messages
    }
    if (!content.trim() && !calls.length) {
      // Small models sometimes end a turn without text (e.g. an unparsable tool call). Nudge once.
      if (emptyRetries++ < 1) {
        push({ role: 'user', content: EMPTY, ts: Date.now(), synthetic: true })
        continue
      }
      content = '(the model returned an empty message twice - try a smaller question, disable thinking, or pick another model)'
    }
    if (wrapping && calls.length) calls = [] // told not to: its text, if any, is the answer
    const leak = !calls.length ? LEAKED_CALL.exec(content) : null
    if (leak) {
      // keep what it said before the call; give it one more turn to make the call properly
      content = content.slice(0, leak.index).trimEnd()
      if (agent && !wrapping && useTools && leakRetries++ < 2) {
        if (content) push({ role: 'assistant', content, ts: Date.now(), model: model || undefined })
        push({ role: 'user', content: LEAKED, ts: Date.now(), synthetic: true })
        continue
      }
    }
    // ids for calls the transport did not name (nine letters and digits: some servers insist)
    calls = calls.map((c, i) => ({ ...c, id: c.id || `c${iter.toString(36)}x${i.toString(36)}`.padEnd(9, '0') }))
    const assistant: ChatMessage = { role: 'assistant', content, thinking: thinking || undefined, tool_calls: calls.length ? calls : undefined, ts: Date.now(), stats, model: model || undefined }
    if (!calls.length) {
      if (sendBack(content, iter)) {
        push({ ...assistant, draft: true })
        push({ role: 'user', content: UNCITED, ts: Date.now(), synthetic: true })
        continue
      }
      if (agent) {
        const cites = citationsIn(content, seen)
        assistant.final = true
        assistant.cites = { verified: cites.filter((c) => c.verified).length, unverified: cites.filter((c) => !c.verified).map((c) => c.key) }
        await appendLedger(caseId, 'answer', content.slice(0, 200), {
          model: model || undefined,
          chars: content.length,
          sha256: await sha256Hex(content),
          cites: assistant.cites.verified,
          unverified: assistant.cites.unverified.slice(0, 20),
        }).catch(() => undefined)
      }
      push(assistant)
      report()
      return messages
    }
    push(assistant)
    if (opts.tools === false) {
      push({ role: 'assistant', content: '(stopped: this request does not permit tool calls)', ts: Date.now() })
      return messages
    }
    for (const c of calls) {
      if (opts.signal?.aborted) {
        // every call gets a result, or an OpenAI-style server refuses the conversation next time
        push({ role: 'tool', content: '(stopped by the analyst)', tool_name: c.name, tool_call_id: c.id, ts: Date.now() })
        continue
      }
      opts.onToolCall?.(c.name, c.arguments)
      const t0 = Date.now()
      const key = callKey(c.name, c.arguments)
      const again = !REPEATABLE.has(c.name) && !c.name.startsWith('propose_') ? cache.get(key) : undefined
      let msg: ChatMessage
      if (again) {
        msg = {
          role: 'tool',
          content: JSON.stringify({ note: `same call as step ${again.step}: the result has not changed. Use it, or change the arguments.` }),
          tool_name: c.name,
          tool_call_id: c.id,
          ts: Date.now(),
          ms: 0,
        }
      } else {
        const out = await runTool(c.name, c.arguments ?? {}, { kase, seen, signal: opts.signal, model: model || opts.model, session: agent?.session, exposed: () => exposed })
        if (out.suspects.length) {
          exposed = true
          run.suspects += out.suspects.length
          if (agent) await appendLedger(caseId, 'notice', `${c.name}: ${out.suspects.length} place(s) addressed to a model`, { suspects: out.suspects.slice(0, 5) }).catch(() => undefined)
        }
        if (out.plan) run.plan = out.plan
        if (out.proposal) run.proposals.push(out.proposal.id)
        msg = {
          role: 'tool',
          content: out.content,
          tool_name: c.name,
          tool_call_id: c.id,
          ts: Date.now(),
          ms: Date.now() - t0,
          refs: out.refs.length ? out.refs : undefined,
          suspects: out.suspects.length ? out.suspects : undefined,
          proposal: out.proposal?.id,
        }
        if (!out.error) cache.set(key, { content: out.content, step: iter + 1 })
        if (agent)
          await appendLedger(caseId, 'tool', c.name, {
            args: JSON.stringify(c.arguments ?? {}).slice(0, 300),
            sha256: (await sha256Hex(out.content)).slice(0, 32),
            refs: out.refs.length,
            error: out.error || undefined,
          }).catch(() => undefined)
        if (out.final && sendBack(out.final.answer, iter)) {
          msg.content = JSON.stringify({ error: UNCITED.replace(/^REMN: /, '') + ' Then call finish again.' })
          out.final = undefined
        }
        if (out.final) {
          run.toolCalls++
          opts.onToolResult?.(c.name, msg.content, msg.ms ?? 0)
          push(msg)
          const cites = citationsIn(out.final.answer, seen)
          const verified = { verified: cites.filter((x) => x.verified).length, unverified: cites.filter((x) => !x.verified).map((x) => x.key) }
          await appendLedger(caseId, 'answer', out.final.answer.slice(0, 200), {
            model: model || undefined,
            chars: out.final.answer.length,
            sha256: await sha256Hex(out.final.answer),
            cites: verified.verified,
            unverified: verified.unverified.slice(0, 20),
          }).catch(() => undefined)
          push({
            role: 'assistant',
            content: out.final.answer,
            ts: Date.now(),
            model: model || undefined,
            final: true,
            confidence: out.final.confidence,
            openQuestions: out.final.openQuestions,
            cites: verified,
          })
          run.step = iter + 1
          report()
          return messages
        }
      }
      run.toolCalls++
      opts.onToolResult?.(c.name, msg.content, msg.ms ?? 0)
      push(msg)
    }
    run.step = iter + 1
    report()
  }
  push({
    role: 'assistant',
    content: agent ? '(stopped: the model kept calling tools after the step budget)' : '(stopped: tool-call iteration limit reached - ask a narrower question or continue)',
    ts: Date.now(),
  })
  return messages
}
