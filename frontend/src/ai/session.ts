import { create } from 'zustand'
import { getDb, type AiSession, type Case } from '../db/schema'
import { toast, useStore } from '../state/store'
import { runAgent, type AgentRun, type ChatMessage } from './chat'
import { SeenSet } from './evidence'
import type { PlanStep } from './tools'

/**
 * The analyst conversation lives outside the AI view: switching pages must not drop the
 * transcript or the answer in flight. The view renders this store; `sendMessage` runs the
 * agent and keeps writing here whether or not the view is mounted, and every turn is saved
 * to the case's sessions as soon as it exists, with the refs the conversation may cite and
 * its plan.
 */
export interface ChatState {
  caseId: number | null
  session: AiSession | null
  messages: ChatMessage[]
  input: string
  busy: boolean
  live: string
  liveThinking: string
  abort: AbortController | null
  /** the refs the tools returned in this conversation (what its answers may cite) */
  seen: string[]
  plan: PlanStep[]
  /** the investigation in flight, or the last one */
  run: AgentRun | null
  /** the analyst asked for the answer now */
  wrapUp: boolean
  /** bumped after a session is created, updated or deleted */
  sessionsVersion: number
  set: (patch: Partial<Omit<ChatState, 'set'>>) => void
}

export const useChat = create<ChatState>((set) => ({
  caseId: null,
  session: null,
  messages: [],
  input: '',
  busy: false,
  live: '',
  liveThinking: '',
  abort: null,
  seen: [],
  plan: [],
  run: null,
  wrapUp: false,
  sessionsVersion: 0,
  set: (patch) => set(patch),
}))

const blank = { session: null, messages: [], seen: [], plan: [], run: null }

/** Show another case's conversation only while it is still running; otherwise start blank. */
export function bindChatToCase(caseId: number): void {
  const s = useChat.getState()
  if (s.caseId === caseId) return
  if (s.busy) return
  useChat.setState({ caseId, ...blank, live: '', liveThinking: '' })
}

export function newChatSession(): void {
  if (useChat.getState().busy) return
  useChat.setState({ ...blank })
}

export function openChatSession(s: AiSession): void {
  if (useChat.getState().busy) return
  useChat.setState({ session: s, messages: s.messages as unknown as ChatMessage[], caseId: s.caseId, seen: s.seen ?? [], plan: (s.plan as PlanStep[] | undefined) ?? [], run: null })
}

/** What a session keeps: REMN's own nudges to the model are not part of the conversation. */
const kept = (msgs: ChatMessage[]) => msgs.filter((m) => !m.synthetic)

async function persist(kase: Case, msgs: ChatMessage[], seen: SeenSet, plan: PlanStep[]): Promise<void> {
  const db = getDb()
  const title = msgs.find((m) => m.role === 'user' && !m.synthetic)?.content.slice(0, 80) || 'session'
  const rows = kept(msgs) as unknown as Record<string, unknown>[]
  const extra = { seen: seen.toJSON(), plan }
  const current = useChat.getState().session
  if (current?.id) {
    await db.aiSessions.update(current.id, { messages: rows, updatedAt: Date.now(), title, ...extra })
    useChat.setState({ session: { ...current, messages: rows, updatedAt: Date.now(), title, ...extra } })
  } else {
    const now = Date.now()
    const id = await db.aiSessions.add({ caseId: kase.id!, title, messages: rows, createdAt: now, updatedAt: now, ...extra })
    useChat.setState({ session: { id, caseId: kase.id!, title, messages: rows, createdAt: now, updatedAt: now, ...extra } })
  }
  useChat.setState((s) => ({ sessionsVersion: s.sessionsVersion + 1 }))
}

export interface SendOptions {
  /** analyst: an investigation with tools; free: a plain conversation */
  mode: 'analyst' | 'free'
  model?: string
  think: boolean
  tools: boolean
  /** tool rounds before the model must answer */
  budget?: number
  /** a playbook's starting plan */
  plan?: PlanStep[]
  /** for the ledger: what started the run */
  label?: string
}

/** Append the analyst's question, run the agent to completion and save the session; safe to call from a view that unmounts. */
export async function sendMessage(kase: Case, question: string, opts: SendOptions): Promise<void> {
  const q = question.trim()
  const st = useChat.getState()
  if (!q || st.busy) return
  const same = st.caseId === kase.id
  const msgs: ChatMessage[] = [...(same ? st.messages : []), { role: 'user', content: q, ts: Date.now() }]
  const seen = new SeenSet(same ? st.seen : [])
  let plan: PlanStep[] = opts.plan ?? (same ? st.plan : [])
  const abort = new AbortController()
  useChat.setState({ caseId: kase.id!, messages: msgs, input: '', busy: true, live: '', liveThinking: '', abort, plan, wrapUp: false, run: null })
  // the question is on record before the answer: a session exists even if the model never replies
  await persist(kase, msgs, seen, plan).catch(() => undefined)
  const agent = opts.mode === 'analyst' && opts.tools
  try {
    await runAgent(msgs, kase, {
      mode: opts.mode,
      model: opts.model,
      think: opts.think,
      tools: opts.tools,
      maxIterations: agent ? (opts.budget ?? 24) : 8,
      signal: abort.signal,
      onToken: (t) => useChat.setState((s) => ({ live: s.live + t })),
      onThinking: (t) => useChat.setState((s) => ({ liveThinking: s.liveThinking + t })),
      onMessage: (m) => {
        useChat.setState({ messages: [...msgs], seen: seen.toJSON() })
        if (m.role === 'assistant') useChat.setState({ live: '', liveThinking: '' })
      },
      onToolCall: (name, args) => useStore.getState().log('info', `ai → ${name}(${JSON.stringify(args).slice(0, 200)})`),
      onToolResult: (name, result, ms) => useStore.getState().log('ok', `ai ← ${name}: ${result.length} chars in ${ms} ms`),
      agent: agent
        ? {
            seen,
            session: useChat.getState().session?.id,
            plan,
            label: opts.label,
            wrapUp: () => useChat.getState().wrapUp,
            onRun: (r) => {
              plan = r.plan
              useChat.setState({ run: r, plan: r.plan })
            },
          }
        : undefined,
    })
  } catch (e) {
    if ((e as Error).name !== 'AbortError') toast('err', `AI error: ${(e as Error).message}`)
  } finally {
    useChat.setState({ busy: false, live: '', liveThinking: '', abort: null, messages: [...msgs], seen: seen.toJSON(), wrapUp: false })
    await persist(kase, msgs, seen, plan).catch(() => undefined)
    if (useStore.getState().view !== 'ai') toast('info', 'the analyst answered - open the AI analyst page', 8000)
  }
}

/** Stop now: the turn in flight is cancelled. */
export function stopChat(): void {
  useChat.getState().abort?.abort()
}

/** Finish now: the agent gets one more turn, without tools, to write its answer from what it has. */
export function wrapUpChat(): void {
  if (useChat.getState().busy) useChat.setState({ wrapUp: true })
}
