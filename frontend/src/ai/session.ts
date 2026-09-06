import { create } from 'zustand'
import { getDb, type AiSession, type Case } from '../db/schema'
import { toast, useStore } from '../state/store'
import { runAgent, type ChatMessage } from './chat'

/**
 * The analyst conversation lives outside the AI view: switching pages must not drop the
 * transcript or the answer in flight. The view renders this store; `sendMessage` runs the
 * agent and keeps writing here whether or not the view is mounted, and every turn is saved
 * to the case's sessions as soon as it exists.
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
  sessionsVersion: 0,
  set: (patch) => set(patch),
}))

/** Show another case's conversation only while it is still running; otherwise start blank. */
export function bindChatToCase(caseId: number): void {
  const s = useChat.getState()
  if (s.caseId === caseId) return
  if (s.busy) return
  useChat.setState({ caseId, session: null, messages: [], live: '', liveThinking: '' })
}

export function newChatSession(): void {
  if (useChat.getState().busy) return
  useChat.setState({ session: null, messages: [] })
}

export function openChatSession(s: AiSession): void {
  if (useChat.getState().busy) return
  useChat.setState({ session: s, messages: s.messages as unknown as ChatMessage[], caseId: s.caseId })
}

async function persist(kase: Case, msgs: ChatMessage[]): Promise<void> {
  const db = getDb()
  const title = msgs.find((m) => m.role === 'user')?.content.slice(0, 80) || 'session'
  const rows = msgs as unknown as Record<string, unknown>[]
  const current = useChat.getState().session
  if (current?.id) {
    await db.aiSessions.update(current.id, { messages: rows, updatedAt: Date.now(), title })
    useChat.setState({ session: { ...current, messages: rows, updatedAt: Date.now(), title } })
  } else {
    const now = Date.now()
    const id = await db.aiSessions.add({ caseId: kase.id!, title, messages: rows, createdAt: now, updatedAt: now })
    useChat.setState({ session: { id, caseId: kase.id!, title, messages: rows, createdAt: now, updatedAt: now } })
  }
  useChat.setState((s) => ({ sessionsVersion: s.sessionsVersion + 1 }))
}

export interface SendOptions {
  mode: 'analyst' | 'free'
  model?: string
  think: boolean
  tools: boolean
}

/** Append the analyst's question, run the agent to completion and save the session; safe to call from a view that unmounts. */
export async function sendMessage(kase: Case, question: string, opts: SendOptions): Promise<void> {
  const q = question.trim()
  const st = useChat.getState()
  if (!q || st.busy) return
  const msgs: ChatMessage[] = [...(st.caseId === kase.id ? st.messages : []), { role: 'user', content: q, ts: Date.now() }]
  const abort = new AbortController()
  useChat.setState({ caseId: kase.id!, messages: msgs, input: '', busy: true, live: '', liveThinking: '', abort })
  // the question is on record before the answer: a session exists even if the model never replies
  persist(kase, msgs).catch(() => undefined)
  try {
    await runAgent(msgs, kase, {
      mode: opts.mode,
      model: opts.model,
      think: opts.think,
      tools: opts.tools,
      signal: abort.signal,
      onToken: (t) => useChat.setState((s) => ({ live: s.live + t })),
      onThinking: (t) => useChat.setState((s) => ({ liveThinking: s.liveThinking + t })),
      onMessage: (m) => {
        useChat.setState({ messages: [...msgs] })
        if (m.role === 'assistant') useChat.setState({ live: '', liveThinking: '' })
      },
      onToolCall: (name, args) => useStore.getState().log('info', `ai → ${name}(${JSON.stringify(args).slice(0, 200)})`),
      onToolResult: (name, result, ms) => useStore.getState().log('ok', `ai ← ${name}: ${result.length} chars in ${ms} ms`),
    })
  } catch (e) {
    if ((e as Error).name !== 'AbortError') toast('err', `AI error: ${(e as Error).message}`)
  } finally {
    useChat.setState({ busy: false, live: '', liveThinking: '', abort: null, messages: [...msgs] })
    await persist(kase, msgs).catch(() => undefined)
    if (useStore.getState().view !== 'ai') toast('info', 'the analyst answered - open the AI analyst page', 8000)
  }
}

export function stopChat(): void {
  useChat.getState().abort?.abort()
}
