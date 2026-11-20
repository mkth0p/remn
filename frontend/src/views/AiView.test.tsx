// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case } from '../db/schema'

// the model connection: which models it lists, what the chosen one can do, and whether it answers
const model = vi.hoisted(() => ({ caps: ['completion', 'tools'] as string[], pings: 0, reachable: true }))
vi.mock('../ai/transport', async (original) => ({
  ...(await original<typeof import('../ai/transport')>()),
  getTransport: () => ({
    listModels: async () => [{ name: 'qwen3:14b', parameterSize: '14B' }],
    capabilities: async () => model.caps,
    ping: async () => {
      model.pings++
      return model.reachable ? { reachable: true, models: 1 } : { reachable: false, error: 'connection refused' }
    },
  }),
}))
// a question sent goes nowhere: the test keeps what the page asked for
const sent = vi.hoisted(() => [] as { question: string; opts: Record<string, unknown> }[])
const fresh = vi.hoisted(() => ({ count: 0 }))
vi.mock('../ai/session', async (original) => ({
  ...(await original<typeof import('../ai/session')>()),
  sendMessage: async (_kase: unknown, question: string, opts: Record<string, unknown>) => void sent.push({ question, opts }),
  newChatSession: () => void fresh.count++,
}))
vi.mock('../ai/tools', async (original) => ({ ...(await original<typeof import('../ai/tools')>()), caseShape: async () => null }))

const { AiView } = await import('./AiView')
const { useStore } = await import('../state/store')
const { useChat } = await import('../ai/session')

let db: RemnDB
const kase: Case = { id: 1, name: 'c', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
const settle = () => act(() => new Promise((r) => setTimeout(r, 20)))

beforeEach(async () => {
  db = new RemnDB(`ai-view-${Math.random()}`)
  setDb(db)
  await db.cases.add(kase)
  model.caps = ['completion', 'tools']
  model.pings = 0
  model.reachable = true
  sent.length = 0
  fresh.count = 0
  useChat.setState({ caseId: null, session: null, messages: [], input: '', busy: false, live: '', liveThinking: '', seen: [], plan: [], run: null })
  useStore.setState({
    currentCase: kase,
    aiPrompt: null,
    aiConfig: { transport: 'browser', ollamaUrl: 'http://localhost:11434', openaiUrl: 'http://localhost:1234/v1', model: '', numCtx: null, claudeModel: 'sonnet' },
    aiStatus: { reachable: true, checkedAt: 1 },
    toasts: [],
  })
})
afterEach(async () => {
  cleanup()
  db.close()
  await db.delete()
})

describe('the AI analyst page', () => {
  it('sends a starter question to the agent with its tools and step budget', async () => {
    render(<AiView />)
    await settle()
    fireEvent.change(screen.getByRole('combobox', { name: 'steps' }), { target: { value: '40' } })
    fireEvent.click(screen.getByRole('button', { name: /Give me an overview of this case/ }))
    expect(sent).toEqual([{ question: 'Give me an overview of this case and the most suspicious things you see.', opts: { mode: 'analyst', model: undefined, think: false, tools: true, budget: 40 } }])
  })

  it('sends the question typed on Enter, and keeps a new line on Shift+Enter', async () => {
    render(<AiView />)
    const box = screen.getByRole('textbox')
    fireEvent.change(box, { target: { value: 'who logged on to WS-017 at night?' } })
    fireEvent.keyDown(box, { key: 'Enter', shiftKey: true })
    expect(sent).toHaveLength(0)
    fireEvent.keyDown(box, { key: 'Enter' })
    expect(sent.map((s) => s.question)).toEqual(['who logged on to WS-017 at night?'])
  })

  it('asks a model that cannot call tools without them, and offers it no playbook', async () => {
    model.caps = ['completion']
    // the page asks what a model can do once one is named
    useStore.setState({ aiConfig: { ...useStore.getState().aiConfig, model: 'gemma2:9b' } })
    render(<AiView />)
    expect(await screen.findByText('tools unsupported by model')).toBeTruthy()
    expect(screen.queryByText('Phishing to compromise')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /Which mails look like phishing/ }))
    expect(sent[0].opts).toMatchObject({ mode: 'free', tools: false })
  })

  it('runs a playbook as a new investigation, with at least 24 steps', async () => {
    render(<AiView />)
    await settle()
    fireEvent.change(screen.getByRole('combobox', { name: 'steps' }), { target: { value: '8' } })
    fireEvent.click(screen.getByRole('button', { name: /^Phishing to compromise/ }))
    expect(fresh.count).toBe(1)
    expect(sent[0].opts).toMatchObject({ mode: 'analyst', tools: true, budget: 24, label: 'playbook: Phishing to compromise' })
    expect(sent[0].opts.plan).toBeTruthy()
  })

  it('says the model does not answer instead of sending, and checks again on retry', async () => {
    model.reachable = false
    useStore.setState({ aiStatus: { reachable: false, error: 'connection refused', checkedAt: 1 } })
    render(<AiView />)
    expect(screen.getByText(/connection refused/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /Which accounts logged on outside business hours/ }))
    expect(sent).toHaveLength(0)
    expect(useStore.getState().toasts.at(-1)?.text).toBe('your local model (browser-direct · http://localhost:11434) is not reachable - start it, or change the connection in Settings')
    model.reachable = true
    fireEvent.click(screen.getByRole('button', { name: 'retry' }))
    await waitFor(() => expect(useStore.getState().aiStatus.reachable).toBe(true))
    expect(model.pings).toBe(1)
  })

  it('checks the model when the analyst first comes, not before', async () => {
    useStore.setState({ aiStatus: { reachable: null, checkedAt: 0 } })
    render(<AiView />)
    await waitFor(() => expect(useStore.getState().aiStatus.reachable).toBe(true))
    expect(model.pings).toBe(1)
  })

  it('takes the question another page put to it, ready to send', async () => {
    useStore.setState({ aiPrompt: 'Explain this event: 4625 on WS-017' })
    render(<AiView />)
    await waitFor(() => expect((screen.getByRole('textbox') as HTMLTextAreaElement).value).toBe('Explain this event: 4625 on WS-017'))
    expect(useStore.getState().aiPrompt).toBeNull()
    expect(sent).toHaveLength(0)
  })

  it("lists the case's investigations and deletes one", async () => {
    await db.aiSessions.bulkAdd([
      { caseId: 1, title: 'night logons on WS-017', messages: [], createdAt: 1, updatedAt: 2 },
      { caseId: 1, title: 'invoice lure', messages: [], createdAt: 1, updatedAt: 3 },
      { caseId: 2, title: 'another case', messages: [], createdAt: 1, updatedAt: 4 },
    ])
    render(<AiView />)
    expect(await screen.findByText('invoice lure')).toBeTruthy()
    expect(screen.queryByText('another case')).toBeNull()
    fireEvent.click(screen.getAllByRole('button', { name: 'delete the chat' })[0])
    await waitFor(() => expect(screen.queryByText('invoice lure')).toBeNull())
    expect((await db.aiSessions.toArray()).map((s) => s.title).sort()).toEqual(['another case', 'night logons on WS-017'])
  })

  it('says where the prompts go for the connection in use', () => {
    useStore.setState({ aiConfig: { ...useStore.getState().aiConfig, transport: 'openai' } })
    render(<AiView />)
    expect(screen.getByText(/^Local model server: this page talks straight to http:\/\/localhost:1234\/v1/)).toBeTruthy()
  })
})
