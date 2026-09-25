import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { composeSystem, pyJson, resetAiMetaCache, type AiMeta } from './meta'
import { capMessages, CLAUDE_MODELS, getTransport, isLocalModelUrl, openAiMessages, pickClaudeModel, ThinkSplitter, type ChatChunk, type ChatTurnParams } from './transport'
import { DEFAULT_REPORT } from '../data/review'
import { useStore } from '../state/store'

const FIXTURE = JSON.parse(readFileSync(join(__dirname, '../../../tests/fixtures/ai_system_compose.json'), 'utf-8')) as {
  version: string
  meta: { prompts: Record<string, string>; schemaDoc: string }
  cases: { name: string; mode: string; context: Record<string, unknown>; expected: string }[]
}

const META: AiMeta = {
  prompts: FIXTURE.meta.prompts as AiMeta['prompts'],
  tools: [],
  querySchema: { properties: { source: { enum: ['events', 'mails'] } } },
  schemaDoc: FIXTURE.meta.schemaDoc,
  numCtx: 32768,
  defaultModel: 'qwen3:8b',
  limits: { maxMessages: 200, maxMessageChars: 200000 },
  version: FIXTURE.version,
}

describe('composeSystem parity with backend golden fixture', () => {
  for (const c of FIXTURE.cases) {
    it(c.name, () => {
      expect(composeSystem(c.mode, c.context, META)).toBe(c.expected)
    })
  }
})

describe('pyJson', () => {
  it('matches python json.dumps spacing', () => {
    expect(pyJson({ a: [1, 'x', true, null], b: { c: 2.5 } })).toBe('{"a": [1, "x", true, null], "b": {"c": 2.5}}')
  })
  it('keeps unicode unescaped like ensure_ascii=False', () => {
    expect(pyJson({ n: 'Café' })).toBe('{"n": "Café"}')
  })
})

// ---------------------------------------------------------------------------
function metaResponse(version: string): Response {
  return new Response(JSON.stringify({ prompts: META.prompts, tools: [], querySchema: META.querySchema, schemaDoc: META.schemaDoc, numCtx: 4096, defaultModel: 'd', limits: META.limits, version }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function ndjsonResponse(lines: unknown[], status = 200): Response {
  const body = lines.map((l) => JSON.stringify(l)).join('\n') + '\n'
  return new Response(body, { status, headers: { 'Content-Type': 'application/x-ndjson' } })
}

const fetchMock = vi.fn()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
  resetAiMetaCache()
  useStore.getState().setAiConfig({ transport: 'browser', ollamaUrl: 'http://localhost:11434', model: 'testmodel', numCtx: 8192 })
})
afterEach(() => vi.unstubAllGlobals())

function chatParams(): ChatTurnParams {
  return {
    messages: [{ role: 'user', content: 'hi' }],
    mode: 'free',
    tools: false,
    context: { storage: 'browser' },
  }
}

describe('BrowserOllamaTransport.chatTurn', () => {
  it('parses tokens, thinking, accumulated tool_calls and done stats from NDJSON', async () => {
    fetchMock
      .mockResolvedValueOnce(metaResponse('v1'))
      .mockResolvedValueOnce(
        ndjsonResponse([
          { message: { thinking: 'hmm' } },
          { message: { content: 'Hel' } },
          { message: { content: 'lo' } },
          { message: { tool_calls: [{ function: { name: 'search_events', arguments: { limit: 5 } } }] } },
          { message: { tool_calls: [{ function: { name: 'get_event', arguments: '{"id": 3}' } }] } },
          { done: true, model: 'testmodel', eval_count: 42, done_reason: 'stop' },
        ]),
      )
    const chunks: ChatChunk[] = []
    await getTransport().chatTurn(chatParams(), (c) => chunks.push(c))
    expect(
      chunks
        .filter((c) => c.type === 'token')
        .map((c) => (c as { content: string }).content)
        .join(''),
    ).toBe('Hello')
    expect(chunks.some((c) => c.type === 'thinking' && c.content === 'hmm')).toBe(true)
    const tc = chunks.find((c) => c.type === 'tool_calls') as Extract<ChatChunk, { type: 'tool_calls' }>
    expect(tc.calls).toEqual([
      { name: 'search_events', arguments: { limit: 5 } },
      { name: 'get_event', arguments: { id: 3 } },
    ])
    const done = chunks.find((c) => c.type === 'done') as Extract<ChatChunk, { type: 'done' }>
    expect(done.model).toBe('testmodel')
    expect(done.stats.eval_count).toBe(42)
    // ollama request shape
    const [url, init] = fetchMock.mock.calls[1] as [string, RequestInit]
    expect(url).toBe('http://localhost:11434/api/chat')
    const body = JSON.parse(String(init.body))
    expect(body.options.num_ctx).toBe(8192)
    expect(body.think).toBeUndefined()
    expect(body.messages[0].role).toBe('system') // composed system prepended
    expect(init.headers).toEqual({ 'Content-Type': 'application/json' }) // no X-Forensic header to Ollama
  })

  it('turns network failure into an error chunk followed by done, never throws', async () => {
    fetchMock.mockResolvedValueOnce(metaResponse('v2')).mockRejectedValueOnce(new TypeError('Failed to fetch'))
    const chunks: ChatChunk[] = []
    await getTransport().chatTurn(chatParams(), (c) => chunks.push(c))
    expect(chunks[0].type).toBe('error')
    expect((chunks[0] as { error: string }).error).toMatch(/Cannot reach Ollama/)
    expect(chunks[1].type).toBe('done')
  })

  it('retries once without think on a 400 mentioning think', async () => {
    fetchMock
      .mockResolvedValueOnce(metaResponse('v3'))
      .mockResolvedValueOnce(new Response('"think" is not supported by this model', { status: 400 }))
      .mockResolvedValueOnce(ndjsonResponse([{ message: { content: 'ok' } }, { done: true, model: 'm' }]))
    const chunks: ChatChunk[] = []
    await getTransport().chatTurn({ ...chatParams(), think: true }, (c) => chunks.push(c))
    expect(chunks.some((c) => c.type === 'error')).toBe(false)
    expect(chunks.some((c) => c.type === 'token' && c.content === 'ok')).toBe(true)
    const second = JSON.parse(String((fetchMock.mock.calls[1] as [string, RequestInit])[1].body))
    const third = JSON.parse(String((fetchMock.mock.calls[2] as [string, RequestInit])[1].body))
    expect(second.think).toBe(true)
    expect(third.think).toBeUndefined()
  })

  it('reports a missing model with a pull hint', async () => {
    fetchMock.mockResolvedValueOnce(metaResponse('v4')).mockResolvedValueOnce(new Response('model "testmodel" not found', { status: 404 }))
    const chunks: ChatChunk[] = []
    await getTransport().chatTurn(chatParams(), (c) => chunks.push(c))
    const err = chunks.find((c) => c.type === 'error') as Extract<ChatChunk, { type: 'error' }>
    expect(err.error).toContain('ollama pull testmodel')
  })

  it('queryJson salvages JSON wrapped in prose', async () => {
    fetchMock
      .mockResolvedValueOnce(metaResponse('v5'))
      .mockResolvedValueOnce(new Response(JSON.stringify({ message: { content: 'Sure! {"source": "events", "filter": {}} hope that helps' } }), { status: 200 }))
    const res = await getTransport().queryJson('failed logons', { now: 'T' })
    expect(res.query).toEqual({ source: 'events', filter: {} })
    expect(res.model).toBe('testmodel')
  })
})

describe('Claude Code transport', () => {
  it('keeps Claude aliases and full ids, drops Ollama names', () => {
    expect(pickClaudeModel('opus', 'sonnet')).toBe('opus')
    expect(pickClaudeModel('Claude-Opus-5', 'sonnet')).toBe('claude-opus-5')
    expect(pickClaudeModel('qwen3:8b', 'haiku')).toBe('haiku')
    expect(pickClaudeModel('', 'fable')).toBe('fable')
    expect(pickClaudeModel(undefined, 'gemma4:latest')).toBe('sonnet')
    expect(pickClaudeModel(undefined, undefined)).toBe('sonnet')
  })
  it('lists every alias with tool support', () => {
    expect(CLAUDE_MODELS.map((m) => m.name)).toEqual(['sonnet', 'opus', 'fable', 'haiku'])
    expect(CLAUDE_MODELS.every((m) => m.capabilities?.includes('tools'))).toBe(true)
  })
})

describe('report defaults', () => {
  it('prints chain graphs unless switched off', () => {
    expect(DEFAULT_REPORT.includeGraphs).toBe(true)
  })
})

// ---------------------------------------------------------------------------
function sseResponse(events: unknown[]): Response {
  const text = events.map((e) => `data: ${typeof e === 'string' ? e : JSON.stringify(e)}\n\n`).join('')
  // split mid-line, as a network does
  const bytes = new TextEncoder().encode(text)
  const cut = Math.floor(bytes.length / 2)
  const stream = new ReadableStream({
    start(c) {
      c.enqueue(bytes.slice(0, cut))
      c.enqueue(bytes.slice(cut))
      c.close()
    },
  })
  return new Response(stream, { status: 200, headers: { 'Content-Type': 'text/event-stream' } })
}

describe('local OpenAI-compatible servers', () => {
  it('accept only this machine or the local network', () => {
    for (const u of [
      'http://localhost:1234/v1',
      'http://127.0.0.1:8080/v1',
      'http://[::1]:8000/v1',
      'http://192.168.1.20:1234/v1',
      'http://10.0.0.3/v1',
      'http://172.20.1.1/v1',
      'http://gpu-box:8000/v1',
      'http://studio.local:1234/v1',
    ])
      expect(isLocalModelUrl(u), u).toBe(true)
    for (const u of ['https://api.openai.com/v1', 'https://api.anthropic.com/v1', 'http://8.8.8.8/v1', 'http://172.32.0.1/v1', 'ftp://localhost/v1', 'not a url'])
      expect(isLocalModelUrl(u), u).toBe(false)
  })

  it('split <think> out of streamed text, across chunk boundaries', () => {
    const t = new ThinkSplitter()
    const parts = ['Hi <thi', 'nk>let me see</th', 'ink> there', ' <'].map((x) => t.push(x))
    const rest = t.flush()
    expect(parts.map((p) => p.content).join('') + rest.content).toBe('Hi  there <')
    expect(parts.map((p) => p.thinking).join('') + rest.thinking).toBe('let me see')
  })

  it('send tool calls with ids and each result answering its call, ids made up for older transcripts', () => {
    const out = openAiMessages('SYS', [
      { role: 'user', content: 'q' },
      {
        role: 'assistant',
        content: '',
        tool_calls: [
          { name: 'a', arguments: { x: 1 } },
          { id: 'k2', name: 'b', arguments: {} },
        ],
      },
      { role: 'tool', content: 'ra', tool_name: 'a' },
      { role: 'tool', content: 'rb', tool_name: 'b', tool_call_id: 'k2' },
      { role: 'assistant', content: 'done' },
    ])
    expect(out[0]).toEqual({ role: 'system', content: 'SYS' })
    const calls = (out[2] as { tool_calls: { id: string; function: { arguments: string } }[] }).tool_calls
    expect(calls[0].function.arguments).toBe('{"x":1}')
    expect(out[3]).toEqual({ role: 'tool', tool_call_id: calls[0].id, content: 'ra' })
    expect(out[4]).toEqual({ role: 'tool', tool_call_id: 'k2', content: 'rb' })
  })

  it('stream tokens, reasoning, tool calls assembled from deltas, and usage', async () => {
    useStore.getState().setAiConfig({ transport: 'openai', openaiUrl: 'http://localhost:1234/v1', model: 'qwen2.5-7b-instruct' })
    fetchMock
      .mockResolvedValueOnce(metaResponse('v-oa'))
      .mockResolvedValueOnce(
        sseResponse([
          { model: 'qwen2.5-7b-instruct', choices: [{ delta: { reasoning_content: 'plan' } }] },
          { choices: [{ delta: { content: 'Look' } }] },
          { choices: [{ delta: { tool_calls: [{ index: 0, id: 'call_a', function: { name: 'search_', arguments: '{"filter":' } }] } }] },
          { choices: [{ delta: { tool_calls: [{ index: 0, function: { name: 'events', arguments: '{}, "limit": 5}' } }] } }] },
          { choices: [{ delta: { tool_calls: [{ index: 1, id: 'call_b', function: { name: 'finish', arguments: '{"answer":"x"}' } }] }, finish_reason: 'tool_calls' }] },
          { choices: [], usage: { prompt_tokens: 900, completion_tokens: 40 } },
          '[DONE]',
        ]),
      )
    const chunks: ChatChunk[] = []
    await getTransport().chatTurn({ ...chatParams(), mode: 'analyst', tools: true, toolNames: ['search_events'] }, (c) => chunks.push(c))
    const [url, init] = fetchMock.mock.calls[1] as [string, RequestInit]
    expect(url).toBe('http://localhost:1234/v1/chat/completions')
    const body = JSON.parse(String(init.body))
    expect(body.stream).toBe(true)
    expect(body.model).toBe('qwen2.5-7b-instruct')
    expect(init.headers).toEqual({ 'Content-Type': 'application/json' }) // no key, no REMN header
    expect(chunks.find((c) => c.type === 'thinking')).toEqual({ type: 'thinking', content: 'plan' })
    expect(chunks.find((c) => c.type === 'token')).toEqual({ type: 'token', content: 'Look' })
    expect(chunks.find((c) => c.type === 'tool_calls')).toEqual({
      type: 'tool_calls',
      calls: [
        { id: 'call_a', name: 'search_events', arguments: { filter: {}, limit: 5 } },
        { id: 'call_b', name: 'finish', arguments: { answer: 'x' } },
      ],
    })
    expect(chunks.at(-1)).toEqual({ type: 'done', model: 'qwen2.5-7b-instruct', stats: { prompt_eval_count: 900, eval_count: 40, done_reason: 'tool_calls' } })
  })

  it('never sends a case to a cloud endpoint', async () => {
    useStore.getState().setAiConfig({ transport: 'openai', openaiUrl: 'https://api.openai.com/v1' })
    const chunks: ChatChunk[] = []
    await getTransport().chatTurn(chatParams(), (c) => chunks.push(c))
    expect(fetchMock).not.toHaveBeenCalled()
    expect(chunks[0]).toMatchObject({ type: 'error', error: expect.stringContaining('Cloud APIs are not supported') })
    expect((await getTransport().ping()).reachable).toBe(false)
  })

  it('retry a turn without tools when the server has no tool support', async () => {
    useStore.getState().setAiConfig({ transport: 'openai', openaiUrl: 'http://localhost:8080/v1', model: 'm' })
    fetchMock
      .mockResolvedValueOnce(metaResponse('v-oa2'))
      .mockResolvedValueOnce(new Response('{"error":"tools param requires --jinja flag"}', { status: 400 }))
      .mockResolvedValueOnce(sseResponse([{ choices: [{ delta: { content: 'plain' } }] }, '[DONE]']))
    const chunks: ChatChunk[] = []
    await getTransport().chatTurn({ ...chatParams(), tools: true }, (c) => chunks.push(c))
    expect(JSON.parse(String((fetchMock.mock.calls[2] as [string, RequestInit])[1].body)).tools).toBeUndefined()
    expect(chunks.find((c) => c.type === 'token')).toEqual({ type: 'token', content: 'plain' })
  })
})

describe('long conversations', () => {
  it('keep the question and the newest messages, not the oldest', () => {
    const msgs = Array.from({ length: 10 }, (_, i) => i)
    expect(capMessages(msgs, 4)).toEqual([0, 7, 8, 9])
    expect(capMessages(msgs, 20)).toBe(msgs)
  })
})
