import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case, type EventRow } from '../db/schema'
import type { ChatChunk, ChatTurnParams } from './transport'

/**
 * The agent loop against a scripted model: each turn of the script is what the "model" says;
 * the tools run for real against an IndexedDB case.
 */
type Turn = { text?: string; calls?: { name: string; arguments: Record<string, unknown> }[] }
const script: Turn[] = []
const seenParams: ChatTurnParams[] = []

vi.mock('./transport', () => ({
  contextWindow: () => 32768,
  getTransport: () => ({
    kind: 'browser',
    chatTurn: async (p: ChatTurnParams, on: (c: ChatChunk) => void) => {
      seenParams.push(JSON.parse(JSON.stringify(p)))
      const t = script.shift() ?? { text: 'nothing more' }
      if (t.text) on({ type: 'token', content: t.text })
      if (t.calls) on({ type: 'tool_calls', calls: t.calls })
      on({ type: 'done', model: 'scripted:1b', stats: { prompt_eval_count: 1234 } })
    },
  }),
}))
vi.mock('./meta', async (orig) => ({ ...(await orig<typeof import('./meta')>()), fetchAiMeta: () => Promise.reject(new Error('offline')) }))

const { runAgent } = await import('./chat')
const { SeenSet } = await import('./evidence')
const { loadLedger, verifyLedger } = await import('./ledger')

let db: RemnDB
const kase = { id: 1, name: 'c', settings: defaultSettings(), storage: 'browser', createdAt: 1, updatedAt: 1 } as Case
beforeEach(async () => {
  db = new RemnDB(`agent-${Math.random()}`)
  setDb(db)
  await db.cases.add(kase)
  await db.evidence.add({ caseId: 1, name: 'Security.evtx', size: 1, kind: 'evtx', integrity: 'verified', addedAt: 1, status: 'done', count: 2 })
  await db.events.bulkAdd([1, 2].map((id) => ({ id, caseId: 1, evidenceId: 1, ts: id, eventId: 4625, targetUser: 'admin', ipAddress: '10.0.0.5' }) as EventRow))
  script.length = 0
  seenParams.length = 0
})
afterEach(async () => {
  db.close()
  await db.delete()
})

const search = { name: 'search_events', arguments: { filter: { conditions: [{ field: 'eventId', op: 'eq', value: 4625 }] } } }

describe('an investigation', () => {
  it('plans, reads, answers from a cache when a call repeats, and checks the citations of its answer', async () => {
    script.push(
      { calls: [{ name: 'update_plan', arguments: { steps: [{ title: 'failures', status: 'doing' }] } }, search] },
      { calls: [search] },
      { text: 'Two failures for admin from 10.0.0.5 [ev:1] [ev:2], and a success [ev:77].' },
    )
    const seen = new SeenSet()
    const runs: unknown[] = []
    const msgs = await runAgent([{ role: 'user', content: 'what failed?' }], kase, { mode: 'analyst', tools: true, maxIterations: 6, agent: { seen, onRun: (r) => runs.push(r) } })
    const tools = msgs.filter((m) => m.role === 'tool')
    expect(tools.map((m) => m.tool_name)).toEqual(['update_plan', 'search_events', 'search_events'])
    expect(tools[2].content).toContain('same call as step 1')
    const final = msgs[msgs.length - 1]
    expect(final).toMatchObject({ role: 'assistant', final: true, model: 'scripted:1b', cites: { verified: 2, unverified: ['ev:77'], sentences: 1, unsupported: [] } })
    expect(seen.toJSON().sort()).toEqual(['ev:1', 'ev:2'])
    expect(runs.at(-1)).toMatchObject({ plan: [{ title: 'failures', status: 'doing' }], toolCalls: 3, contextTokens: 1234 })
    // the case tools only: no mail tools in an events-only case, the propose tools because it is an investigation
    expect(seenParams[0].toolNames).toContain('propose_decision')
    expect(seenParams[0].toolNames).not.toContain('search_mails')
    expect(seenParams[0].context.steps).toEqual({ used: 0, budget: 6 })
    expect(seenParams[1].context.memory).toContain('- [doing] failures')
    // every tool call gives its result an id the next turn answers
    const calls = msgs.filter((m) => m.tool_calls?.length).flatMap((m) => m.tool_calls!.map((c) => c.id))
    expect(tools.map((m) => m.tool_call_id)).toEqual(calls)
    const ledger = await loadLedger(1)
    expect(ledger.map((e) => e.kind)).toEqual(['run', 'tool', 'tool', 'answer'])
    expect((await verifyLedger(1)).intact).toBe(true)
  })

  it('reads each sentence against the rows it cites, whatever the tools returned', async () => {
    script.push({ calls: [search] }, { text: 'Failures for admin from 10.0.0.5 [ev:1]. Then 10.0.0.9 logged on [ev:2].' })
    const msgs = await runAgent([{ role: 'user', content: 'what failed?' }], kase, { mode: 'analyst', tools: true, maxIterations: 4, agent: { seen: new SeenSet() } })
    expect(msgs[msgs.length - 1]).toMatchObject({
      final: true,
      cites: { verified: 2, unverified: [], sentences: 2, unsupported: [{ sentence: 'Then 10.0.0.9 logged on .', reason: 'it names 10.0.0.9, which none of its 1 row holds' }] },
    })
    const answer = (await loadLedger(1)).find((e) => e.kind === 'answer')
    expect(JSON.parse(String(answer?.data))).toMatchObject({ cites: 2, unsupported: 1 })
  })

  it('asks for the answer without tools when the step budget is used up', async () => {
    for (let i = 0; i < 3; i++) script.push({ calls: [{ name: 'count_events', arguments: { filter: { conditions: [{ field: 'id', op: 'eq', value: i }] } } }] })
    script.push({ text: 'Out of steps: two failures [ev:1].' })
    const msgs = await runAgent([{ role: 'user', content: 'q' }], kase, { mode: 'analyst', tools: true, maxIterations: 3, agent: { seen: new SeenSet() } })
    expect(seenParams).toHaveLength(4)
    expect(seenParams[3].tools).toBe(false)
    const nudge = msgs.find((m) => m.synthetic)
    expect(nudge?.content).toContain('step budget is used up')
    expect(msgs[msgs.length - 1]).toMatchObject({ final: true, content: 'Out of steps: two failures [ev:1].' })
  })

  it('ends at finish, with its open questions', async () => {
    script.push({ calls: [search] }, { calls: [{ name: 'finish', arguments: { answer: 'Spraying [ev:1].', confidence: 'low', open_questions: ['owner of 10.0.0.5'] } }] })
    const msgs = await runAgent([{ role: 'user', content: 'q' }], kase, { mode: 'analyst', tools: true, agent: { seen: new SeenSet() } })
    expect(msgs[msgs.length - 1]).toMatchObject({ final: true, content: 'Spraying [ev:1].', confidence: 'low', openQuestions: ['owner of 10.0.0.5'], cites: { verified: 1 } })
    expect(script).toHaveLength(0)
  })

  it('gives a model that wrote its tool call as text another turn, and keeps only what it said', async () => {
    script.push({ text: 'Checking the failures now.<tool_call>{"name": "search_events"' }, { calls: [search] }, { text: 'Two failures [ev:1] [ev:2].' })
    const msgs = await runAgent([{ role: 'user', content: 'q' }], kase, { mode: 'analyst', tools: true, agent: { seen: new SeenSet() } })
    expect(msgs.map((m) => m.content).join('|')).not.toContain('<tool_call>')
    expect(msgs.find((m) => m.synthetic)?.content).toContain('tool call written as text')
    expect(msgs.find((m) => m.role === 'assistant')?.content).toBe('Checking the failures now.')
    expect(msgs[msgs.length - 1]).toMatchObject({ final: true, cites: { verified: 2 } })
  })

  it('sends an answer that cites nothing back once, and keeps the draft visible as a draft', async () => {
    script.push({ calls: [search] }, { text: 'There were two failures.' }, { text: 'There were two failures [ev:1] [ev:2].' })
    const msgs = await runAgent([{ role: 'user', content: 'q' }], kase, { mode: 'analyst', tools: true, agent: { seen: new SeenSet() } })
    const draft = msgs.find((m) => m.draft)
    expect(draft?.content).toBe('There were two failures.')
    expect(draft?.final).toBeUndefined()
    expect(msgs.find((m) => m.synthetic)?.content).toContain('cites no rows')
    expect(msgs[msgs.length - 1]).toMatchObject({ final: true, cites: { verified: 2 } })
  })

  it('refuses a finish that cites nothing once, then takes the next one as it comes', async () => {
    script.push({ calls: [search] }, { calls: [{ name: 'finish', arguments: { answer: 'Spraying.' } }] }, { calls: [{ name: 'finish', arguments: { answer: 'Still spraying.' } }] })
    const msgs = await runAgent([{ role: 'user', content: 'q' }], kase, { mode: 'analyst', tools: true, agent: { seen: new SeenSet() } })
    const finishes = msgs.filter((m) => m.role === 'tool' && m.tool_name === 'finish')
    expect(finishes[0].content).toContain('cites no rows')
    // asked once: an answer that still cites nothing is shown, flagged by its citation count
    expect(msgs[msgs.length - 1]).toMatchObject({ final: true, content: 'Still spraying.', cites: { verified: 0 } })
  })

  it('stops early when the analyst asks for the answer now', async () => {
    let asked = false
    script.push({ calls: [search] }, { text: 'Answer [ev:1].' })
    const msgs = await runAgent([{ role: 'user', content: 'q' }], kase, {
      mode: 'analyst',
      tools: true,
      agent: { seen: new SeenSet(), wrapUp: () => asked, onRun: () => (asked = true) },
    })
    expect(seenParams[1].tools).toBe(false)
    expect(msgs[msgs.length - 1]).toMatchObject({ final: true, content: 'Answer [ev:1].' })
  })
})
