import { describe, expect, it } from 'vitest'
import type { ChatMessage } from './chat'
import { compactToolResult, conversationBudget, fitToBudget } from './context'

const big = (n: number) => 'x'.repeat(n)

function round(i: number, size = 6000): ChatMessage[] {
  return [
    { role: 'assistant', content: '', tool_calls: [{ id: `c${i}`, name: 'search_events', arguments: { i } }] },
    { role: 'tool', content: big(size), tool_name: 'search_events', tool_call_id: `c${i}`, refs: [`ev:${i}`] },
  ]
}

describe('fitting a conversation to the context', () => {
  it('keeps everything when it fits', () => {
    const msgs: ChatMessage[] = [{ role: 'user', content: 'q' }, ...round(1, 100)]
    const r = fitToBudget(msgs, 10_000)
    expect(r.messages).toEqual(msgs)
    expect(r.omitted).toBe(0)
    expect(r.compacted).toBe(0)
  })

  it('compacts older tool results first and keeps their refs citable', () => {
    const msgs: ChatMessage[] = [{ role: 'user', content: 'the question' }, ...[1, 2, 3, 4, 5].flatMap((i) => round(i))]
    const r = fitToBudget(msgs, 9_000)
    expect(r.omitted).toBe(0)
    expect(r.compacted).toBe(2)
    const tools = r.messages.filter((m) => m.role === 'tool')
    expect(tools[0].compacted).toBe(true)
    expect(tools[0].content).toContain('Refs it returned, still citable: ev:1')
    expect(tools[4].content).toHaveLength(6000)
    expect(msgs[2].content).toHaveLength(6000) // the transcript itself is not changed
  })

  it('then leaves out the oldest rounds whole, never the question or the newest round', () => {
    const msgs: ChatMessage[] = [{ role: 'user', content: 'the question' }, ...[1, 2, 3, 4, 5, 6, 7, 8].flatMap((i) => round(i, 20_000))]
    const r = fitToBudget(msgs, 7_000)
    expect(r.messages[0].content).toBe('the question')
    expect(r.omitted).toBeGreaterThan(0)
    expect(r.omitted % 2).toBe(0) // a call is never sent without its result
    const last = r.messages[r.messages.length - 1]
    expect(last.tool_call_id).toBe('c8')
    for (let i = 1; i < r.messages.length; i++) if (r.messages[i].role === 'tool') expect(r.messages[i - 1].role === 'assistant' || r.messages[i - 1].role === 'tool').toBe(true)
    expect(r.tokens).toBeLessThanOrEqual(7_000)
  })

  it('does not compact a short result', () => {
    const m: ChatMessage = { role: 'tool', content: 'short', tool_name: 'x' }
    expect(compactToolResult(m)).toBe(m)
  })

  it('budgets the conversation after the system message, the tools and room to answer', () => {
    expect(conversationBudget(32768, big(3300), [{ a: big(3300) }])).toBeLessThan(32768 - 2000)
    expect(conversationBudget(2048, big(33_000), null)).toBe(1024)
  })
})
