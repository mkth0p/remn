import { expect, it, vi } from 'vitest'
import { runAgent } from './chat'
import { executeTool } from './tools'
import { defaultSettings, type Case } from '../db/schema'

vi.mock('./tools', () => ({ executeTool: vi.fn() }))
vi.mock('./transport', () => ({
  getTransport: () => ({
    chatTurn: async (_request: unknown, onEvent: (event: unknown) => void) => {
      onEvent({ type: 'tool_calls', calls: [{ name: 'search', arguments: {} }] })
      onEvent({ type: 'done' })
    },
  }),
}))

it('refuses unexpected model tool calls when the request forbids tools', async () => {
  const kase = { id: 1, settings: defaultSettings() } as Case
  const messages = await runAgent([{ role: 'user', content: 'Review evidence' }], kase, { mode: 'triage', tools: false, maxIterations: 1 })
  expect(executeTool).not.toHaveBeenCalled()
  expect(messages.at(-1)?.content).toContain('does not permit tool calls')
})
