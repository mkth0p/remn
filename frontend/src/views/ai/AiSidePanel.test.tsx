// @vitest-environment jsdom
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { propose } from '../../ai/inbox'
import { appendLedger } from '../../ai/ledger'
import { defaultSettings, RemnDB, setDb, type Case } from '../../db/schema'
import { AiSidePanel } from './AiSidePanel'

let db: RemnDB
const kase = { id: 1, name: 'c', settings: defaultSettings(), storage: 'browser', createdAt: 1, updatedAt: 1 } as Case
const base = { reason: 'r', citations: [{ source: 'events' as const, id: 1 }], by: 'agent' as const }

beforeEach(async () => {
  db = new RemnDB(`side-${Math.random()}`)
  setDb(db)
  await db.cases.add(kase)
})
afterEach(async () => {
  cleanup()
  db.close()
  await db.delete()
})

const panel = () => render(<AiSidePanel kase={kase} run={null} plan={[]} seenCount={0} busy={false} />)

describe('the side panel of the AI analyst', () => {
  it('says which proposals accept all leaves for a one-by-one look, and why each one waits', async () => {
    // invented proposals: one lowers a severity after nothing suspicious was read, one is a note
    // made after a lure was read, one raises a severity
    await propose(1, { ...base, kind: 'decision', title: 'lower the spray', target: 'finding:1', decision: { decision: 'reviewed', severity: 'low', from: 'high' } })
    await propose(1, { ...base, kind: 'note', title: 'timeline: first logon', note: { kind: 'timeline', text: 'first logon' }, exposed: true })
    await propose(1, { ...base, kind: 'decision', title: 'raise the task', target: 'finding:2', decision: { decision: 'escalated', severity: 'critical', from: 'high' } })
    const user = userEvent.setup()
    panel()
    await user.click(screen.getByRole('button', { name: /^inbox/ }))
    expect(await screen.findByRole('button', { name: 'accept all 1 of 3' })).toBeTruthy()
    const why = screen.getByText(/proposal\(s\) are not part of accept all/).textContent
    expect(why).toContain('2 proposal(s) are not part of accept all and wait for a one-by-one look')
    expect(why).toContain('1 that would lower a severity, leave an item out of the report or dismiss it')
    expect(why).toContain('1 made after the agent read evidence text addressed to a model')
    expect(screen.getByText('not part of accept all: it would lower the severity from high to low')).toBeTruthy()
    expect(screen.queryByText(/not part of accept all: .*critical/)).toBeNull()
  })

  it('lists the ledger with the notices of what was cut or addressed to a model', async () => {
    await appendLedger(1, 'run', 'what failed?', { model: 'invented:1b' })
    await appendLedger(1, 'notice', 'the question: 1 place(s) addressed to a model', { suspects: [] })
    const user = userEvent.setup()
    panel()
    await user.click(screen.getByRole('button', { name: 'ledger' }))
    expect(await screen.findByText(/the question: 1 place\(s\) addressed to a model/)).toBeTruthy()
    await user.click(screen.getByRole('button', { name: 'verify the chain' }))
    expect(await screen.findByText(/intact/)).toBeTruthy()
  })

  it('shows the head of the chain whole, as the report prints it, and says what the check does not find', async () => {
    await appendLedger(1, 'run', 'what failed?', { model: 'invented:1b' })
    const last = await appendLedger(1, 'answer', 'two failures', null)
    const user = userEvent.setup()
    panel()
    await user.click(screen.getByRole('button', { name: 'ledger' }))
    await user.click(screen.getByRole('button', { name: 'verify the chain' }))
    expect((await screen.findByRole('status')).textContent).toBe('✓ intact · 2 entries')
    expect(screen.getByTitle('the SHA-256 of the newest entry').textContent).toBe(last.hash)
    expect(last.hash).toMatch(/^[0-9a-f]{64}$/)
    expect(screen.getByText(/It does not find the newest entries removed, nor the chain written again from any entry onward/)).toBeTruthy()
    expect(screen.queryByText(/an entry changed afterwards breaks the chain/)).toBeNull()
  })
})
