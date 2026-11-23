import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case, type EventRow } from '../db/schema'
import type { Rule } from '../rules/engine'
import type { RunRequest } from './rules.worker'

/**
 * The rule worker's messages, with the worker's global scope stood in for: a run request goes in
 * through onmessage, and what it posts back (progress, a failed rule, the end of the run) is kept.
 */
const posted: Record<string, unknown>[] = []
const scope: { postMessage: (m: Record<string, unknown>) => void; onmessage: ((ev: { data: unknown }) => Promise<void>) | null } = {
  postMessage: (m) => posted.push(m),
  onmessage: null,
}
vi.stubGlobal('self', scope)
await import('./rules.worker')
const { settingsForRules } = await import('../data/rules')

let db: RemnDB
const kase: Case = { id: 1, name: 'c', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
const settings = settingsForRules(kase)
const send = async (req: Omit<RunRequest, 'cmd' | 'caseId' | 'settings'> & Partial<RunRequest>) => {
  posted.length = 0
  await scope.onmessage!({ data: { cmd: 'run', caseId: 1, settings, ...req } })
  return {
    messages: [...posted],
    done: posted.find((m) => m.type === 'done') as
      { total: number; byRule: Record<string, number>; diagnostics: { ruleId: string; reason: string }[]; findings?: { ruleId: string; refs: number[] }[] } | undefined,
  }
}
const rule = (id: string, extra: Partial<Rule> = {}): Rule => ({ id, title: `Rule ${id}`, severity: 'high', source: 'events', where: { eventId: 4625 }, ...extra })

beforeEach(async () => {
  db = new RemnDB(`rules-worker-${Math.random()}`)
  setDb(db)
  await db.cases.add(kase)
  await db.evidence.add({ id: 1, caseId: 1, name: 'Security.evtx', size: 1, kind: 'evtx', integrity: 'verified', addedAt: 1, status: 'done', count: 4 })
  // invented logons: three failures for one account and a success, and a failure in another case
  await db.events.bulkAdd([
    ...[1, 2, 3].map((id) => ({ id, caseId: 1, evidenceId: 1, ts: id * 1000, eventId: 4625, channel: 'Security', targetUser: 'svc-backup', ipAddress: '10.0.0.5' }) as EventRow),
    { id: 4, caseId: 1, evidenceId: 1, ts: 5000, eventId: 4624, channel: 'Security', targetUser: 'svc-backup' } as EventRow,
    { id: 5, caseId: 2, evidenceId: 9, ts: 1000, eventId: 4625, channel: 'Security', targetUser: 'other' } as EventRow,
  ])
})
afterEach(async () => {
  db.close()
  await db.delete()
})

describe('the rule worker', () => {
  it("runs each rule on its case's events, stores the findings and reports each rule and the run", async () => {
    const { messages, done } = await send({ rules: [rule('failures', { group_by: ['targetUser'] })] })
    const progress = messages.filter((m) => m.type === 'progress')
    expect(progress).toEqual([expect.objectContaining({ index: 1, total: 1, ruleId: 'failures', findings: 1, rows: 3 })])
    expect(done).toMatchObject({ total: 1, byRule: { failures: 1 } })
    const findings = await db.findings.toArray()
    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({ caseId: 1, ruleId: 'failures', refs: [1, 2, 3] })
  })

  it('skips a rule pinned to an event the evidence does not hold, and says why', async () => {
    const { messages, done } = await send({ rules: [rule('service', { where: { eventId: 7045 } })] })
    expect(messages.find((m) => m.type === 'progress')).toMatchObject({ ruleId: 'service', findings: 0, rows: 0 })
    expect(done?.byRule).toEqual({ service: 0 })
    expect(done?.diagnostics).toEqual([expect.objectContaining({ ruleId: 'service', reason: 'not_applicable' })])
  })

  it('returns the findings of a dry run and stores none', async () => {
    const { done } = await send({ rules: [rule('failures', { group_by: ['targetUser'] })], dryRun: true })
    expect(done?.findings).toEqual([expect.objectContaining({ ruleId: 'failures', refs: [1, 2, 3] })])
    expect(await db.findings.count()).toBe(0)
  })

  it('leaves out a rule switched off, and reports a rule that fails without stopping the others', async () => {
    const { messages, done } = await send({
      rules: [rule('broken', { where: { eventId: 4625, 'targetUser|sounds': 'svc' } }), rule('off', { enabled: false }), rule('success', { where: { eventId: 4624 } })],
    })
    expect(messages.find((m) => m.type === 'rule-error')).toMatchObject({ ruleId: 'broken', total: 3 })
    expect(Object.keys(done?.byRule ?? {})).toEqual(['success'])
    expect(messages[messages.length - 1].type).toBe('done')
  })

  it('reads mail bodies for a rule that asks for them', async () => {
    await db.mails.bulkAdd([
      { id: 1, caseId: 1, evidenceId: 1, ts: 1, subject: 'Supplier update' },
      { id: 2, caseId: 1, evidenceId: 1, ts: 2, subject: 'Lunch' },
    ] as never)
    await db.mailBodies.bulkAdd([
      { caseId: 1, mailId: 1, bodyText: 'Please send the wire transfer to the new account today.' },
      { caseId: 1, mailId: 2, bodyText: 'Pizza on Friday?' },
    ] as never)
    const { done } = await send({ rules: [rule('bank-change', { source: 'mails', where: { 'bodyText|contains': 'wire transfer' } })], dryRun: true })
    expect(done?.findings?.map((f) => f.refs)).toEqual([[1]])
  })

  it('answers a request it cannot run with an error, and ignores a command it does not know', async () => {
    posted.length = 0
    await scope.onmessage!({ data: { cmd: 'run', caseId: 1, settings, rules: null } })
    expect(posted).toEqual([{ type: 'error', error: expect.any(String) }])
    posted.length = 0
    await scope.onmessage!({ data: { cmd: 'stop' } })
    expect(posted).toEqual([])
  })
})
