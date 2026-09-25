import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case, type Finding } from '../db/schema'
import { listNotes } from '../data/caseNotes'
import { applySuggestion, loadSuggestions, proposalDecision, reviewItemFor } from '../data/aiReview'
import { acceptProposals, loadInbox, propose, rejectProposals, undoProposal } from './inbox'
import { loadLedger } from './ledger'

let db: RemnDB
const kase = { id: 1, name: 'c', settings: defaultSettings(), storage: 'browser', createdAt: 1, updatedAt: 1 } as Case
const finding = (patch: Partial<Finding> = {}): Finding => ({
  caseId: 1,
  key: 'win-brute-force|1',
  ruleId: 'win-brute-force',
  title: 'Brute force',
  source: 'events',
  severity: 'medium',
  refs: [1],
  entities: { ipAddress: '10.0.0.5' },
  count: 1,
  attack: ['T1110'],
  ts: 1,
  status: 'new',
  createdAt: 1,
  ...patch,
})

beforeEach(async () => {
  db = new RemnDB(`inbox-${Math.random()}`)
  setDb(db)
  await db.cases.add(kase)
})
afterEach(async () => {
  db.close()
  await db.delete()
})

const base = { reason: 'r', citations: [{ source: 'events' as const, id: 1 }], by: 'agent' as const }

describe('the approval inbox', () => {
  it('writes nothing until the analyst accepts, and undo takes it back out', async () => {
    const p = await propose(1, { ...base, kind: 'note', title: 'timeline: first logon', note: { kind: 'timeline', text: 'first logon from 10.0.0.5', ts: 1000 } })
    expect(await listNotes(1)).toHaveLength(0)
    const r = await acceptProposals(kase, [p.id], { [p.id]: { note: { kind: 'timeline', text: 'first logon from 10.0.0.5 (edited)', ts: 1000 } } })
    expect(r).toEqual({ accepted: 1, failed: [] })
    const notes = await listNotes(1, 'timeline')
    expect(notes.map((n) => n.text)).toEqual(['first logon from 10.0.0.5 (edited)'])
    expect((await loadInbox(1))[0]).toMatchObject({ status: 'accepted', applied: { created: { source: 'caseNotes', id: notes[0].id } } })
    await undoProposal(kase, p.id)
    expect(await listNotes(1)).toHaveLength(0)
    expect((await loadInbox(1))[0].applied?.undone).toBe(true)
    expect((await loadLedger(1)).map((e) => e.kind)).toEqual(['proposal', 'accepted', 'undone'])
  })

  it('keeps the newest decision on a target and settles the older one', async () => {
    const a = await propose(1, { ...base, kind: 'decision', title: 'a', target: 'finding:1', decision: { decision: 'reviewed' } })
    const b = await propose(1, { ...base, kind: 'decision', title: 'b', target: 'finding:1', decision: { decision: 'escalated' } })
    const items = await loadInbox(1)
    expect(items.find((x) => x.id === a.id)?.status).toBe('superseded')
    expect(items.find((x) => x.id === b.id)?.status).toBe('pending')
    await rejectProposals(1, [b.id])
    expect((await loadInbox(1)).every((x) => x.status !== 'pending')).toBe(true)
  })

  it('applies a chain word on an incident as its incident meaning ("confirmed" is "escalated", not "reviewed")', async () => {
    await db.findings.add(finding())
    const found = await reviewItemFor(1, 'finding:1')
    expect(found?.item.kind).toBe('incident')
    expect(proposalDecision(found!.item, 'confirmed')).toBe('escalated')
    expect(proposalDecision(found!.item, 'benign')).toBe('reviewed')
    const p = await propose(1, { ...base, kind: 'decision', title: 'confirm', target: 'finding:1', decision: { decision: 'confirmed', severity: 'high' } })
    await acceptProposals(kase, [p.id])
    const f = (await db.findings.toArray())[0]
    expect(f).toMatchObject({ status: 'escalated', decidedBy: 'ai', severityOverride: 'high' })
    await undoProposal(kase, p.id)
    const back = (await db.findings.toArray())[0]
    expect(back.status).toBe('new')
    expect(back.decidedBy).toBeUndefined()
    expect(back.severityOverride).toBeUndefined()
  })

  it('shows pending decisions on the Review page as suggestions, and accepting one there settles the proposal', async () => {
    await db.findings.add(finding())
    const p = await propose(1, { ...base, kind: 'decision', title: 'fp', target: 'finding:1', decision: { decision: 'false_positive' }, exposed: true })
    const sugg = await loadSuggestions(1)
    expect(sugg['finding:1']).toMatchObject({ decision: 'false_positive', proposalId: p.id, exposed: true })
    const { item, reviews } = (await reviewItemFor(1, 'finding:1'))!
    await applySuggestion(1, item, sugg['finding:1'], reviews)
    expect((await loadInbox(1))[0]).toMatchObject({ status: 'accepted' })
    expect(await loadSuggestions(1)).toEqual({})
  })

  it('moves suggestions stored before the inbox into it', async () => {
    await db.kv.put({ key: 'ai-suggestions-1', value: { 'finding:1': { target: 'finding:1', decision: 'escalated', reason: 'old', at: 1, by: 'chat' } } })
    expect(Object.keys(await loadSuggestions(1))).toEqual(['finding:1'])
    expect(await db.kv.get('ai-suggestions-1')).toBeUndefined()
    expect((await loadInbox(1))[0]).toMatchObject({ kind: 'decision', status: 'pending', reason: 'old' })
  })

  it('says why a decision cannot be applied when its item is gone', async () => {
    const p = await propose(1, { ...base, kind: 'decision', title: 'x', target: 'finding:99', decision: { decision: 'escalated' } })
    const r = await acceptProposals(kase, [p.id])
    expect(r.accepted).toBe(0)
    expect(r.failed[0].error).toContain('no longer in the review queue')
    expect((await loadInbox(1))[0]).toMatchObject({ status: 'pending', error: expect.stringContaining('no longer') })
  })
})
