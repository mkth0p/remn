import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { runAgent } from '../ai/chat'
import { defaultSettings, deleteCaseData, RemnDB, setDb, type Case } from '../db/schema'
import { adviceFingerprint, advicePacket, loadHypothesisDecisions, reviewStory, saveHypothesisDecision, validateAdvice } from './relationshipAssistant'
import { assessStory } from './relationshipIntelligence'
import { benchmarkStory } from './relationshipIntelligence.fixtures'
import type { RelationshipReview } from './relationshipReviews'

vi.mock('../ai/chat', () => ({ runAgent: vi.fn() }))
const kase: Case = { id: 1, name: 'test', settings: defaultSettings(), createdAt: 1, updatedAt: 1 }
let db: RemnDB
beforeEach(() => {
  db = new RemnDB(`relationship-ai-test-${Math.random()}`)
  setDb(db)
  vi.mocked(runAgent).mockReset()
})
afterEach(async () => {
  await db.delete()
})
const story = benchmarkStory(),
  assessment = assessStory(story),
  packet = advicePacket(story, assessment)
const valid = () => ({
  claims: [{ edgeId: packet.edges[0].id, citations: packet.edges[0].citations, explanation: 'This record reports the digest.' }],
  hypotheses: [{ text: 'Content may have been reused.', citations: [packet.records[0].id], checkId: packet.checks[0].id }],
  nextStepIds: [packet.checks[0].id],
})

it('rejects fabricated citations, unrelated witnesses and invented check IDs', () => {
  expect(validateAdvice(valid(), packet)).toEqual(valid())
  const fabricated = valid()
  fabricated.claims[0].citations = ['nonexistent']
  expect(() => validateAdvice(fabricated, packet)).toThrow(/cited/)
  const unrelated = valid()
  unrelated.claims[0].citations = packet.edges[1].citations
  expect(() => validateAdvice(unrelated, packet)).toThrow(/match/)
  const invented = valid()
  invented.nextStepIds = ['run-command']
  expect(() => validateAdvice(invented, packet)).toThrow(/unapproved/)
})
it('makes one tool-free request and serves repeats from the evidence cache', async () => {
  vi.mocked(runAgent).mockResolvedValue([{ role: 'assistant', content: JSON.stringify(valid()) }])
  const key = await adviceFingerprint(story, assessment, {}, { model: 'local' })
  const first = await reviewStory(kase, packet, key, new AbortController().signal)
  const second = await reviewStory(kase, packet, key, new AbortController().signal)
  expect(first.cached).toBe(false)
  expect(second.cached).toBe(true)
  expect(runAgent).toHaveBeenCalledTimes(1)
  expect(vi.mocked(runAgent).mock.calls[0][2]).toMatchObject({ tools: false, think: false, maxIterations: 1 })
})
it('invalidates on relevant evidence or model changes, not unrelated reviews', async () => {
  const key = await adviceFingerprint(story, assessment, {}, 'model-a')
  expect(await adviceFingerprint(story, assessment, { unrelated: { status: 'accepted', notes: 'irrelevant' } as RelationshipReview }, 'model-a')).toBe(key)
  expect(await adviceFingerprint(story, assessment, {}, 'model-b')).not.toBe(key)
  expect(await adviceFingerprint({ ...story, records: story.records.map((r, i) => (i ? r : { ...r, ts: 42 })) }, assessment, {}, 'model-a')).not.toBe(key)
})
it('does not cache invalid output or cancelled results', async () => {
  vi.mocked(runAgent).mockResolvedValue([{ role: 'assistant', content: '{"claims":[]}' }])
  await expect(reviewStory(kase, packet, 'invalid', new AbortController().signal)).rejects.toThrow()
  expect(await db.kv.get('relationship-ai-1-invalid')).toBeUndefined()
  const abort = new AbortController()
  abort.abort()
  await expect(reviewStory(kase, packet, 'cancelled', abort.signal)).rejects.toThrow(/Cancelled/)
  expect(runAgent).toHaveBeenCalledTimes(1)
})
it('persists analyst hypothesis decisions separately from observed graph links', async () => {
  const hypothesis = valid().hypotheses[0]
  await saveHypothesisDecision(1, 'evidence-version', hypothesis, { status: 'rejected', notes: 'Known test file' })
  expect(await loadHypothesisDecisions(1, 'evidence-version')).toEqual([expect.objectContaining({ status: 'rejected', notes: 'Known test file', text: hypothesis.text })])
  expect(await loadHypothesisDecisions(2, 'evidence-version')).toEqual([])
  expect(await loadHypothesisDecisions(1, 'changed-evidence')).toEqual([])
  await db.kv.put({ key: 'relationship-ai-1-example', value: valid() })
  await db.kv.put({ key: 'relationship-ai-10-example', value: valid() })
  await deleteCaseData(db, 1)
  expect(await loadHypothesisDecisions(1, 'evidence-version')).toEqual([])
  expect(await db.kv.get('relationship-ai-1-example')).toBeUndefined()
  expect(await db.kv.get('relationship-ai-10-example')).toBeDefined()
})
