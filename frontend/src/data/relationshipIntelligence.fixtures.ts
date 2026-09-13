import type { Finding } from '../db/schema'
import { buildStories, type Story } from './relationshipStories'
import type { RelationshipNode, RelationshipRef, RelationshipResult } from './relationships'

export const T = 1788257100000
export function benchmarkGraph(kind = 'hash', value = 'sha256:' + 'a'.repeat(64), contexts: Record<string, string | number>[] = [{}, {}]): RelationshipResult {
  const refs: RelationshipRef[] = contexts.map((context, i) => ({
    id: i + 1,
    evidenceId: i + 1,
    source: 'events',
    sourceFile: `source-${i}.evtx`,
    sourceSha256: null,
    sourceIndex: i,
    recordKind: 'event',
    ts: T + i * 1000,
    observedAt: null,
    title: `record ${i}`,
    context,
  }))
  const entity: RelationshipNode = { id: 'entity', kind, value, scope: kind === 'hash' ? '' : 'ws01', label: value }
  return {
    nodes: [entity, ...refs.map((r) => ({ id: `record:${r.id}`, kind: 'record', value: `events:${r.id}:${r.evidenceId}`, scope: '', label: r.title }))],
    edges: refs.map((r) => ({ source: `record:${r.id}`, target: entity.id, relation: 'names', reason: 'Explicit record field', confidence: 'high', assertion: 'observed', refs: [r], count: 1 })),
    stats: { events: refs.length, mails: 0, truncated: false, rowCap: 20000, referenceCap: 30 },
  }
}
export const seed: Finding = {
  id: 1,
  caseId: 1,
  key: 'test',
  ruleId: 'test',
  title: 'Test finding',
  severity: 'low',
  source: 'events',
  refs: [1],
  count: 1,
  status: 'new',
  createdAt: T,
  ts: T,
  entities: {},
  attack: [],
}
export const benchmarkStory = (graph = benchmarkGraph()): Story => buildStories(graph, [seed], []).stories.find((s) => s.records.some((r) => r.id === 1))!
