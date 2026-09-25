import { expect, it } from 'vitest'
import { relationshipLeads } from './relationshipLeads'
import type { RelationshipResult, RelationshipRef } from './relationships'

const ref = (id: number, sourceFile: string): RelationshipRef => ({
  id,
  evidenceId: 1,
  sourceFile,
  source: 'events',
  sourceSha256: null,
  sourceIndex: id,
  recordKind: 'event',
  ts: id,
  observedAt: null,
  title: sourceFile,
})
const fixture = (): RelationshipResult => ({
  nodes: [
    { id: 'hash', kind: 'hash', value: 'sha256:a', label: 'sha256:a', scope: '' },
    { id: 'host', kind: 'host', value: 'pc', label: 'pc', scope: '' },
  ],
  edges: [
    { source: 'record-a', target: 'hash', relation: 'reports hash', reason: '', confidence: 'high', count: 1, refs: [ref(1, 'Processes/processes.csv')] },
    { source: 'record-b', target: 'hash', relation: 'attachment digest', reason: '', confidence: 'high', count: 1, refs: [ref(2, 'mail.eml')] },
    { source: 'record-a', target: 'host', relation: 'observed on', reason: '', confidence: 'high', count: 1, refs: [ref(1, 'Processes/processes.csv'), ref(2, 'mail.eml')] },
  ],
  stats: { events: 2, mails: 0, truncated: false, rowCap: 20000, referenceCap: 30 },
})
it('surfaces shared hashes across package members without treating a busy host as a lead', () => {
  const leads = relationshipLeads(fixture())
  expect(leads).toHaveLength(1)
  expect(leads[0]).toMatchObject({ node: { id: 'hash' }, records: 2, sources: ['Processes/processes.csv', 'mail.eml'] })
})
it('does not mistake repeated rows or multiple edges from one source for corroboration', () => {
  const graph = fixture()
  graph.edges[1].refs = [ref(1, 'Processes/processes.csv'), ref(3, 'Processes/processes.csv')]
  expect(relationshipLeads(graph)).toEqual([])
})
it('deduplicates the same supporting record across edges', () => {
  const graph = fixture()
  graph.edges.push({ ...graph.edges[0], relation: 'reported digest' })
  expect(relationshipLeads(graph)[0].records).toBe(2)
})
