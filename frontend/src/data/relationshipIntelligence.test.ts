import { describe, expect, it } from 'vitest'
import { assessStory } from './relationshipIntelligence'
import { benchmarkGraph, benchmarkStory, T, seed } from './relationshipIntelligence.fixtures'
import { buildStories } from './relationshipStories'
import { relationshipLeads } from './relationshipLeads'
import { relationshipKey, reviewedRelationships, type RelationshipReview } from './relationshipReviews'
import { mergeRelationships } from './relationships'

describe('link accuracy benchmark', () => {
  const cases = [
    { name: 'exact digest', kind: 'hash', value: 'sha256:' + 'a'.repeat(64), expected: true },
    { name: 'same process instance', kind: 'process', value: 'guid:1', expected: true },
    { name: 'same scoped session', kind: 'logon-session', value: 'boot1:123', expected: true },
    { name: 'same account, unrelated activity', kind: 'account', value: 'corp\\alice', expected: false },
    { name: 'same unresolved PID', kind: 'process-observation', value: '42', expected: false },
    { name: 'common executable', kind: 'file', value: 'c:\\windows\\system32\\cmd.exe', expected: false },
    { name: 'same host', kind: 'host', value: 'ws01', expected: false },
  ]
  it.each(cases)('$name', ({ kind, value, expected }) => {
    const story = benchmarkStory(benchmarkGraph(kind, value))
    expect(story.records.some((r) => r.id === 2)).toBe(expected)
  })
  it('different versions at a path are excluded with an inspectable contradiction', () => {
    const path = 'c:\\temp\\payload.exe'
    const graph = benchmarkGraph(
      'file',
      path,
      ['a', 'b'].map((v) => ({ computer: 'ws01', path, hashes: 'SHA256=' + v.repeat(64) })),
    )
    const story = benchmarkStory(graph)
    expect(story.records.map((r) => r.id)).toEqual([1])
    expect(assessStory(story).issues).toContainEqual(expect.objectContaining({ kind: 'contradiction', related: expect.objectContaining({ id: 2 }) }))
  })
  it('a shared location outside the time window cannot join records', () => {
    const graph = benchmarkGraph('file', 'c:\\temp\\payload.exe')
    graph.edges[1].refs[0].ts = T + 30 * 86400000
    expect(benchmarkStory(graph).records).toHaveLength(1)
  })
  it('a score never promotes severity, and repeated imports do not corroborate', () => {
    const graph = benchmarkGraph()
    for (const edge of graph.edges) {
      edge.refs[0].sourceSha256 = 'duplicate'
      edge.refs[0].sourceIndex = 0
    }
    const story = benchmarkStory(graph),
      assessment = assessStory(story)
    expect(story.severity).toBe('low')
    expect(assessment.coverage.uniqueRecords).toBe(1)
    expect(assessment.confidence).toBe('limited')
    expect(relationshipLeads(graph)).toEqual([])
    const repeated = mergeRelationships(graph, graph)
    expect(repeated.edges[0].count).toBe(1)
  })
  it('rejected links change the graph used to construct stories and can be restored', () => {
    const graph = benchmarkGraph(),
      key = relationshipKey(graph.edges[1], new Map(graph.nodes.map((n) => [n.id, n])))
    const review = { key, status: 'rejected' } as RelationshipReview
    expect(benchmarkStory(reviewedRelationships(graph, { [key]: review })).records).toHaveLength(1)
    expect(benchmarkStory(reviewedRelationships(graph, { [key]: { ...review, status: 'accepted' } })).records).toHaveLength(2)
  })
  it('confidence requires independent telemetry and exposes partial coverage', () => {
    const graph = benchmarkGraph('hash', 'sha256:a', [{ provider: 'Sysmon' }, { artifactType: 'file' }])
    const story = benchmarkStory(graph)
    expect(assessStory(story).confidence).toBe('strong')
    expect(assessStory(story, true).confidence).toBe('supported')
    expect(assessStory(story, true).coverage.partial).toBe(true)
  })
  it('distinguishes earlier execution from the mail that might have delivered it', () => {
    const story = benchmarkStory()
    story.records[1].source = 'mails'
    story.records[0].ref!.context = { provider: 'Microsoft-Windows-Sysmon', eventId: 1 }
    expect(assessStory(story).issues.some((i) => i.id.startsWith('order:'))).toBe(true)
  })
  it('does not borrow another record’s file digest through an entity hop', () => {
    const graph = benchmarkGraph('file', 'c:\\temp\\payload.exe')
    graph.nodes.push({ id: 'hash', kind: 'hash', value: 'sha256:b', scope: '', label: 'hash' })
    graph.edges[1].target = 'hash'
    graph.edges.push({ ...graph.edges[0], source: 'entity', target: 'hash', relation: 'reported digest', refs: [{ ...graph.edges[0].refs[0], id: 99, sourceIndex: 99 }] })
    expect(benchmarkStory(graph).records).toHaveLength(1)
  })
  it('produces the same memberships after input order changes', () => {
    const graph = benchmarkGraph()
    const expected = buildStories(graph, [seed], []).stories.map((s) => s.records.map((r) => r.id).sort())
    expect(buildStories({ ...graph, nodes: [...graph.nodes].reverse(), edges: [...graph.edges].reverse() }, [seed], []).stories.map((s) => s.records.map((r) => r.id).sort())).toEqual(expected)
  })
})
