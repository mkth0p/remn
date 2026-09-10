import type { RelationshipNode, RelationshipRef, RelationshipResult } from './relationships'

export interface RelationshipLead {
  node: RelationshipNode
  sources: string[]
  records: number
  relations: string[]
  references: RelationshipRef[]
  score: number
}

const weights: Record<string, number> = { hash: 8, file: 6, process: 6, url: 4, domain: 3, ip: 2, account: 1 }

/** Rank observed overlap, never suspiciousness. Duplicate edges/rows are not independent sources. */
export function relationshipLeads(result: RelationshipResult | null): RelationshipLead[] {
  if (!result) return []
  const nodes = new Map(result.nodes.filter((n) => weights[n.kind]).map((n) => [n.id, n]))
  const support = new Map<string, { sources: Map<string, string>; records: Set<string>; relations: Set<string>; references: RelationshipRef[] }>()
  for (const edge of result.edges) {
    for (const id of new Set([edge.source, edge.target])) {
      if (!nodes.has(id)) continue
      let item = support.get(id)
      if (!item) {
        item = { sources: new Map(), records: new Set(), relations: new Set(), references: [] }
        support.set(id, item)
      }
      for (const ref of edge.refs) {
        // A source is an archive member or evidence item, not an arbitrary row.
        if (ref.evidenceId == null) continue
        const source = JSON.stringify([ref.evidenceId, ref.sourceFile || null])
        const record = JSON.stringify([source, ref.source, ref.id, ref.sourceIndex])
        item.sources.set(source, ref.sourceFile || `Evidence ${ref.evidenceId}`)
        if (!item.records.has(record) && item.references.length < 8) item.references.push(ref)
        item.records.add(record)
        item.relations.add(edge.relation)
      }
    }
  }
  return [...support]
    .flatMap(([id, item]) => {
      if (item.sources.size < 2) return []
      const node = nodes.get(id)!
      return [
        {
          node,
          sources: [...item.sources.values()],
          records: item.records.size,
          relations: [...item.relations],
          references: item.references,
          score: weights[node.kind] * 10 + Math.min(item.sources.size, 10) * 3 + Math.min(item.relations.size, 5),
        },
      ]
    })
    .sort((a, b) => b.score - a.score || a.node.label.localeCompare(b.node.label))
}
