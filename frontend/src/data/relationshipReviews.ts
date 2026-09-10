import { getDb } from '../db/schema'
import type { RelationshipEdge, RelationshipNode, RelationshipRef, RelationshipAliases } from './relationships'

export interface RelationshipReview {
  key: string
  status: 'unreviewed' | 'accepted' | 'rejected'
  notes: string
  includeInReport: boolean
  sourceLabel: string
  targetLabel: string
  relation: string
  reason: string
  confidence: string
  references: RelationshipRef[]
  aliases: RelationshipAliases
  updatedAt: number
}

/**
 * Content provenance keeps decisions stable when database IDs change on case restore.
 *
 * Only package members carry sourceSha256; a plain .evtx or .eml import has none. Falling back to
 * raw row IDs meant every key changed when a restored case renumbered its rows, orphaning accepted
 * decisions while the report still printed them. The fallback therefore uses stable content of the
 * witness instead: where it came from and when, never a database identifier.
 *
 * The alias map is deliberately NOT part of the key. An alias that matters has already changed the
 * node values the key is built from, so including the whole map only meant that adding one
 * unrelated alias re-keyed every review in the case at once, orphaning them all while the rebuilt
 * edges came back unreviewed. The map stays on the stored review, for citation.
 */
export function relationshipKey(edge: RelationshipEdge, nodes: Map<string, RelationshipNode>): string {
  const witness = edge.refs[0]
  const provenance = witness?.sourceSha256
    ? [witness.source, witness.sourceSha256, witness.sourceFile, witness.sourceIndex]
    : [witness?.source, witness?.sourceFile ?? null, witness?.ts ?? null, witness?.title ?? null]
  const entity = (id: string) => {
    const n = nodes.get(id)
    return n && (n.kind === 'record' || n.kind === 'process-observation') ? [n.kind, provenance] : [n?.kind, n?.scope, n?.value]
  }
  return JSON.stringify([entity(edge.source), edge.relation, entity(edge.target)])
}

export async function loadRelationshipReviews(caseId: number): Promise<Record<string, RelationshipReview>> {
  return ((await getDb().kv.get(`relationship-reviews-${caseId}`))?.value as Record<string, RelationshipReview>) ?? {}
}

export async function saveRelationshipReview(caseId: number, review: RelationshipReview): Promise<void> {
  const db = getDb()
  await db.transaction('rw', db.kv, async () => {
    const all = await loadRelationshipReviews(caseId)
    all[review.key] = review
    await db.kv.put({ key: `relationship-reviews-${caseId}`, value: all })
  })
}

/**
 * Accepted relationships for the report.
 *
 * `liveKeys` limits the result to edges the current graph still produces, when the caller knows
 * them. Without it an accepted review keeps printing after the evidence or the aliases changed
 * such that the edge is no longer built, while the rebuilt graph shows nothing to review.
 */
export async function reportRelationships(caseId: number, liveKeys?: Set<string>): Promise<RelationshipReview[]> {
  const db = getDb()
  const [all, evidence] = await Promise.all([loadRelationshipReviews(caseId), db.evidence.where('caseId').equals(caseId).toArray()])
  const liveEvidence = new Set(evidence.filter((e) => e.status === 'done').map((e) => e.id))
  // references is a bounded sample of the supporting rows, not the whole support set, so requiring
  // every sampled reference to survive dropped reviewed relationships whose evidence was still
  // present. Keep the relationship while any reference resolves, and report only the live ones.
  const kept: RelationshipReview[] = []
  for (const review of Object.values(all)) {
    if (review.status !== 'accepted' || !review.includeInReport || !review.references.length) continue
    if (liveKeys && !liveKeys.has(review.key)) continue
    const references = review.references.filter((ref) => liveEvidence.has(ref.evidenceId ?? -1))
    if (references.length) kept.push(references.length === review.references.length ? review : { ...review, references })
  }
  return kept
}

/**
 * Accepted relationships the report cannot stand behind, for its warnings: those whose supporting
 * evidence is entirely gone, and those the current graph no longer produces.
 */
export async function strandedRelationships(caseId: number, liveKeys?: Set<string>): Promise<{ evidenceGone: number; notProduced: number }> {
  const db = getDb()
  const [all, evidence] = await Promise.all([loadRelationshipReviews(caseId), db.evidence.where('caseId').equals(caseId).toArray()])
  const live = new Set(evidence.filter((e) => e.status === 'done').map((e) => e.id))
  let evidenceGone = 0
  let notProduced = 0
  for (const r of Object.values(all)) {
    if (r.status !== 'accepted' || !r.includeInReport || !r.references.length) continue
    if (!r.references.some((ref) => live.has(ref.evidenceId ?? -1))) evidenceGone++
    else if (liveKeys && !liveKeys.has(r.key)) notProduced++
  }
  return { evidenceGone, notProduced }
}
