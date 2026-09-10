import { apiPost } from '../api/client'
import { getDb, type Case } from '../db/schema'

export interface RelationshipNode {
  id: string
  kind: string
  value: string
  scope: string
  label: string
}
export interface RelationshipRef {
  id: number | null
  evidenceId: number | null
  source: 'events' | 'mails'
  sourceFile: string | null
  sourceSha256: string | null
  sourceIndex: number | null
  recordKind: string
  ts: number | null
  observedAt: number | null
  title: string
}
export interface RelationshipEdge {
  source: string
  target: string
  relation: string
  reason: string
  confidence: string
  refs: RelationshipRef[]
  count: number
}
export interface RelationshipResult {
  nodes: RelationshipNode[]
  edges: RelationshipEdge[]
  stats: { events: number; mails: number; truncated: boolean; rowCap: number; referenceCap: number }
  cursor?: { events: number; mails: number } | null
  /** The process snapshot used for this build, so later pages reuse it instead of re-reading it. */
  processContext?: Record<string, unknown>[]
  processContextTruncated?: boolean
}
export type RelationshipAliases = { hosts?: Record<string, string>; accounts?: Record<string, string> }
export const RELATIONSHIP_CAP = 20_000
const FIELDS =
  'id evidenceId sourceFile sourceName sourceIndex sourceSha256 packageId memberIndex recordKind artifactType observedAt ts date computer targetUser targetDomain targetSid subjectUser subjectDomain user upn image processName processGuid processId newProcessId callerProcessId imageLoaded processStart parentProcessGuid parentImage parentProcessName serviceName serviceFile taskName path targetFilename hashes destinationIp sourceIp ipAddress destinationHostname query fromAddr toList to summary subject name groupName memberName serviceAccount company deceptionEpisodeId deceptionExhibitId deceptionParentExhibitId deceptionScope deceptionAction deceptionResult deceptionStage'.split(
    ' ',
  )

/** Omit heavy event payloads and message bodies; all joins use explicit fields. */
export function relationshipRow(row: Record<string, unknown>): Record<string, unknown> {
  const slim = Object.fromEntries(FIELDS.filter((key) => row[key] != null).map((key) => [key, row[key]]))
  for (const [field, keys] of [
    ['attachments', ['name', 'sha256']],
    ['urls', ['url', 'normalized']],
  ] as const) {
    if (Array.isArray(row[field])) slim[field] = row[field].filter((item) => item && typeof item === 'object').map((item) => Object.fromEntries(keys.map((key) => [key, item[key]])))
  }
  return slim
}

export async function buildRelationships(
  kase: Case,
  evidenceId?: number,
  cursor = { events: 0, mails: 0 },
  aliases: RelationshipAliases = {},
  processContext?: Record<string, unknown>[],
  inheritedContextTruncated = false,
): Promise<RelationshipResult> {
  const pageSize = 1000
  if (kase.storage === 'server' && kase.serverKey) return apiPost('/api/relationships/build', { storeKey: kase.serverKey, evidenceId, cursor, pageSize, options: { aliases } })
  const db = getDb()
  const eventQuery = db.events
    .where('[caseId+id]')
    .between([kase.id!, cursor.events], [kase.id!, Infinity], false, true)
    .filter((r) => !evidenceId || r.evidenceId === evidenceId)
  const mailQuery = db.mails
    .where('[caseId+id]')
    .between([kase.id!, cursor.mails], [kase.id!, Infinity], false, true)
    .filter((r) => !evidenceId || r.evidenceId === evidenceId)
  const [events, mails] = await Promise.all([eventQuery.limit(pageSize + 1).toArray(), mailQuery.limit(pageSize + 1).toArray()])
  // The process snapshot is the same for every page of a build, so it is read and mapped once and
  // handed back to the caller rather than re-read from the database and re-uploaded per page.
  let context = processContext
  let contextTruncated = inheritedContextTruncated
  if (!context) {
    const processes = await db.events
      .where('[caseId+artifactType]')
      .equals([kase.id!, 'process'])
      .filter((r) => !evidenceId || r.evidenceId === evidenceId)
      .limit(RELATIONSHIP_CAP + 1)
      .toArray()
    contextTruncated = processes.length > RELATIONSHIP_CAP
    context = processes.slice(0, RELATIONSHIP_CAP).map(relationshipRow)
  }
  const result = await apiPost<RelationshipResult>('/api/relationships/build', {
    events: events.slice(0, pageSize).map(relationshipRow),
    mails: mails.slice(0, pageSize).map(relationshipRow),
    processContext: context,
    truncated: contextTruncated,
    options: { aliases },
  })
  result.processContext = context
  result.processContextTruncated = contextTruncated
  result.cursor =
    events.length > pageSize || mails.length > pageSize
      ? { events: events[Math.min(pageSize, events.length) - 1]?.id ?? cursor.events, mails: mails[Math.min(pageSize, mails.length) - 1]?.id ?? cursor.mails }
      : null
  return result
}

/** Merge disjoint ID pages; capped reference samples retain the total support count. */
export function mergeRelationships(previous: RelationshipResult | null, next: RelationshipResult): RelationshipResult {
  if (!previous) return next
  const nodes = new Map(previous.nodes.map((n) => [n.id, n]))
  const edges = new Map(previous.edges.map((e) => [JSON.stringify([e.source, e.target, e.relation]), e]))
  let capped = false
  for (const node of next.nodes) {
    if (nodes.size < 100_000 || nodes.has(node.id)) nodes.set(node.id, node)
    else capped = true
  }
  for (const edge of next.edges) {
    const key = JSON.stringify([edge.source, edge.target, edge.relation])
    const old = edges.get(key)
    if (!nodes.has(edge.source) || !nodes.has(edge.target) || (!old && edges.size >= 200_000)) {
      capped = true
      continue
    }
    edges.set(
      key,
      old
        ? { ...old, count: old.count + edge.count, refs: [...old.refs, ...edge.refs].slice(0, next.stats.referenceCap), confidence: old.confidence === 'contextual' ? 'contextual' : edge.confidence }
        : edge,
    )
  }
  return {
    nodes: [...nodes.values()],
    edges: [...edges.values()],
    cursor: next.cursor,
    processContext: next.processContext ?? previous.processContext,
    processContextTruncated: next.processContextTruncated ?? previous.processContextTruncated,
    stats: { ...next.stats, events: previous.stats.events + next.stats.events, mails: previous.stats.mails + next.stats.mails, truncated: previous.stats.truncated || next.stats.truncated || capped },
  }
}

/** Scan successive pages once, retaining the current page when the analyst stops. */
export async function scanRelationships(
  initial: RelationshipResult | null,
  load: (previous: RelationshipResult | null) => Promise<RelationshipResult>,
  stopped: () => boolean,
  progress: (result: RelationshipResult) => void,
): Promise<RelationshipResult | null> {
  let next = initial
  do {
    if (stopped()) break
    const page = await load(next)
    if (page.cursor && next?.cursor && page.cursor.events === next.cursor.events && page.cursor.mails === next.cursor.mails) throw new Error('The scan cursor did not advance. Please rebuild.')
    next = mergeRelationships(next, page)
    progress(next)
    if (next.nodes.length >= 100_000 || next.edges.length >= 200_000) return { ...next, stats: { ...next.stats, truncated: true } }
  } while (next.cursor && !stopped())
  return next
}
