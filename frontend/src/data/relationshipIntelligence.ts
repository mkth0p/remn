import type { Filter } from '../rules/filter'
import type { Story, StoryRecord } from './relationshipStories'
import { referenceIdentity, sourceIdentity, type RelationshipNode, type RelationshipRef } from './relationships'

export const INTELLIGENCE_VERSION = 2
export interface AssessmentIssue {
  id: string
  kind: 'contradiction' | 'alternative' | 'gap'
  message: string
  records: string[]
  related?: RelationshipRef
}
export interface InvestigationStep {
  id: string
  title: string
  purpose: string
  priority: number
  source: 'events' | 'mails'
  filter: Filter
  collect: string
  records: string[]
}
export interface StoryAssessment {
  confidence: 'limited' | 'supported' | 'strong'
  reasons: string[]
  coverage: { records: number; uniqueRecords: number; sources: number; families: string[]; timed: number; snapshots: number; partial: boolean }
  issues: AssessmentIssue[]
  steps: InvestigationStep[]
}
const text = (value: unknown) => String(value ?? '').toLowerCase()
const time = (record: StoryRecord) => record.ts ?? record.observedAt
const hashes = (record: StoryRecord) => new Map([...text(record.ref?.context?.hashes).matchAll(/(sha256|sha1|md5)=([a-f0-9]+)/g)].map((m) => [m[1], m[2]]))

/** A path is a location, an account is context, and a digest is content: none proves causation. */
export function joinDecision(a: StoryRecord, b: StoryRecord, entity: Pick<RelationshipNode, 'kind' | 'value'>, windowMs: number): { allowed: boolean; reason: string } {
  if (['host', 'group', 'account', 'sid', 'process-observation', 'logon-observation'].includes(entity.kind))
    return { allowed: false, reason: 'Shared account, host or unresolved identity alone is insufficient' }
  if (['hash', 'process', 'logon-session', 'deception-exhibit'].includes(entity.kind)) return { allowed: true, reason: 'Exact scoped identity; this establishes overlap, not causal order' }
  if (entity.kind === 'file') {
    // Compare hashes only when each record attributes its digest to this location.
    const subject = (r: StoryRecord) => {
      const c = r.ref?.context
      return text(c?.targetFilename || c?.imageLoaded || c?.path || c?.image || c?.processName).replaceAll('/', '\\')
    }
    if (subject(a) === text(entity.value) && subject(b) === text(entity.value)) {
      const hb = hashes(b)
      for (const [alg, digest] of hashes(a)) if (hb.has(alg) && hb.get(alg) !== digest) return { allowed: false, reason: 'Different digests at the same path: separate file versions' }
    }
    if (/\\windows\\(?:system32|syswow64)\\|\\program files(?: \(x86\))?\\/i.test(entity.value))
      return { allowed: false, reason: 'Common executable location requires a process instance or matching content' }
  }
  const ta = time(a),
    tb = time(b)
  return ta != null && tb != null && Number.isFinite(ta) && Number.isFinite(tb) && Math.abs(ta - tb) <= windowMs
    ? { allowed: true, reason: 'Shared entity within the configured time window; identity remains contextual' }
    : { allowed: false, reason: 'Missing comparable times or outside the configured window' }
}

export function assessStory(story: Story, partial = false): StoryAssessment {
  const unique = [...new Map(story.records.map((r) => [r.ref ? referenceIdentity(r.ref) : r.nodeId, r])).values()]
  const sources = new Set(unique.filter((r) => r.ref).map((r) => sourceIdentity(r.ref!)))
  const families = [
    ...new Set(unique.map((r) => (r.source === 'mails' ? 'mail' : text(r.ref?.context?.provider || r.ref?.context?.artifactType || r.ref?.context?.channel) || 'unclassified events'))),
  ].sort()
  const issues: AssessmentIssue[] = []
  for (const link of story.blockedLinks ?? [])
    issues.push({
      id: `blocked:${link.from}:${referenceIdentity(link.ref)}`,
      kind: link.reason.startsWith('Different digests') ? 'contradiction' : 'alternative',
      message: `Excluded ${link.ref.source} #${link.ref.id}: ${link.reason}`,
      records: [link.from],
      related: link.ref,
    })
  const add = (kind: AssessmentIssue['kind'], key: string, message: string, records: string[]) => {
    if (!issues.some((i) => i.id === key)) issues.push({ id: key, kind, message, records })
  }
  for (const r of unique) {
    for (const message of r.ref?.identityIssues ?? []) add('contradiction', `identity:${r.nodeId}:${message}`, message, [r.nodeId])
    if (time(r) == null) add('gap', `time:${r.nodeId}`, 'No event or collection time is available for this record.', [r.nodeId])
  }
  const instances = new Map<string, StoryRecord>()
  const numberId = (v: unknown) => {
    const n = Number(v)
    return Number.isSafeInteger(n) && n > 0 ? String(n) : ''
  }
  for (const r of unique) {
    const c = r.ref?.context
    if (!c?.processGuid || !c.computer) continue
    const key = `${text(c.computer)}:${text(c.processGuid).replace(/[{}]/g, '')}`,
      prior = instances.get(key)
    const pid = numberId(c.newProcessId ?? c.callerProcessId ?? (r.recordKind === 'observation' ? c.processId : undefined))
    const previous = prior?.ref?.context
    const previousPid = numberId(previous?.newProcessId ?? previous?.callerProcessId ?? (prior?.recordKind === 'observation' ? previous?.processId : undefined))
    if (prior && pid && previousPid && pid !== previousPid)
      add(
        'contradiction',
        `guid-pid:${key}`,
        'The same process GUID is reported with different subject PIDs. Check parser mapping, host aliases and source integrity before treating it as one instance.',
        [prior.nodeId, r.nodeId],
      )
    instances.set(key, r)
  }
  // Indexed by location; bounded pair selection reports versions without quadratic record comparisons.
  const versions = new Map<string, Map<string, StoryRecord>>()
  for (const r of unique) {
    const c = r.ref?.context
    const path = text(c?.targetFilename || c?.imageLoaded || c?.path || c?.image || c?.processName)
    if (!path) continue
    for (const [alg, digest] of hashes(r)) {
      const key = `${text(c?.computer)}:${path}:${alg}`
      const seen = versions.get(key) ?? new Map<string, StoryRecord>()
      const different = [...seen].find(([d]) => d !== digest)?.[1]
      if (different) add('contradiction', `version:${key}`, `Different ${alg} digests at ${path}. A replacement or unrelated version can explain the shared location.`, [different.nodeId, r.nodeId])
      seen.set(digest, r)
      versions.set(key, seen)
    }
  }
  const mails = unique.filter((r) => r.source === 'mails' && r.ts != null)
  const execution = unique.filter(
    (r) =>
      r.source === 'events' &&
      r.ts != null &&
      (r.ref?.context?.artifactType === 'process' || (text(r.ref?.context?.provider).includes('sysmon') && Number(r.ref?.context?.eventId) === 1) || Number(r.ref?.context?.eventId) === 4688),
  )
  for (const mail of mails) {
    const earlier = execution.find((r) => r.ts! < mail.ts!)
    if (earlier)
      add(
        'alternative',
        `order:${mail.nodeId}`,
        'Execution predates this mail. The mail cannot explain that earlier execution unless timestamps are wrong; consider earlier delivery or unrelated reuse.',
        [earlier.nodeId, mail.nodeId],
      )
  }
  if (unique.some((r) => r.recordKind === 'observation'))
    add(
      'gap',
      'snapshots',
      'Collection times show when an artifact was seen, not when it was created or executed.',
      unique
        .filter((r) => r.recordKind === 'observation')
        .slice(0, 5)
        .map((r) => r.nodeId),
    )
  const limited = partial || story.truncated || story.edges.some((e) => e.supportTruncated || e.count > e.refs.length)
  if (limited) add('gap', 'partial', 'Evidence or reference limits were reached; unseen links and contradictions remain possible.', [])
  if (unique.length < story.records.length) add('alternative', 'duplicates', 'Repeated imports of the same source records count once toward corroboration.', [])
  if (story.entities.some((e) => ['account', 'ip', 'domain'].includes(e.kind)))
    add('alternative', 'shared-infrastructure', 'Shared users, DNS, proxies or infrastructure can connect otherwise unrelated activity. Check a process instance or content digest.', [])
  const exact = story.entities.some((e) => ['hash', 'process', 'logon-session'].includes(e.kind) && e.bridge)
  const classifiedFamilies = families.filter((f) => f !== 'unclassified events')
  const confidence = issues.some((i) => i.kind === 'contradiction') || !exact || sources.size < 2 ? 'limited' : !limited && classifiedFamilies.length >= 2 ? 'strong' : 'supported'
  const reasons = [
    `${unique.length} unique records across ${sources.size} distinct source contents.`,
    exact ? 'An exact content or scoped instance identity crosses sources.' : 'No exact identity corroborated across sources.',
    'Confidence describes the observed association, not the probability of an attack.',
  ]
  const steps: InvestigationStep[] = []
  const push = (step: InvestigationStep) => {
    if (!steps.some((s) => s.id === step.id)) steps.push(step)
  }
  for (const r of unique) {
    const c = r.ref?.context ?? {}
    const host = c.computer
    const hostCondition = host ? [{ field: 'computer', op: 'eq' as const, value: host }] : []
    if (c.processGuid && !r.ref?.identityIssues?.length) {
      push({
        id: `process:${host}:${c.processGuid}`,
        title: 'Trace this process instance',
        purpose: 'Find creation, image loads and network activity for the same GUID.',
        priority: 100,
        source: 'events',
        filter: { conditions: [...hostCondition, { field: 'processGuid', op: 'eq', value: c.processGuid }] },
        collect: 'Collect Sysmon process and network events for this host and time range.',
        records: [r.nodeId],
      })
      push({
        id: `children:${host}:${c.processGuid}`,
        title: 'Find child processes',
        purpose: 'Check explicit parent GUIDs for subsequent execution.',
        priority: 85,
        source: 'events',
        filter: { conditions: [...hostCondition, { field: 'parentProcessGuid', op: 'eq', value: c.processGuid }] },
        collect: 'Collect process creation events with parent process GUIDs.',
        records: [r.nodeId],
      })
    }
    if (host && (c.targetLogonId || c.subjectLogonId)) {
      const field = c.targetLogonId ? 'targetLogonId' : 'subjectLogonId'
      push({
        id: `session:${host}:${c[field]}`,
        title: 'Verify the account session',
        purpose: 'Inspect logon/logoff events and boot boundaries before joining activity by a logon ID.',
        priority: 90,
        source: 'events',
        filter: {
          conditions: [...hostCondition, { field, op: 'eq', value: c[field] }],
          timeRange: story.start != null ? { from: story.start - 3600000, to: (story.end ?? story.start) + 3600000 } : undefined,
        },
        collect: 'Collect Security logon/logoff events and system boot events from this host.',
        records: [r.nodeId],
      })
    }
  }
  for (const entity of story.entities) {
    if (entity.kind === 'hash')
      push({
        id: `digest:${entity.value}`,
        title: 'Find other records with this digest',
        purpose: 'Check content reuse across file, process and attachment evidence.',
        priority: 95,
        source: 'events',
        filter: { conditions: [{ field: 'hashes', op: 'contains', value: entity.value.replace(':', '=') }] },
        collect: 'Collect file hashes, process creation logs and the original attachment for comparison.',
        records: story.records
          .filter((r) => story.edges.some((e) => e.source === r.nodeId && e.target === entity.id))
          .slice(0, 5)
          .map((r) => r.nodeId),
      })
    if (entity.kind === 'file')
      push({
        id: `path:${entity.scope}:${entity.value}`,
        title: 'Check activity at this path',
        purpose: 'Look for replacement, writes and execution; the same path can hold different content.',
        priority: issues.some((i) => i.id.startsWith('version:')) ? 110 : 75,
        source: 'events',
        filter: { text: entity.value, conditions: entity.scope ? [{ field: 'computer', op: 'eq', value: entity.scope }] : [] },
        collect: 'Collect file creation/change events, filesystem metadata and hashes for each version.',
        records: [],
      })
  }
  if (!steps.length)
    push({
      id: 'timeline',
      title: 'Inspect surrounding activity',
      purpose: 'Find an exact process, session or digest that can confirm or separate this association.',
      priority: 50,
      source: 'events',
      filter: {
        timeRange: story.start != null ? { from: story.start - 3600000, to: (story.end ?? story.start) + 3600000 } : undefined,
        conditions: story.entities
          .filter((e) => e.kind === 'host')
          .slice(0, 1)
          .map((e) => ({ field: 'computer', op: 'eq', value: e.value })),
      },
      collect: 'Collect process creation and authentication telemetry covering the story interval.',
      records: [story.anchor],
    })
  return {
    confidence,
    reasons,
    coverage: {
      records: story.records.length,
      uniqueRecords: unique.length,
      sources: sources.size,
      families,
      timed: unique.filter((r) => r.ts != null).length,
      snapshots: unique.filter((r) => r.recordKind === 'observation').length,
      partial: limited,
    },
    issues: issues.slice(0, 60),
    steps: steps.sort((a, b) => b.priority - a.priority || a.id.localeCompare(b.id)).slice(0, 8),
  }
}
