/**
 * Where the evidence stops: what it cannot show, said in words, from what the files record about
 * themselves and from what the case holds. Each statement is checkable against the evidence:
 *
 * - holes in an EVTX file's own record numbering (records deleted, or in a part that could not be
 *   read), and write times that run backwards (a clock change, or records added later);
 * - chunks that fail the EVTX checksum (records changed after Windows wrote them, or damaged);
 * - record numbers in none of the files read between two files of one log (a missing archive);
 * - logs that start after the first finding (overwritten, or not collected);
 * - Unified Audit Log exports cut at a service limit (exactly 5,000 or 50,000 records);
 * - MailItemsAccessed throttled (item reads not recorded for 24 hours);
 * - Entra sign-ins that start after the first finding (Entra keeps them 7 or 30 days).
 *
 * The parser records the numbering and checksums per file (backend/services/parsers/evtx_parser.py
 * FileSequence); the rest comes from the case through the data source, so browser and server cases
 * read the same.
 */
import { getDb, type Evidence, type Finding } from '../db/schema'
import { effectiveSeverity } from '../rules/incidents'
import { fmtDuration, fmtNum, fmtUtc } from '../util/format'
import type { AggGroup, DataSource } from './source'

/** One EVTX file's record numbering and checksums, as the parser reports it. */
export interface FileSequenceStats {
  file: string
  count: number
  channel?: string
  channels?: number
  computer?: string
  computers?: number
  first?: number
  last?: number
  missing?: number
  holes?: [number, number][]
  holeCount?: number
  firstTs?: number | null
  lastTs?: number | null
  backwards?: number
  backwardsMaxMs?: number
  backwardsAt?: number[]
  /** too fragmented to follow every hole: the counts are a floor */
  overflow?: boolean
  checksums?: { chunks: number; fileHeader: boolean; dirty: boolean; badHeader?: number[]; badHeaderCount?: number; badData?: number[]; badDataCount?: number } | null
}

export type GapKind = 'record-holes' | 'time-backwards' | 'checksum' | 'missing-between-files' | 'log-starts-late' | 'export-cap' | 'mail-throttled' | 'signins-start-late'

export interface GapStatement {
  kind: GapKind
  severity: 'high' | 'medium' | 'low'
  text: string
  /** the evidence file it is about, when it is about one */
  evidenceId?: number
}

export interface GapInput {
  evidence: Evidence[]
  /** each channel's first and last record time in the case (DataSource.aggregateEvents on channel) */
  channels?: AggGroup[]
  /** the time of the first finding that matters; logs that start after it are named */
  incidentStart?: number | null
  /** MailItemsAccessed records marked IsThrottled */
  throttled?: { user: string; ts: number }[]
}

type Located = FileSequenceStats & { evidenceId: number }

const UAL_FORMATS = ['m365-ual-csv', 'm365-ual-json']
/** what one Search-UnifiedAuditLog call returns at most, and a ReturnLargeSet search */
const EXPORT_CAPS = [5000, 50000]
const ENTRA_CHANNEL = 'Entra SignIn'
/** a log that starts within this of the first finding is not said to start after it */
const LATE_MS = 3_600_000

const plural = (n: number, one: string, many = `${one}s`) => (n === 1 ? one : many)

function records(stats: Record<string, unknown> | undefined): Record<string, unknown>[] {
  const files = stats?.files
  return Array.isArray(files) ? (files.filter((f) => f && typeof f === 'object') as Record<string, unknown>[]) : []
}

function sequencesOf(value: unknown): FileSequenceStats[] {
  return Array.isArray(value) ? (value.filter((s) => s && typeof s === 'object' && typeof (s as FileSequenceStats).file === 'string') as FileSequenceStats[]) : []
}

/** Every EVTX file the case read, with its numbering: a log uploaded alone or in an archive, and a package member. */
export function fileSequences(evidence: Evidence[]): Located[] {
  const out: Located[] = []
  for (const e of evidence) {
    if (e.id == null) continue
    for (const s of sequencesOf(e.stats?.sequences)) out.push({ ...s, evidenceId: e.id })
    for (const f of records(e.stats)) for (const s of sequencesOf(f.sequences)) out.push({ ...s, evidenceId: e.id })
  }
  return out
}

/** One log from one computer: a file forwarded from several machines or holding several channels has no single name. */
const homogeneous = (s: FileSequenceStats) => !!s.channel && !!s.computer && (s.channels ?? 1) <= 1 && (s.computers ?? 1) <= 1

function where(s: FileSequenceStats): string {
  if (homogeneous(s)) return `${s.channel} on ${s.computer} (${s.file})`
  if ((s.channels ?? 0) > 1 || (s.computers ?? 0) > 1)
    return `${s.file} (${fmtNum(s.channels ?? 1)} ${plural(s.channels ?? 1, 'channel')} from ${fmtNum(s.computers ?? 1)} ${plural(s.computers ?? 1, 'computer')})`
  return s.file
}

function fileStatements(s: Located): GapStatement[] {
  const out: GapStatement[] = []
  const at = { evidenceId: s.evidenceId }
  if (s.missing && s.holes?.length) {
    const count = s.holeCount ?? s.holes.length
    const largest = s.holes.reduce((a, b) => (b[1] - b[0] > a[1] - a[0] ? b : a))
    const floor = s.overflow ? 'at least ' : ''
    out.push({
      kind: 'record-holes',
      severity: 'high',
      text:
        `${where(s)}: ${floor}${fmtNum(s.missing)} ${plural(s.missing, 'record')} missing from its numbering, in ${floor}${fmtNum(count)} ${plural(count, 'gap')} ` +
        `between record ${fmtNum(s.first)} and ${fmtNum(s.last)} (the largest: ${fmtNum(largest[0])}${largest[1] > largest[0] ? `–${fmtNum(largest[1])}` : ''}). ` +
        'Records deleted from the log, or in a part that could not be read.',
      ...at,
    })
  }
  if (s.backwards) {
    out.push({
      kind: 'time-backwards',
      severity: 'medium',
      text:
        `${where(s)}: write times run backwards ${fmtNum(s.backwards)} ${plural(s.backwards, 'time')} between consecutive records ` +
        `(the largest step ${fmtDuration(s.backwardsMaxMs)}${s.backwardsAt?.length ? `, first at record ${fmtNum(s.backwardsAt[0])}` : ''}): a clock change, or records added later.`,
      ...at,
    })
  }
  const c = s.checksums
  if (c) {
    const bad = c.badDataCount ?? c.badData?.length ?? 0
    const badHeader = c.badHeaderCount ?? c.badHeader?.length ?? 0
    if (bad)
      out.push({
        kind: 'checksum',
        severity: 'high',
        text: `${s.file}: ${fmtNum(bad)} of ${fmtNum(c.chunks)} ${plural(c.chunks, 'chunk')} fail their checksum. Their records were changed after Windows wrote them, or damaged; they were read all the same.`,
        ...at,
      })
    if (badHeader || c.fileHeader === false)
      out.push({
        kind: 'checksum',
        severity: 'medium',
        text: `${s.file}: ${[badHeader ? `${fmtNum(badHeader)} chunk ${plural(badHeader, 'header')}` : '', c.fileHeader === false ? 'the file header' : ''].filter(Boolean).join(' and ')} fail${badHeader + (c.fileHeader === false ? 1 : 0) === 1 ? 's' : ''} its checksum: the file's structure was changed after it was written.`,
        ...at,
      })
  }
  return out
}

/** Between files of one log: record numbers that are in none of them (a missing archive or export). */
function betweenFiles(seqs: Located[]): GapStatement[] {
  const byLog = new Map<string, Located[]>()
  for (const s of seqs) {
    if (!homogeneous(s) || s.first == null || s.last == null) continue
    const key = `${s.computer}\u0000${s.channel}`
    byLog.set(key, [...(byLog.get(key) ?? []), s])
  }
  const out: GapStatement[] = []
  for (const list of byLog.values()) {
    if (list.length < 2) continue
    const sorted = [...list].sort((a, b) => a.first! - b.first!)
    let reach = sorted[0]
    for (const next of sorted.slice(1)) {
      if (next.first! > reach.last! + 1) {
        const [a, b] = [reach.last! + 1, next.first! - 1]
        out.push({
          kind: 'missing-between-files',
          severity: 'medium',
          text: `${next.channel} on ${next.computer}: ${a === b ? `record ${fmtNum(a)} is` : `records ${fmtNum(a)}–${fmtNum(b)} are`} in none of the files read (${reach.file} ends at record ${fmtNum(reach.last)}, ${next.file} starts at ${fmtNum(next.first)}): an archive or export is missing.`,
        })
      }
      if (next.last! > reach.last!) reach = next
    }
  }
  return out
}

/** Logs whose first record is after the first finding: what happened there before is not in them. */
function startsLate(seqs: Located[], incidentStart: number): GapStatement[] {
  const first = new Map<string, Map<string, number>>()
  for (const s of seqs) {
    if (!homogeneous(s) || s.firstTs == null) continue
    const channels = first.get(s.computer!) ?? new Map<string, number>()
    channels.set(s.channel!, Math.min(channels.get(s.channel!) ?? Infinity, s.firstTs))
    first.set(s.computer!, channels)
  }
  const out: GapStatement[] = []
  for (const [computer, channels] of first) {
    const late = [...channels].filter(([, ts]) => ts > incidentStart + LATE_MS).sort((a, b) => a[1] - b[1])
    if (!late.length) continue
    const shown = late.slice(0, 4).map(([channel, ts]) => `${channel} at ${fmtUtc(ts)}`)
    const more = late.length > 4 ? ` and ${late.length - 4} more` : ''
    out.push({
      kind: 'log-starts-late',
      severity: 'medium',
      text: `On ${computer}, ${late.length === 1 ? 'one log starts' : `${late.length} logs start`} after the first finding (${fmtUtc(incidentStart)}): ${shown.join(', ')}${more}. Earlier events there were overwritten or not collected.`,
    })
  }
  return out
}

/** Unified Audit Log exports that hold exactly as many records as a service limit returns. */
function exportCaps(evidence: Evidence[]): GapStatement[] {
  const out: GapStatement[] = []
  const check = (e: Evidence, file: string, format: unknown, count: unknown, duplicates: unknown) => {
    if (!UAL_FORMATS.includes(String(format))) return
    const n = Number(count ?? 0) + Number(duplicates ?? 0)
    if (!EXPORT_CAPS.includes(n)) return
    out.push({
      kind: 'export-cap',
      severity: 'high',
      text: `${file}: exactly ${fmtNum(n)} Unified Audit Log records, the most ${n === 5000 ? 'one Search-UnifiedAuditLog call' : 'a large-set search'} returns. Records after that point in its time window are probably missing.`,
      evidenceId: e.id,
    })
  }
  for (const e of evidence) {
    check(e, e.name, e.format, e.stats?.count, e.stats?.duplicates)
    for (const f of records(e.stats)) if (f.status === 'parsed') check(e, String(f.name ?? e.name), f.format, f.count, f.duplicates)
  }
  return out
}

function throttledStatements(throttled: { user: string; ts: number }[]): GapStatement[] {
  const first = new Map<string, number>()
  for (const t of throttled) first.set(t.user, Math.min(first.get(t.user) ?? Infinity, t.ts))
  return [...first]
    .sort((a, b) => a[1] - b[1])
    .map(([user, ts]) => ({
      kind: 'mail-throttled' as const,
      severity: 'high' as const,
      text: `MailItemsAccessed for ${user} was throttled from ${fmtUtc(ts)}: for the 24 hours after it, the mailbox's item reads were not recorded one by one, so which messages were read then cannot be listed.`,
    }))
}

const ORDER = { high: 0, medium: 1, low: 2 }

/** Everything the evidence cannot show, most serious first. */
export function evidenceGaps(input: GapInput): GapStatement[] {
  const seqs = fileSequences(input.evidence)
  const out = [...seqs.flatMap(fileStatements), ...betweenFiles(seqs), ...exportCaps(input.evidence)]
  const start = input.incidentStart
  if (start != null) {
    out.push(...startsLate(seqs, start))
    const entra = input.channels?.find((g) => g.value === ENTRA_CHANNEL)
    if (entra?.first != null && entra.first > start + LATE_MS)
      out.push({
        kind: 'signins-start-late',
        severity: 'medium',
        text: `Entra sign-ins start at ${fmtUtc(entra.first)}, after the first finding (${fmtUtc(start)}): earlier sign-ins are not in the evidence. Entra keeps them 7 days without a P1 or P2 licence, 30 days with one.`,
      })
  }
  out.push(...throttledStatements(input.throttled ?? []))
  return out.sort((a, b) => ORDER[a.severity] - ORDER[b.severity])
}

/** The first finding that matters: not a false positive, medium severity or above. */
export function incidentStart(findings: Finding[]): number | null {
  let start: number | null = null
  for (const f of findings) {
    if (f.status === 'false_positive' || f.ts == null) continue
    if (!['critical', 'high', 'medium'].includes(effectiveSeverity(f))) continue
    if (start == null || f.ts < start) start = f.ts
  }
  return start
}

/** The statements for a case: its evidence, its findings, and what the rows say about throttling and sign-ins. */
export async function loadEvidenceGaps(caseId: number, source: DataSource): Promise<GapStatement[]> {
  const db = getDb()
  const [evidence, findings] = await Promise.all([db.evidence.where('caseId').equals(caseId).toArray(), db.findings.where('caseId').equals(caseId).toArray()])
  const [channels, throttled] = await Promise.all([
    source
      .aggregateEvents({}, 'channel', 500)
      .then((a) => a.groups)
      .catch(() => [] as AggGroup[]),
    source
      .searchEvents(
        {
          conditions: [
            { field: 'operation', op: 'eq', value: 'MailItemsAccessed' },
            { field: 'data.IsThrottled', op: 'eq', value: 'true' },
          ],
        },
        1000,
      )
      .then((r) => r.rows.map((row) => ({ user: String(row.upn ?? row.user ?? row.subjectUser ?? 'an unnamed mailbox'), ts: row.ts ?? 0 })))
      .catch(() => [] as { user: string; ts: number }[]),
  ])
  return evidenceGaps({ evidence, channels, incidentStart: incidentStart(findings), throttled })
}
