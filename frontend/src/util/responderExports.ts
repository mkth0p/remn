import type { Case, CaseNote, EventRow, Finding, Severity } from '../db/schema'
import { effectiveSeverity } from '../data/review'
import { toCsv } from './export'

/**
 * Exports for the tools a responder carries the case into: a timeline for Timesketch (JSONL) or
 * Timeline Explorer (CSV), and a layer for the MITRE ATT&CK Navigator.
 */

// ---------------------------------------------------------------------------
// timeline
// ---------------------------------------------------------------------------

/**
 * One line of a timeline. `message`, `datetime` and `timestamp_desc` are the three fields
 * Timesketch requires; the rest are attributes it indexes as they are. Every time is UTC.
 */
export interface TimelineRecord {
  message: string
  datetime: string
  timestamp_desc: string
  data_type: string
  source: 'finding' | 'note' | 'event'
  severity?: string
  status?: string
  rule_id?: string
  attack?: string
  host?: string
  user?: string
  ip?: string
  last_seen?: string
  source_file?: string
  remn_ref?: string
  tag?: string[]
}

export interface TimelineInput {
  findings?: Finding[]
  /** case notes; only the timeline entries with an event time are placed */
  notes?: CaseNote[]
  events?: EventRow[]
}

const iso = (ms: number) => new Date(ms).toISOString()
const pick = (e: Record<string, unknown>, keys: string[]): string | undefined => {
  for (const k of keys) {
    const v = e[k]
    if (v != null && v !== '') return Array.isArray(v) ? v.map(String).join(' | ') : String(v)
  }
  return undefined
}
const HOST = ['computer', 'host', 'hostname', 'device', 'workstation']
const USER = ['targetUser', 'user', 'upn', 'subjectUser', 'account', 'recipient', 'to']
const IP = ['ipAddress', 'ip', 'srcIp', 'clientIp', 'originIp', 'destinationIp']
const clean = <T extends object>(o: T): T => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined && v !== '' && !(Array.isArray(v) && !v.length))) as T

/**
 * The records of a timeline, in time order, and how many items had no time to place them at (a
 * collected artefact, an untimed note): Timesketch needs a time on every line, so those are left out
 * and counted.
 */
export function timelineRecords(input: TimelineInput): { records: TimelineRecord[]; untimed: number } {
  const records: TimelineRecord[] = []
  let untimed = 0
  for (const f of input.findings ?? []) {
    if (f.ts == null || !Number.isFinite(f.ts)) {
      untimed++
      continue
    }
    const sev = effectiveSeverity(f)
    records.push(
      clean({
        message: `[${sev}] ${f.title}`,
        datetime: iso(f.ts),
        timestamp_desc: 'Finding first seen',
        data_type: 'remn:finding',
        source: 'finding' as const,
        severity: sev,
        status: f.status,
        rule_id: f.ruleId,
        attack: f.attack.join(' '),
        host: pick(f.entities, HOST),
        user: pick(f.entities, USER),
        ip: pick(f.entities, IP),
        last_seen: f.tsEnd && f.tsEnd !== f.ts ? iso(f.tsEnd) : undefined,
        remn_ref: f.id != null ? `finding:${f.id}` : undefined,
        tag: ['remn', sev, ...(f.status === 'escalated' ? ['confirmed'] : []), ...f.attack],
      }),
    )
  }
  for (const n of input.notes ?? []) {
    if (n.kind !== 'timeline') continue
    if (n.untimed || !Number.isFinite(n.ts)) {
      untimed++
      continue
    }
    records.push(
      clean({
        message: n.text,
        datetime: iso(n.ts),
        timestamp_desc: 'Analyst timeline entry',
        data_type: 'remn:note',
        source: 'note' as const,
        severity: n.severity,
        remn_ref: n.link ? `${n.link.source}:${n.link.id}` : undefined,
        tag: ['remn', 'analyst'],
      }),
    )
  }
  for (const e of input.events ?? []) {
    const observation = e.recordKind === 'observation'
    const at = observation ? (e.observedAt ?? e.ts) : e.ts
    if (at == null || !Number.isFinite(at)) {
      untimed++
      continue
    }
    const what = e.summary || e.description || e.message || [e.provider, e.eventId].filter((x) => x != null && x !== '').join(' ') || e.artifactType || 'record'
    records.push(
      clean({
        message: String(what),
        datetime: iso(at),
        timestamp_desc: observation ? 'Collected' : timestampDesc(e),
        data_type: e.artifactType ? `remn:${e.artifactType}` : 'windows:evtx:record',
        source: 'event' as const,
        host: e.computer ?? undefined,
        user: e.targetUser ?? e.subjectUser ?? undefined,
        ip: e.ipAddress ?? undefined,
        source_file: e.sourceFile,
        remn_ref: e.id != null ? `events:${e.id}` : undefined,
        tag: ['remn'],
      }),
    )
  }
  records.sort((a, b) => a.datetime.localeCompare(b.datetime))
  return { records, untimed }
}

/**
 * What an event's time is. A disk artifact carries several times with different meanings (an MFT
 * entry's $SI created and $FN modified, a USN change, a prefetch file's earlier runs), and the
 * parser states which one a row holds in its description. An event log record's description is
 * its event type instead, and its time is when it was recorded.
 */
function timestampDesc(e: { artifactType?: unknown; description?: unknown }): string {
  const disk = typeof e.artifactType === 'string' && e.artifactType !== '' && e.artifactType !== 'event-export'
  return disk && typeof e.description === 'string' && e.description ? e.description : 'Event Recorded'
}

/** Timesketch's JSONL import: one JSON object per line. */
export function toTimesketchJsonl(records: TimelineRecord[]): string {
  return records.map((r) => JSON.stringify(r)).join('\n') + (records.length ? '\n' : '')
}

const CSV_COLUMNS: (keyof TimelineRecord)[] = [
  'datetime',
  'timestamp_desc',
  'message',
  'data_type',
  'source',
  'severity',
  'status',
  'rule_id',
  'attack',
  'host',
  'user',
  'ip',
  'last_seen',
  'source_file',
  'remn_ref',
  'tag',
]

/**
 * The same timeline as CSV, for Timeline Explorer or Timesketch's CSV import. A cell that would
 * start a spreadsheet formula gets a leading quote (see toCsv), since the file is as likely to be
 * opened in Excel.
 */
export function toTimelineCsv(records: TimelineRecord[]): string {
  return toCsv(
    records.map((r) => ({ ...r, tag: r.tag?.join(',') })),
    CSV_COLUMNS,
  )
}

// ---------------------------------------------------------------------------
// ATT&CK Navigator
// ---------------------------------------------------------------------------

const SEV_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical']
/** the report's severity colours */
const SEV_COLOR: Record<Severity, string> = { info: '#8a95a3', low: '#2f6fdb', medium: '#d9822b', high: '#d1403f', critical: '#a8231f' }
const STATUS_WORD: Record<string, string> = { new: 'not reviewed', reviewed: 'reviewed', escalated: 'confirmed', false_positive: 'false positive' }

/** A technique id as the Navigator reads it (T1059 or T1059.001), from the forms rules write it in. */
export function techniqueId(t: string): string | null {
  const m = /^(?:attack\.)?(t\d{4})(?:\.(\d{3}))?$/i.exec(t.trim())
  return m ? (m[2] ? `${m[1].toUpperCase()}.${m[2]}` : m[1].toUpperCase()) : null
}

interface TechniqueAcc {
  worst: Severity
  findings: number
  confirmed: number
  rules: Map<string, string>
}

/**
 * A Navigator layer (format 4.5, enterprise ATT&CK) of the techniques the case's findings name.
 * Each technique is coloured by the worst severity among its findings and scored by that severity
 * (1 info to 5 critical); its comment says how many findings, how many confirmed, and which rules.
 * False positives are left out: the layer says what the case shows, not what the rules matched.
 */
export function navigatorLayer(kase: Case, findings: Finding[], opts: { generatedAt?: number } = {}): Record<string, unknown> {
  const acc = new Map<string, TechniqueAcc>()
  for (const f of findings) {
    if (f.status === 'false_positive') continue
    const sev = effectiveSeverity(f)
    const ids = new Set(f.attack.map(techniqueId).filter((x): x is string => !!x))
    for (const id of ids) {
      let a = acc.get(id)
      if (!a) acc.set(id, (a = { worst: sev, findings: 0, confirmed: 0, rules: new Map() }))
      if (SEV_ORDER.indexOf(sev) > SEV_ORDER.indexOf(a.worst)) a.worst = sev
      a.findings++
      if (f.status === 'escalated') a.confirmed++
      a.rules.set(f.ruleId, f.title.replace(/\s+→.*$/, ''))
    }
  }
  const techniques: Record<string, unknown>[] = []
  const parentsShown = new Set([...acc.keys()].filter((id) => id.includes('.')).map((id) => id.split('.')[0]))
  for (const [id, a] of [...acc.entries()].sort(([x], [y]) => x.localeCompare(y))) {
    const rules = [...a.rules.entries()]
    techniques.push({
      techniqueID: id,
      score: SEV_ORDER.indexOf(a.worst) + 1,
      color: SEV_COLOR[a.worst],
      comment: `${a.findings} finding${a.findings === 1 ? '' : 's'}${a.confirmed ? `, ${a.confirmed} confirmed` : ''}; worst ${a.worst}. Rules: ${rules
        .slice(0, 8)
        .map(([rid, title]) => `${title} (${rid})`)
        .join('; ')}${rules.length > 8 ? `; and ${rules.length - 8} more` : ''}`,
      enabled: true,
      metadata: [
        { name: 'findings', value: String(a.findings) },
        { name: 'confirmed', value: String(a.confirmed) },
        { name: 'worst severity', value: a.worst },
      ],
      showSubtechniques: parentsShown.has(id),
    })
  }
  // a sub-technique shows only when its parent is expanded: add the parent, uncoloured, when the case names only its children
  for (const parent of parentsShown) if (!acc.has(parent)) techniques.push({ techniqueID: parent, enabled: true, showSubtechniques: true })
  techniques.sort((x, y) => String(x.techniqueID).localeCompare(String(y.techniqueID)))
  const statuses = new Set(findings.filter((f) => f.status !== 'false_positive').map((f) => STATUS_WORD[f.status] ?? f.status))
  return {
    name: `REMN · ${kase.name}`.slice(0, 120),
    versions: { layer: '4.5', navigator: '5.1.0' },
    domain: 'enterprise-attack',
    description: `Techniques named by the findings of the REMN case "${kase.name}" (${[...statuses].join(', ') || 'no finding'}), coloured by the worst severity. Generated ${new Date(opts.generatedAt ?? Date.now()).toISOString()}.`,
    sorting: 3,
    layout: { layout: 'side', aggregateFunction: 'max', showID: true, showName: true, showAggregateScores: false, countUnscored: false, expandedSubtechniques: 'annotated' },
    hideDisabled: false,
    techniques,
    gradient: { colors: [SEV_COLOR.info, SEV_COLOR.critical], minValue: 1, maxValue: 5 },
    legendItems: [...SEV_ORDER].reverse().map((s) => ({ label: s, color: SEV_COLOR[s] })),
    metadata: [{ name: 'case', value: kase.name }, ...(kase.analyst ? [{ name: 'analyst', value: kase.analyst }] : [])],
    showTacticRowBackground: false,
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
    selectVisibleTechniques: false,
  }
}
