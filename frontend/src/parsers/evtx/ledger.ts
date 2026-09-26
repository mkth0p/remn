/**
 * What the server keeps beside the rows of an EVTX file, ported from evtx_parser.py: the file's own
 * record numbering and its holes (FileSequence), the counts of the whole upload (Stats), and the
 * parent and signer details an older log leaves out (Lineage). They make the completeness ledger:
 * records read and failed, EventRecordID ranges and holes, chunks that fail their checksum.
 */
import { parseTimestamp, type Row } from './flatten'
import { BigInteger, isDict, strip, truthy } from './py'

/** collections.Counter with most_common's order: count, then first seen. */
class Counter<K> {
  readonly map = new Map<K, number>()
  add(k: K): void {
    this.map.set(k, (this.map.get(k) ?? 0) + 1)
  }
  get size(): number {
    return this.map.size
  }
  mostCommon(n?: number): [K, number][] {
    const all = [...this.map.entries()]
    // Array.prototype.sort is stable: equal counts keep their first-seen order, as Counter does
    all.sort((a, b) => b[1] - a[1])
    return n === undefined ? all : all.slice(0, n)
  }
}

const obj = <K>(entries: [K, number][]) => Object.fromEntries(entries.map(([k, v]) => [String(k), v]))

export interface Checksums {
  chunks: number
  fileHeader: boolean
  dirty: boolean
  badHeader?: number[]
  badHeaderCount?: number
  badData?: number[]
  badDataCount?: number
}

export class FileSequence {
  static MAX_SPANS = 100_000
  static LISTED = 50
  static NAMES = 20
  static MARKS = 500
  static BACKWARD_MS = 1000

  count = 0
  spans: [number, number][] = []
  overflow = false
  channels = new Counter<string>()
  computers = new Counter<string>()
  firstTs: number | null = null
  lastTs: number | null = null
  prevId: number | null = null
  prevWritten: number | null = null
  backwards = 0
  backwardsMax = 0
  steps: [number, number, number][] = []
  clockChanges: { computer: unknown; old: number; new: number }[] = []
  logStarts: { computer: unknown; ts: number }[] = []
  checksums: Checksums | null = null

  constructor(readonly name: string) {}

  add(recordId: unknown, written: number | null, row?: Row): void {
    this.count++
    if (row) {
      if (truthy(row.channel)) this.channels.add(row.channel as string)
      if (truthy(row.computer)) this.computers.add(row.computer as string)
      const ts = row.ts as number | null
      if (ts !== null && ts !== undefined) {
        this.firstTs = this.firstTs === null ? ts : Math.min(this.firstTs, ts)
        this.lastTs = this.lastTs === null ? ts : Math.max(this.lastTs, ts)
      }
      if (row.eventId === 1 || row.eventId === 4616 || row.eventId === 6005) this.mark(row)
    }
    if (typeof recordId !== 'number' || !Number.isInteger(recordId) || recordId < 1) return
    if (this.prevId !== null && recordId === this.prevId + 1 && written !== null && this.prevWritten !== null) {
      const step = this.prevWritten - written
      if (step > FileSequence.BACKWARD_MS) {
        this.backwards++
        this.backwardsMax = Math.max(this.backwardsMax, step)
        if (this.steps.length < FileSequence.LISTED) this.steps.push([recordId, this.prevWritten, written])
      }
    }
    this.prevId = recordId
    this.prevWritten = written
    this.cover(recordId)
  }

  private mark(row: Row): void {
    const eid = row.eventId
    const provider = row.provider
    if (eid === 6005 && provider === 'EventLog') {
      if (row.ts !== null && row.ts !== undefined && this.logStarts.length < FileSequence.MARKS) this.logStarts.push({ computer: row.computer ?? null, ts: row.ts as number })
      return
    }
    let oldT: unknown
    let newT: unknown
    if (eid === 1 && provider === 'Microsoft-Windows-Kernel-General') {
      const data = (truthy(row.data) ? row.data : {}) as Record<string, unknown>
      oldT = data.OldTime
      newT = data.NewTime
    } else if (eid === 4616 && provider === 'Microsoft-Windows-Security-Auditing') {
      oldT = row.previousTime
      newT = row.newTime
    } else return
    const oldMs = parseTimestamp(oldT)[0]
    const newMs = parseTimestamp(newT)[0]
    // the time service corrects the clock by fractions of a second all day
    if (oldMs === null || newMs === null || Math.abs(newMs - oldMs) <= FileSequence.BACKWARD_MS) return
    if (this.clockChanges.length < FileSequence.MARKS) this.clockChanges.push({ computer: row.computer ?? null, old: oldMs, new: newMs })
  }

  private cover(rid: number): void {
    const spans = this.spans
    if (spans.length && spans[spans.length - 1][1] + 1 === rid) {
      spans[spans.length - 1][1] = rid
      return
    }
    if (this.overflow) return
    // the first span that starts after rid
    let lo = 0
    let hi = spans.length
    while (lo < hi) {
      const mid = (lo + hi) >> 1
      if (rid < spans[mid][0]) hi = mid
      else lo = mid + 1
    }
    const i = lo
    if (i && spans[i - 1][1] >= rid) return
    const joinsPrev = i > 0 && spans[i - 1][1] + 1 === rid
    const joinsNext = i < spans.length && spans[i][0] - 1 === rid
    if (joinsPrev && joinsNext) {
      spans[i - 1][1] = spans[i][1]
      spans.splice(i, 1)
    } else if (joinsPrev) spans[i - 1][1] = rid
    else if (joinsNext) spans[i][0] = rid
    else {
      spans.splice(i, 0, [rid, rid])
      if (spans.length > FileSequence.MAX_SPANS) this.overflow = true
    }
  }

  holes(): [number, number][] {
    const out: [number, number][] = []
    for (let i = 0; i + 1 < this.spans.length; i++) out.push([this.spans[i][1] + 1, this.spans[i + 1][0] - 1])
    return out
  }

  toDict(): Record<string, unknown> {
    const holes = this.holes()
    const out: Record<string, unknown> = { file: this.name, count: this.count }
    if (this.channels.size) {
      out.channel = this.channels.mostCommon(1)[0][0]
      out.channels = this.channels.size
    }
    if (this.computers.size) {
      out.computer = this.computers.mostCommon(1)[0][0]
      out.computers = this.computers.size
      out.computerNames = this.computers.mostCommon(FileSequence.NAMES).map(([c]) => c)
    }
    if (this.spans.length) {
      out.first = this.spans[0][0]
      out.last = this.spans[this.spans.length - 1][1]
      out.missing = holes.reduce((n, [a, b]) => n + b - a + 1, 0)
      if (holes.length) {
        out.holes = holes.slice(0, FileSequence.LISTED)
        out.holeCount = holes.length
      }
    }
    out.firstTs = this.firstTs
    out.lastTs = this.lastTs
    if (this.backwards) Object.assign(out, { backwards: this.backwards, backwardsMaxMs: this.backwardsMax, steps: this.steps })
    if (this.clockChanges.length) out.clockChanges = this.clockChanges
    if (this.logStarts.length) out.logStarts = this.logStarts
    // too fragmented to follow every hole: the ones listed and counted are a floor
    if (this.overflow) out.overflow = true
    if (this.checksums !== null) out.checksums = this.checksums
    return out
  }
}

export class Stats {
  count = 0
  errors = 0
  sequences: FileSequence[] = []
  firstTs: number | null = null
  lastTs: number | null = null
  eventIds = new Counter<unknown>()
  channels = new Counter<string>()
  providers = new Counter<string>()
  computers = new Counter<string>()
  levels = new Counter<string>()

  add(row: Row): void {
    this.count++
    const ts = row.ts as number | null
    if (ts !== null && ts !== undefined) {
      if (this.firstTs === null || ts < this.firstTs) this.firstTs = ts
      if (this.lastTs === null || ts > this.lastTs) this.lastTs = ts
    }
    if (row.eventId !== null && row.eventId !== undefined) this.eventIds.add(row.eventId instanceof BigInteger ? row.eventId.digits : row.eventId)
    if (truthy(row.channel)) this.channels.add(row.channel as string)
    if (truthy(row.provider)) this.providers.add(row.provider as string)
    if (truthy(row.computer)) this.computers.add(row.computer as string)
    if (truthy(row.levelName)) this.levels.add(row.levelName as string)
  }

  beginFile(name: string): FileSequence {
    const seq = new FileSequence(name)
    this.sequences.push(seq)
    return seq
  }

  toDict(): Record<string, unknown> {
    return {
      count: this.count,
      errors: this.errors,
      firstTs: this.firstTs,
      lastTs: this.lastTs,
      eventIds: obj(this.eventIds.mostCommon(500)),
      channels: obj(this.channels.mostCommon(100)),
      providers: obj(this.providers.mostCommon(200)),
      computers: obj(this.computers.mostCommon(200)),
      levels: obj([...this.levels.map.entries()]),
      ...(this.sequences.length ? { sequences: this.sequences.slice(0, 500).map((s) => s.toDict()) } : {}),
    }
  }
}

function enriched(row: Row, note: string): string {
  return truthy(row.enriched) ? `${row.enriched}; ${note}` : note
}

/** Keeps the latest MAX entries, as the server's OrderedDict with move_to_end does. */
class Recent<K, V> {
  readonly map = new Map<K, V>()
  constructor(private readonly max: number) {}
  keep(k: K, v: V): void {
    this.map.delete(k)
    this.map.set(k, v)
    if (this.map.size > this.max) this.map.delete(this.map.keys().next().value as K)
  }
}

const lower = (v: unknown) => String(truthy(v) ? v : '').toLowerCase()
const stripBraces = (s: string) => s.replace(/^[{}]+|[{}]+$/g, '')
const int0 = (v: unknown) => (truthy(v) ? Math.trunc(Number(v)) : 0)

/**
 * The parent's account on a Sysmon 1 written before Sysmon had ParentUser, the parent's image on a
 * 4688 written before Windows logged ParentProcessName, and the code signer of a Sysmon 8 or 10's
 * source process; what was filled in is named in the row's `enriched` field.
 */
export class Lineage {
  static MAX = 200_000
  private users = new Recent<string, string>(Lineage.MAX)
  private images = new Recent<string, [string, number]>(Lineage.MAX)
  private signers = new Recent<string, string | null>(Lineage.MAX)

  apply(row: Row): void {
    const eid = row.eventId
    const data = isDict(row.data) ? (row.data as Record<string, unknown>) : null
    const sysmon = lower(row.provider).includes('sysmon')
    if ((eid === 7 || eid === 8 || eid === 10) && data !== null && sysmon) {
      this.signer(row, eid, data)
      return
    }
    if (eid === 1 && data !== null && sysmon) {
      const guid = lower(row.processGuid)
      if (guid && truthy(data.User)) this.users.keep(guid, String(data.User))
      const parent = lower(row.parentProcessGuid)
      if (!truthy(data.ParentUser) && this.users.map.has(parent)) {
        data.ParentUser = this.users.map.get(parent)!
        row.enriched = enriched(row, "data.ParentUser from the parent's process creation event")
      }
    } else if (eid === 4688 && String(truthy(row.channel) ? row.channel : '') === 'Security') {
      const computer = lower(row.computer)
      const pid = lower(row.newProcessId)
      if (pid && truthy(row.processName)) this.images.keep(computer + '\u0000' + pid, [String(row.processName), int0(row.ts)])
      const creator = lower(row.callerProcessId)
      if (!truthy(row.parentProcessName) && creator) {
        const hit = this.images.map.get(computer + '\u0000' + creator)
        // the latest creation of that process id before this one, within a week (ids are reused)
        if (hit) {
          const gap = int0(row.ts) - hit[1]
          if (gap >= 0 && gap <= 7 * 86_400_000) {
            row.parentProcessName = hit[0]
            row.enriched = enriched(row, 'parentProcessName from the 4688 that created the parent process id')
          }
        }
      }
    }
  }

  private signer(row: Row, eid: number, data: Record<string, unknown>): void {
    if (eid === 7) {
      const guid = stripBraces(String(truthy(row.processGuid) ? row.processGuid : truthy(data.ProcessGuid) ? data.ProcessGuid : '')).toLowerCase()
      if (!guid) return
      const signed = String(truthy(row.signed) ? row.signed : truthy(data.Signed) ? data.Signed : '').toLowerCase() === 'true'
      if (!signed) {
        this.signers.keep(guid, null)
        return
      }
      const loaded = lower(row.imageLoaded)
      const image = String(truthy(row.image) ? row.image : truthy(data.Image) ? data.Image : '').toLowerCase()
      const status = String(truthy(row.signatureStatus) ? row.signatureStatus : truthy(data.SignatureStatus) ? data.SignatureStatus : '').toLowerCase()
      const signature = strip(String(truthy(row.signature) ? row.signature : truthy(data.Signature) ? data.Signature : ''))
      const prior = this.signers.map.has(guid) ? this.signers.map.get(guid) : ''
      if (loaded && loaded === image && status === 'valid' && signature && prior !== null) this.signers.keep(guid, signature)
      return
    }
    const source = stripBraces(String(truthy(data.SourceProcessGUID) ? data.SourceProcessGUID : truthy(data.SourceProcessGuid) ? data.SourceProcessGuid : '')).toLowerCase()
    const signer = source ? this.signers.map.get(source) : null
    if (signer) {
      row.sourceSigner = signer
      row.enriched = enriched(row, "sourceSigner from the source process's own image load (Sysmon 7)")
    }
  }
}
