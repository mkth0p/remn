/**
 * The date order and time zone an evidence file is read in where it does not say. Microsoft 365
 * and Entra exports written by Export-Csv carry their dates in the culture of the session that
 * wrote them (9/1/2026 or 01/09/2026) and, from the admin centres, times without a zone. The
 * server reads them in the order the file shows and as UTC unless the evidence sets otherwise
 * (services/parsers/m365.py date_setting), and its statistics say which records that applied to.
 */
import type { DateSetting, Evidence } from '../db/schema'
import { fmtNum } from '../util/format'

// the zones the server takes: UTC, an offset of up to 14 hours, or an IANA name (m365.time_zone)
const OFFSET = /^(?:UTC|GMT)?\s*([+-])(\d{1,2})(?::?(\d{2}))?$/i
const ZONE_NAME = /^[A-Za-z][A-Za-z0-9_+\-/]{0,63}$/

/** Why the server would not take this time zone, in the analyst's words; null when it would. */
export function zoneError(zone: string): string | null {
  const z = zone.trim()
  if (!z || /^(utc|z|gmt)$/i.test(z)) return null
  const offset = OFFSET.exec(z)
  if (offset) return Number(offset[2]) > 14 || Number(offset[3] ?? 0) > 59 ? `the offset ${z} is not one a clock uses` : null
  if (ZONE_NAME.test(z)) {
    try {
      new Intl.DateTimeFormat('en-US', { timeZone: z })
      return null
    } catch {
      // not a zone this browser knows: said below
    }
  }
  return `the time zone ${z} is not known: give UTC, an offset such as +02:00, or a name such as Europe/Paris`
}

/** The setting the analyst chose, without what is left unset; undefined when nothing is set. */
export function dateSetting(order: string, zone: string): DateSetting | undefined {
  const out: DateSetting = {}
  if (order === 'day-first' || order === 'month-first') out.order = order
  if (zone.trim()) out.zone = zone.trim()
  return out.order || out.zone ? out : undefined
}

/** The setting in words. */
export function describeDates(s: DateSetting | undefined): string {
  const order = s?.order ? `dates ${s.order}` : 'dates in the order the file shows'
  const zone = s?.zone ? `times without a zone in ${s.zone}` : 'times without a zone as UTC'
  return `${order}, ${zone}${s?.order || s?.zone ? ', as set for the evidence' : ''}`
}

function settingOf(value: unknown): DateSetting | undefined {
  if (!value || typeof value !== 'object') return undefined
  const v = value as Record<string, unknown>
  return dateSetting(typeof v.order === 'string' ? v.order : '', typeof v.zone === 'string' ? v.zone : '')
}

// what the server counted (Stats.to_dict and m365.date_stats name them so), as m365._NOTES says it
const COUNTS: [string, (n: string, s: DateSetting) => string][] = [
  ['dateOrderGuessed', (n) => `${n} record(s) were dated month-first: no date in the file has a day above 12 to show its order`],
  ['dateOrderSet', (n, s) => `${n} record(s) were dated ${s.order ?? 'in the order set'}, the date order set for the evidence`],
  ['dateOrderContradicted', (n, s) => `${n} record(s) have a date that cannot be read ${s.order ?? 'in the order set'}, but can be read the other way`],
  ['zoneSet', (n, s) => `${n} record(s) were read in ${s.zone ?? 'the zone set'}: their times say none`],
  ['zoneAssumed', (n) => `${n} record(s) were read as UTC: their times say no time zone, and none is set for the evidence`],
]

export interface DatesRead {
  /** the setting the file was read with, in words */
  setting: string
  /** what the import counted of it, in words */
  counts: string[]
}

/**
 * How an evidence file's dates were read: the setting the server says it used (or the one the
 * evidence records) and what it counted. Null for a file with nothing to say: every time in it
 * carried its zone and every date its order, and no setting was asked for.
 */
export function datesRead(evidence: Pick<Evidence, 'stats' | 'dates'>): DatesRead | null {
  const stats = evidence.stats ?? {}
  const used = settingOf(stats.dates) ?? evidence.dates
  const counts = COUNTS.filter(([name]) => Number(stats[name] ?? 0) > 0).map(([name, text]) => text(fmtNum(Number(stats[name])), used ?? {}))
  if (!counts.length && !used) return null
  return { setting: describeDates(used), counts }
}
