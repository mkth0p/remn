import { describe, expect, it } from 'vitest'
import { dateSetting, datesRead, describeDates, zoneError } from './dateSetting'

describe('the date setting of an evidence file', () => {
  it('takes the zones the server takes and says why it would refuse another', () => {
    for (const zone of ['', 'UTC', 'z', '+02:00', '-0530', 'UTC+2', 'GMT-11', 'Europe/Paris', 'America/Argentina/Buenos_Aires']) expect(zoneError(zone)).toBeNull()
    expect(zoneError('+15:00')).toBe('the offset +15:00 is not one a clock uses')
    expect(zoneError('+02:75')).toBe('the offset +02:75 is not one a clock uses')
    expect(zoneError('Mars/Olympus_Mons')).toMatch(/^the time zone Mars\/Olympus_Mons is not known: give UTC/)
    expect(zoneError('Paris time')).toMatch(/is not known/)
  })

  it('keeps only what the analyst set', () => {
    expect(dateSetting('', '')).toBeUndefined()
    expect(dateSetting('as the file shows', '  ')).toBeUndefined()
    expect(dateSetting('day-first', '')).toEqual({ order: 'day-first' })
    expect(dateSetting('', ' Europe/Paris ')).toEqual({ zone: 'Europe/Paris' })
    expect(describeDates(undefined)).toBe('dates in the order the file shows, times without a zone as UTC')
    expect(describeDates({ order: 'day-first', zone: '+02:00' })).toBe('dates day-first, times without a zone in +02:00, as set for the evidence')
  })

  it('says how the server read the dates, from what it counted', () => {
    expect(datesRead({ stats: { count: 4 } })).toBeNull()
    const guessed = datesRead({ stats: { count: 4, dateOrderGuessed: 4, zoneAssumed: 1200 } })
    expect(guessed?.setting).toBe('dates in the order the file shows, times without a zone as UTC')
    expect(guessed?.counts).toEqual([
      '4 record(s) were dated month-first: no date in the file has a day above 12 to show its order',
      '1,200 record(s) were read as UTC: their times say no time zone, and none is set for the evidence',
    ])
    // the setting the server says it used comes first; the one the evidence asked for is shown until it answers
    const set = datesRead({ stats: { dates: { order: 'day-first', zone: 'Europe/Paris' }, dateOrderSet: 3, dateOrderContradicted: 1, zoneSet: 3 }, dates: { order: 'month-first' } })
    expect(set?.setting).toBe('dates day-first, times without a zone in Europe/Paris, as set for the evidence')
    expect(set?.counts).toEqual([
      '3 record(s) were dated day-first, the date order set for the evidence',
      '1 record(s) have a date that cannot be read day-first, but can be read the other way',
      '3 record(s) were read in Europe/Paris: their times say none',
    ])
    expect(datesRead({ dates: { zone: 'UTC' } })?.setting).toBe('dates in the order the file shows, times without a zone in UTC, as set for the evidence')
  })
})
