import { afterEach, describe, expect, it, vi } from 'vitest'
import { fmtTs, fmtUtc, setLocalTime, tzLabel } from './format'

// 2026-03-04 09:15:00.250 UTC, an invented moment
const at = Date.UTC(2026, 2, 4, 9, 15, 0, 250)

/** The browser's zone, as its offset from UTC in minutes the way getTimezoneOffset gives it (east is negative). */
function zone(getTimezoneOffset: number) {
  vi.spyOn(Date.prototype, 'getTimezoneOffset').mockReturnValue(getTimezoneOffset)
}

afterEach(() => {
  setLocalTime(false)
  vi.restoreAllMocks()
})

describe('times on screen', () => {
  it('end in Z when they are UTC', () => {
    zone(-60)
    expect(fmtTs(at)).toBe('2026-03-04 09:15:00Z')
    expect(tzLabel()).toBe('UTC')
  })

  it('name their offset from UTC when they are local, so a copied time keeps its zone', () => {
    setLocalTime(true)
    zone(-60)
    expect(fmtTs(at)).toBe('2026-03-04 10:15:00+01:00')
    expect(fmtTs(at, { ms: true })).toBe('2026-03-04 10:15:00.250+01:00')
    zone(300)
    expect(fmtTs(at)).toBe('2026-03-04 04:15:00-05:00')
    zone(-330)
    expect(fmtTs(at)).toBe('2026-03-04 14:45:00+05:30')
    zone(0)
    expect(fmtTs(at)).toBe('2026-03-04 09:15:00+00:00')
    expect(tzLabel()).toBe('local')
  })

  it('take the local date when local time moves them past midnight', () => {
    setLocalTime(true)
    zone(-120)
    expect(fmtTs(Date.UTC(2026, 2, 4, 23, 30))).toBe('2026-03-05 01:30:00+02:00')
    expect(fmtTs(Date.UTC(2026, 2, 4, 23, 30), { date: true })).toBe('2026-03-05')
  })

  it('stay UTC in what is printed or handed over, whatever the display setting', () => {
    setLocalTime(true)
    zone(-60)
    expect(fmtUtc(at)).toBe('2026-03-04 09:15:00Z')
  })
})
