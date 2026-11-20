// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { fmtTs, fmtUtc, highlightJson, setLocalTime, tzLabel } from './format'

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

describe('highlighted JSON', () => {
  it('marks keys, strings, numbers, booleans and null', () => {
    const html = highlightJson({ user: 'carla', eventId: 4625, elevated: true, parent: null })
    expect(html).toContain('<span class="k">&quot;user&quot;:</span> <span class="s">&quot;carla&quot;</span>')
    expect(html).toContain('<span class="k">&quot;eventId&quot;:</span> <span class="n">4625</span>')
    expect(html).toContain('<span class="b">true</span>')
    expect(html).toContain('<span class="z">null</span>')
  })

  it('leaves the digits and words inside a string alone', () => {
    const html = highlightJson({ account: 'admin1', note: "it's null or true" })
    expect(html).toContain('<span class="s">&quot;admin1&quot;</span>')
    expect(html).toContain('<span class="s">&quot;it&#39;s null or true&quot;</span>')
    expect(html).not.toContain('class="n"')
    expect(html).not.toContain('class="z"')
  })

  it('escapes every value, so markup in a record stays text', () => {
    // an invented record carrying markup in a key and a value
    const html = highlightJson({ '<b>k</b>': '<img src=x onerror="alert(1)">', '&amp;': '"quoted"' })
    const pre = document.createElement('pre')
    pre.innerHTML = html
    expect(pre.querySelector('img, b')).toBeNull()
    expect(pre.textContent).toBe(JSON.stringify({ '<b>k</b>': '<img src=x onerror="alert(1)">', '&amp;': '"quoted"' }, null, 2))
    expect([...pre.querySelectorAll('span')].map((s) => s.className)).toEqual(['k', 's', 'k', 's'])
  })
  it('reads a string never closed once, and shows the rest as text', () => {
    // invented text, not JSON: escaped quotes with no closing one, which a pattern would read again from each quote
    const hostile = '"' + '\\"'.repeat(16_000)
    const started = performance.now()
    const html = highlightJson(hostile)
    expect(performance.now() - started).toBeLessThan(100)
    const pre = document.createElement('pre')
    pre.innerHTML = html
    expect(pre.textContent).toBe(hostile)
    expect(highlightJson('{"a": 1, "b": "open')).toBe('{<span class="k">&quot;a&quot;:</span> <span class="n">1</span>, <span class="k">&quot;b&quot;:</span> &quot;open')
  })
})
