import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

/**
 * The contrast of the theme's text colours, computed from theme.css as WCAG 2.1 defines it: every
 * colour text is written in must read at 4.5:1 or more on every surface of its theme (AA for text
 * of normal size), a severity's colour on its own tinted badge too, and the accent's text on the
 * accent.
 */
const CSS = readFileSync(new URL('./theme.css', import.meta.url), 'utf-8')

/** The custom properties of the first block that opens with `selector`. */
function tokens(selector: string): Record<string, string> {
  const start = CSS.indexOf(`${selector} {`)
  const body = CSS.slice(start, CSS.indexOf('}', start))
  return Object.fromEntries([...body.matchAll(/--([\w-]+):\s*([^;]+);/g)].map((m) => [m[1], m[2].trim()]))
}
const LIGHT = tokens(':root')
const DARK = { ...LIGHT, ...tokens("[data-theme='dark']") }

type Rgb = [number, number, number]
function parse(colour: string): { rgb: Rgb; alpha: number } {
  const hex = /^#([0-9a-f]{6})$/i.exec(colour)
  if (hex) return { rgb: [0, 2, 4].map((i) => parseInt(hex[1].slice(i, i + 2), 16)) as Rgb, alpha: 1 }
  const rgba = /^rgba\(([\d.]+),\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)\)$/.exec(colour)
  if (rgba) return { rgb: [Number(rgba[1]), Number(rgba[2]), Number(rgba[3])], alpha: Number(rgba[4]) }
  throw new Error(`not a colour this test reads: ${colour}`)
}
const over = (top: { rgb: Rgb; alpha: number }, under: Rgb): Rgb => top.rgb.map((c, i) => c * top.alpha + under[i] * (1 - top.alpha)) as Rgb
function luminance([r, g, b]: Rgb): number {
  const lin = (c: number) => (c / 255 <= 0.03928 ? c / 255 / 12.92 : ((c / 255 + 0.055) / 1.055) ** 2.4)
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
}
function contrast(a: Rgb, b: Rgb): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (hi + 0.05) / (lo + 0.05)
}

const TEXT = ['fg', 'fg-1', 'fg-2', 'fg-3', 'accent', 'accent-2', 'ok', 'warn', 'danger', 'violet', 'sev-critical', 'sev-high', 'sev-medium', 'sev-low', 'sev-info']
const SURFACES = ['bg', 'surface', 'surface-2', 'surface-3']
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const AA = 4.5

/** Every pair of the theme below AA, as "text on surface: ratio". */
function failing(theme: Record<string, string>): string[] {
  const out: string[] = []
  const check = (what: string, fg: Rgb, bg: Rgb) => {
    const r = contrast(fg, bg)
    if (r < AA) out.push(`${what}: ${r.toFixed(2)}`)
  }
  for (const t of TEXT) for (const s of SURFACES) check(`--${t} on --${s}`, parse(theme[t]).rgb, parse(theme[s]).rgb)
  for (const sev of SEVERITIES) {
    const badge = over(parse(theme[`sev-${sev}-bg`]), parse(theme.surface).rgb)
    check(`--sev-${sev} on its badge`, parse(theme[`sev-${sev}`]).rgb, badge)
  }
  check('--accent-fg on --accent', parse(theme['accent-fg']).rgb, parse(theme.accent).rgb)
  return out
}

describe('the theme colours', () => {
  it('compute contrast as WCAG does', () => {
    expect(contrast([0, 0, 0], [255, 255, 255])).toBeCloseTo(21, 5)
    expect(contrast([255, 255, 255], [255, 255, 255])).toBe(1)
    // the muted grey the light theme had: 3.04 on white
    expect(contrast(parse('#8a95a3').rgb, [255, 255, 255])).toBeCloseTo(3.04, 2)
  })

  it('read at 4.5:1 or more on every surface of the light theme', () => {
    expect(failing(LIGHT)).toEqual([])
  })

  it('read at 4.5:1 or more on every surface of the dark theme', () => {
    expect(failing(DARK)).toEqual([])
  })
})
