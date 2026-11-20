import { readdirSync, readFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { expect, it } from 'vitest'

/**
 * A button that shows only an icon or a symbol has no words for a screen reader to say. The title
 * a mouse user sees on hover is not read out everywhere, so such a button carries an aria-label.
 */

const SRC = join(__dirname, '..')
// what a button may show without words: icons and the symbols the pages use for close, more and remove
const SYMBOLS = new Set(['', '×', '✕', '✓', '…', '‹', '›', '+', '−', '-', '↑', '↓', '←', '→', '▲', '▼', '⋯'])

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const path = join(dir, e.name)
    if (e.isDirectory()) return sources(path)
    return e.name.endsWith('.tsx') && !e.name.endsWith('.test.tsx') ? [path] : []
  })
}

/** The opening tag of an element and what it holds, with braces in attribute values skipped. */
function split(element: string): [string, string] {
  let depth = 0
  for (let i = 0; i < element.length; i++) {
    const c = element[i]
    if (c === '{') depth++
    else if (c === '}') depth--
    else if (c === '>' && depth === 0) return [element.slice(0, i), element.slice(i + 1)]
  }
  return [element, '']
}

/** Whether a button, up to its closing tag, shows no words and has no label of its own. */
function bare(button: string): boolean {
  const [open, content] = split(button)
  if (/\baria-label(ledby)?=/.test(open)) return false
  return SYMBOLS.has(content.replace(/<Icon\w+(?:[^<>]|\{[^{}]*\})*\/>/g, '').replace(/\s+/g, ''))
}

function unlabelled(path: string): string[] {
  const text = readFileSync(path, 'utf-8')
  const out: string[] = []
  for (const m of text.matchAll(/<button\b/g)) {
    const end = text.indexOf('</button>', m.index)
    if (end >= 0 && bare(text.slice(m.index, end))) out.push(`${relative(SRC, path)}:${text.slice(0, m.index).split('\n').length}`)
  }
  return out
}

it('gives every button that shows only an icon or a symbol an aria-label', () => {
  expect(sources(SRC).flatMap(unlabelled)).toEqual([])
})

it('finds such a button when it has no aria-label, and leaves buttons with words alone', () => {
  expect(bare('<button className="btn icon" onClick={() => go({ a: 1 })} title="close"><IconClose />')).toBe(true)
  expect(bare('<button className="btn" onClick={x}>×')).toBe(true)
  expect(bare('<button className="btn icon" aria-label="close" onClick={x}><IconClose />')).toBe(false)
  expect(bare('<button className="btn" onClick={x}><IconAi /> analyse')).toBe(false)
})
