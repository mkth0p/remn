import { readdirSync, readFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import ts from 'typescript'
import { describe, expect, it } from 'vitest'
import { PRIVATE_ANSWER, REMOTE_SCRIPT } from '../data/stories'

/**
 * Every pattern the browser code writes answers hostile text in a time that grows with its length.
 * A pattern runs on the page's one thread: one that backtracks over a long run in a field of the
 * evidence holds the tab for seconds, and for minutes past 100,000 characters.
 *
 * The test reads each regular expression the sources write (a literal, or a RegExp built from a
 * string) and times it on runs of each character it names, of each literal piece of it and of a
 * few common characters: alone or after another character, with or without a character that stops
 * the match at the end. A run that takes more than three times as long at twice the length is tried
 * at growing lengths up to 100,000 characters, where it must answer within the budget.
 */

const SRC = join(__dirname, '..')
const SHORT = 24 // units of the first try: a pattern that backtracks without end takes long here already
const SHORT_MS = 20
const SCREEN = 4_000 // characters of the quick try
const SCREEN_MS = 2 // past this, the run is tried again at twice the length
const GROWTH = 3 // a linear pattern takes twice as long at twice the length
const SUSPECT_MS = 50 // a quick try this slow is suspect whatever its growth
const LENGTH = 100_000 // characters of the decisive try
const BUDGET_MS = 250 // time the decisive try may take
const HEADS = ['', '\0', 'a', '0']
const TAILS = ['', '\0']
const COMMON = [' ', 'a', '0', '.', '\\"']
const CLASSES: Record<string, string[]> = { d: ['0'], w: ['a'], s: [' ', '\n'], D: ['a'], W: [' '], S: ['a'], n: ['\n'], r: ['\r'], t: ['\t'], b: [], B: [] }

/** Patterns left as they are, with why: none of them reads text that comes from the evidence. */
const EXEMPT: Record<string, string> = {
  [String.raw`ai/evidence.ts /^([a-z]+)\s*[:#\s]\s*(\S+)$/i`]: 'a row reference the model writes in a tool call',
  [String.raw`ai/transport.ts /\/+$/`]: 'the endpoint address the analyst types in the settings',
  [String.raw`views/SettingsView.tsx /\/+$/`]: 'the endpoint address the analyst types in the settings',
  [String.raw`components/graphLayout.ts /([\d.]+)px/`]: "a font the app's own stylesheet names",
  [String.raw`data/claims.ts /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g`]: 'text the model wrote (an answer or a summary), read to check the addresses it names',
  [String.raw`data/reportDocx.ts /\[([^\]]+)\]\(([^)]+)\)/g`]: "the analyst's notes and the model's answers, written into a Word report on request",
  [String.raw`util/format.ts /("(?:\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g`]:
    'JSON after HTML escaping, which holds no double quote, so the string branch never starts',
  [String.raw`rules/filter.ts /<[^>]*>/g`]: 'applied up to the last ">" only, which regexRewrites.test.ts times end to end',
}

/** Patterns built from something other than a string literal, with how each is covered. */
const BUILT: Record<string, string> = {
  'components/FilterBar.tsx regex': "the analyst's own filter",
  'data/queryOps.ts re.source': 'a pattern its caller passes, with the global flag added',
  'data/stories.ts REMOTE_SCRIPT': 'imported and timed here',
  'data/stories.ts PRIVATE_ANSWER': 'imported and timed here',
  'parsers/evtx/py.ts `^[${WS}]+|(?<![${WS}])[${WS}]+$`': 'timed through strip() in regexRewrites.test.ts',
  'rules/filter.ts p': "a rule's own pattern (the re operator), which the rule author writes",
}

interface Site {
  key: string
  where: string
  source: string
  flags: string
  all: boolean
}

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = join(dir, e.name)
    if (e.isDirectory()) return e.name === 'test' ? [] : sourceFiles(p)
    return /\.tsx?$/.test(e.name) && !/\.test\.tsx?$/.test(e.name) ? [p] : []
  })
}

/** Each pattern of the sources once, and the expressions that build one at run time. */
function readSites(): { sites: Map<string, Site>; built: string[] } {
  const sites = new Map<string, Site>()
  const built: string[] = []
  const add = (file: string, line: number, source: string, flags: string, all: boolean) => {
    const key = `${file} /${source}/${flags}`
    const known = sites.get(key)
    if (known) known.all ||= all
    else sites.set(key, { key, where: `${file}:${line}`, source, flags, all: all || flags.includes('g') })
  }
  for (const path of sourceFiles(SRC)) {
    const file = relative(SRC, path).split('\\').join('/')
    const sf = ts.createSourceFile(path, readFileSync(path, 'utf-8'), ts.ScriptTarget.Latest, true, path.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS)
    const lineOf = (n: ts.Node) => sf.getLineAndCharacterOfPosition(n.getStart()).line + 1
    // a pattern handed to split, matchAll or replaceAll is applied to the whole text
    const scansAll = (n: ts.Node) => ts.isCallExpression(n.parent) && ts.isPropertyAccessExpression(n.parent.expression) && ['split', 'matchAll', 'replaceAll'].includes(n.parent.expression.name.text)
    const visit = (n: ts.Node): void => {
      if (ts.isRegularExpressionLiteral(n)) {
        const end = n.text.lastIndexOf('/')
        add(file, lineOf(n), n.text.slice(1, end), n.text.slice(end + 1), scansAll(n))
      } else if ((ts.isNewExpression(n) || ts.isCallExpression(n)) && n.expression.getText() === 'RegExp' && n.arguments?.length) {
        const [first, second] = n.arguments
        if (ts.isStringLiteralLike(first) && (!second || ts.isStringLiteralLike(second))) add(file, lineOf(n), first.text, second ? second.text : '', scansAll(n))
        else built.push(`${file} ${first.getText()}`)
      }
      ts.forEachChild(n, visit)
    }
    visit(sf)
  }
  add('data/stories.ts', 0, REMOTE_SCRIPT, '', false)
  add('data/stories.ts', 0, PRIVATE_ANSWER, '', false)
  return { sites, built }
}

/** The runs a pattern is tried on: each character it names, each literal piece of it, a few common ones. */
function units(source: string): string[] {
  const out = new Set(COMMON)
  for (let i = 0; i < source.length; i++) {
    if (source[i] !== '\\') {
      out.add(source[i])
      continue
    }
    const e = source[++i] ?? ''
    for (const c of CLASSES[e] ?? (/[ux0-9pPkc]/.test(e) ? [] : [e])) out.add(c)
  }
  // the literal pieces, and each with the next one ("<!--" and "-->" make a comment)
  const pieces = [...source.matchAll(/(?:\\[^dwsDWSbBnrtux0-9pPkc]|[^\\()[\]{}|*+?.^$])+/g)].map((m) => m[0].replace(/\\(.)/g, '$1')).filter((p) => p.length > 1)
  pieces.forEach((p, i) => out.add(p).add(p + (pieces[i + 1] ?? '')))
  return [...out].filter(Boolean)
}

interface Shape {
  head: string
  unit: string
  tail: string
}

const text = ({ head, unit, tail }: Shape, length: number) => head + unit.repeat(Math.max(1, Math.round((length * Math.sqrt(unit.length)) / unit.length))) + tail

function runner(site: Pick<Site, 'source' | 'flags' | 'all'>): (t: string) => number {
  const re = new RegExp(site.source, site.all && !site.flags.includes('g') ? site.flags + 'g' : site.flags)
  return (t: string) => {
    const t0 = performance.now()
    if (re.global) t.match(re)
    else re.exec(t)
    return performance.now() - t0
  }
}

/** The first run on which the pattern takes long already, or grows faster than the run. */
function suspect(site: Pick<Site, 'source' | 'flags' | 'all'>): Shape | null {
  const run = runner(site)
  for (const unit of units(site.source))
    for (const head of HEADS)
      for (const tail of TAILS) {
        const shape = { head, unit, tail }
        if (run(head + unit.repeat(SHORT) + tail) > SHORT_MS) return shape
        const quick = run(text(shape, SCREEN))
        if (quick < SCREEN_MS) continue
        if (quick > SUSPECT_MS || run(text(shape, 2 * SCREEN)) > GROWTH * quick) return shape
      }
  return null
}

/** The time a suspect run takes at growing lengths, up to the full length or past the budget. */
function decisive(site: Pick<Site, 'source' | 'flags' | 'all'>, shape: Shape): { length: number; ms: number } {
  const run = runner(site)
  if (run(shape.head + shape.unit.repeat(SHORT) + shape.tail) > SHORT_MS) return { length: SHORT * shape.unit.length, ms: Infinity }
  for (let length = 4 * SCREEN; ; length = Math.min(2 * length, LENGTH)) {
    const ms = run(text(shape, length))
    if (ms > BUDGET_MS || length === LENGTH) return { length, ms }
  }
}

const { sites, built } = readSites()
const timed = [...sites.values()].filter((s) => !(s.key in EXEMPT))

describe('the patterns of the browser code', () => {
  it.each(timed.map((s) => [s.where, s] as const))('%s answers hostile text in linear time', (_where, site) => {
    const shape = suspect(site)
    if (!shape) return
    const { length, ms } = decisive(site, shape)
    expect(ms, `/${site.source}/${site.flags} at ${site.where} on ${JSON.stringify(shape)} repeated to ${length} characters`).toBeLessThan(BUDGET_MS)
  })

  it('reads the literals of every folder and every pattern built at run time', () => {
    const where = [...sites.values()].map((s) => s.where)
    for (const dir of ['parsers/evtx/', 'rules/', 'data/', 'ai/', 'views/', 'workers/']) expect(where.some((w) => w.startsWith(dir))).toBe(true)
    expect(sites.size).toBeGreaterThan(200)
    expect(Object.keys(EXEMPT).filter((k) => !sites.has(k))).toEqual([])
    expect([...new Set(built)].sort()).toEqual(Object.keys(BUILT).sort())
  })

  it.each([
    // an evtx parser trim before it was made linear: a run of carriage returns inside a line
    ['\\r+$', ''],
    ['^[{}]+|[{}]+$', 'g'],
    // a rule's duration: three runs of blanks side by side, split every way when what follows fails
    ['^\\s*(\\d+(?:\\.\\d+)?)\\s*(ms|s|m|h|d|w)?\\s*$', 'i'],
    // a tag with no closing bracket, rescanned from every opening
    ['<[^>]*>', 'g'],
    ['\\s*,\\s*', 'g'],
    // nested repetition: exponential
    ['^(?:\\s|<!--[\\s\\S]*?-->)*<Events?[\\s>]', ''],
  ])('finds the pattern /%s/%s that backtracks', (source, flags) => {
    expect(suspect({ source, flags, all: flags.includes('g') })).not.toBeNull()
  })

  it('finds a pattern that backtracks past the budget at the full length', () => {
    const site = { source: '\\s*,\\s*', flags: 'g', all: true }
    const shape = suspect(site)
    expect(shape).not.toBeNull()
    expect(decisive(site, shape as Shape).ms).toBeGreaterThan(BUDGET_MS)
  })
})
