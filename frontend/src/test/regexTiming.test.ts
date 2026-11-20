import { readdirSync, readFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import yaml from 'js-yaml'
import ts from 'typescript'
import { describe, expect, it } from 'vitest'
import { PRIVATE_ANSWER, REMOTE_SCRIPT } from '../data/stories'
import { compileRegex } from '../rules/filter'

/**
 * Every pattern the browser code writes, and every pattern of REMN's own rule packs, answers hostile
 * text in a time that grows with its length. A pattern runs on one thread: one that backtracks over
 * a long run in a field of the evidence holds the page (or the rules worker) for seconds, and for
 * minutes past 100,000 characters.
 *
 * The test reads each regular expression the sources write (a literal, or a RegExp built from a
 * string) and each `re` pattern of the own packs. For each part of a pattern that repeats without a
 * bound, it builds runs of a few strings that part matches: alone, after the text that leads to the
 * part, or after another character, with or without a character at the end that stops the match.
 * A run that takes more than three times as long at twice the length is tried at growing lengths up
 * to 100,000 characters, where it must answer within the budget. tests/backend/test_regex_timing.py
 * does the same for the server's patterns.
 */

const SRC = join(__dirname, '..')
const RULES = join(__dirname, '../../../rules')
const SHORT = 24 // units of the first try: a pattern that backtracks without end takes long here already
const SHORT_MS = 20
const SCREEN = 4_000 // characters of the quick try
const SCREEN_MS = 2 // past this, the run is tried again at twice the length
const GROWTH = 3 // a linear pattern takes twice as long at twice the length
const SUSPECT_MS = 50 // a quick try this slow is suspect whatever its growth
const LENGTH = 100_000 // characters of the decisive try
const BUDGET_MS = 250 // time the decisive try may take
const UNIVERSE = [...Array.from({ length: 0x5f }, (_, k) => String.fromCharCode(0x20 + k)), '\t', '\n', '\r', '\x0b', '\x0c', '\0', '\xa0', '\u00e9', '\u0436', '\u200b', '\u2028']
const PREFERRED = 'a0_ .-/@%\\:=\n\t"\'<>;,&?#+(\u00e9'
const GENERIC = [' ', '.', '@', '/', '%41', 'a', '<a', '\t\n']
const TAILS = ['', '\0']

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

/**
 * Patterns of REMN's own rule packs left as they are, by rule, with why. A token, any text, then
 * another token is tried again from each occurrence of the first token: bound the text between them
 * (a gap of up to 1,000 characters on the line, the most RE2 repeats) instead of adding the rule here.
 */
const RULE_EXEMPT: Record<string, string> = {}

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

/** The `re` and `not_re` patterns of REMN's own rule packs (the converted community packs are not REMN's to change). */
function rulePatterns(dir = RULES): { rule: string; pattern: string }[] {
  const out: { rule: string; pattern: string }[] = []
  const walk = (node: unknown, rule: string): void => {
    if (Array.isArray(node)) node.forEach((x) => walk(x, rule))
    else if (node && typeof node === 'object')
      for (const [k, v] of Object.entries(node)) {
        if (/\|(not_)?re$/.test(k)) for (const p of Array.isArray(v) ? v : [v]) out.push({ rule, pattern: String(p) })
        walk(v, rule)
      }
  }
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory() && e.name !== 'community') out.push(...rulePatterns(join(dir, e.name)))
    else if (e.name.endsWith('.yaml')) for (const doc of yaml.loadAll(readFileSync(join(dir, e.name), 'utf-8'))) if (doc && typeof doc === 'object') walk(doc, String((doc as { id?: unknown }).id))
  }
  return out
}

type Part =
  | { kind: 'char'; text: string } // one character: a literal, an escape, a class or a dot
  | { kind: 'none' } // an anchor, a word boundary or a back reference
  | { kind: 'look'; alts: Part[][] }
  | { kind: 'group'; alts: Part[][] }
  | { kind: 'repeat'; body: Part; min: number; max: number }

/** A pattern's parts: enough to know what each repeated part reads and which text leads to it. */
function parse(source: string): Part[][] {
  let i = 0
  const past = (ch: string) => {
    const at = source.indexOf(ch, i)
    i = at < 0 ? source.length : at + 1
  }
  const escape = (): Part => {
    const start = i
    const e = source[i + 1] ?? ''
    i += 2
    if (e === 'b' || e === 'B' || /[1-9]/.test(e)) {
      while (/[0-9]/.test(source[i] ?? '')) i++
      return { kind: 'none' }
    }
    if (e === 'k') {
      past('>')
      return { kind: 'none' }
    }
    if (e === 'x') i += 2
    else if (e === 'c') i += 1
    else if (e === 'u') {
      if (source[i] === '{') past('}')
      else i += 4
    } else if ((e === 'p' || e === 'P') && source[i] === '{') past('}')
    return { kind: 'char', text: source.slice(start, i) }
  }
  const part = (): Part => {
    const c = source[i]
    if (c === '\\') return escape()
    if (c === '[') {
      const start = i++
      if (source[i] === '^') i++
      if (source[i] === ']') i++
      while (i < source.length && source[i] !== ']') i += source[i] === '\\' ? 2 : 1
      i++
      return { kind: 'char', text: source.slice(start, i) }
    }
    if (c === '(') {
      i++
      let look = false
      if (source[i] === '?') {
        const next = source.slice(i + 1, i + 3)
        if (next[0] === ':') i += 2
        else if (next[0] === '=' || next[0] === '!' || next === '<=' || next === '<!') {
          i += next[0] === '<' ? 3 : 2
          look = true
        } else past('>')
      }
      const alts = sequence()
      i++
      return look ? { kind: 'look', alts } : { kind: 'group', alts }
    }
    i++
    return c === '^' || c === '$' ? { kind: 'none' } : { kind: 'char', text: c }
  }
  const bounds = (): [number, number] | null => {
    const c = source[i]
    const m = /^\{(\d+)(,(\d*))?\}/.exec(source.slice(i))
    const b: [number, number] | null = c === '*' ? [0, Infinity] : c === '+' ? [1, Infinity] : c === '?' ? [0, 1] : m ? [Number(m[1]), m[2] ? (m[3] ? Number(m[3]) : Infinity) : Number(m[1])] : null
    if (!b) return null
    i += m && c === '{' ? m[0].length : 1
    if (source[i] === '?') i++
    return b
  }
  const sequence = (): Part[][] => {
    const alts: Part[][] = [[]]
    while (i < source.length && source[i] !== ')') {
      if (source[i] === '|') {
        i++
        alts.push([])
        continue
      }
      const p = part()
      const b = bounds()
      alts[alts.length - 1].push(b ? { kind: 'repeat', body: p, min: b[0], max: b[1] } : p)
    }
    return alts
  }
  return sequence()
}

const ESCAPED: Record<string, string> = { n: '\n', r: '\r', t: '\t', f: '\x0c', v: '\x0b', '0': '\0' }

/** The characters a pattern names itself: its literals, the members and range ends of its classes. */
function ownCharacters(seq: Part[], acc: Set<string>): void {
  for (const p of seq) {
    if (p.kind === 'repeat') ownCharacters([p.body], acc)
    else if (p.kind === 'group' || p.kind === 'look') p.alts.forEach((alt) => ownCharacters(alt, acc))
    else if (p.kind === 'char' && !p.text.startsWith('[^')) {
      // a negated class names what it does not take: [^\n]* says nothing of the text it reads
      const inner = p.text.startsWith('[') ? p.text.slice(1, -1) : p.text === '.' ? '' : p.text
      for (let k = 0; k < inner.length; k++) {
        if (inner[k] === '\\') {
          const e = inner[++k] ?? ''
          if (e in ESCAPED) acc.add(ESCAPED[e])
          else if (!/[0-9A-Za-z]/.test(e)) acc.add(e)
        } else if (!(inner[k] === '-' && p.text.startsWith('[') && k > 0 && k < inner.length - 1)) acc.add(inner[k])
      }
    }
  }
}

/** For each repeated part of a pattern, the text that leads to it and a few strings the part matches once. */
class Pumps {
  readonly found: [string, string[]][] = []
  private readonly order: string[]
  private readonly accepted = new Map<string, string[]>()

  constructor(
    private readonly flags: string,
    source: string,
  ) {
    const parts = parse(source)
    const own = new Set<string>()
    for (const alt of parts) ownCharacters(alt, own)
    this.order = [...new Set([...[...own].filter((c) => UNIVERSE.includes(c)), ...PREFERRED, ...UNIVERSE])]
    for (const alt of parts) this.walk(alt, '')
  }

  /** Up to four characters one position accepts, the pattern's own first. */
  chars(text: string): string[] {
    let out = this.accepted.get(text)
    if (!out) {
      let one: RegExp | null = null
      try {
        one = new RegExp(`^(?:${text})$`, this.flags.replace(/[gy]/g, ''))
      } catch {
        one = null
      }
      out = one ? this.order.filter((c) => (one as RegExp).test(c)).slice(0, 4) : []
      this.accepted.set(text, out)
    }
    return out
  }

  /** A short string the sequence matches: each repeat at its minimum, each alternation its shortest branch. */
  one(seq: Part[]): string {
    return seq
      .map((p) => {
        if (p.kind === 'char') return this.chars(p.text)[0] ?? ''
        if (p.kind === 'group') return p.alts.map((a) => this.one(a)).reduce((a, b) => (b.length < a.length ? b : a))
        if (p.kind === 'repeat') return this.one([p.body]).repeat(Math.min(p.min, 64))
        return ''
      })
      .join('')
  }

  /** A few strings the sequence matches, varying one position at a time. */
  many(seq: Part[]): string[] {
    const choices = seq.map((p) => (p.kind === 'char' ? this.chars(p.text) : p.kind === 'group' ? p.alts.map((a) => this.one(a)) : [this.one([p])]))
    const base = choices.map((c) => c[0] ?? '')
    const out = [base.join('')]
    choices.forEach((c, k) => c.slice(1).forEach((alt) => out.push([...base.slice(0, k), alt, ...base.slice(k + 1)].join(''))))
    return [...new Set(out)].filter(Boolean).slice(0, 6)
  }

  walk(seq: Part[], before: string): void {
    seq.forEach((p, k) => {
      const lead = before + this.one(seq.slice(0, k))
      if (p.kind === 'repeat') {
        const body = p.body.kind === 'group' && p.body.alts.length === 1 ? p.body.alts[0] : [p.body]
        if (p.max > 32) this.found.push([lead, this.many(body)])
        this.walk(body, lead)
      } else if (p.kind === 'group' || p.kind === 'look') p.alts.forEach((alt) => this.walk(alt, lead))
    })
  }
}

interface Shape {
  head: string
  unit: string
  tail: string
}

/** The hostile inputs of one pattern: the head, the unit repeated to the length, then the tail. */
function shapes(source: string, flags: string): Shape[] {
  const units: [string, string][] = []
  const singles: string[] = []
  for (const [lead, strings] of new Pumps(flags, source).found)
    for (const s of strings) {
      units.push(['', s])
      // the lead again and again, also with a blank after it, which a word boundary needs before the next one
      if (lead) units.push([lead, s], ['', lead + s], ['', lead + ' '])
      if (s.length === 1) singles.push(s)
    }
  const pick = [...new Set(singles)].slice(0, 3)
  pick.forEach((a, k) => pick.slice(k + 1).forEach((b) => units.push(['', a + b])))
  GENERIC.forEach((g) => units.push(['', g]))
  const out = new Map<string, Shape>()
  const add = (head: string, unit: string, tail: string) => out.set(JSON.stringify([head, unit, tail]), { head, unit, tail })
  for (const [head, unit] of units) for (const tail of TAILS) add(head, unit, tail)
  // a run after other text: "^\s+|\s+$" takes a leading run whole, and only a run that does not
  // start the text makes it try the second branch from every position of the run
  for (const [head, unit] of units) if (!head) add('\0', unit, '\0')
  return [...out.values()]
}

const text = ({ head, unit, tail }: Shape, length: number) => head + unit.repeat(Math.max(1, Math.round((length * Math.sqrt(unit.length)) / unit.length))) + tail

type Pattern = Pick<Site, 'source' | 'flags' | 'all'>

function runner(site: Pattern): (t: string) => number {
  const re = new RegExp(site.source, site.all && !site.flags.includes('g') ? site.flags + 'g' : site.flags)
  return (t: string) => {
    const t0 = performance.now()
    if (re.global) t.match(re)
    else re.exec(t)
    return performance.now() - t0
  }
}

/** The first input on which the pattern takes long already, or grows faster than the input. */
function suspect(site: Pattern): Shape | null {
  const run = runner(site)
  for (const shape of shapes(site.source, site.flags)) {
    if (run(shape.head + shape.unit.repeat(SHORT) + shape.tail) > SHORT_MS) return shape
    const quick = run(text(shape, SCREEN))
    if (quick < SCREEN_MS) continue
    if (quick > SUSPECT_MS || run(text(shape, 2 * SCREEN)) > GROWTH * quick) return shape
  }
  return null
}

/** The time a suspect input takes at growing lengths, up to the full length or past the budget. */
function decisive(site: Pattern, shape: Shape): { length: number; ms: number } {
  const run = runner(site)
  if (run(shape.head + shape.unit.repeat(SHORT) + shape.tail) > SHORT_MS) return { length: SHORT * shape.unit.length, ms: Infinity }
  for (let length = 4 * SCREEN; ; length = Math.min(2 * length, LENGTH)) {
    const ms = run(text(shape, length))
    if (ms > BUDGET_MS || length === LENGTH) return { length, ms }
  }
}

function answersInTime(site: Pattern, where: string) {
  const shape = suspect(site)
  if (!shape) return
  const { length, ms } = decisive(site, shape)
  expect(ms, `/${site.source}/${site.flags} at ${where} on ${JSON.stringify(shape)} repeated to ${length} characters`).toBeLessThan(BUDGET_MS)
}

const { sites, built } = readSites()
const rules = rulePatterns()

describe('the patterns of the browser code', () => {
  it.each([...sites.values()].filter((s) => !(s.key in EXEMPT)).map((s) => [s.where, s] as const))('%s answers hostile text in linear time', (where, site) => {
    answersInTime(site, where)
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
    // two rule patterns before they were rewritten: two runs that take the same characters, after a prefix
    ['^[a-z]:\\\\[^"]* [^"]*\\.exe', 'i'],
    ['^\\\\[^\\\\]+-[^\\\\]+-[0-9]+-std(in|out|err)$', 'i'],
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

describe("the patterns of REMN's own rule packs", () => {
  it.each(rules.filter((r) => !(r.rule in RULE_EXEMPT)).map((r) => [r.rule, r.pattern] as const))('%s: %s answers a hostile value in linear time', (rule, pattern) => {
    // as the browser engine compiles it: an inline (?i) becomes a flag, and every pattern ignores case
    const re = compileRegex(pattern, 'i')
    expect(re, rule).not.toBeNull()
    answersInTime({ source: (re as RegExp).source, flags: (re as RegExp).flags, all: false }, rule)
  })

  it('reads every own pack and names only rules it holds', () => {
    expect(rules.length).toBeGreaterThan(80)
    expect(new Set(rules.map((r) => r.rule.split('-')[0]))).toEqual(new Set(['win', 'mail', 'm365', 'collection']))
    expect(Object.keys(RULE_EXEMPT).filter((id) => !rules.some((r) => r.rule === id))).toEqual([])
  })

  it.each(Object.keys(RULE_EXEMPT))('still finds the pattern of %s slow, or it can leave the list', (id) => {
    const slow = rules
      .filter((r) => r.rule === id)
      .some((r) => {
        const re = compileRegex(r.pattern, 'i') as RegExp
        return suspect({ source: re.source, flags: re.flags, all: false }) !== null
      })
    expect(slow).toBe(true)
  })
})
