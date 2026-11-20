import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'
import { hostKey } from '../data/stories'
import { psPipeline } from '../parsers/evtx/flatten'
import { strip } from '../parsers/evtx/py'
import { parseDuration, parseThreshold } from '../rules/engine'
import { compileRegex, matchCondition } from '../rules/filter'

/**
 * The patterns made linear answer as they did before, and the code that applies them stays fast.
 * Each rewritten pattern is compared with the one it replaced on random text built from the pieces
 * it reads, in the way the code uses it (a replacement, or a match and its groups). All text here is
 * invented.
 */

const SRC = join(__dirname, '..')
const SAMPLES = 1500
const WS = '\\t\\n\\x0b\\x0c\\r\\x1c-\\x1f \\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000'
const BLANKS = [' ', '\t', '\n', '\u3000']

/** A small seeded generator, so a failure names a text that comes back on the next run. */
function seeded(seed: number): () => number {
  let s = seed
  return () => {
    s = (s + 0x6d2b79f5) | 0
    let t = Math.imul(s ^ (s >>> 15), 1 | s)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const soup = (next: () => number, pieces: string[], longest = 24) => Array.from({ length: Math.floor(next() * (longest + 1)) }, () => pieces[Math.floor(next() * pieces.length)]).join('')

type Answer = (re: RegExp, s: string) => unknown
const replaced: Answer = (re, s) => s.replace(re, '|')
const groups: Answer = (re, s) => {
  const m = re.exec(s)
  return m && [m.index, ...m]
}

// what it reads | file | the pattern before | the pattern now | what the code takes of it | pieces
const REWRITES: [string, string, RegExp, RegExp, Answer, string[]][] = [
  [
    'strip() of the evtx parser',
    'parsers/evtx/py.ts',
    new RegExp(`^[${WS}]+|[${WS}]+$`, 'g'),
    new RegExp(`^[${WS}]+|(?<![${WS}])[${WS}]+$`, 'g'),
    replaced,
    [...BLANKS, '\x85', '\x1c', 'a', '\u200b'],
  ],
  ['the carriage returns of a PowerShell line', 'parsers/evtx/flatten.ts', /\r+$/, /(?<!\r)\r+$/, replaced, ['\r', 'a', ' ', '\r\r']],
  ['the braces around a GUID', 'parsers/evtx/ledger.ts', /^[{}]+|[{}]+$/g, /^[{}]+|(?<![{}])[{}]+$/g, replaced, ['{', '}', 'a', '-', '0']],
  ['the backslashes around a host name', 'data/stories.ts', /^\\+|\\+$/g, /^\\+|(?<!\\)\\+$/g, replaced, ['\\', 'ws', '-', '.']],
  ['the dollar signs after a host name', 'data/stories.ts', /\$+$/, /(?<!\$)\$+$/, replaced, ['$', 'ws', '-', '.']],
  ['the underscores around a file name', 'data/storyFlow.ts', /^_+|_+$/g, /^_+|(?<!_)_+$/g, replaced, ['_', 'a', '.', '-']],
  ['the count after a step title', 'data/chainGraph.ts', /\s*×\d+$/, /(?<!\s)\s*×\d+$/, replaced, [...BLANKS, '×', '3', '12', 'a']],
  ['the blanks around a comma in a value', 'data/claims.ts', /\s*,\s*/g, /(?:(?<!\s)\s+)?,\s*/g, replaced, [...BLANKS, ',', 'a', "'"]],
  ['a rule duration', 'rules/engine.ts', /^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)?\s*$/i, /^\s*(\d+(?:\.\d+)?)\s*(?:(ms|s|m|h|d|w)\s*)?$/i, groups, [...BLANKS, '1', '10', '.', '5', 'ms', 's', 'M', 'x']],
  ['a rule threshold', 'rules/engine.ts', /^\s*(>=|<=|==|=|>|<|!=)?\s*(\d+)\s*$/, /^\s*(?:(>=|<=|==|=|>|<|!=)\s*)?(\d+)\s*$/, groups, [...BLANKS, '>=', '<', '=', '!=', '1', '23', 'x']],
  [
    'the threshold of the length operator',
    'rules/filter.ts',
    /^\s*(>=|<=|==|=|!=|>|<)?\s*(\d+)\s*$/,
    /^\s*(?:(>=|<=|==|=|!=|>|<)\s*)?(\d+)\s*$/,
    groups,
    [...BLANKS, '>=', '<', '=', '!=', '1', '23', 'x'],
  ],
]

describe('the rewritten patterns of the browser code', () => {
  it.each(REWRITES.map((r, i) => [r[0], i] as const))('%s is read as before on random text', (_name, i) => {
    const [, file, before, now, answer, pieces] = REWRITES[i]
    expect(readFileSync(join(SRC, file), 'utf-8')).toContain(file === 'parsers/evtx/py.ts' ? '(?<![${WS}])[${WS}]+$' : `/${now.source}/`)
    const next = seeded(i + 1)
    for (let n = 0; n < SAMPLES; n++) {
      const s = soup(next, pieces)
      expect(answer(now, s), JSON.stringify(s)).toEqual(answer(before, s))
    }
  })

  it('removes the tags of a name up to the last ">" as it removed them in the whole name', () => {
    const next = seeded(99)
    for (let n = 0; n < SAMPLES; n++) {
      const s = soup(next, ['<', '>', 'a', ' ', '<b>', '@'])
      const cut = s.lastIndexOf('>') + 1
      expect(s.slice(0, cut).replace(/<[^>]*>/g, ' ') + s.slice(cut), JSON.stringify(s)).toBe(s.replace(/<[^>]*>/g, ' '))
    }
    const vip = (name: string) => matchCondition({ fromName: name }, { field: 'fromName', op: 'in_setting', value: 'vip_names' }, { vip_names: ['Lefevre Marie'] })
    expect(vip('Marie Lefevre <marie.lefevre@interne.example>')).toBe(true)
    expect(vip('Marie <b>Lefevre</b>')).toBe(true)
    expect(vip('Marie Lefevre-Martin')).toBe(false)
  })

  it.each([
    ['a value of blanks inside the text, stripped', () => strip('a' + ' '.repeat(100_000) + 'a')],
    ['a PowerShell line with a run of carriage returns', () => psPipeline('CommandInvocation(Get-Item): "Get-Item"\na' + '\r'.repeat(100_000) + 'a')],
    ['a host name with a run of backslashes', () => hostKey('ws' + '\\'.repeat(100_000) + 'a')],
    ['a host name with a run of dollar signs', () => hostKey('ws' + '$'.repeat(100_000) + 'a')],
    ['a display name of 100,000 "<"', () => matchCondition({ fromName: '<'.repeat(100_000) }, { field: 'fromName', op: 'in_setting', value: 'vip_names' }, { vip_names: ['Lefevre Marie'] })],
    ['a rule duration of blanks', () => parseDuration('1' + ' '.repeat(100_000) + 'x')],
    ['a rule threshold of blanks', () => parseThreshold(' '.repeat(100_000) + 'x')],
  ])('reads %s in under a second', (_what, run) => {
    // each of these took more than six seconds with the patterns they replace
    const t0 = performance.now()
    run()
    expect(performance.now() - t0).toBeLessThan(1000)
  })
})

const RULES = join(__dirname, '../../../rules')

// rule | file | field | the pattern before | what a value starts with | pieces
const RULE_REWRITES: [string, string, string, string, string, string[]][] = [
  [
    'collection-service-unquoted-path',
    'collection/host-artifacts.yaml',
    'serviceFile|re',
    String.raw`(?i)^[a-z]:\\[^"]* [^"]*\.exe`,
    'C:\\',
    ['C:\\', 'a:\\', '\\', ' ', '"', 'a', 'Program Files', '.exe', '.EXE', 'x', '\n'],
  ],
  [
    'win-psexec-renamed-service-pipe',
    'windows/image-load.yaml',
    'pipeName|re',
    String.raw`^\\[^\\]+-[^\\]+-[0-9]+-std(in|out|err)$`,
    '\\',
    ['-', 'a', 'svc', '1', '23', '\\', '-1-stdin', '-12-stdout', '-stderr', '--3-stdin', 'x'],
  ],
]

function rulePattern(file: string, rule: string, field: string): string {
  const docs = yaml.loadAll(readFileSync(join(RULES, file), 'utf-8')) as { id?: string; where?: Record<string, string> }[]
  return docs.find((d) => d?.id === rule)?.where?.[field] ?? ''
}

describe("the rewritten patterns of REMN's own rule packs", () => {
  it.each(RULE_REWRITES.map((r, i) => [r[0], i] as const))('%s matches the values it matched before in the browser', (_rule, i) => {
    const [rule, file, field, before, head, pieces] = RULE_REWRITES[i]
    const now = rulePattern(file, rule, field)
    expect(now).not.toBe(before)
    // as the browser engine runs them; the store's RE2 is compared in tests/backend/test_regex_rewrites.py
    const [old, rewritten] = [compileRegex(before, 'i') as RegExp, compileRegex(now, 'i') as RegExp]
    const next = seeded(i + 50)
    let matched = 0
    for (let n = 0; n < SAMPLES; n++) {
      const s = head + soup(next, pieces, 12)
      expect(rewritten.test(s), JSON.stringify(s)).toBe(old.test(s))
      if (old.test(s)) matched++
    }
    expect(matched).toBeGreaterThan(50)
  })

  it.each([
    ['collection-service-unquoted-path', 'a service path of 50,000 words', 'C:\\' + 'a '.repeat(50_000)],
    ['win-psexec-renamed-service-pipe', 'a pipe name of 100,000 dashes', '\\' + '-'.repeat(100_000)],
  ])('%s reads %s in under a second', (rule, _what, value) => {
    const [, file, field] = RULE_REWRITES.find((r) => r[0] === rule) as (typeof RULE_REWRITES)[number]
    const re = compileRegex(rulePattern(file, rule, field), 'i') as RegExp
    // the patterns they replace took from four to nine seconds on these values
    const t0 = performance.now()
    re.test(value)
    expect(performance.now() - t0).toBeLessThan(1000)
  })
})
