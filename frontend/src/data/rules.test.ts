import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Meta, PackInfo } from '../api/client'
import { defaultSettings, RemnDB, setDb, type Case } from '../db/schema'
import type { Rule } from '../rules/engine'
import { useStore } from '../state/store'
import type { DataSource } from './source'

const packs = vi.hoisted(() => ({ enabledPackIds: vi.fn(), getPackRules: vi.fn() }))
vi.mock('./packs', () => packs)
const stored = vi.hoisted(() => ({ replaceFindings: vi.fn(), refoldWidespread: vi.fn() }))
vi.mock('./findingReviews', () => stored)
const source = vi.hoisted(() => ({ getSource: vi.fn() }))
vi.mock('./source', () => source)
const duplicates = vi.hoisted(() => ({ reconcileEngineDuplicates: vi.fn() }))
vi.mock('./engineDuplicates', () => duplicates)

import { dryRunRule, loadRules, parseRuleYaml, rulesAtLevel, runRules, runRulesFor, serverRowLoader, settingsForRules, type LoadedRule } from './rules'

const rule = (id: string, extra: Partial<Rule> = {}): Rule => ({ id, title: `Rule ${id}`, severity: 'high', source: 'events', where: { eventId: 4625 }, ...extra })
const browserCase: Case = { id: 1, name: 'Lab', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
const serverCase: Case = { ...browserCase, id: 2, storage: 'server', serverKey: 'k-1' }
const pack = (id: string): PackInfo => ({
  id,
  name: id,
  description: '',
  source: 'events',
  defaultEnabled: true,
  license: { name: 'MIT' },
  upstream: { repo: 'example/rules', ref: 'main', sha: '0', url: 'https://example.test/rules', fetched: '2026-01-01' },
  counts: { upstream: 1, converted: 1, skipped: 0 },
})

function setMeta(rules: Meta['rules'], withPacks: PackInfo[] = []) {
  useStore.setState({ meta: { rules, packs: withPacks } as unknown as Meta })
}

let db: RemnDB
beforeEach(() => {
  db = new RemnDB(`rules-${Math.random()}`)
  setDb(db)
  useStore.setState({ meta: null, toasts: [], console: [] })
  packs.enabledPackIds.mockResolvedValue(new Set())
  packs.getPackRules.mockReset()
  stored.replaceFindings.mockReset()
  stored.refoldWidespread.mockReset().mockResolvedValue(0)
  source.getSource.mockReset()
})
afterEach(async () => {
  vi.unstubAllGlobals()
  db.close()
  await db.delete()
})

describe('parseRuleYaml', () => {
  it('reads each document of a file, skips empty ones and reports the invalid ones', () => {
    const text = ['id: a', 'title: A', 'severity: high', 'source: events', 'where: { eventId: 1 }', '---', 'plain text', '---', 'id: b', 'title: B', 'severity: loud', 'source: events'].join('\n')
    const { rules, errors } = parseRuleYaml(text)
    expect(rules.map((r) => r.id)).toEqual(['a'])
    expect(errors).toEqual([expect.stringMatching(/^b: severity must be one of/)])
  })

  it('gives the parser message for text that is not YAML', () => {
    const { rules, errors } = parseRuleYaml('id: [unclosed')
    expect(rules).toEqual([])
    expect(errors).toHaveLength(1)
  })
})

describe('loadRules', () => {
  it('loads the bundled rules, keeps the broken ones disabled with their error, and honours the disabled list', async () => {
    setMeta([
      { file: 'a.yml', yaml: 'a', rule: rule('a') as unknown as Record<string, unknown>, measured: { attacks: 1 } as never },
      { file: 'b.yml', yaml: 'b', rule: rule('b') as unknown as Record<string, unknown> },
      { file: 'c.yml', yaml: 'c', error: 'could not parse' },
      { file: 'd.yml', yaml: 'd', rule: { id: 'd', title: 'D', severity: 'high', source: 'files' } },
    ])
    await db.kv.put({ key: 'disabledRules', value: ['b'] })
    const out = await loadRules(1)
    expect(out.map((r) => [r.rule.id, r.origin, r.enabled, r.error ?? null])).toEqual([
      ['a', 'bundled', true, null],
      ['b', 'bundled', false, null],
      ['c.yml', 'bundled', false, 'could not parse'],
      ['d.yml', 'bundled', false, 'd: source must be events or mails'],
    ])
    expect(out[0].measured).toEqual({ attacks: 1 })
  })

  it('lets a custom rule replace the bundled rule of the same id, for every case or for its own', async () => {
    setMeta([{ file: 'a.yml', yaml: 'a', rule: rule('a') as unknown as Record<string, unknown> }])
    const yamlOf = (id: string, title: string) => `id: ${id}\ntitle: ${title}\nseverity: low\nsource: events\nwhere: { eventId: 2 }\n`
    await db.customRules.bulkAdd([
      { caseId: null, ruleId: 'a', yaml: yamlOf('a', 'Mine'), enabled: true, updatedAt: 1 },
      { caseId: 1, ruleId: 'x', yaml: yamlOf('x', 'This case'), enabled: false, updatedAt: 1 },
      { caseId: 9, ruleId: 'y', yaml: yamlOf('y', 'Another case'), enabled: true, updatedAt: 1 },
      { caseId: 1, ruleId: 'z', yaml: 'id: [', enabled: true, updatedAt: 1 },
    ])
    const out = await loadRules(1)
    expect(out.map((r) => [r.rule.id, r.rule.title, r.origin, r.enabled])).toEqual([
      ['a', 'Mine', 'custom', true],
      ['x', 'This case', 'custom', false],
      ['z', 'z', 'custom', false],
    ])
    expect(out[2].error).toBeTruthy()
  })

  it('loads the rules of the enabled packs only, and keeps a broken pack rule disabled', async () => {
    setMeta([], [pack('on'), pack('off')])
    packs.enabledPackIds.mockResolvedValue(new Set(['on']))
    packs.getPackRules.mockResolvedValue({
      pack: pack('on'),
      rules: [
        { file: 'p1.yml', rule: rule('p1') as unknown as Record<string, unknown> },
        { file: 'p2.yml', error: 'unsupported modifier' },
        { file: 'p3.yml' },
        { file: 'p4.yml', rule: { id: 'p4' } },
      ],
    })
    const out = await loadRules(1)
    expect(packs.getPackRules).toHaveBeenCalledTimes(1)
    expect(packs.getPackRules).toHaveBeenCalledWith('on')
    expect(out.map((r) => [r.rule.id, r.origin, r.pack, r.enabled, r.error ?? null])).toEqual([
      ['p1', 'pack', 'on', true, null],
      ['p2.yml', 'pack', 'on', false, 'unsupported modifier'],
      ['p3.yml', 'pack', 'on', false, 'empty rule'],
      ['p4.yml', 'pack', 'on', false, 'p4: missing title'],
    ])
  })

  it('goes on without a pack that cannot be fetched, unless asked to be strict', async () => {
    setMeta([], [pack('on')])
    packs.enabledPackIds.mockResolvedValue(new Set(['on']))
    packs.getPackRules.mockRejectedValue(new Error('offline'))
    expect(await loadRules(1)).toEqual([])
    expect(useStore.getState().console.at(-1)).toMatchObject({ level: 'err', text: 'rule pack on: offline' })
    await expect(loadRules(1, true)).rejects.toThrow('Could not load enabled rule pack on: offline')
  })

  it('refuses to run strictly without the rule metadata or with a broken rule', async () => {
    await expect(loadRules(1, true)).rejects.toThrow(/Rule metadata is unavailable/)
    expect(await loadRules(1)).toEqual([])
    setMeta([{ file: 'c.yml', yaml: 'c', error: 'could not parse' }])
    await expect(loadRules(1, true)).rejects.toThrow(/Some rules could not be loaded/)
  })
})

describe('rulesAtLevel and settingsForRules', () => {
  it('runs the enabled rules without errors and gives each a severity floor', () => {
    const loaded: LoadedRule[] = [
      { rule: rule('a'), yaml: '', file: 'a', origin: 'bundled', enabled: true },
      { rule: rule('b'), yaml: '', file: 'b', origin: 'bundled', enabled: false },
      { rule: rule('c'), yaml: '', file: 'c', origin: 'bundled', enabled: true, error: 'broken' },
    ]
    const { run, floors } = rulesAtLevel(browserCase, loaded)
    expect(run.map((r) => r.id)).toEqual(['a'])
    expect(Object.keys(floors)).toEqual(['a'])
  })

  it('hands the rules the case settings under their own names, with countries in upper case', () => {
    const kase: Case = {
      ...browserCase,
      settings: { ...defaultSettings(), internalDomains: ['example.test'], expectedCountries: [' be ', '', 'nl'], vipNames: ['Board Member A'], trustedSenders: undefined as unknown as string[] },
    }
    expect(settingsForRules(kase)).toMatchObject({ internal_domains: ['example.test'], expected_countries: ['BE', 'NL'], vip_names: ['Board Member A'], trusted_senders: [], weekendDays: [0, 6] })
    expect(settingsForRules({ ...kase, settings: { ...kase.settings, expectedCountries: undefined } }).expected_countries).toEqual([])
  })
})

describe('serverRowLoader', () => {
  it('reads rows by id from the events or mails of a server case, and nothing when the server fails', async () => {
    const searchEvents = vi.fn().mockResolvedValue({ rows: [{ id: 3, eventId: 1 }] })
    const searchMails = vi.fn().mockResolvedValue({ rows: [{ id: '4', subject: 's' }] })
    const load = serverRowLoader({ searchEvents, searchMails } as unknown as DataSource)
    expect([...(await load('events', [3])).entries()]).toEqual([[3, { id: 3, eventId: 1 }]])
    expect(searchEvents).toHaveBeenCalledWith({ conditions: [{ field: 'id', op: 'in', value: [3] }] }, 1)
    expect([...(await load('mails', [4])).keys()]).toEqual([4])
    searchEvents.mockRejectedValue(new Error('down'))
    expect((await load('events', [3])).size).toBe(0)
  })
})

/** A rules worker that records what it was sent and answers as the test says. */
class FakeWorker {
  static all: FakeWorker[] = []
  sent: unknown[] = []
  terminated = false
  onmessage: ((ev: { data: Record<string, unknown> }) => void) | null = null
  onerror: ((ev: { message: string }) => void) | null = null
  constructor() {
    FakeWorker.all.push(this)
  }
  postMessage(m: unknown) {
    this.sent.push(m)
  }
  terminate() {
    this.terminated = true
  }
  say(data: Record<string, unknown>) {
    this.onmessage?.({ data })
  }
}
const lastWorker = () => FakeWorker.all[FakeWorker.all.length - 1]

describe('runRules', () => {
  beforeEach(() => {
    FakeWorker.all = []
    vi.stubGlobal('Worker', FakeWorker)
  })

  it('sends the rules and the case settings, reports progress and errors, and resolves when the worker is done', async () => {
    const progress = vi.fn()
    const before = useStore.getState().rulesVersion
    const run = runRules(browserCase, [rule('a'), rule('b')], progress, { a: 2 })
    const w = lastWorker()
    expect(w.sent[0]).toMatchObject({ cmd: 'run', caseId: 1, rules: [{ id: 'a' }, { id: 'b' }], floors: { a: 2 }, settings: { weekendDays: [0, 6] } })
    w.say({ type: 'progress', index: 1, total: 2, ruleId: 'a', findings: 3, rows: 10, ms: 5 })
    w.say({ type: 'rule-error', index: 2, total: 2, ruleId: 'b', error: 'bad regex' })
    w.say({ type: 'done', total: 3, byRule: { a: 3 }, diagnostics: [{ ruleId: 'b', reason: 'no_selector_match', matched: 0, afterExclude: 0, afterTime: 0 }] })
    expect(await run).toEqual({ total: 3, byRule: { a: 3 }, errors: ['b: bad regex'], diagnostics: [{ ruleId: 'b', reason: 'no_selector_match', matched: 0, afterExclude: 0, afterTime: 0 }] })
    expect(progress.mock.calls).toEqual([
      [1, 2, 'a', 3],
      [2, 2, 'b', 0],
    ])
    expect(w.terminated).toBe(true)
    expect(useStore.getState().rulesVersion).toBe(before + 1)
    expect(useStore.getState().toasts.at(-1)).toMatchObject({ kind: 'ok', text: '3 finding(s) from 2 rule(s)' })
  })

  it('resolves with the error when the engine fails or the worker crashes', async () => {
    const failed = runRules(browserCase, [rule('a')])
    lastWorker().say({ type: 'error', error: 'out of memory' })
    expect(await failed).toEqual({ total: 0, byRule: {}, errors: ['out of memory'], diagnostics: [] })
    expect(useStore.getState().toasts.at(-1)).toMatchObject({ kind: 'err', text: 'rule engine error: out of memory' })
    const crashed = runRules(browserCase, [rule('a')])
    lastWorker().onerror?.({ message: 'script error' })
    expect(await crashed).toEqual({ total: 0, byRule: {}, errors: ['script error'], diagnostics: [] })
    expect(lastWorker().terminated).toBe(true)
  })
})

describe('runRulesFor', () => {
  beforeEach(() => {
    FakeWorker.all = []
    vi.stubGlobal('Worker', FakeWorker)
  })

  it('runs a browser case in the worker, refolds widespread rules and keeps the diagnostics with warnings', async () => {
    stored.refoldWidespread.mockResolvedValue(2)
    const run = runRulesFor(browserCase, [rule('a')], undefined, { a: 1 })
    lastWorker().say({
      type: 'done',
      total: 1,
      byRule: { a: 1 },
      diagnostics: [
        { ruleId: 'a', reason: 'truncated', detail: 'kept 10,000', matched: 1, afterExclude: 1, afterTime: 1, dropped: 2_345 },
        { ruleId: 'b', reason: 'missing_setting', detail: 'internal domains', matched: 0, afterExclude: 0, afterTime: 0 },
        { ruleId: 'c', reason: 'not_applicable', matched: 0, afterExclude: 0, afterTime: 0 },
      ],
    })
    const res = await run
    expect(res.total).toBe(1)
    expect(stored.refoldWidespread).toHaveBeenCalledWith(1, { a: 1 })
    // Hayabusa's findings of the same Sigma rules and records join the run's, once it has refolded
    expect(duplicates.reconcileEngineDuplicates).toHaveBeenCalledWith(1)
    expect(duplicates.reconcileEngineDuplicates.mock.invocationCallOrder[0]).toBeGreaterThan(stored.refoldWidespread.mock.invocationCallOrder[0])
    const saved = (await db.kv.get('ruleDiags-1'))?.value as { byRule: Record<string, number>; diagnostics: unknown[] }
    expect(saved.byRule).toEqual({ a: 1 })
    expect(saved.diagnostics).toHaveLength(3)
    const texts = useStore.getState().toasts.map((t) => t.text)
    expect(texts).toContain('2,345 finding(s) left out: 1 rule(s) found more than a run keeps. See the Rules view.')
    expect(texts.some((t) => t.startsWith('1 finding(s) · 1 rule(s) not applicable to this evidence · 0 rule(s) had no matching events · 1 need Settings (internal domains, VIPs…)'))).toBe(true)
    const lines = useStore.getState().console.map((l) => l.text)
    expect(lines).toContain("2 finding(s) of rules that fire on most of the case's hosts were folded")
    expect(lines.some((l) => l.startsWith('b: disarmed') && l.endsWith('internal domains'))).toBe(true)
    expect(lines).toContain('a: kept 10,000')
  })

  it('runs a server case on the server and keeps only the findings of the rules that completed', async () => {
    const runOnServer = vi.fn().mockResolvedValue({
      findings: [
        { ruleId: 'a', key: 'k1' },
        { ruleId: 'b', key: 'k2' },
      ],
      byRule: { a: 1, b: 1 },
      errors: ['b: timed out'],
    })
    source.getSource.mockReturnValue({ runRules: runOnServer, searchEvents: vi.fn(), searchMails: vi.fn() })
    stored.replaceFindings.mockResolvedValue(1)
    const res = await runRulesFor(serverCase, [rule('a'), rule('b')])
    expect(FakeWorker.all).toHaveLength(0)
    expect(stored.replaceFindings).toHaveBeenCalledWith(2, ['a'], [{ ruleId: 'a', key: 'k1' }], expect.any(Function), undefined)
    expect(res).toEqual({ total: 1, byRule: { a: 1, b: 1 }, errors: ['b: timed out'], diagnostics: [] })
    expect(useStore.getState().toasts.map((t) => t.text)).toContain('1 finding(s) from 2 rule(s)')
  })

  it('counts the findings the cut rules left out, not the rules, and says when a count is missing', async () => {
    const cut = (ruleId: string, dropped?: number) => ({ ruleId, reason: 'truncated', detail: 'kept 2,000', matched: 2000, afterExclude: 2000, afterTime: 2000, dropped })
    const run = runRulesFor(browserCase, [rule('a'), rule('b')])
    lastWorker().say({ type: 'done', total: 4000, byRule: { a: 2000, b: 2000 }, diagnostics: [cut('a', 12_000), cut('b', 1)] })
    await run
    expect(useStore.getState().toasts.map((t) => t.text)).toContain('12,001 finding(s) left out: 2 rule(s) found more than a run keeps. See the Rules view.')
    useStore.setState({ toasts: [] })
    // a server from before the count was sent says only that the rule was cut
    const older = runRulesFor(browserCase, [rule('a'), rule('b')])
    lastWorker().say({ type: 'done', total: 4000, byRule: { a: 2000, b: 2000 }, diagnostics: [cut('a', 500), cut('b')] })
    await older
    expect(useStore.getState().toasts.map((t) => t.text)).toContain('At least 500 finding(s) left out: 2 rule(s) found more than a run keeps. See the Rules view.')
  })
})

describe('dryRunRule', () => {
  beforeEach(() => {
    FakeWorker.all = []
    vi.stubGlobal('Worker', FakeWorker)
  })

  it('runs one rule in the worker without storing, and gives its count, errors and sample', async () => {
    const run = dryRunRule(browserCase, rule('a'))
    const w = lastWorker()
    expect(w.sent[0]).toMatchObject({ cmd: 'run', dryRun: true, rules: [{ id: 'a' }] })
    w.say({ type: 'rule-error', error: 'slow regex' })
    w.say({ type: 'done', total: 4, findings: [{ ruleId: 'a', key: 'k' }] })
    expect(await run).toEqual({ findings: 4, errors: ['slow regex'], diagnostics: [], sample: [{ ruleId: 'a', key: 'k' }] })
    expect(w.terminated).toBe(true)
  })

  it('gives the error when the engine fails or the worker crashes', async () => {
    const failed = dryRunRule(browserCase, rule('a'))
    lastWorker().say({ type: 'error', error: 'broken' })
    expect(await failed).toEqual({ findings: 0, errors: ['broken'], diagnostics: [], sample: [] })
    const crashed = dryRunRule(browserCase, rule('a'))
    lastWorker().onerror?.({ message: 'script error' })
    expect(await crashed).toEqual({ findings: 0, errors: ['script error'], diagnostics: [], sample: [] })
  })

  it('stops the worker when the caller gives up', async () => {
    const ac = new AbortController()
    const run = dryRunRule(browserCase, rule('a'), ac.signal)
    ac.abort()
    await expect(run).rejects.toMatchObject({ name: 'AbortError' })
    expect(lastWorker().terminated).toBe(true)
  })

  it('runs a server case through its rule job and samples fifty findings in the worker shape', async () => {
    const findings = Array.from({ length: 60 }, (_, i) => ({
      ruleId: 'a',
      title: 'T',
      severity: 'high',
      key: `k${i}`,
      ts: i === 0 ? 'x' : i,
      count: 2,
      refs: Array.from({ length: 12 }, (_, j) => j),
      entities: { host: 'WS-01' },
    }))
    findings[1] = { key: 'k1' } as never
    source.getSource.mockReturnValue({ runRules: vi.fn().mockResolvedValue({ findings, byRule: {}, errors: [] }) })
    const res = await dryRunRule(serverCase, rule('a'))
    expect(res.findings).toBe(60)
    expect(res.sample).toHaveLength(50)
    expect(res.sample[0]).toEqual({ ruleId: 'a', title: 'T', severity: 'high', key: 'k0', ts: null, count: 2, refs: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], entities: { host: 'WS-01' } })
    expect(res.sample[1]).toEqual({ ruleId: 'a', title: '', severity: '', key: 'k1', ts: null, count: 0, refs: [], entities: {} })
    expect(FakeWorker.all).toHaveLength(0)
  })
})
