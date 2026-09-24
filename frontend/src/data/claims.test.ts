import { readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import { gunzipSync } from 'node:zlib'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'
import type { Evidence, Finding } from '../db/schema'
import { ruleEventIds, validateRule, type Rule } from '../rules/engine'
import { checkFinding, checkText, checkTextInCase, namedValues, readRows } from './claims'
import { recordRef } from './recordKeys'
import { settingsForRules } from './rules'
import type { DataSource } from './source'

type Row = Record<string, unknown>

const T0 = Date.UTC(2026, 8, 8, 10, 0, 0)
const ev = { id: 3, caseId: 1, name: 'dc01-logs.zip', size: 1, kind: 'evtx', integrity: 'verified', addedAt: 0, status: 'done', count: 3, sha256Client: 'ab'.repeat(32) } as Evidence
const evidence = new Map([[3, ev]])

const logon = (id: number, over: Row = {}): Row => ({
  id,
  caseId: 1,
  evidenceId: 3,
  sourceFile: 'Security.evtx',
  recordId: 4200 + id,
  ts: T0 + id * 60_000,
  eventId: 4625,
  channel: 'Security',
  computer: 'DC01',
  targetUser: 'alice',
  ipAddress: '203.0.113.7',
  ...over,
})

const RULE: Rule = {
  id: 'win-failed-logons',
  title: 'Failed logons',
  severity: 'medium',
  source: 'events',
  where: { eventId: 4625 },
  group_by: ['ipAddress'],
  threshold: '>= 2',
  distinct: 'targetUser',
}

const finding = (over: Partial<Finding> = {}): Finding => ({
  id: 1,
  caseId: 1,
  ruleId: RULE.id,
  key: 'k',
  title: RULE.title,
  severity: 'medium',
  source: 'events',
  ts: T0 + 60_000,
  tsEnd: T0 + 180_000,
  entities: { ipAddress: '203.0.113.7', targetUser: 'alice, bob' },
  count: 3,
  refs: [1, 2, 3],
  attack: [],
  status: 'new',
  createdAt: 0,
  ...over,
})

const rowsOf = (...rows: Row[]) => new Map(rows.map((r) => [r.id as number, r]))
const good = () => rowsOf(logon(1), logon(2, { targetUser: 'bob' }), logon(3))

describe('a finding checked against the rows it cites', () => {
  it('is verified when its rows are there, match its rule and hold what it names', () => {
    const c = checkFinding({ finding: finding(), rows: good(), rule: RULE, evidence })
    expect(c).toMatchObject({ status: 'verified', cited: 3, checked: 3, reasons: [] })
    expect(c.records[0]).toMatchObject({ file: 'dc01-logs.zip › Security.evtx', record: 'record 4,201 (Security on DC01)', duplicateKey: 'dc01|security|4201' })
  })

  it('is unsupported when a row it cites is no longer in the case', () => {
    const rows = good()
    rows.delete(2)
    const c = checkFinding({ finding: finding(), rows, rule: RULE, evidence })
    expect(c.status).toBe('unsupported')
    expect(c.reasons).toEqual(['1 of the 3 rows it cites is not in the case: removed, or numbered anew when evidence was added again'])
    expect(checkFinding({ finding: finding({ refs: [] }), rows, rule: RULE }).reasons).toEqual(['it cites no row'])
  })

  it('is contradicted by a row that no longer matches its rule, a value none of its rows holds, or another first time', () => {
    const changed = rowsOf(logon(1), logon(2, { targetUser: 'bob', eventId: 4624 }), logon(3))
    expect(checkFinding({ finding: finding(), rows: changed, rule: RULE, evidence }).reasons).toEqual(['dc01-logs.zip › Security.evtx record 4,202 (Security on DC01) no longer matches the rule'])
    const other = checkFinding({ finding: finding({ entities: { ipAddress: '198.51.100.9', targetUser: 'alice, carol' } }), rows: good(), rule: RULE })
    expect(other.status).toBe('contradicted')
    expect(other.reasons).toEqual(['it names ipAddress 198.51.100.9, which none of its rows holds', 'it names targetUser carol, which none of its rows holds'])
    expect(checkFinding({ finding: finding({ ts: T0 }), rows: good(), rule: RULE }).reasons).toEqual([
      'its time, 2026-09-08 10:00:00Z, is not its first row’s (2026-09-08 10:01:00Z)'.replace('’', "'"),
    ])
  })

  it('takes a follow-up row as part of the finding, and either engine’s way of writing a value', () => {
    const rule: Rule = { ...RULE, then: { where: { eventId: 4624 }, join: ['ipAddress'], within: '15m' } }
    const rows = rowsOf(logon(1), logon(2, { targetUser: 'bob' }), logon(3), logon(4, { eventId: 4624 }))
    expect(checkFinding({ finding: finding({ refs: [1, 2, 3, 4] }), rows, rule }).status).toBe('verified')
    // the server prints Python's list and number forms
    const listed = rowsOf(logon(1, { targetUser: ['alice', 'bob'], logonType: 3 }))
    const server = finding({ refs: [1], entities: { targetUser: "['alice', 'bob']", logonType: '3.0' } })
    expect(checkFinding({ finding: server, rows: listed }).status).toBe('verified')
  })

  it('asserts only a group’s own key when it cites more rows than were read back', () => {
    const many = finding({ refs: [1, 2, 3, ...Array.from({ length: 60 }, (_, i) => 100 + i)], entities: { ipAddress: '203.0.113.7', targetUser: 'alice, bob, zed', computer: 'DC02' } })
    const rows = rowsOf(logon(1), logon(2, { targetUser: 'bob' }), logon(3), ...Array.from({ length: 60 }, (_, i) => logon(100 + i)))
    // zed and DC02 may be in the rows past the first 50: not said to be absent
    expect(checkFinding({ finding: many, rows, rule: RULE }).status).toBe('verified')
    // the group's key is in every row of the group: a key none of them holds is a contradiction
    expect(checkFinding({ finding: { ...many, entities: { ipAddress: '198.51.100.9' } }, rows, rule: RULE }).reasons).toEqual(['it names ipAddress 198.51.100.9, which none of its rows holds'])
  })

  it('does not stand a rule against rows that lack the column it reads', () => {
    const rule: Rule = { ...RULE, where: { eventId: 4625, 'raw|contains': 'x' } }
    const c = checkFinding({ finding: finding(), rows: good(), rule })
    expect(c.status).toBe('verified')
    expect(c.partial).toBe('the rule reads raw, which the rows read back do not carry: it was not checked against them')
  })
})

describe('values named in a text', () => {
  it('finds the addresses, hashes and case names a text names', () => {
    const text = 'alice@northstar.example signed in from 203.0.113.7 and ran a file (sha256 ' + 'a'.repeat(64) + ') on WS-042. Then 999.1.1.1 and WS-0420.'
    expect(namedValues(text, ['WS-042', 'bob', 'ws'])).toEqual(['203.0.113.7', 'alice@northstar.example', 'a'.repeat(64), 'ws-042'])
  })

  it('says which of them none of its rows holds', () => {
    const rows = [logon(1), logon(2, { ipAddress: '10.0.0.5' })]
    expect(checkText('Logons from 203.0.113.7 and 10.0.0.5 on DC01.', rows, ['DC01'])).toMatchObject({ status: 'verified' })
    const c = checkText('Then 198.51.100.9 connected to WS-042.', rows, ['WS-042'])
    expect(c).toMatchObject({ status: 'unsupported', reasons: ['it names 198.51.100.9, ws-042, which none of its 2 rows holds'] })
  })
})

describe('record references', () => {
  it('name a row by its place in its file, whatever REMN numbered it', () => {
    const a = recordRef(logon(1, { id: 900 }), 'events', ev)
    const b = recordRef(logon(1, { id: 17 }), 'events', ev)
    expect(a.key).toBe(b.key)
    expect(a.key).toBe(`${'ab'.repeat(32)}:Security.evtx#dc01|security|4201`)
    // the same record read from another export keeps its duplicate key
    expect(recordRef(logon(1), 'events', { ...ev, name: 'backup.zip', sha256Client: 'cd'.repeat(32) }).duplicateKey).toBe(a.duplicateKey)
    const mail = recordRef({ id: 5, evidenceId: 3, sourceIndex: 41, messageId: '<A1@x.example>' }, 'mails', { ...ev, name: 'box.mbox' })
    expect(mail).toMatchObject({ file: 'box.mbox', record: 'message 42', duplicateKey: 'mid:<a1@x.example>' })
    const ual = recordRef({ id: 9, evidenceId: 3, recordKey: 'ual:0b1c' }, 'events', { ...ev, name: 'audit.json' })
    expect(ual).toMatchObject({ record: 'audit record 0b1c', duplicateKey: 'ual:0b1c' })
  })
})

it('finds the summary’s values among the indicators first, and in the rows’ text after', async () => {
  const searched: string[] = []
  const source = {
    listIocs: async ({ q }: { q: string }) => ({ rows: q === '203.0.113.7' ? [{ value: '203.0.113.7' }] : [], total: 0, kinds: {} }),
    searchEvents: async (f: { text: string }) => (searched.push(f.text), { rows: f.text === 'alice@northstar.example' ? [{ id: 1 }] : [], truncated: false }),
    searchMails: async () => ({ rows: [], truncated: false }),
  } as unknown as DataSource
  const c = await checkTextInCase('From 203.0.113.7, alice@northstar.example wrote to mallory@evil.example.', source)
  expect(c).toMatchObject({ status: 'unsupported', reasons: ['it names mallory@evil.example, which no row of the evidence holds'] })
  expect(searched).toEqual(['alice@northstar.example', 'mallory@evil.example'])
})

it('reads the cited rows back through the data source, in batches, and a missing id is missing', async () => {
  const calls: number[][] = []
  const source = {
    searchEvents: async (f: { conditions: { value: number[] }[] }) => {
      calls.push(f.conditions[0].value)
      return { rows: f.conditions[0].value.filter((id) => id !== 7).map((id) => ({ id })), truncated: false }
    },
  } as unknown as DataSource
  const rows = await readRows(source, 'events', [...Array.from({ length: 700 }, (_, i) => i + 1), 3])
  expect(calls.map((c) => c.length)).toEqual([500, 200])
  expect(rows.size).toBe(699)
  expect(rows.has(7)).toBe(false)
})

// the lab: its findings, made by the rules from its rows, all hold; a tampered copy does not
const ROOT = path.resolve(__dirname, '../../..')
function yamlFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = path.join(dir, n)
    return statSync(p).isDirectory() ? yamlFiles(p) : /\.ya?ml$/.test(n) ? [p] : []
  })
}

it('verifies every finding of the lab case against its rows, and catches a tampered copy', () => {
  const lines = gunzipSync(readFileSync(path.join(ROOT, 'frontend/public/demo/northstar-lab.remn.ndjson.gz')))
    .toString('utf8')
    .split('\n')
    .filter(Boolean)
  const head = JSON.parse(lines[0])
  const rows = { events: new Map<number, Row>(), mails: new Map<number, Row>() }
  const bodies = new Map<number, Row>()
  const findings: Finding[] = []
  const labEvidence = new Map<number, Evidence>()
  for (const l of lines.slice(1)) {
    const { table, row } = JSON.parse(l)
    if (table === 'events' || table === 'mails') rows[table as 'events' | 'mails'].set(row.id, row)
    else if (table === 'mailBodies') bodies.set(row.mailId, row)
    else if (table === 'findings') findings.push(row)
    else if (table === 'evidence') labEvidence.set(row.id, row)
  }
  for (const [id, b] of bodies) rows.mails.set(id, { ...rows.mails.get(id), ...b })
  const rules = new Map<string, Rule>()
  for (const f of yamlFiles(path.join(ROOT, 'rules')))
    for (const d of yaml.loadAll(readFileSync(f, 'utf8'))) {
      const v = validateRule(d)
      if (v.ok) rules.set(v.rule.id, v.rule)
    }
  const settings = settingsForRules(head.case)
  const check = (f: Finding, r = rows) => checkFinding({ finding: f, rows: r[f.source], rule: rules.get(f.ruleId), settings, evidence: labEvidence })
  const statuses = findings.map((f) => check(f).status)
  expect(findings.length).toBeGreaterThan(100)
  expect(statuses.filter((s) => s !== 'verified')).toEqual([])
  expect(findings.every((f) => !check(f).partial)).toBe(true)

  // the event id changed under a finding of a rule that reads it, and the rows of a mail finding removed
  const target = findings.find((f) => f.source === 'events' && f.refs.length && ruleEventIds(rules.get(f.ruleId)?.where))!
  const tampered = { events: new Map(rows.events), mails: new Map(rows.mails) }
  const first = tampered.events.get(target.refs[0])!
  tampered.events.set(target.refs[0], { ...first, eventId: 65_535 })
  expect(check(target, tampered)).toMatchObject({ status: 'contradicted' })
  expect(check(target, tampered).reasons[0]).toMatch(/no longer matches the rule$/)
  const mailFinding = findings.find((f) => f.source === 'mails' && f.refs.length)!
  for (const id of mailFinding.refs) tampered.mails.delete(id)
  expect(check(mailFinding, tampered)).toMatchObject({ status: 'unsupported' })
})
