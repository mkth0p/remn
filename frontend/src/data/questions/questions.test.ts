import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case, type EventRow, type Finding } from '../../db/schema'
import { matchCondition, type Filter } from '../../rules/filter'
import { restoreCaseBundle, writeCaseBundle } from '../caseBundle'
import { recordRef } from '../recordKeys'
import type { DataSource } from '../source'
import {
  addCitation,
  citationId,
  findingCitation,
  loadAnswers,
  loadScenarioChoice,
  questionsForReport,
  recordKeyFilter,
  removeCitation,
  resolveCitation,
  rowCitation,
  saveScenarioChoice,
  setAnswer,
} from './answers'
import { CATALOG, FACETS, QUESTIONS, questionsOf, relatedRules, scenarioViews, SCENARIOS, techniqueRelated } from './catalog'
import { activitySpan, coverage, evidenceProfile } from './coverage'

vi.mock('../../state/store', () => ({ toast: vi.fn(), useStore: { getState: () => ({ setCurrentCase: vi.fn(), bumpRules: vi.fn() }) } }))

describe('the bundled catalog', () => {
  it('keeps the DFIQ ids and gives REMN its own ids in the private range', () => {
    for (const s of CATALOG.scenarios) expect(s.id).toMatch(s.origin === 'dfiq' ? /^S[1-9]\d{3}$/ : /^S0\d{3}$/)
    for (const q of CATALOG.questions) expect(q.id).toMatch(q.origin === 'dfiq' ? /^Q[1-9]\d{3}$/ : /^Q0\d{3}$/)
    expect(SCENARIOS.get('S1008')?.name).toBe('Lateral Movement')
    expect(SCENARIOS.get('S1007')?.name).toBe('Host Persistence Audit')
    expect(SCENARIOS.get('S1001')?.name).toBe('Data Exfiltration')
    expect(SCENARIOS.get('S0001')?.origin).toBe('remn')
    expect(SCENARIOS.get('S0002')?.name).toMatch(/Business email compromise/)
    expect(CATALOG.dfiq).toMatchObject({ license: 'Apache-2.0', version: '1.0.1' })
  })

  it('leaves out the questions nothing REMN reads can answer', () => {
    // macOS launch agents, cron jobs, Chrome extensions: in DFIQ, not in REMN's checklist
    for (const id of ['Q1053', 'Q1062', 'Q1021']) {
      expect(QUESTIONS.has(id)).toBe(false)
      expect(CATALOG.skipped.map((s) => s.id)).toContain(id)
    }
    // no facet is left without a question
    for (const f of CATALOG.facets) expect(f.questions.length).toBeGreaterThan(0)
  })

  it('links every scenario, facet and question, and every question to evidence it can be answered from', () => {
    for (const s of CATALOG.scenarios) for (const f of s.facets) expect(FACETS.has(f)).toBe(true)
    for (const f of CATALOG.facets) for (const q of f.questions) expect(QUESTIONS.has(q)).toBe(true)
    for (const q of CATALOG.questions) {
      expect(q.evidence.length).toBeGreaterThan(0)
      for (const e of q.evidence) expect(CATALOG.evidence[e]).toBeDefined()
    }
  })

  it('writes every search in the filter language the Events and Mails pages run', () => {
    const row = { eventId: 1102, channel: 'Security', operation: 'Send', folder: 'Sent Items', attachmentCount: 1 }
    for (const q of CATALOG.questions)
      for (const s of q.searches) {
        expect(['events', 'mails']).toContain(s.source)
        for (const c of s.filter.conditions ?? []) expect(() => matchCondition(row, c)).not.toThrow()
      }
    const cleared = QUESTIONS.get('Q1074')!.searches[0].filter
    expect((cleared.conditions ?? []).every((c) => matchCondition(row, c))).toBe(true)
  })

  it('lists the chosen scenarios in catalog order and each shared question once', () => {
    const views = scenarioViews(['S1008', 'S1007', 'nope'])
    expect(views.map((v) => v.scenario.id)).toEqual(['S1007', 'S1008'])
    // F1021 "new accounts" belongs to both
    expect(views.every((v) => v.facets.some((f) => f.facet.id === 'F1021'))).toBe(true)
    const ids = questionsOf(['S1007', 'S1008']).map((q) => q.id)
    expect(ids.filter((id) => id === 'Q1059')).toHaveLength(1)
  })

  it('relates rules by technique, parent or child, and by tag', () => {
    expect(techniqueRelated('T1053.005', 'T1053')).toBe(true)
    expect(techniqueRelated('T1053', 'T1053.005')).toBe(true)
    expect(techniqueRelated('T1053.005', 'T1053.002')).toBe(false)
    const rules = [
      { rule: { id: 'task', attack: ['T1053.005'], tags: [] } },
      { rule: { id: 'inbox', attack: ['T1564.008'], tags: ['m365', 'inbox-rule'] } },
      { rule: { id: 'tagged', attack: [], tags: ['Inbox-Rule'] } },
      { rule: { id: 'other', attack: ['T1110'], tags: ['brute-force'] } },
    ]
    expect(relatedRules({ attack: ['T1053'], ruleTags: [] }, rules).map((r) => r.rule.id)).toEqual(['task'])
    expect(relatedRules(QUESTIONS.get('Q0012')!, rules).map((r) => r.rule.id)).toEqual(['inbox', 'tagged'])
  })
})

describe('coverage by the evidence of the case', () => {
  it('says which evidence answers a question, from the channel and category facets', () => {
    const p = evidenceProfile([{ value: 'SECURITY', count: 1204 }], [], 0)
    const c = coverage(QUESTIONS.get('Q1074')!, p)
    expect(c.covered).toBe(true)
    expect(c.held).toEqual([{ id: 'security', label: 'Security log', count: 1204 }])
    expect(c.text).toBe('covered by the Security log (1,204 rows)')
  })

  it('names what is missing when the case holds none of it', () => {
    const c = coverage(QUESTIONS.get('Q1020')!, evidenceProfile([{ value: 'Security', count: 5 }], [], 3))
    expect(c.covered).toBe(false)
    expect(c.text).toBe('not covered: no browser history in this case')
    expect(coverage(QUESTIONS.get('Q1074')!, evidenceProfile([], [], 0)).text).toBe('not covered: no Security log or System log in this case')
  })

  it('reads M365 audit categories by prefix, collection artefacts by category and mailboxes by count', () => {
    const p = evidenceProfile(
      [{ value: 'Exchange', count: 40 }],
      [
        { value: 'M365 Exchange', count: 40 },
        { value: 'collection:task', count: 12 },
      ],
      7,
    )
    expect(coverage(QUESTIONS.get('Q0012')!, p).covered).toBe(true)
    expect(coverage(QUESTIONS.get('Q1061')!, p).held.map((h) => h.id)).toEqual(['tasks'])
    expect(coverage(QUESTIONS.get('Q1080')!, p).text).toBe('covered by the mailboxes (7 rows)')
    expect(coverage(QUESTIONS.get('Q0016')!, p).held[0]).toMatchObject({ id: 'm365-audit', count: 40 })
  })

  it('takes the first and last attacker activity from findings that matter', () => {
    const f = (id: number, ts: number | null, severity: Finding['severity'], status: Finding['status'] = 'new') => ({ id, ts, severity, status }) as Finding
    const span = activitySpan([f(1, 50, 'low'), f(2, 100, 'high'), f(3, 10, 'critical', 'false_positive'), f(4, 300, 'medium'), f(5, null, 'critical')])
    expect(span.first?.id).toBe(2)
    expect(span.last?.id).toBe(4)
  })
})

describe('answers', () => {
  let db: RemnDB
  let kase: Case
  const event: EventRow = {
    id: 80,
    caseId: 1,
    evidenceId: 9,
    ts: 1_700_000_000_000,
    eventId: 1102,
    recordId: 4200,
    computer: 'DC01',
    channel: 'Security',
    sourceSha256: 'a'.repeat(64),
    sourceFile: 'Security.evtx',
  }
  const finding = {
    id: 90,
    caseId: 1,
    key: 'win-log-cleared|80',
    ruleId: 'win-log-cleared',
    title: 'Security log cleared',
    source: 'events',
    refs: [80],
    status: 'reviewed',
    ts: event.ts,
    severity: 'high',
    attack: [],
    entities: {},
    count: 1,
    createdAt: 1,
  } as Finding

  /** A data source over this browser's rows, the way the query worker reads them. */
  const source = (): DataSource =>
    ({
      getEvent: async (id: number) => (await db.events.get(id)) ?? null,
      getMail: async (id: number) => {
        const row = await db.mails.get(id)
        return row ? { row, body: null } : null
      },
      searchEvents: async (filter: Filter) => ({ rows: (await db.events.toArray()).filter((r) => (filter.conditions ?? []).every((c) => matchCondition(r, c))), truncated: false }),
      searchMails: async (filter: Filter) => ({ rows: (await db.mails.toArray()).filter((r) => (filter.conditions ?? []).every((c) => matchCondition(r, c))), truncated: false }),
    }) as unknown as DataSource

  beforeEach(async () => {
    db = new RemnDB(`questions-${Math.random()}`)
    setDb(db)
    kase = { id: 1, name: 'Questions', createdAt: 1, updatedAt: 1, storage: 'browser', settings: defaultSettings() }
    await db.cases.add(kase)
    await db.evidence.add({ id: 9, caseId: 1, name: 'Security.evtx', kind: 'evtx', status: 'done', count: 1, size: 1, integrity: 'verified', addedAt: 1 })
    await db.events.add(event)
    await db.findings.add(finding)
  })
  afterEach(async () => {
    await db.delete()
    setDb(null)
  })

  it('keeps the chosen scenarios and each answer with its status, text and citations', async () => {
    await saveScenarioChoice(1, ['S1007', 'S0001', 'S1007'])
    expect(await loadScenarioChoice(1)).toEqual(['S1007', 'S0001'])
    expect(await loadScenarioChoice(2)).toEqual([])

    await setAnswer(1, 'Q1074', { status: 'answered', text: 'The Security log was cleared on DC01.' })
    const row = rowCitation(event, 'events', await db.evidence.get(9))
    expect(row.label).toBe('Security.evtx record 4,200 (Security on DC01)')
    expect(row.recordKey).toBe(recordRef(event, 'events', await db.evidence.get(9)).key)
    await addCitation(1, 'Q1074', row)
    await addCitation(1, 'Q1074', { ...row, addedAt: 2 }) // the same record once
    await addCitation(1, 'Q1074', findingCitation(finding))
    let a = (await loadAnswers(1)).get('Q1074')!
    expect(a).toMatchObject({ status: 'answered', text: 'The Security log was cleared on DC01.' })
    expect(a.citations.map((c) => c.source)).toEqual(['events', 'findings'])

    await removeCitation(1, 'Q1074', citationId(row))
    a = (await loadAnswers(1)).get('Q1074')!
    expect(a.citations.map((c) => c.source)).toEqual(['findings'])
    expect(await db.questionAnswers.count()).toBe(1)
  })

  it('finds a cited row again by its record key after the evidence is added again', async () => {
    const c = rowCitation(event, 'events', await db.evidence.get(9))
    expect(recordKeyFilter('events', c.recordKey!)).toEqual({ conditions: [{ field: 'recordId', op: 'eq', value: 4200 }] })
    expect(await resolveCitation(c, source(), await db.evidence.toArray(), [])).toEqual({ id: 80, moved: false })
    // removed and read again: the same record under another id, and another record where the old id pointed
    await db.events.clear()
    await db.events.bulkAdd([
      { ...event, id: 80, recordId: 9999 },
      { ...event, id: 500 },
    ])
    expect(await resolveCitation(c, source(), await db.evidence.toArray(), [])).toEqual({ id: 500, moved: true })
    await db.events.clear()
    expect(await resolveCitation(c, source(), await db.evidence.toArray(), [])).toEqual({ id: null, moved: false })
    // a finding by the key its decision is kept under
    expect(await resolveCitation(findingCitation(finding), source(), [], [finding])).toEqual({ id: 90, moved: false })
  })

  it('travels in the case bundle with the rows it cites renumbered', async () => {
    await saveScenarioChoice(1, ['S1007'])
    await setAnswer(1, 'Q1074', { status: 'answered', text: 'Cleared.' })
    await addCitation(1, 'Q1074', rowCitation(event, 'events', await db.evidence.get(9)))
    await addCitation(1, 'Q1074', findingCitation(finding))
    await setAnswer(1, 'Q1061', { status: 'cannot', text: 'No task log.' })
    const chunks: string[] = []
    await writeCaseBundle(kase, { write: async (t) => void chunks.push(t) })
    const restored = await restoreCaseBundle(new File(chunks, 'case.remn.ndjson'))

    expect(await loadScenarioChoice(restored)).toEqual(['S1007'])
    const answers = await loadAnswers(restored)
    expect(answers.get('Q1061')).toMatchObject({ status: 'cannot', text: 'No task log.' })
    const a = answers.get('Q1074')!
    const newEvent = (await db.events.where('caseId').equals(restored).first())!
    const newFinding = (await db.findings.where('caseId').equals(restored).first())!
    expect(newEvent.id).not.toBe(80)
    expect(a.citations[0]).toMatchObject({ source: 'events', rowId: newEvent.id, recordKey: rowCitation(event, 'events', await db.evidence.get(9)).recordKey })
    expect(a.citations[1]).toMatchObject({ source: 'findings', key: newFinding.key })
    const evidence = await db.evidence.where('caseId').equals(restored).toArray()
    expect(await resolveCitation(a.citations[0], source(), evidence, [newFinding])).toEqual({ id: newEvent.id, moved: false })
    expect(await resolveCitation(a.citations[1], source(), evidence, [newFinding])).toEqual({ id: newFinding.id, moved: false })
    // the original case is untouched
    expect((await loadAnswers(1)).get('Q1074')?.citations[0].rowId).toBe(80)
  })

  it('gives the report every question of the chosen scenarios with its answer and coverage', async () => {
    await setAnswer(1, 'Q1074', { status: 'answered', text: 'Cleared.' })
    await addCitation(1, 'Q1074', rowCitation(event, 'events', await db.evidence.get(9)))
    await setAnswer(1, 'Q1010', { status: 'cannot', text: 'No print log.' })
    const r = questionsForReport(['S1001'], await loadAnswers(1), evidenceProfile([{ value: 'Security', count: 3 }], [], 0))!
    const all = r.scenarios.flatMap((s) => s.facets.flatMap((f) => f.questions))
    expect(all.find((q) => q.id === 'Q1074')).toMatchObject({ status: 'answered', citations: [{ label: 'Security.evtx record 4,200 (Security on DC01)' }], covered: true })
    expect(all.find((q) => q.id === 'Q1010')).toMatchObject({ status: 'cannot', covered: false })
    expect(r.counts).toEqual({ answered: 1, cannot: 1, open: all.length - 2 })
    expect(r.uncovered).toBeGreaterThan(0)
    expect(questionsForReport([], new Map())).toBeUndefined()
  })
})
