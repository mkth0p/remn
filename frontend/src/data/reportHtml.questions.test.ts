import { expect, it } from 'vitest'
import { defaultSettings, type Case, type QuestionAnswer } from '../db/schema'
import { questionsForReport } from './questions/answers'
import { evidenceProfile } from './questions/coverage'
import { buildReportHtml, questionsSection, type ReportData } from './reportHtml'
import { DEFAULT_REPORT } from './review'

const kase: Case = { id: 1, name: 'Questions case', createdAt: 0, updatedAt: 0, storage: 'browser', settings: defaultSettings() }
const answer = (questionId: string, status: QuestionAnswer['status'], text: string, citations: QuestionAnswer['citations'] = []): QuestionAnswer => ({
  caseId: 1,
  questionId,
  status,
  text,
  citations,
  createdAt: 0,
  updatedAt: 1_700_000_000_000,
})
const answers = new Map([
  [
    'Q1074',
    answer('Q1074', 'answered', 'The Security log of <b>DC01</b> was cleared.', [
      { source: 'events', rowId: 80, recordKey: 'abc:#dc01|security|4200', label: 'Security.evtx record 4,200 (Security on DC01)', ts: 1_700_000_000_000, addedAt: 0 },
      { source: 'findings', key: 'win-log-cleared|rk:abc', label: 'Security log cleared (win-log-cleared)', addedAt: 0 },
    ]),
  ],
  ['Q1010', answer('Q1010', 'cannot', 'The Print Service log was not collected.')],
])
const questions = questionsForReport(['S1001'], answers, evidenceProfile([{ value: 'Security', count: 10 }], [], 0))!

const data = (over: Partial<ReportData> = {}): ReportData => ({
  kase,
  generatedAt: 1_700_000_000_000,
  settings: DEFAULT_REPORT,
  summary: '',
  evidence: [],
  chains: [],
  reviews: {},
  membersOf: new Map(),
  graphs: {},
  campaignInsights: [],
  incidents: [],
  findings: [],
  iocs: [],
  timeline: [],
  tasks: [],
  notes: [],
  undecided: 0,
  ...over,
})

it('prints each question with its answer, what it cites and the open ones flagged', () => {
  const html = questionsSection(questions)
  expect(html).toContain('Data Exfiltration')
  expect(html).toContain('Were any system event logs cleared?')
  expect(html).toContain('The Security log of &lt;b&gt;DC01&lt;/b&gt; was cleared.')
  expect(html).toContain('Security.evtx record 4,200 (Security on DC01)')
  expect(html).toContain('<span class="dim">finding</span> Security log cleared (win-log-cleared)')
  expect(html).toContain('cannot answer from this evidence')
  expect(html).toContain('The Print Service log was not collected.')
  // an open question says so, and one the case holds no evidence for says what is missing
  expect(html).toContain('<div class="cap warn">unanswered</div>')
  expect(html).toContain('Evidence: not covered: no browser history in this case')
  expect(html).toMatch(/1 answered, 1 cannot be answered from this evidence, \d+ still open/)
})

it('adds a Questions section to the report and names the open questions where it stops', () => {
  const html = buildReportHtml(data({ questions }))
  expect(html).toContain('<section class="s" id="questions">')
  expect(html).toMatch(/<h2>Questions<\/h2>/)
  expect(html).toMatch(/\d+ investigative questions are still open; \d+ of them with no evidence in the case that could answer them\./)
  expect(html).toContain('1 investigative question cannot be answered from this evidence.')
  expect(buildReportHtml(data())).not.toContain('id="questions"')
})
