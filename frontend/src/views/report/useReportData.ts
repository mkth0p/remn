import { useEffect, useState } from 'react'
import { summariseLedger } from '../../ai/ledger'
import { listNotes } from '../../data/caseNotes'
import { chainCoverageWarnings, loadChains, type Chain } from '../../data/chains'
import { loadEvidenceGaps, type GapStatement } from '../../data/evidenceGaps'
import { findingsStaleness } from '../../data/findingsState'
import { loadAnswers, loadScenarioChoice } from '../../data/questions/answers'
import { loadEvidenceProfile, type EvidenceProfile } from '../../data/questions/coverage'
import { reportRelationships, type RelationshipReview } from '../../data/relationshipReviews'
import { evidenceScope, loadReportFont, SCOPE_READ, type AiUsage, type EvidenceScope } from '../../data/reportHtml'
import { loadReportIssue, type ReportIssue } from '../../data/reportPreflight'
import { effectiveSeverity, loadChainReviews, loadReportSettings, type ChainReview, type ReportSettings } from '../../data/review'
import { readMeasure, type MeasureReading } from '../../data/ruleMeasures'
import { loadRules } from '../../data/rules'
import { getSource } from '../../data/source'
import { loadStories, loadStoryNotes, storiesStaleness, storyInputs, type StoryNotes, type StoryResult } from '../../data/stories'
import { loadStoryDecisions, type StoryDecisions } from '../../data/storyDecisions'
import { getDb, type Case, type CaseNote, type Evidence, type Finding, type Ioc, type QuestionAnswer } from '../../db/schema'
import type { Rule } from '../../rules/engine'
import { useStore } from '../../state/store'
import { ORDER } from './model'

/**
 * What the Report page reads for a case, and reads again after a rule run: the evidence, the
 * findings worst first, the flagged indicators and how many were looked up, the chains and their
 * reviews, the stories with their notes and decisions, the case notes, the questions and their
 * answers, the report's settings and issue, the summary and who wrote it, the rule measures, what
 * the evidence covers and cannot show, and the font the report embeds.
 */
export function useReportData(kase: Case | null) {
  const rulesVersion = useStore((s) => s.rulesVersion)
  const mailCount = useStore((s) => s.counts.mails)
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [chains, setChains] = useState<Chain[]>([])
  /** the case's stories, the analyst's notes on them, and why the stories no longer read the case as it is */
  const [storyResult, setStoryResult] = useState<StoryResult | null>(null)
  const [storyNotes, setStoryNotes] = useState<StoryNotes>({})
  /** the analyst's decisions on the stories (data/storyDecisions.ts), applied to them as the Stories page applies them */
  const [storyDecisions, setStoryDecisions] = useState<StoryDecisions>({})
  const [storiesStale, setStoriesStale] = useState<string[]>([])
  const [coverageWarnings, setCoverageWarnings] = useState<string[]>([])
  const [reviews, setReviews] = useState<Record<string, ChainReview>>({})
  const [relationships, setRelationships] = useState<RelationshipReview[]>([])
  const [settings, setSettings] = useState<ReportSettings | null>(null)
  const [iocs, setIocs] = useState<Ioc[]>([])
  const [iocCounts, setIocCounts] = useState<{ total: number; checked: number }>({ total: 0, checked: 0 })
  const [aiUsage, setAiUsage] = useState<AiUsage | undefined>(undefined)
  const [issue, setIssue] = useState<ReportIssue>({ waivers: {} })
  const [rulesState, setRulesState] = useState<{ lastRun: number | null; evidenceAfter: number; errors: number } | undefined>(undefined)
  /** what the evidence cannot show, for "Where it stops" */
  const [gaps, setGaps] = useState<GapStatement[]>([])
  /** how far each rule's finding can be taken as a detection */
  const [measures, setMeasures] = useState<Record<string, MeasureReading>>({})
  /** the rules as they are now, to check each printed finding's rows against */
  const [ruleMap, setRuleMap] = useState<Map<string, Rule>>(new Map())
  const [notes, setNotes] = useState<CaseNote[]>([])
  /** the investigative scenarios chosen for the case, the answers, and what evidence the case holds (data/questions) */
  const [questionScenarios, setQuestionScenarios] = useState<string[]>([])
  const [answers, setAnswers] = useState<Map<string, QuestionAnswer>>(new Map())
  const [profile, setProfile] = useState<EvidenceProfile | null>(null)
  const [summary, setSummary] = useState<string>('')
  /** who wrote the summary last: the model's draft is labelled in the report until the analyst edits it */
  const [summaryBy, setSummaryBy] = useState<'analyst' | 'ai' | undefined>(undefined)
  const [summaryAt, setSummaryAt] = useState<number | undefined>(undefined)
  const [fontData, setFontData] = useState<string | undefined>(undefined)
  /** what the evidence covers, for the report's scope when the analyst wrote none */
  const [scope, setScope] = useState<EvidenceScope | undefined>(undefined)
  useEffect(() => {
    loadReportFont().then(setFontData)
  }, [])
  useEffect(() => {
    if (!kase?.id) return
    const db = getDb()
    db.evidence.where('caseId').equals(kase.id).toArray().then(setEvidence)
    db.findings
      .where('caseId')
      .equals(kase.id)
      .toArray()
      .then((f) => setFindings(f.sort((a, b) => ORDER.indexOf(effectiveSeverity(a)) - ORDER.indexOf(effectiveSeverity(b)) || (a.ts ?? 0) - (b.ts ?? 0))))
    getSource(kase)
      .listIocs({ onlyBad: true, limit: 500 })
      .then((r) => setIocs(r.rows))
      .catch(() => setIocs([]))
    // what the report says about enrichment follows the lookups that ran, not the setting
    Promise.all([getSource(kase).listIocs({ limit: 1 }), getSource(kase).listIocs({ unchecked: true, limit: 1 })])
      .then(([all, unchecked]) => setIocCounts({ total: all.total, checked: Math.max(0, all.total - unchecked.total) }))
      .catch(() => setIocCounts({ total: 0, checked: 0 }))
    loadReportIssue(kase.id).then(setIssue)
    loadEvidenceGaps(kase.id, getSource(kase))
      .then(setGaps)
      .catch(() => setGaps([]))
    loadRules(kase.id)
      .then((rs) => {
        setMeasures(Object.fromEntries(rs.map((r) => [r.rule.id, readMeasure(r.measured, r.origin)])))
        setRuleMap(new Map(rs.filter((r) => !r.error).map((r) => [r.rule.id, r.rule])))
      })
      .catch(() => setMeasures({}))
    summariseLedger(kase.id)
      .then(setAiUsage)
      .catch(() => setAiUsage(undefined))
    findingsStaleness(kase.id)
      .then((s) => setRulesState({ lastRun: s.lastRun, evidenceAfter: s.evidenceAfter, errors: s.errors.length }))
      .catch(() => setRulesState(undefined))
    db.kv.get(`report-summary-${kase.id}`).then((k) => setSummary((k?.value as string) ?? ''))
    db.kv.get(`report-summary-by-${kase.id}`).then((k) => setSummaryBy((k?.value as 'analyst' | 'ai' | undefined) ?? undefined))
    db.kv.get(`report-summary-at-${kase.id}`).then((k) => setSummaryAt((k?.value as number | undefined) ?? undefined))
    listNotes(kase.id).then(setNotes)
    loadScenarioChoice(kase.id).then(setQuestionScenarios)
    loadAnswers(kase.id).then(setAnswers)
    loadChains(kase.id).then((r) => {
      setChains(r?.chains ?? [])
      setCoverageWarnings(chainCoverageWarnings(r?.stats))
    })
    loadStories(kase.id).then(async (r) => {
      setStoryResult(r)
      setStoriesStale(r ? storiesStaleness(r, await storyInputs(kase)) : [])
    })
    loadStoryNotes(kase.id).then(setStoryNotes)
    loadStoryDecisions(kase.id).then(setStoryDecisions)
    loadChainReviews(kase.id).then(setReviews)
    reportRelationships(kase.id).then(setRelationships)
    loadReportSettings(kase.id).then(setSettings)
    const src = getSource(kase)
    Promise.all([src.facets('events', 'computer', SCOPE_READ), src.facets('events', 'targetUser', SCOPE_READ), src.facets('events', 'subjectUser', SCOPE_READ)])
      .then(([hosts, targets, subjects]) => setScope(evidenceScope(hosts, [targets, subjects])))
      .catch(() => setScope(undefined))
  }, [kase, rulesVersion])
  useEffect(() => {
    if (!kase?.id || !questionScenarios.length) return
    loadEvidenceProfile(getSource(kase), mailCount)
      .then(setProfile)
      .catch(() => setProfile(null))
  }, [kase, questionScenarios.length, mailCount])
  return {
    evidence,
    findings,
    chains,
    storyResult,
    storyNotes,
    storyDecisions,
    storiesStale,
    coverageWarnings,
    reviews,
    relationships,
    settings,
    setSettings,
    iocs,
    iocCounts,
    aiUsage,
    issue,
    setIssue,
    rulesState,
    gaps,
    measures,
    ruleMap,
    notes,
    questionScenarios,
    answers,
    profile,
    summary,
    setSummary,
    summaryBy,
    setSummaryBy,
    summaryAt,
    setSummaryAt,
    fontData,
    scope,
  }
}
