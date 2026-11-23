import { useEffect, useMemo, useState } from 'react'
import { renderGraphPng } from '../../components/graphDrawing'
import type { Chain } from '../../data/chains'
import { loadReportClaims, type ReportClaims } from '../../data/claims'
import { questionsForReport } from '../../data/questions/answers'
import { reportText } from '../../data/reportText'
import type { EvidenceProfile } from '../../data/questions/coverage'
import { chainSeverity, selectForReport, type ChainReview, type ReportSettings } from '../../data/review'
import { settingsForRules } from '../../data/rules'
import { getSource } from '../../data/source'
import { storyRowIds, type StoryNotes, type StoryResult } from '../../data/stories'
import { storiesForReport, type StoryDecisions } from '../../data/storyDecisions'
import type { Case, Evidence, Finding, QuestionAnswer } from '../../db/schema'
import type { Rule } from '../../rules/engine'
import { buildIncidents } from '../../rules/incidents'

/**
 * What the report prints, from what the page read: the questions and their answers, the findings
 * and chains the Review page's settings select, the stories past the floor, the chain graphs drawn
 * off-screen, and the printed findings and texts read back against the rows they cite.
 */
export function useReportContents({
  kase,
  settings,
  findings,
  chains,
  reviews,
  evidence,
  summary,
  ruleMap,
  stories: { result: storyResult, notes: storyNotes, decisions: storyDecisions },
  questions: { scenarios: questionScenarios, answers, profile },
}: {
  kase: Case | null
  settings: ReportSettings | null
  findings: Finding[]
  chains: Chain[]
  reviews: Record<string, ChainReview>
  evidence: Evidence[]
  summary: string
  ruleMap: Map<string, Rule>
  stories: { result: StoryResult | null; notes: StoryNotes; decisions: StoryDecisions }
  questions: { scenarios: string[]; answers: Map<string, QuestionAnswer>; profile: EvidenceProfile | null }
}) {
  /** the printed findings and texts read back against the rows they cite */
  const [claims, setClaims] = useState<ReportClaims | undefined>(undefined)
  // the page shows only how many questions are open; the report prints them in its own language
  const language = settings?.language ?? 'en'
  const questions = useMemo(() => questionsForReport(questionScenarios, answers, profile, reportText(language)), [questionScenarios, answers, profile, language])
  const selection = useMemo(() => (settings ? selectForReport(findings, chains, reviews, settings) : { findings: [], chains: [] }), [findings, chains, reviews, settings])
  const printedStories = useMemo(
    () =>
      settings
        ? storiesForReport(storyResult, storyNotes, storyDecisions, findings, settings.minSeverity, settings.onlyReviewed, 20)
        : { stories: [], left: 0, orphans: 0, dismissed: 0, decided: [], decisionsOrphaned: 0 },
    [storyResult, storyNotes, storyDecisions, findings, settings],
  )
  // graph pictures for the report, drawn off-screen from the same models as the Chains page
  const [graphs, setGraphs] = useState<Record<string, string>>({})
  useEffect(() => {
    if (!settings?.includeGraphs || !selection.chains.length) {
      setGraphs({})
      return
    }
    const out: Record<string, string> = {}
    for (const c of selection.chains) {
      const png = renderGraphPng({ mode: 'chain', chain: c })
      if (png) out[c.id] = png
    }
    if (selection.chains.length > 1) {
      const png = renderGraphPng({ mode: 'campaign', chains: selection.chains })
      if (png) out['campaign'] = png
    }
    setGraphs(out)
  }, [selection.chains, settings?.includeGraphs])
  // what the report will print, read back against the rows it cites (after the summary settles)
  useEffect(() => {
    if (!kase?.id || !settings) return
    let alive = true
    setClaims(undefined)
    const printed = buildIncidents(selection.findings, { chains: selection.chains, severityOf: (c) => chainSeverity(c, reviews[c.id]) }).filter((i) => i.kind !== 'chain')
    const timer = setTimeout(() => {
      loadReportClaims({
        source: getSource(kase),
        findings: selection.findings,
        rules: ruleMap,
        settings: settingsForRules(kase),
        evidence,
        chains: selection.chains,
        narratives: Object.fromEntries(Object.entries(reviews).map(([id, r]) => [id, r.narrative])),
        incidents: printed,
        summary,
        stories: printedStories.stories.filter((st) => st.note).map((st) => ({ key: st.key, title: st.story.title, note: st.note!, ids: storyRowIds(st.story) })),
      })
        .then((c) => alive && setClaims(c))
        .catch(() => alive && setClaims(undefined))
    }, 400)
    return () => {
      alive = false
      clearTimeout(timer)
    }
  }, [kase, settings, selection, reviews, ruleMap, evidence, summary, printedStories])
  return { questions, selection, printedStories, graphs, claims }
}
