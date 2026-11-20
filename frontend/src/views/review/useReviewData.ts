import { useCallback, useEffect, useState } from 'react'
import { loadSuggestions, loadTriageRun, type Suggestion, type TriageRun } from '../../data/aiReview'
import { loadChains, type Chain } from '../../data/chains'
import { loadStories, loadStoryNotes, type StoryNotes, type StoryResult } from '../../data/stories'
import { loadStoryDecisions, type StoryDecisions } from '../../data/storyDecisions'
import { loadChainReviews, loadReportSettings, type ChainReview, type ReportSettings } from '../../data/review'
import { getDb, type Evidence, type Finding } from '../../db/schema'
import { useStore } from '../../state/store'

/**
 * What the Review page reads for a case: its findings and evidence, the chains and their reviews,
 * the report's settings, the stories with the analyst's notes and decisions (a decided story counts
 * in the verdict, data/storyDecisions.ts), the model's pending proposals and its last triage, read
 * again on a case change and after a rule run.
 */
export function useReviewData(caseId: number | undefined) {
  const rulesVersion = useStore((s) => s.rulesVersion)
  const [findings, setFindings] = useState<Finding[]>([])
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [chains, setChains] = useState<Chain[]>([])
  const [reviews, setReviews] = useState<Record<string, ChainReview>>({})
  const [settings, setSettings] = useState<ReportSettings | null>(null)
  const [stories, setStories] = useState<{ result: StoryResult | null; notes: StoryNotes; decisions: StoryDecisions }>({ result: null, notes: {}, decisions: {} })
  const [suggestions, setSuggestions] = useState<Record<string, Suggestion>>({})
  const [lastRun, setLastRun] = useState<TriageRun | null>(null)

  const reload = useCallback(() => {
    if (!caseId) return
    getDb().findings.where('caseId').equals(caseId).toArray().then(setFindings)
    loadSuggestions(caseId).then(setSuggestions)
  }, [caseId])
  useEffect(() => {
    if (!caseId) return
    reload()
    getDb().evidence.where('caseId').equals(caseId).toArray().then(setEvidence)
    loadChains(caseId).then((r) => setChains(r?.chains ?? []))
    loadChainReviews(caseId).then(setReviews)
    loadReportSettings(caseId).then(setSettings)
    Promise.all([loadStories(caseId), loadStoryNotes(caseId), loadStoryDecisions(caseId)]).then(([result, notes, decisions]) => setStories({ result, notes, decisions }))
    loadTriageRun(caseId).then(setLastRun)
  }, [caseId, rulesVersion, reload])

  return { findings, evidence, chains, reviews, setReviews, settings, setSettings, stories, suggestions, setSuggestions, lastRun, setLastRun, reload }
}
