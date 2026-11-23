import { useCallback, useMemo } from 'react'
import { computeConfidence, computeVerdict, threatProfile, type ReportData } from '../../data/reportHtml'
import { storiesForReport, type StoryDecisions } from '../../data/storyDecisions'
import type { StoryNotes, StoryResult } from '../../data/stories'
import type { Chain } from '../../data/chains'
import { chainSeverity, selectForReport, unprintedConfirmed, type ChainReview, type ReportSettings, type ReviewItem, type Verdict } from '../../data/review'
import type { Case, Evidence, Finding } from '../../db/schema'
import { buildIncidents } from '../../rules/incidents'
import type { Status } from './model'

/**
 * The report's cover, live: the same selection and the same functions the Report page uses, and
 * what the verdict would become if the current item took a given decision.
 */
export function useReviewReport({
  kase,
  settings,
  findings,
  chains,
  reviews,
  evidence,
  undecided,
  stories,
  current,
}: {
  kase: Case | null
  settings: ReportSettings | null
  findings: Finding[]
  chains: Chain[]
  reviews: Record<string, ChainReview>
  evidence: Evidence[]
  undecided: number
  stories: { result: StoryResult | null; notes: StoryNotes; decisions: StoryDecisions }
  current: ReviewItem | undefined
}) {
  const report = useMemo(() => {
    if (!kase || !settings) return null
    const selection = selectForReport(findings, chains, reviews, settings)
    const grouped = buildIncidents(selection.findings, { chains: selection.chains, severityOf: (c) => chainSeverity(c, reviews[c.id]) })
    const membersOf = new Map(grouped.filter((i) => i.kind === 'chain' && i.chain).map((i) => [i.chain!.id, i.findings.filter((f) => f.ruleId !== 'chain')]))
    const data: ReportData = {
      kase,
      generatedAt: 0,
      settings,
      summary: '',
      evidence,
      chains: selection.chains,
      reviews,
      membersOf,
      graphs: {},
      campaignInsights: [],
      incidents: grouped.filter((i) => i.kind !== 'chain'),
      findings: selection.findings,
      iocs: [],
      timeline: [],
      tasks: [],
      notes: [],
      undecided,
      unprintedConfirmed: unprintedConfirmed(findings, chains, reviews, selection),
      decidedStories: storiesForReport(stories.result, stories.notes, stories.decisions, findings, settings.minSeverity, settings.onlyReviewed).decided,
    }
    return { data, verdict: computeVerdict(data), confidence: computeConfidence(data), profile: threatProfile(data) }
  }, [kase, settings, findings, chains, reviews, evidence, undecided, stories])
  /** what the verdict becomes if the current incident gets this status, or the current chain this verdict */
  const effectOf = useCallback(
    (decision: string): string | null => {
      if (!report || !current) return null
      const d = report.data
      let next: ReportData
      if (current.kind === 'chain' && current.chain) {
        const c = current.chain
        const r: ChainReview = { ...(reviews[c.id] ?? {}), verdict: decision as Verdict }
        next = { ...d, reviews: { ...reviews, [c.id]: r }, undecided: d.undecided - (reviews[c.id]?.verdict ? 0 : 1) }
      } else if (current.incident) {
        const inc = current.incident
        next = {
          ...d,
          incidents: d.incidents.map((i) => (i.id === inc.id ? { ...i, status: decision as Status } : i)),
          undecided: d.undecided - (inc.status === 'new' ? 1 : 0),
        }
        if (!d.incidents.some((i) => i.id === inc.id) && decision === 'escalated') next.incidents = [...next.incidents, { ...inc, status: 'escalated' }]
      } else return null
      const v = computeVerdict(next)
      return v.label === report.verdict.label ? null : v.label
    },
    [report, current, reviews],
  )
  return { report, effectOf }
}
