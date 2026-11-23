import { useCallback, useEffect, useMemo, useState } from 'react'
import { loadRules, type LoadedRule } from '../../data/rules'
import { decisionCases, loadDecisionSources, loadPastDecisions, saveDecisionSources, type DecisionCase, type PastDecision } from '../../data/findingPriority'
import { findingsStaleness, type Staleness } from '../../data/findingsState'
import { getDb, type Case, type Finding } from '../../db/schema'
import { effectiveSeverity } from '../../rules/incidents'
import { loadChains, type Chain } from '../../data/chains'
import { loadChainReviews, type ChainReview } from '../../data/review'
import { useStore } from '../../state/store'
import { ORDER, type LastRun } from './model'

/**
 * What the Findings page reads for a case: its findings, chains and their reviews, the rules, the
 * last run and the counts before it, whether the findings are behind the evidence, and the past
 * decisions the priority reads (this case's, and those of the other cases the analyst chose).
 */
export function useFindingsData(kase: Case | null) {
  const rulesVersion = useStore((s) => s.rulesVersion)
  const running = useStore((s) => s.rulesRun)
  const [all, setAll] = useState<Finding[]>([])
  const [chains, setChains] = useState<Chain[]>([])
  const [chainReviews, setChainReviews] = useState<Record<string, ChainReview>>({})
  // the analysts' false positives and escalations of this case, and of the other cases the analyst chose for it, for the priority
  const [memory, setMemory] = useState<PastDecision[]>([])
  const [otherCases, setOtherCases] = useState<DecisionCase[]>([])
  // the other cases the analyst chose for this one, once read for it
  const [chosen, setChosen] = useState<{ caseId: number; ids: number[] } | null>(null)
  const sources = useMemo(() => (chosen && chosen.caseId === kase?.id ? chosen.ids : null), [chosen, kase?.id])
  const [rules, setRules] = useState<LoadedRule[]>([])
  const [lastRun, setLastRun] = useState<LastRun | null>(null)
  const [previous, setPrevious] = useState<Record<string, number> | null>(null)
  const [stale, setStale] = useState<Staleness | null>(null)

  const reload = useCallback(() => {
    if (!kase?.id) return
    const db = getDb()
    db.findings
      .where('caseId')
      .equals(kase.id)
      .toArray()
      .then((f) => setAll(f.sort((a, b) => ORDER.indexOf(effectiveSeverity(a)) - ORDER.indexOf(effectiveSeverity(b)) || (b.ts ?? 0) - (a.ts ?? 0))))
    db.kv.get(`ruleDiags-${kase.id}`).then((k) => setLastRun((k?.value as LastRun) ?? null))
    loadChains(kase.id).then((r) => setChains(r?.chains ?? []))
    loadChainReviews(kase.id).then(setChainReviews)
    db.kv.get(`findingCounts-${kase.id}`).then((k) => setPrevious(((k?.value as { previous?: Record<string, number> }) ?? {}).previous ?? null))
    findingsStaleness(kase.id)
      .then(setStale)
      .catch(() => setStale(null))
  }, [kase?.id])
  useEffect(() => {
    reload()
  }, [reload, rulesVersion])
  useEffect(() => {
    if (kase) loadRules(kase.id!).then(setRules)
  }, [kase, rulesVersion])
  useEffect(() => {
    if (!kase?.id) return
    let alive = true
    const caseId = kase.id
    loadDecisionSources(caseId)
      .then((ids) => alive && setChosen({ caseId, ids }))
      .catch(() => alive && setChosen({ caseId, ids: [] }))
    return () => {
      alive = false
    }
  }, [kase?.id])
  useEffect(() => {
    // nothing is read until this case's own choice is known, so another case's choice never applies to it
    if (!kase?.id || !sources) return
    let alive = true
    const caseId = kase.id
    Promise.all([loadPastDecisions(caseId, sources), decisionCases(caseId)])
      .then(([m, cases]) => {
        if (!alive) return
        setMemory(m)
        setOtherCases(cases)
      })
      .catch(() => alive && setMemory([]))
    return () => {
      alive = false
    }
  }, [all, sources, kase?.id])
  const chooseSource = (other: number, on: boolean) => {
    if (!kase?.id || !sources) return
    const ids = on ? [...sources, other] : sources.filter((id) => id !== other)
    setChosen({ caseId: kase.id, ids })
    saveDecisionSources(kase.id, ids).catch(() => undefined)
  }
  // a rule run just finished elsewhere (auto-run after ingest): refresh the staleness banner
  useEffect(() => {
    if (!running && kase?.id)
      findingsStaleness(kase.id)
        .then(setStale)
        .catch(() => undefined)
  }, [running, kase?.id])

  return { all, chains, chainReviews, rules, lastRun, previous, stale, memory, otherCases, sources, chooseSource, reload }
}
