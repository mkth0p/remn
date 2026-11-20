import { useRef, useState } from 'react'
import { applySuggestion, loadSuggestions, removeSuggestion, runTriage, undoEntry, type Suggestion, type TriageEntry, type TriageProgress, type TriageRun } from '../../data/aiReview'
import { loadChainReviews, type ChainReview, type ReviewItem } from '../../data/review'
import { getDb, type Case } from '../../db/schema'
import { toast, useStore } from '../../state/store'

/** Whether the analyst model answers; says where to set it up when it does not. */
export function modelReady(): boolean {
  if (useStore.getState().aiStatus.reachable === true) return true
  toast('err', 'the analyst model is not reachable (see the AI section in Settings)')
  return false
}

/**
 * The model's part on the Review page: a proposal asked for one item, a triage of the queue with
 * its progress and a way to stop it, a proposal applied or dismissed, and the undo of what an older
 * triage wrote.
 */
export function useReviewTriage({
  kase,
  queue,
  reviews,
  setReviews,
  setSuggestions,
  lastRun,
  setLastRun,
  reload,
}: {
  kase: Case | null
  queue: ReviewItem[]
  reviews: Record<string, ChainReview>
  setReviews: (r: Record<string, ChainReview>) => void
  setSuggestions: (s: Record<string, Suggestion>) => void
  lastRun: TriageRun | null
  setLastRun: (r: TriageRun) => void
  reload: () => void
}) {
  const caseId = kase?.id
  const [showRun, setShowRun] = useState(false)
  const [askTriage, setAskTriage] = useState(false)
  const [triageDecided, setTriageDecided] = useState(false)
  const [triage, setTriage] = useState<TriageProgress | null>(null)
  const triageAbort = useRef<AbortController | null>(null)
  const [suggesting, setSuggesting] = useState(false)
  const stop = () => triageAbort.current?.abort()

  const suggestOne = async (it: ReviewItem) => {
    if (!kase || !modelReady()) return
    setSuggesting(true)
    try {
      const run = await runTriage(kase, [it], reviews)
      if (run.errors.length) toast('err', run.errors.join('; '), 0)
      else if (!run.entries.length) toast('err', `the model gave no usable decision${run.rejected.length ? `: ${run.rejected[0]}` : ''}`, 0)
      reload()
    } finally {
      setSuggesting(false)
    }
  }
  const accept = async (it: ReviewItem, s: Suggestion) => {
    if (!caseId) return
    await applySuggestion(caseId, it, s, reviews)
    setReviews(await loadChainReviews(caseId))
    reload()
  }
  const dismiss = async (target: string) => {
    if (!caseId) return
    setSuggestions(await removeSuggestion(caseId, target))
  }
  const startTriage = async () => {
    if (!kase || !modelReady()) return
    const items = triageDecided ? queue : queue.filter((it) => !it.done)
    setAskTriage(false)
    if (!items.length) return toast('ok', 'nothing to triage')
    const controller = new AbortController()
    triageAbort.current = controller
    setTriage({ done: 0, total: items.length, batch: 0, batches: 0 })
    try {
      // The model proposes; the analyst decides. Text in the evidence (a mail subject becomes an
      // incident title) can steer a model, and a pass that wrote its answers straight away could
      // take a critical incident out of the report with nobody looking. Each proposal waits on its
      // item, with its reason, for the analyst to apply or dismiss.
      const run = await runTriage(kase, items, reviews, {
        signal: controller.signal,
        onProgress: setTriage,
      })
      setSuggestions(await loadSuggestions(kase.id!))
      setLastRun(run)
      setShowRun(true)
      setReviews(await loadChainReviews(kase.id!))
      reload()
    } catch (e) {
      toast('err', `triage: ${(e as Error).message}`, 0)
    } finally {
      triageAbort.current = null
      setTriage(null)
    }
  }
  const undo = async (entry: TriageEntry) => {
    if (!caseId || !lastRun) return
    await undoEntry(caseId, entry)
    const run = { ...lastRun, entries: lastRun.entries.map((e) => (e.id === entry.id ? { ...e, undone: true } : e)) }
    setLastRun(run)
    await getDb().kv.put({ key: `ai-triage-${caseId}`, value: run })
    setReviews(await loadChainReviews(caseId))
    reload()
  }
  const undoAll = async () => {
    if (!caseId || !lastRun) return
    for (const e of lastRun.entries) if (!e.undone) await undoEntry(caseId, e)
    const run = { ...lastRun, entries: lastRun.entries.map((e) => ({ ...e, undone: true })) }
    setLastRun(run)
    await getDb().kv.put({ key: `ai-triage-${caseId}`, value: run })
    setReviews(await loadChainReviews(caseId))
    reload()
  }

  return { showRun, setShowRun, askTriage, setAskTriage, triageDecided, setTriageDecided, triage, stop, suggesting, suggestOne, accept, dismiss, startTriage, undo, undoAll }
}
