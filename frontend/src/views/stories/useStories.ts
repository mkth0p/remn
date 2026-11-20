import { useCallback, useEffect, useEffectEvent, useRef, useState } from 'react'
import { loadEvidenceGaps, type GapStatement } from '../../data/evidenceGaps'
import { readMeasure, type MeasureReading } from '../../data/ruleMeasures'
import { loadRules } from '../../data/rules'
import { getSource } from '../../data/source'
import { applyStoryDecisions, loadStoryDecisions, splitId, type StoryDecisions, type StoryView } from '../../data/storyDecisions'
import { buildStories, cheapToRebuild, findStory, loadStories, loadStoryNotes, storiesStaleness, storyInputs, type StoryNotes, type StoryResult } from '../../data/stories'
import { getDb, type Case } from '../../db/schema'
import { toast, useStore } from '../../state/store'
import { fmtNum } from '../../util/format'
import type { Follow } from './model'

/**
 * The stories of a case as the page reads them: the snapshot, the analyst's notes and decisions,
 * the rule measures and the case's gaps, whether the snapshot still reads the case as it is, the
 * story and step open, and the build that keeps what was open.
 */
export function useStories(kase: Case | null) {
  const setFocusChain = useStore((s) => s.setFocusChain)
  const bump = useStore((s) => s.bumpRules)
  const rulesVersion = useStore((s) => s.rulesVersion)
  const [res, setRes] = useState<StoryResult | null>(null)
  const [loaded, setLoaded] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  /** why the snapshot no longer reads the case as it is; empty when it does */
  const [stale, setStale] = useState<string[]>([])
  /** what the page could not open as asked: a story or step a link points to that the stories no longer hold */
  const [notice, setNotice] = useState('')
  const [notes, setNotes] = useState<StoryNotes>({})
  /** the analyst's decisions on the stories, applied to every build (data/storyDecisions.ts) */
  const [decisions, setDecisions] = useState<StoryDecisions>({})
  // what a build applies to the stories it returns, read when it returns
  const decisionsRef = useRef<StoryDecisions>({})
  useEffect(() => {
    decisionsRef.current = decisions
  }, [decisions])
  const [storyId, setStoryId] = useState<string | null>(null)
  const [stepId, setStepId] = useState<string | null>(null)
  const [readings, setReadings] = useState<Map<string, MeasureReading>>(new Map())
  const [caseGaps, setCaseGaps] = useState<GapStatement[]>([])

  /**
   * Build the stories. What was open stays open: the story (followed by what it shares when its id
   * changed) and its step, or the story a link asked for; the page says so when it is gone.
   */
  const build = useCallback(
    async (follow?: Follow | null) => {
      if (!kase) return
      setBusy(true)
      setError('')
      try {
        const r = await buildStories(kase)
        setRes(r)
        setStale([])
        // the analyst's decisions apply to the new build as to the last: what was open is found among the stories as they show
        const decided = applyStoryDecisions(r, decisionsRef.current)
        let next: StoryView | null = null
        if (follow && 'link' in follow) {
          next = decided.views.find((v) => v.story.id === follow.link || v.story.chains.includes(follow.link)) ?? decided.byId.get(follow.link) ?? null
          if (next) setNotice('')
        } else if (follow) {
          const found = findStory(follow.story, follow.identities, r.stories, r.identities)
          next = found ? (decided.byId.get(found.id) ?? null) : null
          // the second part of a split story that was open stays open
          if (next && follow.story.id.endsWith('~2')) next = decided.byId.get(splitId(next.base.id)) ?? next
          if (!next) setNotice(`The story of ${follow.story.title} that was open is not among the stories built again: pick one from the list.`)
        }
        setStoryId(follow ? (next?.story.id ?? null) : (decided.views[0]?.story.id ?? null))
        setStepId(follow?.step && next?.story.steps.some((s) => s.id === follow.step) ? follow.step : null)
        bump()
        toast(
          r.stories.length ? 'ok' : 'warn',
          `${r.stories.length} ${r.stories.length === 1 ? 'story' : 'stories'} and ${r.campaigns.length} campaign(s) from ${fmtNum(Number(r.stats.events ?? 0))} event(s) and ${fmtNum(Number(r.stats.mails ?? 0))} mail(s)`,
        )
      } catch (e) {
        setError((e as Error).message)
      } finally {
        setBusy(false)
      }
    },
    [kase, bump],
  )

  // the snapshot, the notes, the rule measures and the case's gaps. A case with findings and no snapshot is read
  // into stories at once, and so is an out-of-date snapshot when building it again is cheap.
  const load = useEffectEvent((isAlive: () => boolean) => {
    if (!kase?.id) return
    setLoaded(false)
    setRes(null)
    setNotice('')
    Promise.all([loadStories(kase.id), loadStoryNotes(kase.id), loadStoryDecisions(kase.id)]).then(async ([r, n, d]) => {
      if (!isAlive()) return
      setRes(r)
      setNotes(n)
      setDecisions(d)
      decisionsRef.current = d
      // a link from the case timeline or the review: a chain's story, or a story and, after '#', one of its steps
      const want = useStore.getState().focusChain
      if (want) setFocusChain(null)
      const wantId = want ? want.split('#')[0] : null
      const wantStep = want && want.includes('#') ? want.slice(want.indexOf('#') + 1) : null
      const decided = applyStoryDecisions(r, d)
      const focus = wantId ? (decided.views.find((v) => v.story.chains.includes(wantId) || v.story.id === wantId)?.story ?? decided.byId.get(wantId)?.story ?? null) : null
      const focusStep = focus && wantStep ? (focus.steps.find((s) => s.id === wantStep) ?? null) : null
      if (wantId && r && !focus) setNotice('The story this link points to is not among the stories: they were built again since it was added. Pick it from the list.')
      else if (focus && wantStep && !focusStep) setNotice(`The step this link points to is no longer in the story of ${focus.title}: it was built again since the link was added.`)
      setStoryId(focus?.id ?? (wantId ? null : (decided.views[0]?.story.id ?? null)))
      setStepId(focusStep?.id ?? null)
      setLoaded(true)
      if (!r) {
        if (await getDb().findings.where('caseId').equals(kase.id!).count()) build()
        return
      }
      const reasons = storiesStaleness(r, await storyInputs(kase))
      const open = focus ?? (wantId ? null : (decided.views[0]?.story ?? null))
      if (isAlive() && reasons.length && cheapToRebuild(r)) build(open ? { story: open, identities: r.identities, step: focusStep?.id } : wantId ? { link: wantId, step: wantStep ?? undefined } : null)
    })
    loadRules(kase.id)
      .then((rules) => isAlive() && setReadings(new Map(rules.map((r) => [r.rule.id, readMeasure(r.measured, r.origin)]))))
      .catch(() => {})
    loadEvidenceGaps(kase.id, getSource(kase))
      .then((gaps) => isAlive() && setCaseGaps(gaps))
      .catch(() => {})
  })
  // read again on a case change only: the case object changes with every settings edit, and build with it
  const caseId = kase?.id
  useEffect(() => {
    if (!caseId) return
    let alive = true
    load(() => alive)
    return () => {
      alive = false
    }
  }, [caseId])

  // does the snapshot still read the case as it is? Asked again after a rule run, a decision on a finding or a settings change
  useEffect(() => {
    if (!kase?.id || !res) return setStale([])
    let alive = true
    storyInputs(kase)
      .then((now) => alive && setStale(storiesStaleness(res, now)))
      .catch(() => undefined)
    return () => {
      alive = false
    }
  }, [kase, res, rulesVersion])

  return { res, loaded, busy, error, setError, stale, notice, setNotice, notes, setNotes, decisions, setDecisions, storyId, setStoryId, stepId, setStepId, readings, caseGaps, build }
}
