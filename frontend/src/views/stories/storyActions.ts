import { decideFindings } from '../../data/findingReviews'
import {
  attachStoryDecision,
  decideStory,
  deleteStoryDecision,
  dropStepCall,
  mergeInto,
  putBack,
  setCall,
  setStepCall,
  splitAt,
  splitId,
  takeOut,
  type DecisionSource,
  type StepCall,
  type StoryDecision,
  type StoryDecisions,
  type StoryView,
} from '../../data/storyDecisions'
import { attachStoryNote, deleteStoryNote, saveStoryNote, storyAnchor, type Identity, type NoteOnStory, type OrphanNote, refRow, type Story, type StoryNotes, type StoryStep } from '../../data/stories'
import type { Case } from '../../db/schema'
import { getSource } from '../../data/source'
import type { Detail } from './model'
import { confirmAction } from '../../components/confirm'
import { toast, useStore } from '../../state/store'

/** The analyst's note on the open story: saved, a note whose story is gone attached to it, or deleted after asking. */
export function storyNoteActions({
  kase,
  story,
  identities,
  noteOf,
  setNotes,
}: {
  kase: Case
  story: Story | null
  identities: Identity[]
  /** the note on a story, found again under its anchor */
  noteOf: (id: string) => NoteOnStory | undefined
  setNotes: (n: StoryNotes) => void
}) {
  const saveNote = async (text: string) => {
    if (!story) return
    setNotes(await saveStoryNote(kase.id!, story, identities, text, noteOf(story.id)?.key))
  }
  const attachNote = async (o: OrphanNote) => {
    if (!story) return
    setNotes(await attachStoryNote(kase.id!, o.key, story, identities, noteOf(story.id)?.key))
  }
  const dropNote = async (o: OrphanNote) => {
    if (!(await confirmAction(`Delete the note written on the story of ${o.title}? It cannot be undone.`, { title: 'Delete the note', action: 'Delete', danger: true }))) return
    setNotes(await deleteStoryNote(kase.id!, o.key))
  }
  return { saveNote, attachNote, dropNote }
}

/**
 * The analyst's decisions on the stories: a call on a step (and, when asked, its findings marked
 * false positive), a step taken out, a story split at a step or merged into another, and decisions
 * whose story is gone attached to the open one or deleted.
 */
export function storyDecisionActions({
  kase,
  identities,
  view,
  setDecisions,
  setError,
  setStoryId,
  setStepId,
  bump,
}: {
  kase: Case
  identities: Identity[]
  /** the open story as the page shows it */
  view: StoryView | null
  setDecisions: (d: StoryDecisions) => void
  setError: (message: string) => void
  setStoryId: (id: string | null) => void
  setStepId: (id: string | null) => void
  /** says the findings changed */
  bump: () => void
}) {
  // the analyst's decisions: each written to the engine story it is about, the one that holds the step for a step's
  const decide = async (target: DecisionSource, change: (d: StoryDecision) => void) => {
    try {
      setDecisions(await decideStory(kase.id!, target, identities, change))
    } catch (e) {
      setError((e as Error).message)
    }
  }
  const ownerOf = (v: StoryView, st: StoryStep) => v.sources.find((src) => src.story.steps.some((x) => x.id === st.id)) ?? v.sources[0]
  const decideStep = async (v: StoryView, st: StoryStep, verdict: StepCall['verdict'] | null, reason: string, alsoFalsePositive: boolean) => {
    await decide(ownerOf(v, st), (d) => setStepCall(d, st, verdict, reason))
    // disputing a step leaves its findings as they are, unless the analyst asks: then through the findings' own review
    if (verdict !== 'disputed' || !alsoFalsePositive) return
    const why = `False positive: the analyst disputed the step "${st.title}" of the story of ${v.story.title}${reason.trim() ? `: ${reason.trim()}` : '.'}`
    const n = await decideFindings(kase.id!, st.findings.map((f) => f.key ?? '').filter(Boolean), 'false_positive', why)
    bump()
    toast('ok', `${n} finding(s) marked false positive: the stories are out of date until they are built again`)
  }
  const stepOut = async (v: StoryView, st: StoryStep, reason: string) => {
    await decide(ownerOf(v, st), (d) => takeOut(d, st, reason))
    setStepId(null)
  }
  const split = async (v: StoryView, st: StoryStep, reason: string) => {
    await decide(v.sources[0], (d) => splitAt(d, st, reason))
    setStoryId(splitId(v.base.id))
  }
  const merge = async (v: StoryView, target: StoryView, reason: string, orgs?: string[]) => {
    await decide(v.sources[0], (d) => mergeInto(d, storyAnchor(target.base, identities), reason, orgs))
    setStoryId(target.story.id)
    setStepId(null)
  }
  const attachDecision = async (key: string) => {
    if (view) setDecisions(await attachStoryDecision(kase.id!, key, view.sources[0], identities))
  }
  const dropDecision = async (key: string) => setDecisions(await deleteStoryDecision(kase.id!, key))
  // the decisions panel takes each one back
  const undoCall = (v: StoryView) => decide(v.sources[0], (d) => setCall(d, v.part, 'open', ''))
  const undoStep = (v: StoryView, st: StoryStep) => decide(ownerOf(v, st), (d) => setStepCall(d, st, null))
  const dropLost = (l: StoryView['lostSteps'][number]) => decide(l.source, (d) => dropStepCall(d, l.call))
  const putBackOut = (o: StoryView['out'][number]) => decide(o.source, (d) => putBack(d, o.out))
  const unsplit = (v: StoryView) => {
    void decide(v.sources[0], (d) => delete d.split)
    setStoryId(v.base.id)
  }
  const unmerge = (v: StoryView, m: DecisionSource | null) => decide(m ?? v.sources[0], (d) => delete d.merge)
  return { decide, decideStep, stepOut, split, merge, attachDecision, dropDecision, undoCall, undoStep, dropLost, putBackOut, unsplit, unmerge }
}

/** A step's records: one opens in its detail, several mails open on the Mails page, several events on the Events page. */
export function recordOpeners({ kase, setDetail, setError }: { kase: Case; setDetail: (d: Detail) => void; setError: (message: string) => void }) {
  const { setFocus, setView, setEventsFilter } = useStore.getState()
  const openRow = async (source: 'events' | 'mails', id: number) => {
    try {
      const ds = getSource(kase)
      if (source === 'events') {
        const row = await ds.getEvent(id)
        if (!row) throw new Error(`Event #${id} is no longer in the case. Build the stories again.`)
        setDetail({ source: 'events', row })
      } else {
        const mail = await ds.getMail(id)
        if (!mail) throw new Error(`Mail #${id} is no longer in the case. Build the stories again.`)
        setDetail({ source: 'mails', row: mail.row })
      }
    } catch (e) {
      setError((e as Error).message)
    }
  }
  const openRefs = (refs: string[]) => {
    const rows = refs.map(refRow).filter((r): r is NonNullable<ReturnType<typeof refRow>> => !!r)
    const events = rows.filter((r) => r.source === 'events').map((r) => r.id)
    if (rows.length === 1) return openRow(rows[0].source, rows[0].id)
    if (!events.length && rows.length) {
      setFocus({ source: 'mails', id: rows[0].id })
      return setView('mails')
    }
    setEventsFilter({ conditions: [{ field: 'id', op: 'in', value: events.slice(0, 500) }], sort: { field: 'ts', dir: 'asc' } })
    setView('events')
  }
  return { openRow, openRefs }
}
