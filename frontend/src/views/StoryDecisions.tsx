import { useState } from 'react'
import { CopyButton, Dot } from '../components/ui'
import type { StoryStep } from '../data/stories'
import { downloadTimeline, timelineMarkdown } from '../data/storyExport'
import { decisionSummary, dismissed, mergeCheck, needsReason, STORY_VERDICT_LABEL, STORY_VERDICTS, type StepCall, type StoryDecision, type StoryVerdict, type StoryView } from '../data/storyDecisions'
import { fmtNum, fmtTs } from '../util/format'

/**
 * The analyst's decisions on a story (data/storyDecisions.ts, docs/stories.md "Decisions"): the
 * decision on the story, a step confirmed, disputed, taken out or split at, a story merged into
 * another, the timeline exported, the list of what was decided with a way back from each, and the
 * decisions whose story a rebuild no longer holds. Every one carries a reason; the page asks in
 * place, never in a browser dialog.
 */

const when = (t: number) => fmtTs(t)

/** The decision on a story (or on the second part of a split one), with its reason. */
export function StoryCallBar({ view, onDecide }: { view: StoryView; onDecide: (verdict: StoryVerdict, reason: string) => Promise<void> }) {
  const saved = view.call
  const [pick, setPick] = useState<StoryVerdict>(saved?.verdict ?? 'open')
  const [reason, setReason] = useState(saved?.reason ?? '')
  const [busy, setBusy] = useState(false)
  const dirty = pick !== (saved?.verdict ?? 'open') || reason.trim() !== (saved?.reason ?? '')
  const missing = needsReason(pick) && !reason.trim()
  const withIt = view.part === 'story' ? view.merged.length : 0
  const save = async () => {
    setBusy(true)
    try {
      await onDecide(pick, reason)
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="story-decide" role="group" aria-label="Story decision">
      <span className="lbl">{view.part === 'split' ? 'Decision on this part' : 'Decision'}</span>
      <div className="segmented">
        {STORY_VERDICTS.map((v) => (
          <button key={v.id} className={pick === v.id ? 'active ' + v.id : ''} aria-pressed={pick === v.id} onClick={() => setPick(v.id)}>
            {v.label}
          </button>
        ))}
      </div>
      <input
        className="input"
        aria-label="Reason for the story decision"
        placeholder={needsReason(pick) ? 'why (required): what the records show' : 'why (optional)'}
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        style={{ flex: 1, minWidth: 180 }}
      />
      <button className="btn sm" disabled={!dirty || missing || busy} onClick={save} title={missing ? 'a confirmed, benign or false positive story needs a reason: the report prints it' : ''}>
        Save decision
      </button>
      {saved && !dirty && saved.verdict !== 'open' && (
        <span className="small muted" role="status">
          decided {STORY_VERDICT_LABEL[saved.verdict]} · {when(saved.decidedAt)}
        </span>
      )}
      {dirty && dismissed(pick) && withIt > 0 && (
        <span className="small" role="note" style={{ color: 'var(--sev-medium)' }}>
          {withIt === 1 ? 'The story merged into this one is' : `The ${withIt} stories merged into this one are`} dismissed with it.
        </span>
      )}
    </div>
  )
}

/** Export the timeline, and merge the story into another, asking in the page when the two are of different organisations. */
export function StoryTools({
  view,
  views,
  labels,
  onMerge,
}: {
  view: StoryView
  views: StoryView[]
  labels: Map<string, string>
  onMerge: (target: StoryView, reason: string, orgs?: string[]) => Promise<void>
}) {
  const [merging, setMerging] = useState(false)
  const [target, setTarget] = useState('')
  const [reason, setReason] = useState('')
  const [asking, setAsking] = useState<string[] | null>(null)
  const into = views.find((v) => v.story.id === target) ?? null
  const check = into ? mergeCheck(view, into) : null
  const cannot = view.part === 'split' ? 'The second part of a split story is not merged: undo the split first.' : view.split ? 'A story split in two is not merged: undo the split first.' : ''
  const close = () => {
    setMerging(false)
    setTarget('')
    setReason('')
    setAsking(null)
  }
  const merge = async (orgs?: string[]) => {
    if (!into) return
    await onMerge(into, reason, orgs)
    close()
  }
  const submit = () => {
    if (!check?.ok) return
    if (check.orgs) setAsking(check.orgs)
    else void merge()
  }
  return (
    <div className="col" style={{ gap: 6 }}>
      <div className="row wrap small" style={{ gap: 6 }}>
        <span className="muted">timeline:</span>
        <button className="btn xs" aria-label="export the timeline as CSV" onClick={() => downloadTimeline('csv', view, labels)} title="one row per step, times in UTC">
          CSV
        </button>
        <button className="btn xs" aria-label="export the timeline as JSON" onClick={() => downloadTimeline('json', view, labels)}>
          JSON
        </button>
        <button className="btn xs" aria-label="export the timeline as Markdown" onClick={() => downloadTimeline('md', view, labels)} title="a table to paste into a report">
          Markdown
        </button>
        <CopyButton text={timelineMarkdown(view, labels)} label="copy Markdown" />
        <span className="spacer" />
        <button className="btn xs" disabled={!!cannot} title={cannot || 'read this story as part of another one'} onClick={() => (merging ? close() : setMerging(true))}>
          {merging ? 'cancel merge' : 'merge into another story'}
        </button>
      </div>
      {merging && (
        <div className="panel col" role="region" aria-label="Merge the story" style={{ padding: '8px 10px', gap: 6 }}>
          <div className="small muted">
            The steps of this story become steps of the story you pick, which keeps its name. It is the analyst&apos;s reading, applied to every build; undo it from the Decisions tab.
          </div>
          <div className="row wrap" style={{ gap: 6 }}>
            <select
              className="select"
              aria-label="Story to merge into"
              value={target}
              onChange={(e) => {
                setTarget(e.target.value)
                setAsking(null)
              }}
              style={{ flex: 1, minWidth: 200 }}
            >
              <option value="">pick the story it belongs to</option>
              {views
                .filter((v) => v.part === 'story' && v.base.id !== view.base.id)
                .map((v) => (
                  <option key={v.story.id} value={v.story.id}>
                    {v.story.title} · {v.story.severity} · {fmtTs(v.story.start)}
                    {v.call && v.call.verdict !== 'open' ? ` · ${STORY_VERDICT_LABEL[v.call.verdict]}` : ''}
                  </option>
                ))}
            </select>
            <input
              className="input"
              aria-label="Reason for the merge"
              placeholder="why they are one incident (required)"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              style={{ flex: 2, minWidth: 200 }}
            />
            <button className="btn sm" disabled={!into || !check?.ok || !reason.trim() || !!asking} onClick={submit}>
              Merge
            </button>
          </div>
          {check && !check.ok && (
            <div className="small" role="alert" style={{ color: 'var(--danger)' }}>
              {check.why}
            </div>
          )}
          {asking && (
            <div className="panel row wrap" role="alertdialog" aria-label="Merge across organisations" style={{ padding: '6px 10px', gap: 8, borderColor: 'var(--sev-medium)' }}>
              <span className="small">
                This story is about <strong>{asking[0]}</strong> and the one you picked about <strong>{asking[1]}</strong>: two organisations. Merge them anyway? The report says so.
              </span>
              <span className="spacer" />
              <button className="btn xs primary" onClick={() => void merge(asking)}>
                merge across organisations
              </button>
              <button className="btn xs ghost" onClick={() => setAsking(null)}>
                keep them apart
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

type StepMode = 'confirmed' | 'disputed' | 'out' | 'split'

/** The analyst's decision on a step: confirm it, dispute it (and, if asked, mark its findings false positive), take it out, or split the story at it. */
export function StepDecisionPanel({
  view,
  step,
  onCall,
  onOut,
  onSplit,
}: {
  view: StoryView
  step: StoryStep
  onCall: (verdict: StepCall['verdict'] | null, reason: string, alsoFalsePositive: boolean) => Promise<void>
  onOut: (reason: string) => Promise<void>
  onSplit: (reason: string) => Promise<void>
}) {
  const call = view.steps.get(step.id)
  const [mode, setMode] = useState<StepMode | null>(null)
  const [reason, setReason] = useState('')
  const [alsoFp, setAlsoFp] = useState(false)
  const [busy, setBusy] = useState(false)
  const keyed = step.findings.filter((f) => f.key)
  const splitWhy =
    view.part === 'split'
      ? 'This is the second part of a split story: undo that split first.'
      : view.split
        ? 'The story is split already: undo that split first.'
        : view.story.steps[0]?.id === step.id
          ? 'Nothing comes before the first step.'
          : ''
  const required = mode === 'out' || mode === 'split'
  const open = (m: StepMode) => {
    setMode(mode === m ? null : m)
    setReason('')
    setAlsoFp(false)
  }
  const run = async (f: () => Promise<void>) => {
    setBusy(true)
    try {
      await f()
      setMode(null)
      setReason('')
      setAlsoFp(false)
    } finally {
      setBusy(false)
    }
  }
  const submit = () => run(() => (mode === 'out' ? onOut(reason) : mode === 'split' ? onSplit(reason) : onCall(mode as StepCall['verdict'], reason, mode === 'disputed' && alsoFp)))
  const SUBMIT: Record<StepMode, string> = {
    confirmed: 'Confirm step',
    disputed: 'Dispute step',
    out: `Take ${step.count === 1 ? 'it' : `its ${fmtNum(step.count)} records`} out`,
    split: 'Split here',
  }
  return (
    <div className="section" role="group" aria-label="Step decision">
      <h3>Your decision</h3>
      {call ? (
        <div className="small row wrap" style={{ gap: 6 }}>
          <span className={'step-call ' + call.verdict}>{call.verdict === 'disputed' ? 'disputed' : 'confirmed'}</span>
          <span>
            {call.verdict === 'disputed' ? 'left out of the story’s phases and severity' : 'the step and its tie'}
            {call.reason ? `: ${call.reason}` : ''} · {when(call.decidedAt)}
          </span>
          <button className="btn xs ghost" disabled={busy} onClick={() => run(() => onCall(null, '', false))}>
            take back
          </button>
        </div>
      ) : (
        <div className="small muted">Confirm the step and its tie, dispute it, take it out of the story, or start a story of its own here.</div>
      )}
      <div className="row wrap" style={{ gap: 6, marginTop: 6 }}>
        <button className={'btn xs' + (mode === 'confirmed' ? ' active' : '')} aria-pressed={mode === 'confirmed'} onClick={() => open('confirmed')} disabled={call?.verdict === 'confirmed'}>
          confirm
        </button>
        <button className={'btn xs' + (mode === 'disputed' ? ' active' : '')} aria-pressed={mode === 'disputed'} onClick={() => open('disputed')} disabled={call?.verdict === 'disputed'}>
          dispute
        </button>
        <button className={'btn xs' + (mode === 'out' ? ' active' : '')} aria-pressed={mode === 'out'} onClick={() => open('out')} title="its records stay out of this story after every rebuild">
          not part of this story
        </button>
        <button
          className={'btn xs' + (mode === 'split' ? ' active' : '')}
          aria-pressed={mode === 'split'}
          onClick={() => open('split')}
          disabled={!!splitWhy}
          title={splitWhy || 'this step and the ones after it become a story of their own'}
        >
          split the story here
        </button>
      </div>
      {mode && (
        <div className="col" style={{ gap: 6, marginTop: 6 }}>
          <input
            className="input"
            aria-label="Reason for the step decision"
            placeholder={required ? 'why (required)' : 'why (optional)'}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            autoFocus
          />
          {mode === 'disputed' && keyed.length > 0 && (
            <label className="small row" style={{ gap: 6, alignItems: 'flex-start' }}>
              <input type="checkbox" checked={alsoFp} onChange={(e) => setAlsoFp(e.target.checked)} aria-label="also mark the finding false positive" />
              <span>
                also mark {keyed.length === 1 ? 'its finding' : `its ${keyed.length} findings`} false positive ({keyed.map((f) => f.title).join('; ')}), as the Findings page would: disputing a step
                alone leaves the findings as they are.
              </span>
            </label>
          )}
          {mode === 'split' && (
            <div className="small muted">
              This step and the {fmtNum(view.story.steps.length - view.story.steps.findIndex((s) => s.id === step.id) - 1)} after it become a story of their own, with its own decision.
            </div>
          )}
          <div className="row" style={{ gap: 6 }}>
            <button className="btn xs primary" disabled={busy || (required && !reason.trim())} onClick={submit}>
              {SUBMIT[mode]}
            </button>
            <button className="btn xs ghost" onClick={() => setMode(null)}>
              cancel
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function Line({ children }: { children: React.ReactNode }) {
  return (
    <div className="small row wrap" style={{ gap: 6, alignItems: 'baseline', marginBottom: 4 }}>
      {children}
    </div>
  )
}

const reasonOf = (r: { reason: string; decidedAt: number }) => (
  <span className="muted">
    {r.reason ? `${r.reason} · ` : ''}
    {when(r.decidedAt)}
  </span>
)

/** What the analyst decided on the story, each with its reason and a way back. */
export function DecisionsPanel({
  view,
  onOpenStep,
  onUndoCall,
  onUndoStep,
  onDropLost,
  onPutBack,
  onUnsplit,
  onUnmerge,
}: {
  view: StoryView
  onOpenStep: (id: string) => void
  onUndoCall: () => void
  onUndoStep: (step: StoryStep) => void
  onDropLost: (lost: StoryView['lostSteps'][number]) => void
  onPutBack: (out: StoryView['out'][number]) => void
  onUnsplit: () => void
  onUnmerge: (merged: { key: string | null; story: StoryView['base'] } | null) => void
}) {
  const calls = view.story.steps.filter((s) => view.steps.has(s.id))
  return (
    <div className="view-body col" style={{ gap: 14 }} role="region" aria-label="Decisions on the story">
      <div className="section">
        <h3>The story</h3>
        {view.call && view.call.verdict !== 'open' ? (
          <Line>
            <span className={'story-call ' + view.call.verdict}>{STORY_VERDICT_LABEL[view.call.verdict]}</span>
            {reasonOf(view.call)}
            <button className="btn xs ghost" onClick={onUndoCall}>
              set back to open
            </button>
          </Line>
        ) : (
          <div className="small muted">Open: no decision yet. Decide it under the story&apos;s summary; a confirmed story counts in the report&apos;s verdict as a confirmed incident does.</div>
        )}
      </div>
      <div className="section">
        <h3>Steps</h3>
        {!calls.length && !view.lostSteps.length && <div className="small muted">No step confirmed or disputed.</div>}
        {calls.map((s) => {
          const c = view.steps.get(s.id)!
          return (
            <Line key={s.id}>
              <span className={'step-call ' + c.verdict}>{c.verdict}</span>
              <span className="click" onClick={() => onOpenStep(s.id)} style={{ cursor: 'pointer' }}>
                {s.title}
              </span>
              <span className="muted">{fmtTs(s.ts)}</span>
              {reasonOf(c)}
              <button className="btn xs ghost" onClick={() => onUndoStep(s)}>
                take back
              </button>
            </Line>
          )
        })}
        {view.lostSteps.map((l, i) => (
          <Line key={'lost' + i}>
            <span className={'step-call ' + l.call.verdict}>{l.call.verdict}</span>
            <span>{l.call.title}</span>
            <span className="muted">{fmtTs(l.call.ts)} · no longer in this story: the stories were built again without it</span>
            {reasonOf(l.call)}
            <button className="btn xs ghost" onClick={() => onDropLost(l)}>
              delete
            </button>
          </Line>
        ))}
      </div>
      {(view.out.length > 0 || view.part === 'story') && (
        <div className="section">
          <h3>Records taken out</h3>
          {!view.out.length && <div className="small muted">None: every record the build ties to the story is in it.</div>}
          {view.out.map((o, i) => (
            <Line key={'out' + i}>
              <span>{o.out.title}</span>
              <span className="muted">
                {fmtTs(o.out.ts)} · {fmtNum(o.out.rows.length)} record(s){o.found ? `, ${fmtNum(o.found)} of them in the story this build` : ', none of them in the story this build'}
              </span>
              {reasonOf(o.out)}
              <button className="btn xs ghost" onClick={() => onPutBack(o)}>
                put back
              </button>
            </Line>
          ))}
        </div>
      )}
      {(view.merged.length > 0 || view.mergeLost) && (
        <div className="section">
          <h3>Merged</h3>
          {view.merged.map((m) => (
            <Line key={m.story.id}>
              <span>
                The story of <strong>{m.story.title}</strong> is read as part of this one
              </span>
              {m.merge.orgs && <span className="muted">(another organisation: {m.merge.orgs.join(' and ')})</span>}
              {reasonOf(m.merge)}
              <button className="btn xs ghost" onClick={() => onUnmerge({ key: m.key, story: m.story })}>
                undo the merge
              </button>
            </Line>
          ))}
          {view.mergeLost && (
            <Line>
              <span>Merged into the story of {view.mergeLost.into.title}, which the stories no longer hold: it reads on its own until you undo the merge.</span>
              {reasonOf(view.mergeLost)}
              <button className="btn xs ghost" onClick={() => onUnmerge(null)}>
                undo the merge
              </button>
            </Line>
          )}
        </div>
      )}
      {view.split && (
        <div className="section">
          <h3>Split</h3>
          <Line>
            <span>
              {view.part === 'split' ? 'The second part of the story, from' : 'Split in two at'} “{view.split.title}” ({fmtTs(view.split.ts)})
            </span>
            {!view.split.applied && <span className="muted">not applied: the stories no longer hold that step after another</span>}
            {reasonOf(view.split)}
            <button className="btn xs ghost" onClick={onUnsplit}>
              undo the split
            </button>
          </Line>
        </div>
      )}
    </div>
  )
}

/** The decisions whose story the stories no longer hold: kept, to put on the open story or delete (asked in the page). */
export function OrphanDecisions({
  orphans,
  story,
  onAttach,
  onDelete,
}: {
  orphans: { key: string; entry: StoryDecision }[]
  story: StoryView | null
  onAttach: (key: string) => void
  onDelete: (key: string) => void
}) {
  const [asking, setAsking] = useState<string | null>(null)
  return (
    <div className="section" role="region" aria-label="Decisions whose story is gone" style={{ padding: '10px 14px', borderTop: '1px solid var(--line)' }}>
      <h3>Decisions whose story is gone ({orphans.length})</h3>
      <div className="small muted" style={{ lineHeight: 1.5 }}>
        The stories were built again and none of them is what these decisions were taken on. They are kept and do not count in the report: open the story they belong to and attach them, or delete
        them.
      </div>
      {orphans.map((o) => (
        <div key={o.key} className="col" style={{ gap: 3, marginTop: 10 }}>
          <div className="small">
            <strong>{o.entry.anchor.title}</strong> <span className="muted">· {fmtTs(o.entry.anchor.start, { date: true }).slice(0, 10)}</span>
          </div>
          <div className="small" style={{ color: 'var(--fg-2)' }}>
            {decisionSummary(o.entry) || 'nothing decided'}
            {o.entry.call?.reason ? `: ${o.entry.call.reason}` : ''}
          </div>
          {asking === o.key ? (
            <div className="row" style={{ gap: 6 }} role="alertdialog" aria-label="Delete the decisions">
              <span className="small">Delete them? This cannot be undone.</span>
              <button className="btn xs danger" onClick={() => onDelete(o.key)}>
                delete for good
              </button>
              <button className="btn xs ghost" onClick={() => setAsking(null)}>
                keep
              </button>
            </div>
          ) : (
            <div className="row" style={{ gap: 6 }}>
              <button
                className="btn xs"
                disabled={!story || story.part !== 'story'}
                onClick={() => onAttach(o.key)}
                title={story ? `put these decisions on the story of ${story.story.title}` : 'open a story first'}
              >
                attach to the open story
              </button>
              <button className="btn xs ghost" onClick={() => setAsking(o.key)}>
                delete
              </button>
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

/** The mark of a story's decision in the list. */
export function StoryCallTag({ view }: { view: StoryView | undefined }) {
  if (!view) return null
  const call = view.call
  return (
    <>
      {call && call.verdict !== 'open' && (
        <span className={'story-call ' + call.verdict} title={call.reason}>
          {STORY_VERDICT_LABEL[call.verdict]}
        </span>
      )}
      {view.part === 'split' && <span title={`split by the analyst at ${view.split?.title ?? ''}`}>second part</span>}
      {view.part === 'story' && view.merged.length > 0 && <span title={view.merged.map((m) => m.story.title).join(', ')}>+{view.merged.length} merged</span>}
    </>
  )
}

/** The mark of the analyst's call on a step in the timeline. */
export function StepCallTag({ call }: { call: StepCall | undefined }) {
  if (!call) return null
  return (
    <span className={'step-call ' + call.verdict} title={call.reason || undefined}>
      <Dot sev={call.verdict === 'confirmed' ? 'ok' : 'info'} /> {call.verdict} by the analyst
    </span>
  )
}
