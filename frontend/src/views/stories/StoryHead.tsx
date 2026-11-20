import { AddToTimeline } from '../../components/AddToTimeline'
import { IconAi, IconDownload, IconHost } from '../../components/Icons'
import { Sev } from '../../components/ui'
import type { StoryVerdict, StoryView } from '../../data/storyDecisions'
import type { NoteOnStory, Story, StoryResult } from '../../data/stories'
import { downloadAttackFlow } from '../../data/storyFlow'
import type { Case } from '../../db/schema'
import { useStore } from '../../state/store'
import { fmtNum } from '../../util/format'
import { StoryCallBar, StoryTools } from '../StoryDecisions'
import { scoreTitle, spanText } from './model'
import { StoryLinks } from './StoryList'
import { StoryNote } from './StoryNote'
import { pressable } from '../../components/pressable'

/**
 * The head of the open story: who or what it is about, its score, span and confidence, its sources,
 * hosts, campaigns and chain, the stories it links to, the analyst's note, the call on the story and
 * the tools that merge it into another.
 */
export function StoryHead({
  kase,
  story,
  view,
  res,
  byStory,
  views,
  labels,
  note,
  noteNames,
  mergedNotes,
  onSaveNote,
  onNoteDirty,
  onIdentity,
  onAsk,
  onError,
  onStory,
  onCampaign,
  onDecide,
  onMerge,
}: {
  kase: Case
  story: Story
  view: StoryView
  res: StoryResult | null
  byStory: Map<string, Story>
  views: StoryView[]
  labels: Map<string, string>
  /** the note on the story, found again under its anchor */
  note: NoteOnStory | undefined
  /** what the note is checked for */
  noteNames: string[]
  /** the notes of the stories merged into it */
  mergedNotes: { title: string; text: string }[]
  onSaveNote: (text: string) => Promise<void>
  onNoteDirty: (dirty: boolean) => void
  onIdentity: () => void
  onAsk: () => void
  onError: (message: string) => void
  onStory: (id: string) => void
  onCampaign: (id: string) => void
  onDecide: (verdict: StoryVerdict, reason: string) => Promise<void>
  onMerge: (target: StoryView, reason: string, orgs?: string[]) => Promise<void>
}) {
  const setEntity = useStore((s) => s.setEntity)
  const setFocusChain = useStore((s) => s.setFocusChain)
  const setView = useStore((s) => s.setView)
  return (
    <div className="story-head">
      <div className="row" style={{ gap: 10, alignItems: 'flex-start' }}>
        <Sev sev={story.severity} />
        <div className="col" style={{ gap: 3, flex: 1, minWidth: 0 }}>
          <div style={{ fontWeight: 600, color: 'var(--fg-1)', fontSize: 14 }}>
            <span
              {...pressable}
              className="click"
              style={{ cursor: 'pointer' }}
              onClick={() => (story.kind === 'host' ? setEntity({ kind: 'host', value: story.subject.id }) : onIdentity())}
              title={story.kind === 'host' ? 'open the host page' : 'who is who: the forms of this account'}
            >
              {story.title}
            </span>
            {view.part === 'split' && <span className="muted"> (second part)</span>}
            <span className="muted" style={{ fontWeight: 400 }}>
              {' '}
              · <span title={scoreTitle(story)}>score {story.score}</span> · {story.steps.length} steps, {fmtNum(story.records)} records over {spanText(story.end - story.start)} ·{' '}
              <span title={story.confidenceBasis ?? 'how many of its flagged steps a record ties to it'}>{story.confidence} confidence</span>
            </span>
          </div>
          <div className="small" style={{ color: 'var(--fg-1)' }}>
            {story.headline}
          </div>
          <div className="small" style={{ color: 'var(--fg-2)' }}>
            {story.summary}
          </div>
        </div>
        <AddToTimeline ts={story.start} text={`Story ${story.title}: ${story.headline}`} link={{ source: 'stories', id: story.id, label: story.title }} severity={story.severity} />
        <button className="btn sm" onClick={onAsk}>
          <IconAi /> ask the analyst
        </button>
        <button
          className="btn sm"
          onClick={() => downloadAttackFlow(kase, story, res?.identities ?? []).catch((e) => onError((e as Error).message))}
          title="the story as a MITRE Attack Flow: a STIX 2.1 bundle, one action per step of its spine"
        >
          <IconDownload /> Download Attack Flow
        </button>
      </div>
      <div className="row wrap small" style={{ gap: 6, marginTop: 8 }}>
        {story.attackerAddresses.map((ip) => (
          <span {...pressable} key={ip} className="pill" onClick={() => setEntity({ kind: 'ip', value: ip })} title="a source the story's findings name">
            {ip}
          </span>
        ))}
        {story.hosts.map((h) => (
          <span {...pressable} key={h} className="pill" onClick={() => setEntity({ kind: 'host', value: h })} title={res?.hosts.find((x) => x.key === h)?.basis ?? 'a host of the story'}>
            <IconHost /> {h}
          </span>
        ))}
        {story.campaigns.map((c) => {
          const camp = res?.campaigns.find((x) => x.id === c)
          return (
            <span {...pressable} key={c} className="pill" onClick={() => onCampaign(c)} title="the campaign this story is part of">
              campaign {camp?.label ?? c}
            </span>
          )
        })}
        {story.chains.length > 0 && (
          <span
            {...pressable}
            className="pill"
            onClick={() => {
              setFocusChain(story.chains[0])
              setView('review')
            }}
            title="review the phishing chain of this story"
          >
            review the chain
          </span>
        )}
      </div>
      <StoryLinks story={story} stories={byStory} onStory={onStory} />
      {view.part === 'story' ? (
        <StoryNote key={story.id} story={story} entry={note} names={noteNames} onSave={onSaveNote} onDirty={onNoteDirty} />
      ) : (
        <div className="small muted">The note on this story is on its first part.</div>
      )}
      {mergedNotes.map((m) => (
        <div key={m.title} className="small" style={{ whiteSpace: 'pre-wrap', color: 'var(--fg-2)' }}>
          <span className="muted">Note on the story of {m.title}, merged into this one:</span> {m.text}
        </div>
      ))}
      <StoryCallBar key={`call:${story.id}:${view.call?.decidedAt ?? 0}`} view={view} onDecide={onDecide} />
      <StoryTools key={`tools:${story.id}`} view={view} views={views} labels={labels} onMerge={onMerge} />
    </div>
  )
}
