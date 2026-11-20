import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { EventDetail, MailDetail } from '../components/Detail'
import { Explorer, ExploreList } from '../components/Explore'
import { useRelationshipGraph } from '../components/useRelationshipGraph'
import { Tabs } from '../components/ui'
import { applyStoryDecisions, decisionCount, setCall } from '../data/storyDecisions'
import { resolveStoryNotes, storyCoverageWarnings, storyGaps, storyQuestion, type Story } from '../data/stories'
import { downloadCampaignGrouping, spineSteps } from '../data/storyFlow'
import { useStore } from '../state/store'
import { useRouteItem } from '../state/route'
import { DecisionsPanel } from './StoryDecisions'
import { CampaignDetail, CampaignList } from './stories/Campaigns'
import { GapsPanel, IdentityPanel, LineagePanel } from './stories/LineagePanels'
import { PhaseRail } from './stories/StoryList'
import { recordOpeners, storyDecisionActions, storyNoteActions } from './stories/storyActions'
import { StoriesBanners } from './stories/StoriesBanners'
import { StoriesHeader } from './stories/StoriesHeader'
import { StoryHead } from './stories/StoryHead'
import { StoryRail, type StoryKind } from './stories/StoryRail'
import { StoryTimelineTab } from './stories/StoryTimelineTab'
import { useStories } from './stories/useStories'
import { type Detail, type Mode, type Tab } from './stories/model'

/**
 * Stories: one per person or host incident (backend/services/analysis/stories.py). The left list
 * ranks them; the right reads the selected one along ATT&CK's phases, step by step, each step
 * saying why it is in the story and how surely, with the rule's measure on each finding, the
 * sessions, hops and process trees around it, and what the evidence cannot show. Campaigns group
 * the stories that share the attacker's infrastructure; Explore browses the relationship graph.
 */

export function StoriesView() {
  const kase = useStore((s) => s.currentCase)
  const setView = useStore((s) => s.setView)
  const setAiPrompt = useStore((s) => s.setAiPrompt)
  const bump = useStore((s) => s.bumpRules)
  const { res, loaded, busy, error, setError, stale, notice, setNotice, notes, setNotes, decisions, setDecisions, storyId, setStoryId, stepId, setStepId, readings, caseGaps, build } = useStories(kase)
  const [mode, setMode] = useState<Mode>('stories')
  // the open story, and its step after '#', as a link from the timeline names them
  useRouteItem('story', storyId ? (stepId ? `${storyId}#${stepId}` : storyId) : null)
  const [phase, setPhase] = useState<string | null>(null)
  const [full, setFull] = useState(false)
  const [tab, setTab] = useState<Tab>('story')
  const [campaignId, setCampaignId] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState<StoryKind>('')
  const [detail, setDetail] = useState<Detail>(null)
  const [explored, setExplored] = useState('')
  const g = useRelationshipGraph(kase)
  // whether the open story's note holds text not saved yet (StoryNote says so as it changes)
  const noteDirty = useRef(false)
  const onNoteDirty = useCallback((d: boolean) => {
    noteDirty.current = d
  }, [])
  /** True when the analyst keeps an unsaved note rather than let what they do next throw it away. */
  const keepNote = () => noteDirty.current && !confirm('The note on this story is not saved. Discard it?')

  const labels = useMemo(() => new Map((res?.identities ?? []).map((i) => [i.id, i.label])), [res])
  // the stories as the page shows them: the build with the analyst's decisions applied
  const decided = useMemo(() => applyStoryDecisions(res, decisions), [res, decisions])
  const byStory = useMemo(() => new Map([...decided.byId].map(([id, v]) => [id, v.story])), [decided])
  const resolved = useMemo(() => resolveStoryNotes(res?.stories ?? [], res?.identities ?? [], notes), [res, notes])
  const shown = useMemo(
    () =>
      decided.views
        .map((v) => v.story)
        .filter(
          (s) =>
            (!kind || s.kind === kind) && (!query || `${s.title} ${s.headline} ${s.hosts.join(' ')} ${s.attackerAddresses.join(' ')} ${s.ips.join(' ')}`.toLowerCase().includes(query.toLowerCase())),
        ),
    [decided, kind, query],
  )
  const view = storyId ? (decided.byId.get(storyId) ?? null) : null
  const story = view?.story ?? null
  const step = story && stepId ? (story.steps.find((s) => s.id === stepId) ?? null) : null
  const campaign = res?.campaigns.find((c) => c.id === campaignId) ?? null
  const identity = story?.kind === 'person' ? res?.identities.find((i) => i.id === story.subject.id) : undefined
  // what a note on the open story is checked for: its hosts, its accounts and the addresses it came from
  const noteNames = useMemo(() => (story ? [...story.hosts, ...story.accounts.map((a) => labels.get(a) ?? a), ...story.attackerAddresses] : []), [story, labels])
  // a story opens on its spine; the full timeline when asked, when a phase filters it, when the step open is off the spine
  const spine = useMemo(() => (story ? spineSteps(story) : null), [story])
  const showAll = full || !!phase || !spine?.length || (!!stepId && !spine.some((s) => s.id === stepId))

  // j / k move between the steps of the open story
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null
      if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable)) return
      if (mode !== 'stories' || !story || (e.key !== 'j' && e.key !== 'k')) return
      const steps = !showAll && spine ? spine : phase ? story.steps.filter((s) => s.phase === phase) : story.steps
      const i = stepId ? steps.findIndex((s) => s.id === stepId) : -1
      setStepId(steps[e.key === 'j' ? Math.min(steps.length - 1, i + 1) : Math.max(0, i - 1)]?.id ?? null)
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [mode, story, stepId, phase, showAll, spine, setStepId])

  if (!kase) return null
  const { openRow, openRefs } = recordOpeners({ kase, setDetail, setError })
  const selectStory = (id: string) => {
    if (id !== storyId && keepNote()) return
    setMode('stories')
    setStoryId(id)
    setStepId(null)
    setPhase(null)
    setNotice('')
  }
  // the note is shown in the Stories mode only: leaving it asks first, as a story switch does
  const switchMode = (m: Mode) => {
    if (m !== mode && mode === 'stories' && keepNote()) return
    setMode(m)
  }
  const explore = (nodeId: string) => {
    if (keepNote()) return
    setMode('explore')
    setExplored(nodeId)
  }
  const rebuild = () => {
    if (keepNote()) return
    build(story ? { story, identities: res?.identities ?? [], step: stepId ?? undefined } : null)
  }
  // the request is the analyst's; what the story took from the records reaches the model as evidence
  const ask = (s: Story) => {
    setAiPrompt(storyQuestion(s, res?.stats))
    setView('ai')
  }
  const identities = res?.identities ?? []
  const { saveNote, attachNote, dropNote } = storyNoteActions({ kase, story, identities, noteOf: (id) => resolved.byStory.get(id), setNotes })
  const { decide, decideStep, stepOut, split, merge, attachDecision, dropDecision, undoCall, undoStep, dropLost, putBackOut, unsplit, unmerge } = storyDecisionActions({
    kase,
    identities,
    view,
    setDecisions,
    setError,
    setStoryId,
    setStepId,
    bump,
  })
  // the notes of the stories merged into the open one, which read as part of it
  const mergedNotes = view?.part === 'story' ? view.merged.flatMap((m) => (resolved.byStory.has(m.story.id) ? [{ title: m.story.title, text: resolved.byStory.get(m.story.id)!.note.text }] : [])) : []
  const warnings = storyCoverageWarnings(res?.stats)
  return (
    <div className="view">
      <StoriesHeader res={res} views={decided.views} loaded={loaded} busy={busy} onRebuild={rebuild} />
      <StoriesBanners
        error={error}
        stale={busy ? [] : stale}
        onRebuild={rebuild}
        notice={notice}
        onDismiss={() => setNotice('')}
        warnings={warnings}
        orphanNotes={resolved.orphans.length}
        orphanDecisions={decided.orphans.length}
      />
      <div className="split" style={{ gridTemplateColumns: '340px 1fr' }}>
        <div className="left">
          <div className="row" style={{ padding: '10px 14px', gap: 10, borderBottom: '1px solid var(--line)' }}>
            <div className="segmented">
              <button className={mode === 'stories' ? 'active' : ''} onClick={() => switchMode('stories')}>
                Stories
              </button>
              <button className={mode === 'campaigns' ? 'active' : ''} onClick={() => switchMode('campaigns')}>
                Campaigns
              </button>
              <button className={mode === 'explore' ? 'active' : ''} onClick={() => switchMode('explore')}>
                Explore
              </button>
            </div>
          </div>
          {mode === 'stories' && (
            <StoryRail
              res={res}
              loaded={loaded}
              busy={busy}
              query={query}
              setQuery={setQuery}
              kind={kind}
              setKind={setKind}
              shown={shown}
              storyId={storyId}
              onSelect={selectStory}
              views={decided.byId}
              orphanNotes={resolved.orphans}
              story={story}
              onAttachNote={attachNote}
              onDropNote={dropNote}
              orphanDecisions={decided.orphans}
              view={view}
              onAttachDecision={attachDecision}
              onDropDecision={dropDecision}
            />
          )}
          {mode === 'campaigns' && <CampaignList campaigns={res?.campaigns ?? []} stories={byStory} active={campaignId} onSelect={setCampaignId} />}
          {mode === 'explore' && <ExploreList g={g} selected={explored} onSelect={setExplored} />}
        </div>
        <div className="right">
          {mode === 'explore' && <Explorer g={g} selected={explored} onSelect={setExplored} onOpen={(ref) => ref.id != null && openRow(ref.source, ref.id)} />}
          {mode === 'campaigns' &&
            (campaign ? (
              <CampaignDetail
                campaign={campaign}
                stories={byStory}
                onStory={selectStory}
                onOpenRefs={openRefs}
                onExport={() => downloadCampaignGrouping(kase, campaign, [...byStory.values()], res?.identities ?? []).catch((e) => setError((e as Error).message))}
              />
            ) : (
              <div className="muted" style={{ padding: 24 }}>
                {res?.campaigns.length ? 'select a campaign' : ''}
              </div>
            ))}
          {mode === 'stories' && !story && (
            <div className="muted" style={{ padding: 24 }}>
              {res?.stories.length ? 'select a story' : ''}
            </div>
          )}
          {mode === 'stories' && story && view && (
            <>
              <StoryHead
                kase={kase}
                story={story}
                view={view}
                res={res}
                byStory={byStory}
                views={decided.views}
                labels={labels}
                note={resolved.byStory.get(story.id)}
                noteNames={noteNames}
                mergedNotes={mergedNotes}
                onSaveNote={saveNote}
                onNoteDirty={onNoteDirty}
                onIdentity={() => setTab('identity')}
                onAsk={() => ask(story)}
                onError={setError}
                onStory={selectStory}
                onCampaign={(c) => {
                  if (keepNote()) return
                  setMode('campaigns')
                  setCampaignId(c)
                }}
                onDecide={(verdict, reason) => decide(view.sources[0], (d) => setCall(d, view.part, verdict, reason))}
                onMerge={(target, reason, orgs) => merge(view, target, reason, orgs)}
              />
              <PhaseRail story={story} active={phase} onPick={setPhase} />
              <Tabs
                tabs={[
                  { id: 'story' as const, label: 'Story' },
                  { id: 'lineage' as const, label: `Lineage (${story.lineage.sessions.length + story.lineage.hops.length + story.lineage.processes.length})` },
                  { id: 'identity' as const, label: 'Who is who' },
                  { id: 'gaps' as const, label: `Where it stops (${storyGaps(story, res?.stats).length + caseGaps.length})` },
                  { id: 'decisions' as const, label: `Decisions (${decisionCount(view)})` },
                  { id: 'json' as const, label: 'JSON' },
                ]}
                active={tab}
                onChange={setTab}
              />
              {tab === 'story' && (
                <StoryTimelineTab
                  story={story}
                  view={view}
                  step={step}
                  stepId={stepId}
                  setStepId={setStepId}
                  showAll={showAll}
                  spine={spine}
                  phase={phase}
                  setPhase={setPhase}
                  setFull={setFull}
                  labels={labels}
                  readings={readings}
                  g={g}
                  onOpen={openRow}
                  onOpenRefs={openRefs}
                  onExplore={explore}
                  onCall={(st, verdict, reason, alsoFalsePositive) => decideStep(view, st, verdict, reason, alsoFalsePositive)}
                  onOut={(st, reason) => stepOut(view, st, reason)}
                  onSplit={(st, reason) => split(view, st, reason)}
                />
              )}
              {tab === 'lineage' && <LineagePanel story={story} highlight={step?.process} />}
              {tab === 'identity' && <IdentityPanel identity={identity} />}
              {tab === 'gaps' && <GapsPanel story={story} stats={res?.stats} caseGaps={caseGaps} />}
              {tab === 'decisions' && (
                <DecisionsPanel
                  view={view}
                  onOpenStep={(id) => {
                    setTab('story')
                    setStepId(id)
                  }}
                  onUndoCall={() => undoCall(view)}
                  onUndoStep={(st) => undoStep(view, st)}
                  onDropLost={dropLost}
                  onPutBack={putBackOut}
                  onUnsplit={() => unsplit(view)}
                  onUnmerge={(m) => unmerge(view, m)}
                />
              )}
              {tab === 'json' && (
                <div className="view-body">
                  <pre className="codeblock">{JSON.stringify(story, null, 2)}</pre>
                </div>
              )}
            </>
          )}
        </div>
      </div>
      {detail?.source === 'events' && <EventDetail row={detail.row} onClose={() => setDetail(null)} />}
      {detail?.source === 'mails' && <MailDetail row={detail.row} onClose={() => setDetail(null)} />}
    </div>
  )
}
