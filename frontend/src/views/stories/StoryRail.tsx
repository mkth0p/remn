import type { StoryDecision, StoryView } from '../../data/storyDecisions'
import type { OrphanNote, Story, StoryResult } from '../../data/stories'
import { OrphanDecisions } from '../StoryDecisions'
import { StoryList } from './StoryList'
import { OrphanNotes } from './StoryNote'

export type StoryKind = '' | 'person' | 'host'

/** The list of the stories, searched and filtered by kind, with what an empty case says, and the notes and decisions whose story is gone. */
export function StoryRail({
  res,
  loaded,
  busy,
  query,
  setQuery,
  kind,
  setKind,
  shown,
  storyId,
  onSelect,
  views,
  orphanNotes,
  story,
  onAttachNote,
  onDropNote,
  orphanDecisions,
  view,
  onAttachDecision,
  onDropDecision,
}: {
  res: StoryResult | null
  loaded: boolean
  busy: boolean
  query: string
  setQuery: (q: string) => void
  kind: StoryKind
  setKind: (k: StoryKind) => void
  /** the stories the search and the kind leave */
  shown: Story[]
  storyId: string | null
  onSelect: (id: string) => void
  views: Map<string, StoryView>
  orphanNotes: OrphanNote[]
  story: Story | null
  onAttachNote: (o: OrphanNote) => void
  onDropNote: (o: OrphanNote) => void
  orphanDecisions: { key: string; entry: StoryDecision }[]
  view: StoryView | null
  onAttachDecision: (key: string) => void
  onDropDecision: (key: string) => void
}) {
  return (
    <>
      {res && res.stories.length > 0 && (
        <div className="row" style={{ gap: 6, padding: '8px 14px' }}>
          <input className="input" placeholder="Search stories" aria-label="Search stories" value={query} onChange={(e) => setQuery(e.target.value)} style={{ flex: 1 }} />
          <select className="select" aria-label="Story kind" value={kind} onChange={(e) => setKind(e.target.value as StoryKind)}>
            <option value="">All</option>
            <option value="person">People</option>
            <option value="host">Hosts</option>
          </select>
        </div>
      )}
      {!res && loaded && !busy && (
        <div className="muted small" style={{ padding: 14, lineHeight: 1.5 }}>
          A story is what happened to one person, or to one host when its records name no one: the records around a finding of medium severity or more, or a phishing mail and what its recipient did
          next, read along ATT&CK's phases. Each step says why it belongs and how surely; the sessions, hops and process trees around it are drawn from the evidence, and each host says what its logs
          cannot show.
        </div>
      )}
      {res && res.stories.length === 0 && (
        <div className="muted small" style={{ padding: 14, lineHeight: 1.5 }}>
          No story: no finding of medium severity or more names a person or a host beyond a mail received or a failed logon.
          {res.unstoried.length ? ` ${res.unstoried.length} flag(s) stand outside any story; Campaigns groups them by sender and address.` : ''}
        </div>
      )}
      <StoryList stories={shown} incidents={res?.incidents} active={storyId} onSelect={onSelect} views={views} />
      {orphanNotes.length > 0 && <OrphanNotes orphans={orphanNotes} story={story} onAttach={onAttachNote} onDelete={onDropNote} />}
      {orphanDecisions.length > 0 && <OrphanDecisions orphans={orphanDecisions} story={view} onAttach={onAttachDecision} onDelete={onDropDecision} />}
    </>
  )
}
