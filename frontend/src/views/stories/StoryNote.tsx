import { Dot } from '../../components/ui'
import { checkText, readRows, type TextCheck } from '../../data/claims'
import { getSource } from '../../data/source'
import { type NoteOnStory, type OrphanNote, type Story, storyRowIds } from '../../data/stories'
import { useStore } from '../../state/store'
import { day } from './model'
import { useEffect, useState } from 'react'

/**
 * The analyst's note on a story, checked against the story's own rows: every address, hash and name it
 * gives should be in them. A saved note is checked again whenever it is shown, and the page asks
 * before a story switch throws away what is typed and not saved.
 */
export function StoryNote({
  story,
  entry,
  names,
  onSave,
  onDirty,
}: {
  story: Story
  entry: NoteOnStory | undefined
  names: string[]
  onSave: (text: string) => Promise<void>
  onDirty: (dirty: boolean) => void
}) {
  const kase = useStore((s) => s.currentCase)
  const saved = entry?.note.text ?? ''
  // what the analyst is typing; null while the note shown is the saved one
  const [draft, setDraft] = useState<string | null>(null)
  const [check, setCheck] = useState<TextCheck | null>(null)
  const text = draft ?? saved
  const dirty = draft !== null && draft !== saved
  useEffect(() => onDirty(dirty), [dirty, onDirty])
  useEffect(() => {
    let alive = true
    setCheck(null)
    if (!kase || !saved.trim()) return
    const ds = getSource(kase)
    const ids = storyRowIds(story)
    Promise.all([readRows(ds, 'events', ids.events), readRows(ds, 'mails', ids.mails)])
      .then(([ev, ml]) => alive && setCheck(checkText(saved, [...ev.values(), ...ml.values()], names)))
      .catch(() => undefined)
    return () => {
      alive = false
    }
  }, [kase, story, saved, names])
  const save = async () => {
    await onSave(text)
    setDraft(null)
  }
  return (
    <div className="col" style={{ gap: 6 }}>
      <textarea
        className="input"
        aria-label="Story note"
        rows={2}
        placeholder="Your reading of this story: it is checked against the story's own records"
        value={text}
        onChange={(e) => setDraft(e.target.value)}
      />
      <div className="row" style={{ gap: 8 }}>
        <button className="btn sm" disabled={!dirty} onClick={save}>
          Save note
        </button>
        {check && !dirty && (
          <span className="small" role="status">
            <Dot sev={check.status === 'verified' ? 'ok' : check.status === 'nothing_to_check' ? 'info' : 'high'} />{' '}
            {check.status === 'verified'
              ? `every value it names is in the story's records (${check.named.length})`
              : check.status === 'nothing_to_check'
                ? 'it names no address, account or hash: nothing to check against the records'
                : check.reasons.join('; ')}
          </span>
        )}
      </div>
    </div>
  )
}

/** The notes whose story this build no longer holds: kept and listed, to put back on a story or delete. */
export function OrphanNotes({ orphans, story, onAttach, onDelete }: { orphans: OrphanNote[]; story: Story | null; onAttach: (o: OrphanNote) => void; onDelete: (o: OrphanNote) => void }) {
  return (
    <div className="section" role="region" aria-label="Notes whose story is gone" style={{ padding: '10px 14px', borderTop: '1px solid var(--line)' }}>
      <h3>Notes whose story is gone ({orphans.length})</h3>
      <div className="small muted" style={{ lineHeight: 1.5 }}>
        The stories were built again and none of them holds what these notes were written on. They are kept: open the story a note belongs to and attach it there, or delete it.
      </div>
      {orphans.map((o) => (
        <div key={o.key} className="col" style={{ gap: 3, marginTop: 10 }}>
          <div className="small">
            <strong>{o.title}</strong>
            {o.start != null && <span className="muted"> · {day(o.start)}</span>}
          </div>
          <div className="small" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', color: 'var(--fg-2)' }}>
            {o.note.text}
          </div>
          <div className="row" style={{ gap: 6 }}>
            <button className="btn xs" disabled={!story} onClick={() => onAttach(o)} title={story ? `put this note on the story of ${story.title}` : 'open a story first'}>
              attach to the open story
            </button>
            <button className="btn xs ghost" onClick={() => onDelete(o)}>
              delete
            </button>
          </div>
        </div>
      ))}
    </div>
  )
}
