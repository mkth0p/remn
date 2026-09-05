import { useState } from 'react'
import { addTimelineEntry } from '../data/caseNotes'
import type { CaseNote } from '../db/schema'
import { toast, useStore } from '../state/store'
import { IconClock } from './Icons'

/** "Add to the case timeline" button used on findings, mails, events and chain steps. */
export function AddToTimeline({ ts, text, link, severity, label, className }: { ts: number | null | undefined; text: string; link?: CaseNote['link']; severity?: string; label?: string; className?: string }) {
  const kase = useStore((s) => s.currentCase)
  const [added, setAdded] = useState(false)
  const add = async () => {
    if (!kase?.id) return
    const r = await addTimelineEntry(kase.id, { ts: ts ?? Date.now(), text, link, severity })
    toast(r === 'exists' ? 'info' : 'ok', r === 'exists' ? 'already on the case timeline' : 'added to the case timeline')
    setAdded(true)
  }
  return (
    <button className={className ?? 'btn sm' + (added ? ' active' : '')} onClick={add} title="add to the case timeline (Case notes)">
      <IconClock /> {label ?? 'timeline'}
    </button>
  )
}
