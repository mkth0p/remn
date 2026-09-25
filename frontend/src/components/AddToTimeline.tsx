import { useState } from 'react'
import { addTimelineEntry } from '../data/caseNotes'
import type { CaseNote } from '../db/schema'
import { toast, useStore } from '../state/store'
import { IconClock } from './Icons'

/** "Add to the case timeline" button used on findings, mails, events and chain steps. */
export function AddToTimeline({
  ts,
  observedAt,
  text,
  link,
  severity,
  label,
  className,
}: {
  ts: number | null | undefined
  /** when a row without an event time was collected: orders the entry, never shown as its time */
  observedAt?: number | null
  text: string
  link?: CaseNote['link']
  severity?: string
  label?: string
  className?: string
}) {
  const kase = useStore((s) => s.currentCase)
  const [added, setAdded] = useState(false)
  const add = async () => {
    if (!kase?.id) return
    // A row with no event time (a collection snapshot, an undated mail) gets no invented one: the
    // click time used to be stamped on it and printed in the report as when it happened.
    const r = await addTimelineEntry(kase.id, ts != null ? { ts, text, link, severity } : { ts: observedAt ?? Date.now(), text, link, severity, untimed: true })
    toast(r === 'exists' ? 'info' : 'ok', r === 'exists' ? 'already on the case timeline' : 'added to the case timeline')
    setAdded(true)
  }
  return (
    <button className={className ?? 'btn sm' + (added ? ' active' : '')} onClick={add} title="add to the case timeline (Case notes)">
      <IconClock /> {label ?? 'timeline'}
    </button>
  )
}
