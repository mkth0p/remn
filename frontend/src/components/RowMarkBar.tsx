import { useEffect, useState } from 'react'
import { clearRowMarks, markRows, rowMarkTags, type RowMarkPatch } from '../data/rowMarks'
import type { RowMarkVerdict } from '../db/schema'

const VERDICTS: { value: RowMarkVerdict; label: string; hint: string }[] = [
  { value: 'relevant', label: 'relevant', hint: 'Part of the story: keep it in view' },
  { value: 'pivot', label: 'pivot', hint: 'Worth pivoting from: a lead to follow' },
  { value: 'noise', label: 'noise', hint: 'Explained and set aside: not part of the story' },
]

/**
 * Bulk marking for a table of evidence rows.
 *
 * Source-agnostic so the events and mails tables share one implementation: both pass their own
 * visible rows, and the whole row object rather than its id, so each mark can record where the row
 * came from as well as which row it is.
 */
export function RowMarkBar({
  caseId,
  source,
  rows,
  picked,
  onClear,
  onChanged,
}: {
  caseId: number
  source: 'events' | 'mails'
  rows: Record<string, unknown>[]
  picked: Set<string | number>
  onClear: () => void
  onChanged: () => void
}) {
  const [tag, setTag] = useState('')
  const [reason, setReason] = useState('')
  const [known, setKnown] = useState<string[]>([])
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    rowMarkTags(caseId)
      .then(setKnown)
      .catch(() => setKnown([]))
  }, [caseId, picked.size])

  if (!picked.size) return null
  const chosen = rows.filter((r) => picked.has(Number(r.id)))

  const apply = async (patch: RowMarkPatch) => {
    setBusy(true)
    try {
      await markRows(caseId, source, chosen, patch)
      onChanged()
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="bulkbar">
      <b>{picked.size} selected</b>
      <span className="muted">mark as:</span>
      {VERDICTS.map((v) => (
        <button key={v.value} className="btn xs" disabled={busy} title={v.hint} onClick={() => apply({ verdict: v.value })}>
          {v.label}
        </button>
      ))}
      <span className="muted">tag:</span>
      <input
        className="input xs mono"
        style={{ width: 130 }}
        list={`row-mark-tags-${source}`}
        placeholder="scanner"
        value={tag}
        disabled={busy}
        onChange={(e) => setTag(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && tag.trim()) {
            void apply({ addTags: [tag] }).then(() => setTag(''))
          }
        }}
      />
      <datalist id={`row-mark-tags-${source}`}>
        {known.map((t) => (
          <option key={t} value={t} />
        ))}
      </datalist>
      <input
        className="input xs"
        style={{ width: 220 }}
        placeholder="why (recorded with the mark)"
        value={reason}
        disabled={busy}
        onChange={(e) => setReason(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && reason.trim()) {
            void apply({ reason }).then(() => setReason(''))
          }
        }}
      />
      <span className="spacer" />
      <button
        className="btn xs ghost"
        disabled={busy}
        title="Remove the mark from the selected rows"
        onClick={async () => {
          setBusy(true)
          try {
            await clearRowMarks(
              caseId,
              source,
              chosen.map((r) => Number(r.id)),
            )
            onChanged()
          } finally {
            setBusy(false)
          }
        }}
      >
        unmark
      </button>
      <button className="btn xs ghost" onClick={onClear}>
        clear selection
      </button>
    </div>
  )
}
