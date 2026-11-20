/**
 * What the page says above the stories: an error, a snapshot out of date with a rebuild, a link it
 * could not follow, a build that read only part of the case, and notes and decisions whose story is gone.
 */
export function StoriesBanners({
  error,
  stale,
  onRebuild,
  notice,
  onDismiss,
  warnings,
  orphanNotes,
  orphanDecisions,
}: {
  error: string
  /** why the snapshot no longer reads the case as it is; empty when it does or while it is built */
  stale: string[]
  onRebuild: () => void
  notice: string
  onDismiss: () => void
  warnings: string[]
  /** notes on a story the build no longer holds */
  orphanNotes: number
  /** stories with decisions the build no longer holds */
  orphanDecisions: number
}) {
  return (
    <>
      {error && (
        <div role="alert" className="hint" style={{ color: 'var(--danger)', padding: '6px 16px' }}>
          {error}
        </div>
      )}
      {stale.length > 0 && (
        <div className="panel row" role="status" aria-label="Stories out of date" style={{ margin: '6px 16px', padding: '6px 10px', gap: 10, borderColor: 'var(--sev-medium)' }}>
          <span>
            <strong>Out of date:</strong> {stale.join('; ')}. These stories read the case as it was then.
          </span>
          <span className="spacer" />
          <button className="btn xs primary" onClick={onRebuild}>
            rebuild
          </button>
        </div>
      )}
      {notice && (
        <div className="panel row" role="status" style={{ margin: '6px 16px', padding: '6px 10px', gap: 10 }}>
          <span>{notice}</span>
          <span className="spacer" />
          <button className="btn xs ghost" onClick={onDismiss}>
            dismiss
          </button>
        </div>
      )}
      {warnings.map((w) => (
        <div className="panel" role="status" key={w} style={{ margin: '6px 16px', padding: '6px 10px' }}>
          Incomplete: {w} An absent step or story is not a negative result.
        </div>
      ))}
      {orphanNotes > 0 && (
        <div className="panel" role="status" style={{ margin: '6px 16px', padding: '6px 10px' }}>
          {orphanNotes === 1 ? 'A note is' : `${orphanNotes} notes are`} on a story these stories no longer hold: listed under the stories, to attach again or delete.
        </div>
      )}
      {orphanDecisions > 0 && (
        <div className="panel" role="status" style={{ margin: '6px 16px', padding: '6px 10px' }}>
          {orphanDecisions === 1 ? 'The decisions on a story are' : `The decisions on ${orphanDecisions} stories are`} kept for a story these stories no longer hold: listed under the stories, to
          attach again or delete. Until then the report does not count them.
        </div>
      )}
    </>
  )
}
