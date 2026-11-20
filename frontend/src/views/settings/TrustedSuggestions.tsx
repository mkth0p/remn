import { useState } from 'react'
import { Modal } from '../../components/ui'
import type { TrustedSuggestion } from '../../data/trusted'

/** The senders the scan found worth trusting, each to untick before they are added. */
export function TrustedSuggestions({ suggestions, onClose, onAdd }: { suggestions: TrustedSuggestion[]; onClose: () => void; onAdd: (domains: string[]) => void }) {
  const [picked, setPicked] = useState<Set<string>>(() => new Set(suggestions.map((f) => f.registrable)))
  return (
    <Modal
      title="Suggested trusted senders"
      onClose={onClose}
      footer={
        <button className="btn primary" onClick={() => onAdd(suggestions.filter((f) => picked.has(f.registrable)).map((f) => f.registrable))} disabled={!picked.size}>
          add {picked.size} to trusted senders
        </button>
      }
    >
      <div className="small muted">Domains with 5+ mails, passing authentication and no strong indicator in this case. Untick anything you do not recognise.</div>
      <div className="col" style={{ gap: 4, maxHeight: 320, overflowY: 'auto' }}>
        {suggestions.map((f) => (
          <label key={f.registrable} className="checkbox small mono">
            <input
              type="checkbox"
              checked={picked.has(f.registrable)}
              onChange={(e) => {
                const next = new Set(picked)
                if (e.target.checked) next.add(f.registrable)
                else next.delete(f.registrable)
                setPicked(next)
              }}
            />
            <span>{f.registrable}</span>{' '}
            <span className="dim">
              {f.count} mail(s) · e.g. {f.sample}
            </span>
          </label>
        ))}
      </div>
    </Modal>
  )
}
