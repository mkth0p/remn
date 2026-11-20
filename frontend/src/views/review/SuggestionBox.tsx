import { Badge, Sev } from '../../components/ui'
import type { Suggestion } from '../../data/aiReview'
import type { Finding } from '../../db/schema'
import { fmtTs } from '../../util/format'
import { DECISION_LABEL, DECISION_SEV } from './model'

/** A proposal of the model on the open item, with its reason, waiting for the analyst to apply or dismiss it. */
export function SuggestionBox({ s, members, onApply, onDismiss }: { s: Suggestion; members: Finding[]; onApply: () => void; onDismiss: () => void }) {
  return (
    <div className="suggestion">
      <div className="row" style={{ gap: 8, alignItems: 'baseline' }}>
        <b>the model proposes</b>
        <span className="small muted">
          {s.by === 'chat' ? 'from the AI analyst' : 'asked from this page'}
          {s.model ? ` · ${s.model}` : ''} · {fmtTs(s.at)}
          {s.target.startsWith('finding:') ? ` · on finding #${s.target.slice(8)}` : ''}
        </span>
        {s.exposed && (
          <Badge sev="medium" title="the model had read evidence text addressed to a model (asking to mark it benign, skip it…) before it proposed this: check it before applying">
            read text aimed at AI
          </Badge>
        )}
      </div>
      <div className="row wrap" style={{ gap: 10 }}>
        {s.decision && <Badge sev={DECISION_SEV[s.decision]}>{DECISION_LABEL[s.decision] ?? s.decision}</Badge>}
        {s.severity && (
          <span className="row" style={{ gap: 4 }}>
            <span className="small muted">severity</span>
            <Sev sev={s.severity} />
          </span>
        )}
        {s.include !== undefined && <span className="small">{s.include ? 'in the report' : 'not in the report'}</span>}
        {s.unlink?.length ? (
          <span className="small">
            unlink {s.unlink.length} finding{s.unlink.length === 1 ? '' : 's'}: {s.unlink.map((id) => members.find((f) => f.id === id)?.title ?? `#${id}`).join('; ')}
          </span>
        ) : null}
      </div>
      <div className="small">{s.reason}</div>
      {(s.narrative || s.note) && (
        <div className="small muted" style={{ whiteSpace: 'pre-wrap' }}>
          <b>{s.narrative ? 'narrative' : 'note'}:</b> {(s.narrative ?? s.note ?? '').slice(0, 600)}
          {(s.narrative ?? s.note ?? '').length > 600 ? '…' : ''}
        </div>
      )}
      <div className="row" style={{ gap: 6 }}>
        <button className="btn sm primary" onClick={onApply}>
          apply
        </button>
        <button className="btn sm ghost" onClick={onDismiss}>
          dismiss
        </button>
      </div>
    </div>
  )
}
