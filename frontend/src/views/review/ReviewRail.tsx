import { Badge, Dot } from '../../components/ui'
import { suggestionsFor, type Suggestion } from '../../data/aiReview'
import type { ChainReview, ReviewItem } from '../../data/review'
import { classNames } from '../../util/format'
import { chainDecision, factsLine, STATUS_LABEL, STATUS_SEV, type Status } from './model'
import { pressable } from '../../components/pressable'

export interface RailGroup {
  id: string
  label: string
  items: ReviewItem[]
}

/** The queue as the rail shows it: what is still to decide, what was confirmed, the rest; each item with its decision, and whether the model decided or proposed. */
export function ReviewRail({
  groups,
  visible,
  idx,
  setIdx,
  queued,
  reviews,
  suggestions,
}: {
  groups: RailGroup[]
  visible: ReviewItem[]
  idx: number
  setIdx: (i: number) => void
  /** items in the queue, shown or not */
  queued: number
  reviews: Record<string, ChainReview>
  suggestions: Record<string, Suggestion>
}) {
  const aiTag = (it: ReviewItem) => (it.kind === 'chain' ? reviews[it.chain!.id]?.by === 'ai' : it.incident!.lead.decidedBy === 'ai')
  return (
    <div className="left review-rail">
      {!visible.length && (
        <div className="muted small" style={{ padding: 14 }}>
          {queued ? 'everything is decided' : 'run the rules and build the chains first'}
        </div>
      )}
      {groups.map((g) => {
        if (!g.items.length) return null
        const start = visible.indexOf(g.items[0])
        return (
          <div key={g.id} className="group">
            <div className="group-head">
              <span>{g.label}</span>
              <span className="mono">{g.items.length}</span>
            </div>
            {g.items.map((it, j) => {
              const i = start + j
              return (
                <div {...pressable} key={it.id} className={classNames('item', i === idx && 'active', it.done && 'done')} onClick={() => setIdx(i)}>
                  <Dot sev={it.severity} />
                  <div style={{ minWidth: 0 }}>
                    <div className="title ellipsis">{it.title}</div>
                    <div className="sub ellipsis" title={factsLine(it)}>
                      {factsLine(it)}
                    </div>
                  </div>
                  <div className="col" style={{ alignItems: 'flex-end', gap: 2 }}>
                    {it.done ? (
                      <Badge sev={it.kind === 'chain' ? chainDecision(reviews[it.chain!.id]) : STATUS_SEV[it.incident!.status as Status]}>
                        {it.kind === 'chain' ? reviews[it.chain!.id]?.verdict : STATUS_LABEL[it.incident!.status as Status]}
                      </Badge>
                    ) : (
                      <span className="small muted">{i === idx ? 'now' : ''}</span>
                    )}
                    {aiTag(it) && (
                      <span className="ai-tag" title="decided by the model; open the item for its reason">
                        AI
                      </span>
                    )}
                    {suggestionsFor(it, suggestions).length > 0 && !it.done && (
                      <span className="ai-tag proposal" title="the model proposed a decision">
                        proposal
                      </span>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        )
      })}
    </div>
  )
}
