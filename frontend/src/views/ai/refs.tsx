import { refKey, type RowRef } from '../../ai/evidence'
import { openRef } from './openRef'

export function RefChips({ refs, max = 12 }: { refs: RowRef[]; max?: number }) {
  if (!refs.length) return null
  return (
    <span className="cites">
      {refs.slice(0, max).map((r) => (
        <a key={refKey(r)} className="cite ok" onClick={() => openRef(r)} title={`open ${refKey(r)}`}>
          {refKey(r).replace(':', ' ')}
        </a>
      ))}
      {refs.length > max && <span className="dim small"> +{refs.length - max}</span>}
    </span>
  )
}
