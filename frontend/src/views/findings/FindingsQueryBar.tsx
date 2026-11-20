import { IconSearch } from '../../components/Icons'
import type { DecisionCase } from '../../data/findingPriority'
import { classNames, fmtNum } from '../../util/format'
import { ORDER, SORT_LABEL, STATUSES, STATUS_LABEL, type Group, type Sort } from './model'
import type { QueueFilters } from './useFindingsQueue'

const GROUPINGS: [Group, string][] = [
  ['incident', 'incidents'],
  ['', 'flat'],
  ['ruleId', 'rule'],
  ['entity', 'entity'],
  ['source', 'source'],
]

/**
 * The filters of the queue: the search, severity, status, source and sort, the false positives
 * the queue hides, the past decisions the priority reads, and the grouping.
 */
export function FindingsQueryBar({
  filters,
  set,
  counts,
  fpCount,
  summary,
  sources,
  otherCases,
  chooseSource,
  pickSources,
  setPickSources,
  onGroup,
}: {
  filters: QueueFilters
  set: (patch: Partial<QueueFilters>) => void
  counts: Partial<Record<string, number>>
  fpCount: number
  summary: string
  sources: number[] | null
  otherCases: DecisionCase[]
  chooseSource: (other: number, on: boolean) => void
  pickSources: boolean
  setPickSources: (on: boolean) => void
  onGroup: (g: Group) => void
}) {
  const { sev, status, source, q, showFp, group, sort } = filters
  return (
    <div className="querybar">
      <div className="row wrap">
        <div className="search">
          <IconSearch />
          <input data-findings-search placeholder="search title, rule, entities, technique…   ( / )" value={q} onChange={(e) => set({ q: e.target.value })} />
        </div>
        <label className={classNames('pill', sev && 'active')}>
          severity{' '}
          <select value={sev} onChange={(e) => set({ sev: e.target.value })}>
            <option value="">any</option>
            {ORDER.map((s) => (
              <option key={s} value={s}>
                {s} ({counts[s] ?? 0})
              </option>
            ))}
          </select>
        </label>
        <label className={classNames('pill', status && 'active')}>
          status{' '}
          <select value={status} onChange={(e) => set({ status: e.target.value })}>
            <option value="">any</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>
                {STATUS_LABEL[s]}
              </option>
            ))}
          </select>
        </label>
        {fpCount > 0 && (
          <button className={classNames('pill', showFp && 'active')} onClick={() => set({ showFp: !showFp })} title="false positives are hidden from the queue and the counts by default">
            {showFp ? 'hiding' : 'show'} {fmtNum(fpCount)} false positive{fpCount === 1 ? '' : 's'}
          </button>
        )}
        <label className={classNames('pill', source && 'active')}>
          source{' '}
          <select value={source} onChange={(e) => set({ source: e.target.value })}>
            <option value="">events + mails</option>
            <option value="events">events</option>
            <option value="mails">mails</option>
          </select>
        </label>
        <label
          className={classNames('pill', sort !== 'priority' && 'active')}
          title="priority: the findings to look at first, from their severity, their rule's measure, how rare they are in the case, the other rules around them and past decisions"
        >
          sort{' '}
          <select value={sort} onChange={(e) => set({ sort: e.target.value as Sort })}>
            {(Object.keys(SORT_LABEL) as Sort[]).map((k) => (
              <option key={k} value={k}>
                {SORT_LABEL[k]}
              </option>
            ))}
          </select>
        </label>
        {sources && otherCases.length > 0 && (
          <button
            className={classNames('pill', sources.length > 0 && 'active')}
            aria-expanded={pickSources}
            onClick={() => setPickSources(!pickSources)}
            title="the false positives and escalations the priority reads: this case's, and those of other cases only when you choose them"
          >
            past decisions: this case{sources.length ? ` and ${sources.length} other${sources.length === 1 ? '' : 's'}` : ''}
          </button>
        )}
        <div className="segmented" title="how the queue is grouped">
          {GROUPINGS.map(([g, label]) => (
            <button key={g} className={classNames(group === g && 'active')} onClick={() => onGroup(g)}>
              {label}
            </button>
          ))}
        </div>
        <span className="spacer" />
        <span className="mono small dim">{summary}</span>
      </div>
      {pickSources && sources && otherCases.length > 0 && (
        <div className="row wrap small" style={{ marginTop: 8 }} data-decision-sources>
          <span className="muted">
            The priority reads the false positives and escalations of this case. Add another case only when it is the same client&apos;s: a program one network runs every day can be the
            intruder&apos;s on the next.
          </span>
          {otherCases.map((c) => (
            <label key={c.caseId} className="row" style={{ gap: 4 }}>
              <input type="checkbox" checked={sources.includes(c.caseId)} onChange={(e) => chooseSource(c.caseId, e.target.checked)} />
              {c.caseName}
              <span className="muted">
                (
                {[c.falsePositives ? `${fmtNum(c.falsePositives)} false positive${c.falsePositives === 1 ? '' : 's'}` : '', c.escalated ? `${fmtNum(c.escalated)} escalated` : '']
                  .filter(Boolean)
                  .join(', ')}
                )
              </span>
            </label>
          ))}
        </div>
      )}
    </div>
  )
}
