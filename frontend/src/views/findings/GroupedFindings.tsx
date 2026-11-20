import { Dot, SevBar } from '../../components/ui'
import type { MeasureReading } from '../../data/ruleMeasures'
import type { Priority } from '../../data/findingPriority'
import type { Finding } from '../../db/schema'
import { effectiveSeverity, sevCounts } from '../../rules/incidents'
import { fmtNum } from '../../util/format'
import type { Group } from './model'
import { LeadBadge, MemberRow } from './parts'

/** The queue grouped by rule, entity or source: one line per group, opened to its first 300 findings. */
export function GroupedFindings({
  groups,
  group,
  open,
  onToggle,
  onPickAll,
  onOpen,
  scores,
  readings,
  empty,
}: {
  groups: { key: string; label: string; items: Finding[] }[]
  group: Exclude<Group, 'incident' | ''>
  open: Set<string>
  onToggle: (key: string) => void
  onPickAll: (findings: Finding[]) => void
  onOpen: (f: Finding) => void
  scores: Map<string, Priority>
  readings: Map<string, MeasureReading>
  empty: string
}) {
  return (
    <div style={{ flex: 1, overflow: 'auto', background: 'var(--surface)' }}>
      {groups.map((g) => (
        <div key={g.key}>
          <div className="group-row" onClick={() => onToggle(g.key)}>
            <span className="caret">{open.has(g.key) ? '▾' : '▸'}</span>
            <Dot sev={effectiveSeverity(g.items[0])} />
            <span className="name ellipsis" style={{ maxWidth: 520 }}>
              {g.label}
            </span>
            {group === 'ruleId' && <span className="mono small muted">{g.key}</span>}
            {group === 'ruleId' && <LeadBadge reading={readings.get(g.key)} />}
            <span className="count">{fmtNum(g.items.length)}</span>
            <span style={{ width: 120 }}>
              <SevBar counts={sevCounts(g.items)} />
            </span>
            <span className="spacer" />
            <button
              className="btn xs ghost"
              onClick={(e) => {
                e.stopPropagation()
                onPickAll(g.items)
              }}
            >
              select all
            </button>
          </div>
          {open.has(g.key) && (
            <table className="table compact">
              <tbody>
                {g.items.slice(0, 300).map((f) => (
                  <MemberRow key={f.id} f={f} priority={scores.get(f.key)} reading={readings.get(f.ruleId)} onOpen={() => onOpen(f)} />
                ))}
                {g.items.length > 300 && (
                  <tr>
                    <td colSpan={7} className="muted sans">
                      {fmtNum(g.items.length - 300)} more - switch to the flat view with a filter
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>
      ))}
      {!groups.length && <div className="vtable-empty">{empty}</div>}
    </div>
  )
}
