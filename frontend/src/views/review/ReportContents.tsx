import { Toggle } from '../../components/ui'
import { SEVERITIES, type ReportSettings } from '../../data/review'
import type { Severity } from '../../db/schema'

/** What the report carries, chosen here as on the Report page. */
export function ReportContents({ settings, save }: { settings: ReportSettings; save: (patch: Partial<ReportSettings>) => void }) {
  return (
    <details className="report-contents">
      <summary>
        report contents · from {settings.minSeverity} up · chain steps {settings.chainDetail}
        {settings.onlyReviewed ? ' · reviewed items only' : ''}
        {settings.includeFp ? ' · false positives included' : ''}
      </summary>
      <div className="row wrap" style={{ gap: 12, padding: '8px 0' }}>
        <label className="pill active">
          from{' '}
          <select value={settings.minSeverity} onChange={(e) => save({ minSeverity: e.target.value as Severity })}>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>{' '}
          up
        </label>
        <label className="pill active">
          chain steps{' '}
          <select value={settings.chainDetail} onChange={(e) => save({ chainDetail: e.target.value as ReportSettings['chainDetail'] })}>
            <option value="linked">tied to the mail or with a finding</option>
            <option value="weighted">plus weighted steps</option>
            <option value="all">every step</option>
          </select>
        </label>
        <Toggle on={settings.includeChains} onChange={(v) => save({ includeChains: v })} label="chains" />
        <Toggle on={settings.includeGraphs} onChange={(v) => save({ includeGraphs: v })} label="chain graphs" />
        <Toggle on={settings.includeTimeline} onChange={(v) => save({ includeTimeline: v })} label="case timeline" />
        <Toggle on={settings.includeTasks} onChange={(v) => save({ includeTasks: v })} label="tasks" />
        <Toggle on={settings.includeNotes} onChange={(v) => save({ includeNotes: v })} label="notes" />
        <Toggle on={settings.includeIocs} onChange={(v) => save({ includeIocs: v })} label="indicators" />
        <Toggle on={settings.includeEvidence} onChange={(v) => save({ includeEvidence: v })} label="evidence" />
        <Toggle on={settings.onlyReviewed} onChange={(v) => save({ onlyReviewed: v })} label="only what was reviewed" />
        <Toggle on={settings.includeFp} onChange={(v) => save({ includeFp: v })} label="false positives" />
      </div>
    </details>
  )
}
