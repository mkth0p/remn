import { useState } from 'react'
import { Dropzone } from '../../components/Dropzone'
import { IconDownload } from '../../components/Icons'
import { Badge } from '../../components/ui'
import type { IssueStatus, PreflightCheck, ReportIssue } from '../../data/reportPreflight'
import type { ReportSettings } from '../../data/review'
import { getDb, type Case, type CaseNote, type Finding } from '../../db/schema'
import { toast } from '../../state/store'
import { fmtNum, renderMarkdown } from '../../util/format'
import { downloadBlob, exportCaseBundle, importCaseBundle } from '../../util/export'
import { navigatorLayer, timelineRecords, toTimelineCsv, toTimesketchJsonl } from '../../util/responderExports'
import { ORDER } from './model'

/** The checks a report passes before it is issued as final, each waived with a reason when it cannot pass, and the claims not borne out by their rows. */
export function PreflightPanel({
  status,
  checks,
  issue,
  onIssue,
  unverified,
}: {
  status: IssueStatus
  checks: PreflightCheck[]
  issue: ReportIssue
  onIssue: (next: ReportIssue) => void
  unverified: { what: string; status: string; reasons: string[] }[]
}) {
  return (
    <div className="panel">
      <div className="panel-h">
        preflight · the report is <b style={{ color: status.status === 'final' ? 'var(--ok)' : 'var(--warn)' }}>{status.status === 'final' ? 'final' : 'a draft'}</b>
        <span className="spacer" />
        {status.status === 'final' ? (
          <button className="btn xs" onClick={() => onIssue({ ...issue, finalAt: undefined })}>
            back to draft
          </button>
        ) : (
          <button
            className="btn xs primary"
            disabled={status.open.length > 0}
            title={status.open.length ? 'every open check needs to pass or be waived with a reason' : 'print the report as final, with the waivers listed'}
            onClick={() => onIssue({ ...issue, finalAt: Date.now() })}
          >
            issue as final
          </button>
        )}
      </div>
      <div className="panel-b col" style={{ gap: 6 }}>
        {checks.map((c) => (
          <div key={c.id} className="row small" style={{ gap: 8, alignItems: 'flex-start' }}>
            <Badge sev={c.ok ? 'ok' : issue.waivers[c.id]?.trim() ? 'medium' : 'high'}>{c.ok ? 'ok' : issue.waivers[c.id]?.trim() ? 'waived' : 'open'}</Badge>
            <div className="col" style={{ gap: 2, flex: 1 }}>
              <span>
                {c.label} <span className="muted">· {c.detail}</span>
              </span>
              {!c.ok && (
                <input
                  className="input small"
                  placeholder="waive: the reason, printed in the report"
                  defaultValue={issue.waivers[c.id] ?? ''}
                  onBlur={(e) => onIssue({ ...issue, waivers: { ...issue.waivers, [c.id]: e.target.value } })}
                />
              )}
            </div>
          </div>
        ))}
        {unverified.length > 0 && (
          <div className="col small" style={{ gap: 2 }} data-testid="unverified-claims">
            <span className="muted">Not borne out by the rows they cite ({fmtNum(unverified.length)}):</span>
            {unverified.slice(0, 20).map((u, i) => (
              <span key={`${u.what}-${i}`}>
                <Badge sev={u.status === 'contradicted' ? 'high' : 'medium'}>{u.status}</Badge> {u.what}: <span className="muted">{u.reasons.join('; ')}</span>
              </span>
            ))}
            {unverified.length > 20 && <span className="muted">and {fmtNum(unverified.length - 20)} more</span>}
          </div>
        )}
        <div className="hint">
          A draft says so on its cover. Final needs every check to pass or to be waived with a reason; a new open check (evidence added, a rule run that failed) returns it to draft.
        </div>
      </div>
    </div>
  )
}

/** The executive summary: the model's draft or the analyst's own text, shown as it prints, and who wrote it last. */
export function SummaryPanel({
  caseId,
  summary,
  setSummary,
  summaryBy,
  setSummaryBy,
  setSummaryAt,
}: {
  caseId: number | undefined
  summary: string
  setSummary: (s: string) => void
  summaryBy: 'analyst' | 'ai' | undefined
  setSummaryBy: (by: 'analyst' | 'ai') => void
  setSummaryAt: (at: number) => void
}) {
  return (
    <div className="panel">
      <div className="panel-h">executive summary</div>
      <div className="panel-b">
        {summary ? (
          <div className="md" dangerouslySetInnerHTML={{ __html: renderMarkdown(summary) }} />
        ) : (
          <div className="muted small">Click "AI executive summary" to have the local model draft it from the reviewed chains and incidents, or write your own below.</div>
        )}
        <textarea
          className="textarea"
          style={{ marginTop: 8, minHeight: 120 }}
          value={summary}
          onChange={(e) => {
            setSummary(e.target.value)
            setSummaryBy('analyst')
          }}
          onBlur={() => {
            setSummaryAt(Date.now())
            void getDb().kv.bulkPut([
              { key: `report-summary-${caseId}`, value: summary },
              { key: `report-summary-by-${caseId}`, value: summaryBy ?? 'analyst' },
              { key: `report-summary-at-${caseId}`, value: Date.now() },
            ])
          }}
          placeholder="edit the summary…"
        />
      </div>
    </div>
  )
}

/** What the report carries, as the Review page set it, with the findings by severity and the case notes it prints. */
export function ContentsPanel({ settings, bySev, timeline, tasks, notes }: { settings: ReportSettings; bySev: Record<string, number>; timeline: number; tasks: number; notes: number }) {
  return (
    <div className="panel">
      <div className="panel-h">
        contents <span className="muted">· set on the Review page</span>
      </div>
      <div className="panel-b row wrap" style={{ gap: 8 }}>
        <Badge sev="accent">from {settings.minSeverity} up</Badge>
        <Badge>{settings.includeChains ? `chains · steps: ${settings.chainDetail}` : 'no chains'}</Badge>
        {ORDER.map((s) => (
          <Badge key={s} sev={s}>
            {s} {bySev[s] ?? 0}
          </Badge>
        ))}
        <Badge sev={settings.includeTimeline ? 'ok' : 'info'}>timeline {timeline}</Badge>
        <Badge sev={settings.includeTasks ? 'ok' : 'info'}>tasks {tasks}</Badge>
        <Badge sev={settings.includeNotes ? 'ok' : 'info'}>notes {notes}</Badge>
      </div>
    </div>
  )
}

/**
 * What a responder carries into their own tools: every finding but the false positives, whatever
 * the report's floor, and the analyst's timeline, as a Timesketch or Timeline Explorer timeline and
 * an ATT&CK Navigator layer.
 */
export function ResponderExports({ kase, fileBase, findings, timeline }: { kase: Case; fileBase: string; findings: Finding[]; timeline: CaseNote[] }) {
  const responderFindings = findings.filter((f) => f.status !== 'false_positive')
  const exportTimeline = (format: 'jsonl' | 'csv') => {
    const { records, untimed } = timelineRecords({ findings: responderFindings, notes: timeline })
    if (format === 'jsonl') downloadBlob(`${fileBase}-timeline.jsonl`, new Blob([toTimesketchJsonl(records)], { type: 'application/x-ndjson' }))
    else downloadBlob(`${fileBase}-timeline.csv`, new Blob(['\ufeff' + toTimelineCsv(records)], { type: 'text/csv;charset=utf-8' }))
    if (untimed) toast('ok', `${fmtNum(records.length)} line(s) exported; ${fmtNum(untimed)} item(s) without an event time left out`)
  }
  return (
    <div className="panel">
      <div className="panel-h">responder exports</div>
      <div className="panel-b col">
        <div className="row wrap" style={{ gap: 8 }}>
          <button className="btn sm" onClick={() => exportTimeline('jsonl')}>
            <IconDownload /> timeline for Timesketch (.jsonl)
          </button>
          <button className="btn sm" onClick={() => exportTimeline('csv')}>
            <IconDownload /> timeline for Timeline Explorer (.csv)
          </button>
          <button
            className="btn sm"
            onClick={() => downloadBlob(`${fileBase}-attack-layer.json`, new Blob([JSON.stringify(navigatorLayer(kase, responderFindings), null, 2)], { type: 'application/json' }))}
          >
            <IconDownload /> ATT&amp;CK Navigator layer
          </button>
        </div>
        <div className="hint">
          Every finding except the false positives, whatever the report's floor, and the case timeline entries. Times are UTC. The layer colours each technique by the worst severity of its findings.
          The Events page exports its filtered rows as a timeline too.
        </div>
      </div>
    </div>
  )
}

/** The case as one file to move it to another machine, and a dropped bundle imported as a new case. */
export function CaseBundlePanel({ kase }: { kase: Case }) {
  const [progress, setProgress] = useState('')
  return (
    <div className="panel">
      <div className="panel-h">case bundle (move the case to another machine)</div>
      <div className="panel-b col">
        <div className="row">
          <button className="btn sm" onClick={() => exportCaseBundle(kase, setProgress).catch((e) => toast('err', e.message))}>
            <IconDownload /> export case bundle (.remn.ndjson)
          </button>
          <span className="small dim">{progress}</span>
        </div>
        <Dropzone
          compact
          multiple={false}
          onFiles={(f) =>
            importCaseBundle(f[0], setProgress)
              .then((id) =>
                toast(
                  'ok',
                  `case imported (#${id}) - switch to it from the case selector. External lookups are off in the imported case whatever the bundle had; switch them on there if it may use them.`,
                  9000,
                ),
              )
              .catch((e) => toast('err', e.message, 0))
          }
        >
          <div className="big">drop a bundle to import</div>
        </Dropzone>
        <div className="hint">The bundle contains every row of the case and a SHA-256 of its content, verified at import.</div>
      </div>
    </div>
  )
}
