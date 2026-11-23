import { IconAi, IconCheck, IconDownload } from '../../components/Icons'
import { Spinner } from '../../components/ui'
import { fmtNum } from '../../util/format'

/** What the report holds, and the ways it goes out: HTML, Word, a tab of its own, or the printer. */
export function ReportHeader({
  counts,
  minSeverity,
  questions,
  busy,
  onReview,
  onSummary,
  onHtml,
  onWord,
  onTab,
  onPrint,
}: {
  counts: { stories: number; chains: number; incidents: number; findings: number; iocs: number; evidence: number; undecided: number }
  minSeverity: string
  questions: { counts: { open: number; answered: number; cannot: number } } | undefined
  /** the model is drafting the summary */
  busy: boolean
  onReview: () => void
  onSummary: () => void
  onHtml: () => void
  onWord: () => void
  onTab: () => void
  onPrint: () => void
}) {
  return (
    <div className="view-header">
      <div className="desc">
        <h1>Report</h1>
        <span className="sub">
          {counts.stories} stor{counts.stories === 1 ? 'y' : 'ies'} · {counts.chains} chain(s) · {counts.incidents} incident(s) · {counts.findings} finding(s) from {minSeverity} up · {counts.iocs}{' '}
          flagged IOC(s) · {counts.evidence} evidence file(s)
          {counts.undecided ? ` · ${fmtNum(counts.undecided)} item(s) not yet reviewed` : ' · everything reviewed'}
          {questions ? ` · ${fmtNum(questions.counts.open)} of ${fmtNum(questions.counts.open + questions.counts.answered + questions.counts.cannot)} question(s) open` : ''}
        </span>
      </div>
      <span className="spacer" />
      <button className="btn sm" onClick={onReview}>
        <IconCheck /> review and choose contents
      </button>
      <button className="btn sm" onClick={onSummary} disabled={busy}>
        {busy ? <Spinner /> : <IconAi />} AI executive summary
      </button>
      <button className="btn sm primary" onClick={onHtml}>
        <IconDownload /> download HTML
      </button>
      <button className="btn sm" title="the same report as a Word document to edit before it goes out (the graphs stay in the HTML report)" onClick={onWord}>
        <IconDownload /> Word
      </button>
      <button className="btn sm" onClick={onTab}>
        open in a tab
      </button>
      <button className="btn sm" onClick={onPrint}>
        print / PDF
      </button>
    </div>
  )
}

/** What holds the report back: items without a decision, and stories out of date with a way to build them again. */
export function ReportBars({
  undecided,
  storiesStale,
  rebuilding,
  onReview,
  onRebuild,
}: {
  undecided: number
  /** why the stories no longer read the case as it is; empty when they do or there are none */
  storiesStale: string[]
  rebuilding: boolean
  onReview: () => void
  onRebuild: () => void
}) {
  return (
    <>
      {undecided > 0 && (
        <div className="bulkbar" style={{ background: 'var(--sev-medium-bg)', borderColor: 'rgba(217,130,43,0.35)', color: 'var(--sev-medium)', borderRadius: 'var(--radius)' }}>
          <b>{fmtNum(undecided)} item(s) have no decision yet.</b>
          <span>The report prints whatever passes the severity floor; the Review page lets you confirm, dismiss, rescore and annotate first.</span>
          <span className="spacer" />
          <button className="btn xs" onClick={onReview}>
            go to Review
          </button>
        </div>
      )}
      {storiesStale.length > 0 && (
        <div className="bulkbar" role="status" style={{ background: 'var(--sev-medium-bg)', borderColor: 'rgba(217,130,43,0.35)', color: 'var(--sev-medium)', borderRadius: 'var(--radius)' }}>
          <b>The stories are out of date.</b>
          <span>{storiesStale.join('; ')}. The report says so until they are built again.</span>
          <span className="spacer" />
          <button className="btn xs" onClick={onRebuild} disabled={rebuilding}>
            {rebuilding ? <Spinner /> : null} rebuild stories
          </button>
        </div>
      )}
    </>
  )
}
