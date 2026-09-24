import { useEffect, useMemo, useState } from 'react'
import { getSource } from '../data/source'
import { chainCoverageWarnings, loadChains, type Chain } from '../data/chains'
import { listNotes } from '../data/caseNotes'
import { chainSeverity, effectiveSeverity, loadChainReviews, loadReportSettings, selectForReport, unprintedConfirmed, type ChainReview, type ReportSettings } from '../data/review'
import { getDb, type CaseNote, type Evidence, type Finding, type Ioc } from '../db/schema'
import { buildIncidents } from '../rules/incidents'
import { toast, useStore } from '../state/store'
import { fmtNum, renderMarkdown } from '../util/format'
import { downloadBlob, exportCaseBundle, importCaseBundle } from '../util/export'
import { Badge, Spinner } from '../components/ui'
import { Dropzone } from '../components/Dropzone'
import { renderGraphPng } from '../components/ChainGraph'
import { buildReportHtml, loadReportFont, type AiUsage } from '../data/reportHtml'
import { summariseLedger } from '../ai/ledger'
import { draftExecutiveSummary } from '../data/reportSummary'
import { buildCampaignGraph } from '../data/chainGraph'
import { IconAi, IconCheck, IconDownload } from '../components/Icons'
import { reportRelationships, type RelationshipReview } from '../data/relationshipReviews'
import { findingsStaleness } from '../data/findingsState'
import { aiDecided, issueStatus, loadReportIssue, preflightChecks, saveReportIssue, type ReportIssue } from '../data/reportPreflight'
import { loadEvidenceGaps, type GapStatement } from '../data/evidenceGaps'
import { loadRules } from '../data/rules'
import { measuredOn, readMeasure, type MeasureReading } from '../data/ruleMeasures'

const ORDER = ['critical', 'high', 'medium', 'low', 'info']

/**
 * Report: built from the Review page's decisions (severity floor, what is in or out, rescored
 * severities, chain verdicts and narratives, chain detail level) plus the case notes. Every cell is
 * escaped; the document prints from a sandboxed frame.
 */
export function ReportView() {
  const kase = useStore((s) => s.currentCase)
  const rulesVersion = useStore((s) => s.rulesVersion)
  const setView = useStore((s) => s.setView)
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [chains, setChains] = useState<Chain[]>([])
  const [coverageWarnings, setCoverageWarnings] = useState<string[]>([])
  const [reviews, setReviews] = useState<Record<string, ChainReview>>({})
  const [relationships, setRelationships] = useState<RelationshipReview[]>([])
  const [settings, setSettings] = useState<ReportSettings | null>(null)
  const [iocs, setIocs] = useState<Ioc[]>([])
  const [iocCounts, setIocCounts] = useState<{ total: number; checked: number }>({ total: 0, checked: 0 })
  const [aiUsage, setAiUsage] = useState<AiUsage | undefined>(undefined)
  const [issue, setIssue] = useState<ReportIssue>({ waivers: {} })
  // the preview is drawn during render, which must not read the clock: it shows when the page opened
  const [previewAt] = useState(() => Date.now())
  const [rulesState, setRulesState] = useState<{ lastRun: number | null; evidenceAfter: number; errors: number } | undefined>(undefined)
  /** what the evidence cannot show, for "Where it stops" */
  const [gaps, setGaps] = useState<GapStatement[]>([])
  /** how far each rule's finding can be taken as a detection */
  const [measures, setMeasures] = useState<Record<string, MeasureReading>>({})
  const measureSources = useStore((s) => s.meta?.measures)
  const [notes, setNotes] = useState<CaseNote[]>([])
  const [summary, setSummary] = useState<string>('')
  /** who wrote the summary last: the model's draft is labelled in the report until the analyst edits it */
  const [summaryBy, setSummaryBy] = useState<'analyst' | 'ai' | undefined>(undefined)
  const [summaryAt, setSummaryAt] = useState<number | undefined>(undefined)
  const [busy, setBusy] = useState(false)
  const [progress, setProgress] = useState('')
  const [fontData, setFontData] = useState<string | undefined>(undefined)
  useEffect(() => {
    loadReportFont().then(setFontData)
  }, [])
  useEffect(() => {
    if (!kase?.id) return
    const db = getDb()
    db.evidence.where('caseId').equals(kase.id).toArray().then(setEvidence)
    db.findings
      .where('caseId')
      .equals(kase.id)
      .toArray()
      .then((f) => setFindings(f.sort((a, b) => ORDER.indexOf(effectiveSeverity(a)) - ORDER.indexOf(effectiveSeverity(b)) || (a.ts ?? 0) - (b.ts ?? 0))))
    getSource(kase)
      .listIocs({ onlyBad: true, limit: 500 })
      .then((r) => setIocs(r.rows))
      .catch(() => setIocs([]))
    // what the report says about enrichment follows the lookups that ran, not the setting
    Promise.all([getSource(kase).listIocs({ limit: 1 }), getSource(kase).listIocs({ unchecked: true, limit: 1 })])
      .then(([all, unchecked]) => setIocCounts({ total: all.total, checked: Math.max(0, all.total - unchecked.total) }))
      .catch(() => setIocCounts({ total: 0, checked: 0 }))
    loadReportIssue(kase.id).then(setIssue)
    loadEvidenceGaps(kase.id, getSource(kase))
      .then(setGaps)
      .catch(() => setGaps([]))
    loadRules(kase.id)
      .then((rs) => setMeasures(Object.fromEntries(rs.map((r) => [r.rule.id, readMeasure(r.measured, r.origin)]))))
      .catch(() => setMeasures({}))
    summariseLedger(kase.id)
      .then(setAiUsage)
      .catch(() => setAiUsage(undefined))
    findingsStaleness(kase.id)
      .then((s) => setRulesState({ lastRun: s.lastRun, evidenceAfter: s.evidenceAfter, errors: s.errors.length }))
      .catch(() => setRulesState(undefined))
    db.kv.get(`report-summary-${kase.id}`).then((k) => setSummary((k?.value as string) ?? ''))
    db.kv.get(`report-summary-by-${kase.id}`).then((k) => setSummaryBy((k?.value as 'analyst' | 'ai' | undefined) ?? undefined))
    db.kv.get(`report-summary-at-${kase.id}`).then((k) => setSummaryAt((k?.value as number | undefined) ?? undefined))
    listNotes(kase.id).then(setNotes)
    loadChains(kase.id).then((r) => {
      setChains(r?.chains ?? [])
      setCoverageWarnings(chainCoverageWarnings(r?.stats))
    })
    loadChainReviews(kase.id).then(setReviews)
    reportRelationships(kase.id).then(setRelationships)
    loadReportSettings(kase.id).then(setSettings)
  }, [kase, rulesVersion])
  const selection = useMemo(() => (settings ? selectForReport(findings, chains, reviews, settings) : { findings: [], chains: [] }), [findings, chains, reviews, settings])
  // graph pictures for the report, drawn off-screen from the same models as the Chains page
  const [graphs, setGraphs] = useState<Record<string, string>>({})
  useEffect(() => {
    if (!settings?.includeGraphs || !selection.chains.length) {
      setGraphs({})
      return
    }
    const out: Record<string, string> = {}
    for (const c of selection.chains) {
      const png = renderGraphPng({ mode: 'chain', chain: c })
      if (png) out[c.id] = png
    }
    if (selection.chains.length > 1) {
      const png = renderGraphPng({ mode: 'campaign', chains: selection.chains })
      if (png) out['campaign'] = png
    }
    setGraphs(out)
  }, [selection.chains, settings?.includeGraphs])
  if (!kase || !settings) return null
  const shown = selection.findings
  // findings linked to a printed chain are printed with it, not as incidents
  const grouped = buildIncidents(shown, { chains: selection.chains, severityOf: (c) => chainSeverity(c, reviews[c.id]) })
  const incidents = grouped.filter((i) => i.kind !== 'chain')
  const membersOf = new Map(grouped.filter((i) => i.kind === 'chain' && i.chain).map((i) => [i.chain!.id, i.findings.filter((f) => f.ruleId !== 'chain')]))
  const bySev = shown.reduce((acc, f) => ((acc[effectiveSeverity(f)] = (acc[effectiveSeverity(f)] ?? 0) + 1), acc), {} as Record<string, number>)
  const curated = notes.filter((n) => n.kind === 'timeline').sort((a, b) => a.ts - b.ts)
  const tasks = notes.filter((n) => n.kind === 'task').sort((a, b) => Number(a.done ?? false) - Number(b.done ?? false) || a.createdAt - b.createdAt)
  const analystNotes = notes.filter((n) => n.kind === 'note').sort((a, b) => a.createdAt - b.createdAt)
  // same unit as the Review page: incidents without a decision plus chains without a verdict
  const undecided = buildIncidents(findings, { chains }).filter((i) => (i.kind === 'chain' && i.chain ? !reviews[i.chain.id]?.verdict : i.status === 'new')).length
  const hiddenConfirmed = unprintedConfirmed(findings, chains, reviews, selection)
  const checks = preflightChecks({ evidence, rules: rulesState, undecided, aiDecided: aiDecided(findings), unprintedConfirmed: hiddenConfirmed.length })
  const status = issueStatus(checks, issue)
  const updateIssue = (next: ReportIssue) => {
    setIssue(next)
    void saveReportIssue(kase.id!, next)
  }

  const generateSummary = async () => {
    if (useStore.getState().aiStatus.reachable !== true) return toast('err', 'the analyst model is not reachable (see the AI section in Settings)')
    setBusy(true)
    try {
      // draftExecutiveSummary records who wrote it and when with the text
      setSummary(await draftExecutiveSummary(kase))
      setSummaryBy('ai')
      setSummaryAt(Date.now())
    } catch (e) {
      toast('err', (e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  // the report made now (download, print, a tab), or at a given time (the preview, drawn during render)
  const html = (generatedAt?: number) =>
    buildReportHtml({
      kase,
      generatedAt,
      settings,
      summary,
      summaryBy,
      summaryAt,
      falsePositives: buildIncidents(findings, { chains }).filter((i) => (i.kind === 'chain' && i.chain ? reviews[i.chain.id]?.verdict === 'benign' : i.status === 'false_positive')).length,
      evidence,
      chains: selection.chains,
      reviews,
      coverageWarnings,
      relationships,
      membersOf,
      graphs,
      campaignInsights:
        settings.includeGraphs && selection.chains.length > 1
          ? buildCampaignGraph(selection.chains)
              .insights.slice(0, 8)
              .map((x) => x.text)
          : [],
      incidents,
      findings: shown,
      iocs,
      timeline: curated,
      tasks,
      notes: analystNotes,
      undecided,
      unprintedConfirmed: hiddenConfirmed,
      issue: { status: status.status, finalAt: status.finalAt, open: status.open, waived: status.waived },
      rules: rulesState,
      iocsTotal: iocCounts.total,
      iocsChecked: iocCounts.checked,
      fontData,
      ai: aiUsage,
      gaps,
      measures,
      measuredOn: measuredOn(measureSources),
    })
  /** The report in its own tab: the browser's own print-to-PDF, or to keep it open next to the case. */
  const openReport = () => {
    const url = URL.createObjectURL(new Blob([html()], { type: 'text/html' }))
    const w = window.open(url, '_blank')
    if (w) w.opener = null
    else toast('err', 'the browser blocked the new tab: allow pop-ups for this site, or use "download HTML"', 0)
    setTimeout(() => URL.revokeObjectURL(url), 120_000)
  }
  // the report is built from case data: it prints from a frame that runs no script (so nothing in it can
  // reach the case database) but keeps the app's origin, which the browser needs before it lets the page
  // call print() on the frame; a sandbox without allow-same-origin makes that call a SecurityError
  const printReport = () => {
    const frame = document.createElement('iframe')
    frame.setAttribute('sandbox', 'allow-same-origin allow-modals')
    // laid out at full size (a zero-size frame prints blank in some browsers) but invisible and inert
    frame.style.cssText = 'position:fixed;inset:0;width:100vw;height:100vh;border:0;opacity:0;pointer-events:none;z-index:-1'
    frame.srcdoc = html()
    frame.onload = () => {
      const win = frame.contentWindow
      try {
        win?.addEventListener('afterprint', () => frame.remove())
        win?.focus()
        win?.print()
      } catch (e) {
        frame.remove()
        toast('err', `the browser refused to print from the page (${(e as Error).message}); the report opens in a new tab, print it from there`, 0)
        openReport()
        return
      }
      setTimeout(() => frame.remove(), 120_000)
    }
    document.body.appendChild(frame)
  }
  return (
    <div className="view">
      <div className="view-header">
        <div className="desc">
          <h1>Report</h1>
          <span className="sub">
            {selection.chains.length} chain(s) · {incidents.length} incident(s) · {shown.length} finding(s) from {settings.minSeverity} up · {iocs.length} flagged IOC(s) · {evidence.length} evidence
            file(s){undecided ? ` · ${fmtNum(undecided)} item(s) not yet reviewed` : ' · everything reviewed'}
          </span>
        </div>
        <span className="spacer" />
        <button className="btn sm" onClick={() => setView('review')}>
          <IconCheck /> review and choose contents
        </button>
        <button className="btn sm" onClick={generateSummary} disabled={busy}>
          {busy ? <Spinner /> : <IconAi />} AI executive summary
        </button>
        <button className="btn sm primary" onClick={() => downloadBlob(`${kase.name.replace(/[^a-z0-9_-]+/gi, '_')}-report.html`, new Blob([html()], { type: 'text/html' }))}>
          <IconDownload /> download HTML
        </button>
        <button className="btn sm" onClick={openReport}>
          open in a tab
        </button>
        <button className="btn sm" onClick={printReport}>
          print / PDF
        </button>
      </div>
      <div className="view-body col" style={{ gap: 14 }}>
        {undecided > 0 && (
          <div className="bulkbar" style={{ background: 'var(--sev-medium-bg)', borderColor: 'rgba(217,130,43,0.35)', color: 'var(--sev-medium)', borderRadius: 'var(--radius)' }}>
            <b>{fmtNum(undecided)} item(s) have no decision yet.</b>
            <span>The report prints whatever passes the severity floor; the Review page lets you confirm, dismiss, rescore and annotate first.</span>
            <span className="spacer" />
            <button className="btn xs" onClick={() => setView('review')}>
              go to Review
            </button>
          </div>
        )}
        <div className="panel">
          <div className="panel-h">
            preflight · the report is <b style={{ color: status.status === 'final' ? 'var(--ok)' : 'var(--warn)' }}>{status.status === 'final' ? 'final' : 'a draft'}</b>
            <span className="spacer" />
            {status.status === 'final' ? (
              <button className="btn xs" onClick={() => updateIssue({ ...issue, finalAt: undefined })}>
                back to draft
              </button>
            ) : (
              <button
                className="btn xs primary"
                disabled={status.open.length > 0}
                title={status.open.length ? 'every open check needs to pass or be waived with a reason' : 'print the report as final, with the waivers listed'}
                onClick={() => updateIssue({ ...issue, finalAt: Date.now() })}
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
                      onBlur={(e) => updateIssue({ ...issue, waivers: { ...issue.waivers, [c.id]: e.target.value } })}
                    />
                  )}
                </div>
              </div>
            ))}
            <div className="hint">
              A draft says so on its cover. Final needs every check to pass or to be waived with a reason; a new open check (evidence added, a rule run that failed) returns it to draft.
            </div>
          </div>
        </div>
        <div className="grid-2">
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
                    { key: `report-summary-${kase.id}`, value: summary },
                    { key: `report-summary-by-${kase.id}`, value: summaryBy ?? 'analyst' },
                    { key: `report-summary-at-${kase.id}`, value: Date.now() },
                  ])
                }}
                placeholder="edit the summary…"
              />
            </div>
          </div>
          <div className="col">
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
                <Badge sev={settings.includeTimeline ? 'ok' : 'info'}>timeline {curated.length}</Badge>
                <Badge sev={settings.includeTasks ? 'ok' : 'info'}>tasks {tasks.length}</Badge>
                <Badge sev={settings.includeNotes ? 'ok' : 'info'}>notes {analystNotes.length}</Badge>
              </div>
            </div>
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
                      .then((id) => toast('ok', `case imported (#${id}) - switch to it from the case selector`))
                      .catch((e) => toast('err', e.message, 0))
                  }
                >
                  <div className="big">drop a bundle to import</div>
                </Dropzone>
                <div className="hint">The bundle contains every row of the case and a SHA-256 of its content, verified at import.</div>
              </div>
            </div>
          </div>
        </div>
        <div className="panel">
          <div className="panel-h">preview</div>
          <div className="panel-b">
            <iframe title="report preview" sandbox="" srcDoc={html(previewAt)} style={{ width: '100%', height: 560, background: '#fff', border: '1px solid var(--line-2)', borderRadius: 4 }} />
          </div>
        </div>
      </div>
    </div>
  )
}
