import { useState } from 'react'
import { saveReportSettings, type ClientReport, type ReportSettings } from '../data/review'
import { buildIncidents } from '../rules/incidents'
import { toast, useStore } from '../state/store'
import { downloadBlob } from '../util/export'
import { buildReportDocx, DOCX_MIME } from '../data/reportDocx'
import { buildReportHtml, evidencePeriod, impactInventory, ruleAuthors, spineStartingPoint, type ReportData } from '../data/reportHtml'
import { draftExecutiveSummary } from '../data/reportSummary'
import { buildCampaignGraph } from '../data/chainGraph'
import { saveReportIssue, type ReportIssue } from '../data/reportPreflight'
import { measuredOn } from '../data/ruleMeasures'
import { buildStories } from '../data/stories'
import { ClientPanel } from './report/ClientPanel'
import { reportFigures } from './report/model'
import { ReportBars, ReportHeader } from './report/ReportHeader'
import { openReport, printReport } from './report/reportOutput'
import { CaseBundlePanel, ContentsPanel, PreflightPanel, ResponderExports, SummaryPanel } from './report/ReportPanels'
import { useReportContents } from './report/useReportContents'
import { useReportData } from './report/useReportData'

/**
 * Report: built from the Review page's decisions (severity floor, what is in or out, rescored
 * severities, chain verdicts and narratives, chain detail level) plus the case notes. Every cell is
 * escaped; the document prints from a sandboxed frame.
 */
export function ReportView() {
  const kase = useStore((s) => s.currentCase)
  const setView = useStore((s) => s.setView)
  const {
    evidence,
    findings,
    chains,
    storyResult,
    storyNotes,
    storyDecisions,
    storiesStale,
    coverageWarnings,
    reviews,
    relationships,
    settings,
    setSettings,
    iocs,
    iocCounts,
    aiUsage,
    issue,
    setIssue,
    rulesState,
    gaps,
    measures,
    ruleMap,
    notes,
    questionScenarios,
    answers,
    profile,
    summary,
    setSummary,
    summaryBy,
    setSummaryBy,
    summaryAt,
    setSummaryAt,
    fontData,
    scope,
  } = useReportData(kase)
  const [rebuilding, setRebuilding] = useState(false)
  // the preview is drawn during render, which must not read the clock: it shows when the page opened
  const [previewAt] = useState(() => Date.now())
  const measureSources = useStore((s) => s.meta?.measures)
  const [busy, setBusy] = useState(false)
  const { questions, selection, printedStories, graphs, claims } = useReportContents({
    kase,
    settings,
    findings,
    chains,
    reviews,
    evidence,
    summary,
    ruleMap,
    stories: { result: storyResult, notes: storyNotes, decisions: storyDecisions },
    questions: { scenarios: questionScenarios, answers, profile },
  })
  if (!kase || !settings) return null
  const { shown, incidents, membersOf, bySev, curated, tasks, analystNotes, undecided, hiddenConfirmed, unverified, checks, status, words, printedStatus } = reportFigures({
    settings,
    findings,
    chains,
    reviews,
    selection,
    printedStories,
    claims,
    notes,
    evidence,
    rulesState,
    issue,
  })
  /** The stories read again from the case as it is now; the page reloads what it prints once they are. */
  const rebuildStories = async () => {
    setRebuilding(true)
    try {
      await buildStories(kase)
      useStore.getState().bumpRules()
    } catch (e) {
      toast('err', `the stories could not be built: ${(e as Error).message}`)
    } finally {
      setRebuilding(false)
    }
  }
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

  // the report made now (download, print, a tab, Word), or at a given time (the preview, drawn during render)
  const reportData = (generatedAt?: number): ReportData => ({
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
    issue: { status: printedStatus.status, finalAt: printedStatus.finalAt, open: printedStatus.open, waived: printedStatus.waived },
    rules: rulesState,
    iocsTotal: iocCounts.total,
    iocsChecked: iocCounts.checked,
    fontData,
    ai: aiUsage,
    gaps,
    measures,
    measuredOn: measuredOn(measureSources),
    claims,
    stories: printedStories.stories,
    storiesLeft: printedStories.left,
    storyIncidents: storyResult?.incidents,
    storyStats: storyResult?.stats,
    storiesStale,
    storyNotesOrphaned: printedStories.orphans,
    decidedStories: printedStories.decided,
    storiesDismissed: printedStories.dismissed,
    storyDecisionsOrphaned: printedStories.decisionsOrphaned,
    questions,
    scope,
    ruleAuthors: ruleAuthors(ruleMap.values()),
  })
  const html = (generatedAt?: number) => buildReportHtml(reportData(generatedAt))
  /** a change to the client part of the report settings, kept with the case and its bundle */
  const patchClient = (patch: Partial<ClientReport>) => patchSettings({ client: { ...settings.client, ...patch } })
  const patchSettings = (patch: Partial<ReportSettings>) => {
    const next = { ...settings, ...patch }
    setSettings(next)
    void saveReportSettings(kase.id!, next)
  }
  const fileBase = kase.name.replace(/[^a-z0-9_-]+/gi, '_')
  return (
    <div className="view">
      <ReportHeader
        counts={{
          stories: printedStories.stories.length,
          chains: selection.chains.length,
          incidents: incidents.length,
          findings: shown.length,
          iocs: iocs.length,
          evidence: evidence.length,
          undecided,
        }}
        minSeverity={settings.minSeverity}
        questions={questions}
        busy={busy}
        onReview={() => setView('review')}
        onSummary={generateSummary}
        onHtml={() => downloadBlob(`${fileBase}-report.html`, new Blob([html()], { type: 'text/html' }))}
        onWord={() => downloadBlob(`${fileBase}-report.docx`, new Blob([buildReportDocx(reportData()) as BlobPart], { type: DOCX_MIME }))}
        onTab={() => openReport(html())}
        onPrint={() => printReport(html())}
      />
      <div className="view-body col" style={{ gap: 14 }}>
        <ReportBars undecided={undecided} storiesStale={storyResult ? storiesStale : []} rebuilding={rebuilding} onReview={() => setView('review')} onRebuild={rebuildStories} />
        <PreflightPanel status={status} checks={checks} issue={issue} onIssue={updateIssue} unverified={unverified} />
        <div className="grid-2">
          <SummaryPanel caseId={kase.id} summary={summary} setSummary={setSummary} summaryBy={summaryBy} setSummaryBy={setSummaryBy} setSummaryAt={setSummaryAt} />
          <div className="col">
            <ContentsPanel settings={settings} bySev={bySev} timeline={curated.length} tasks={tasks.length} notes={analystNotes.length} />
            <ResponderExports kase={kase} fileBase={fileBase} findings={findings} timeline={curated} />
            <CaseBundlePanel kase={kase} />
          </div>
        </div>
        <ClientPanel
          key={kase.id}
          client={settings.client}
          onChange={patchClient}
          language={settings.language}
          branding={settings.branding}
          onSettings={patchSettings}
          spineDraft={spineStartingPoint(printedStories.stories, words)}
          scope={scope}
          period={evidencePeriod(evidence)}
          impact={impactInventory(reportData(previewAt))}
        />
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
