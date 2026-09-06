import { useEffect, useMemo, useState } from 'react'
import { runAgent } from '../ai/chat'
import { getSource } from '../data/source'
import { loadChains, type Chain } from '../data/chains'
import { listNotes } from '../data/caseNotes'
import { chainSeverity, effectiveSeverity, loadChainReviews, loadReportSettings, selectForReport, stepVisible, type ChainReview, type ReportSettings } from '../data/review'
import { getDb, type CaseNote, type Evidence, type Finding, type Ioc } from '../db/schema'
import { buildIncidents } from '../rules/incidents'
import { toast, useStore } from '../state/store'
import { defang, escapeHtml, fmtBytes, fmtNum, fmtTs, renderMarkdown } from '../util/format'
import { downloadBlob, exportCaseBundle, importCaseBundle } from '../util/export'
import { Badge, Spinner } from '../components/ui'
import { Dropzone } from '../components/Dropzone'
import { IconAi, IconCheck, IconDownload } from '../components/Icons'

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
  const [reviews, setReviews] = useState<Record<string, ChainReview>>({})
  const [settings, setSettings] = useState<ReportSettings | null>(null)
  const [iocs, setIocs] = useState<Ioc[]>([])
  const [notes, setNotes] = useState<CaseNote[]>([])
  const [summary, setSummary] = useState<string>('')
  const [busy, setBusy] = useState(false)
  const [progress, setProgress] = useState('')
  useEffect(() => {
    if (!kase?.id) return
    const db = getDb()
    db.evidence.where('caseId').equals(kase.id).toArray().then(setEvidence)
    db.findings.where('caseId').equals(kase.id).toArray().then((f) => setFindings(f.sort((a, b) => ORDER.indexOf(effectiveSeverity(a)) - ORDER.indexOf(effectiveSeverity(b)) || (a.ts ?? 0) - (b.ts ?? 0))))
    getSource(kase).listIocs({ onlyBad: true, limit: 500 }).then((r) => setIocs(r.rows)).catch(() => setIocs([]))
    db.kv.get(`report-summary-${kase.id}`).then((k) => setSummary((k?.value as string) ?? ''))
    listNotes(kase.id).then(setNotes)
    loadChains(kase.id).then((r) => setChains(r?.chains ?? []))
    loadChainReviews(kase.id).then(setReviews)
    loadReportSettings(kase.id).then(setSettings)
  }, [kase, rulesVersion])
  const selection = useMemo(() => (settings ? selectForReport(findings, chains, reviews, settings) : { findings: [], chains: [] }), [findings, chains, reviews, settings])
  if (!kase || !settings) return null
  const shown = selection.findings
  const incidents = buildIncidents(shown)
  const bySev = shown.reduce((acc, f) => ((acc[effectiveSeverity(f)] = (acc[effectiveSeverity(f)] ?? 0) + 1), acc), {} as Record<string, number>)
  const curated = notes.filter((n) => n.kind === 'timeline').sort((a, b) => a.ts - b.ts)
  const tasks = notes.filter((n) => n.kind === 'task').sort((a, b) => Number(a.done ?? false) - Number(b.done ?? false) || a.createdAt - b.createdAt)
  const analystNotes = notes.filter((n) => n.kind === 'note').sort((a, b) => a.createdAt - b.createdAt)
  // same unit as the Review page: incidents without a decision plus chains without a verdict
  const undecided = buildIncidents(findings).filter((i) => i.status === 'new').length + chains.filter((c) => !reviews[c.id]?.verdict).length

  const generateSummary = async () => {
    if (useStore.getState().aiStatus.reachable !== true) return toast('err', 'Ollama is not reachable (check the AI section in Settings)')
    setBusy(true)
    try {
      const data = {
        case: { name: kase.name, analyst: kase.analyst, settings: { internalDomains: kase.settings.internalDomains } },
        summary: await getSource(kase).summary(),
        chains: selection.chains.slice(0, 10).map((c) => ({ recipient: c.identityLabel, severity: chainSeverity(c, reviews[c.id]), verdict: reviews[c.id]?.verdict, narrative: reviews[c.id]?.narrative || c.summary })),
        incidents: incidents.slice(0, 40).map((i) => ({ title: i.title, severity: i.severity, status: i.status, findings: i.findings.map((f) => f.title), entities: i.entities, note: i.lead.notes })),
        iocs: iocs.slice(0, 40).map((i) => ({ kind: i.kind, value: i.value, verdict: i.verdict, tags: i.tags })),
      }
      const msgs = await runAgent([{ role: 'user', content: `Write the executive summary for this investigation:\n\`\`\`json\n${JSON.stringify(data).slice(0, 60000)}\n\`\`\`` }], kase, { mode: 'report', tools: false, think: false, maxIterations: 1 })
      const text = msgs.filter((m) => m.role === 'assistant').map((m) => m.content).join('\n')
      setSummary(text)
      await getDb().kv.put({ key: `report-summary-${kase.id}`, value: text })
    } catch (e) {
      toast('err', (e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const html = () => {
    // every cell is escaped here; the few cells that carry markup build it from already-escaped text
    const h = escapeHtml
    const rows = (xs: string[][]) => xs.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('')
    const sev = (x: string) => { const k = ORDER.includes(x) ? x : 'info'; return `<span class="sev-${k}">${h(x)}</span>` }
    const chainSection = selection.chains.map((c) => {
      const r = reviews[c.id]
      const steps = c.steps.filter((s) => stepVisible(s, settings.chainDetail))
      const hidden = c.steps.length - steps.length
      return `<h3>${h(c.identityLabel)} · ${sev(chainSeverity(c, r))} · score ${c.score}${r?.verdict ? ` · ${h(r.verdict)}` : ''}</h3>
<p class="muted">Seed mail "${h(c.seed.subject)}" from ${h(c.seed.fromAddr ?? '')} at ${fmtTs(c.seed.ts)} (risk ${c.seed.risk}) · ${c.steps.length} steps from ${fmtTs(c.start)} to ${fmtTs(c.end)} · ${c.artifactLinks} artifact link(s)${c.entities.attackerAddresses.length ? ` · attacker ${h(c.entities.attackerAddresses.join(', '))}` : ''}${c.entities.ips.length ? ` · IPs ${h(c.entities.ips.join(', '))}` : ''}</p>
<p>${r?.narrative ? renderMarkdown(r.narrative) : h(c.summary)}</p>
<table><tr><th>time (UTC)</th><th>offset</th><th>source</th><th>step</th><th>ties to the mail / findings</th></tr>${rows(steps.map((s) => [fmtTs(s.ts), `${s.offsetMin >= 0 ? '+' : ''}${Math.round(s.offsetMin)} min`, h(s.kind === 'mail' ? 'mailbox' : s.origin === 'm365' ? 'Microsoft 365' : 'host'), h(s.title) + (s.computer || s.ipAddress ? `<br><span class="muted">${h([s.computer, s.ipAddress].filter(Boolean).join(' · '))}</span>` : ''), h([...s.artifacts, ...s.findings.map((f) => f.title)].join('; '))]))}</table>${hidden ? `<p class="muted">${hidden} routine step(s) not printed at the "${h(settings.chainDetail)}" detail level.</p>` : ''}`
    }).join('\n')
    return `<!doctype html><html><head><meta charset="utf-8"><title>REMN report - ${h(kase.name)}</title>
<style>body{font:13px/1.5 Segoe UI,Arial,sans-serif;color:#111;margin:40px;max-width:1100px}h1{font-size:22px;border-bottom:2px solid #222;padding-bottom:6px}h2{font-size:16px;margin-top:28px;border-bottom:1px solid #ccc}h3{font-size:14px;margin-top:20px}table{border-collapse:collapse;width:100%;font-size:12px;margin:6px 0 12px}td,th{border:1px solid #ccc;padding:4px 6px;text-align:left;vertical-align:top}th{background:#eee}code,.mono{font-family:Consolas,monospace;font-size:11px}.sev-critical{color:#b00035;font-weight:bold}.sev-high{color:#c4471b;font-weight:bold}.sev-medium{color:#9a6b00}.sev-low{color:#1f5fb0}.sev-info{color:#666}.muted{color:#666}</style></head><body>
<h1>Forensic analysis report — ${h(kase.name)}</h1>
<p class="muted">Generated ${new Date().toISOString()} by REMN${kase.analyst ? ` · analyst ${h(kase.analyst)}` : ''}. All timestamps UTC. Findings from ${h(settings.minSeverity)} severity up${settings.onlyReviewed ? ', reviewed items only' : ''}${settings.includeFp ? ', false positives included' : ''}.</p>
${summary ? `<h2>Executive summary</h2><div>${renderMarkdown(summary)}</div>` : ''}
${settings.includeEvidence ? `<h2>Evidence &amp; chain of custody</h2>
<table><tr><th>file</th><th>kind</th><th>size</th><th>rows</th><th>SHA-256</th><th>integrity</th><th>added</th></tr>${rows(evidence.map((e) => [h(e.name), h(e.format || e.kind), fmtBytes(e.size), fmtNum(e.count), `<code>${h(e.sha256Client ?? '')}</code>`, h(e.integrity), fmtTs(e.addedAt)]))}</table>` : ''}
${selection.chains.length ? `<h2>Attack chains (${selection.chains.length})</h2>${chainSection}` : ''}
<h2>Incidents (${incidents.length})</h2>
<p>${ORDER.map((s) => `<span class="sev-${s}">${s}: ${bySev[s] ?? 0}</span>`).join(' · ')} finding(s). Findings on the same mail, or about the same user, host or IP within six hours, are one incident.</p>
${incidents.map((i) => `<h3>${sev(i.severity)} · ${h(i.title)}${i.status !== 'new' ? ` · ${h(i.status === 'escalated' ? 'confirmed' : i.status === 'false_positive' ? 'false positive' : i.status)}` : ''}</h3>
<p class="muted">${h(i.subtitle)} · ${fmtTs(i.ts)}${i.tsEnd && i.tsEnd !== i.ts ? ` → ${fmtTs(i.tsEnd)}` : ''} · entities: <code>${h(Object.entries(i.entities).slice(0, 8).map(([k, v]) => `${k}=${v}`).join('; '))}</code></p>
${i.lead.notes ? `<p>${renderMarkdown(i.lead.notes)}</p>` : ''}
<table><tr><th>severity</th><th>finding</th><th>rule</th><th>rows</th><th>first</th><th>ATT&amp;CK</th></tr>${rows(i.findings.map((f) => [sev(effectiveSeverity(f)) + (f.severityOverride ? `<br><span class="muted">rule: ${h(f.severity)}</span>` : ''), h(f.title) + (f.escalation ? `<br><span class="muted">${h(f.escalation)}</span>` : ''), `<code>${h(f.ruleId)}</code>`, String(f.count), fmtTs(f.ts), h(f.attack.join(' '))]))}</table>`).join('\n')}
${settings.includeIocs ? `<h2>Indicators of compromise (flagged by reputation)</h2>
${iocs.length ? `<table><tr><th>kind</th><th>indicator (defanged)</th><th>verdict</th><th>tags</th><th>seen</th></tr>${rows(iocs.map((i) => [h(i.kind), `<code>${h(defang(i.value))}</code>`, h(i.verdict ?? ''), h((i.tags ?? []).join(' ')), h(`${i.count} (${i.sources.join(', ')})`)]))}</table>` : '<p class="muted">No indicator flagged (reputation checks not run, or nothing malicious).</p>'}` : ''}
${settings.includeTimeline && curated.length ? `<h2>Case timeline</h2><table><tr><th>time (UTC)</th><th>severity</th><th>entry</th><th>source</th></tr>${rows(curated.map((n) => [fmtTs(n.ts), sev(n.severity ?? 'info'), h(n.text), n.link ? h(`${n.link.source} ${n.link.label ?? n.link.id}`) : '']))}</table>` : ''}
${settings.includeTasks && tasks.length ? `<h2>Tasks</h2><table><tr><th>status</th><th>task</th><th>updated</th></tr>${rows(tasks.map((t) => [t.done ? 'done' : '<b>open</b>', h(t.text), fmtTs(t.updatedAt)]))}</table>` : ''}
${settings.includeNotes && analystNotes.length ? `<h2>Analyst notes</h2>${analystNotes.map((n) => `<div><p class="muted">${fmtTs(n.createdAt)}</p>${renderMarkdown(n.text)}</div>`).join('<hr>')}` : ''}
<h2>Timeline of findings</h2>
<table><tr><th>time (UTC)</th><th>severity</th><th>finding</th><th>entities</th></tr>${rows([...shown].filter((f) => f.ts).sort((a, b) => (a.ts ?? 0) - (b.ts ?? 0)).map((f) => [fmtTs(f.ts), sev(effectiveSeverity(f)), h(f.title), `<code>${h(Object.values(f.entities).slice(0, 3).join(' · '))}</code>`]))}</table>
<h2>Case settings</h2>
<p class="mono">internal domains: ${h(kase.settings.internalDomains.join(', ') || '—')} · VIPs: ${h(kase.settings.vipNames.join(', ') || '—')} · business hours ${kase.settings.businessHours.start}h–${kase.settings.businessHours.end}h (${h(kase.settings.businessHours.tz)}) · external lookups ${kase.settings.networkAllowed ? 'enabled' : 'disabled'}</p>
</body></html>`
  }
  // the report is built from case data: print it from a sandboxed frame (opaque origin, no access to the case database)
  const printReport = () => {
    const frame = document.createElement('iframe')
    frame.setAttribute('sandbox', 'allow-modals')
    frame.style.cssText = 'position:fixed;right:0;bottom:0;width:0;height:0;border:0'
    frame.srcdoc = html()
    frame.onload = () => {
      try {
        frame.contentWindow?.print()
      } finally {
        setTimeout(() => frame.remove(), 60_000)
      }
    }
    document.body.appendChild(frame)
  }
  return (
    <div className="view">
      <div className="view-header">
        <div className="desc">
          <h1>Report</h1>
          <span className="sub">{selection.chains.length} chain(s) · {incidents.length} incident(s) · {shown.length} finding(s) from {settings.minSeverity} up · {iocs.length} flagged IOC(s) · {evidence.length} evidence file(s){undecided ? ` · ${fmtNum(undecided)} item(s) not yet reviewed` : ' · everything reviewed'}</span>
        </div>
        <span className="spacer" />
        <button className="btn sm" onClick={() => setView('review')}><IconCheck /> review and choose contents</button>
        <button className="btn sm" onClick={generateSummary} disabled={busy}>{busy ? <Spinner /> : <IconAi />} AI executive summary</button>
        <button className="btn sm primary" onClick={() => downloadBlob(`${kase.name.replace(/[^a-z0-9_-]+/gi, '_')}-report.html`, new Blob([html()], { type: 'text/html' }))}><IconDownload /> download HTML</button>
        <button className="btn sm" onClick={printReport}>print / PDF</button>
      </div>
      <div className="view-body col" style={{ gap: 14 }}>
        {undecided > 0 && (
          <div className="bulkbar" style={{ background: 'var(--sev-medium-bg)', borderColor: 'rgba(217,130,43,0.35)', color: 'var(--sev-medium)', borderRadius: 'var(--radius)' }}>
            <b>{fmtNum(undecided)} item(s) have no decision yet.</b>
            <span>The report prints whatever passes the severity floor; the Review page lets you confirm, dismiss, rescore and annotate first.</span>
            <span className="spacer" />
            <button className="btn xs" onClick={() => setView('review')}>go to Review</button>
          </div>
        )}
        <div className="grid-2">
          <div className="panel">
            <div className="panel-h">executive summary</div>
            <div className="panel-b">
              {summary ? <div className="md" dangerouslySetInnerHTML={{ __html: renderMarkdown(summary) }} /> : <div className="muted small">Click "AI executive summary" to have the local model draft it from the reviewed chains and incidents, or write your own below.</div>}
              <textarea className="textarea" style={{ marginTop: 8, minHeight: 120 }} value={summary} onChange={(e) => setSummary(e.target.value)} onBlur={() => getDb().kv.put({ key: `report-summary-${kase.id}`, value: summary })} placeholder="edit the summary…" />
            </div>
          </div>
          <div className="col">
            <div className="panel">
              <div className="panel-h">contents <span className="muted">· set on the Review page</span></div>
              <div className="panel-b row wrap" style={{ gap: 8 }}>
                <Badge sev="accent">from {settings.minSeverity} up</Badge>
                <Badge>{settings.includeChains ? `chains · steps: ${settings.chainDetail}` : 'no chains'}</Badge>
                {ORDER.map((s) => <Badge key={s} sev={s}>{s} {bySev[s] ?? 0}</Badge>)}
                <Badge sev={settings.includeTimeline ? 'ok' : 'info'}>timeline {curated.length}</Badge>
                <Badge sev={settings.includeTasks ? 'ok' : 'info'}>tasks {tasks.length}</Badge>
                <Badge sev={settings.includeNotes ? 'ok' : 'info'}>notes {analystNotes.length}</Badge>
              </div>
            </div>
            <div className="panel">
              <div className="panel-h">case bundle (move the case to another machine)</div>
              <div className="panel-b col">
                <div className="row"><button className="btn sm" onClick={() => exportCaseBundle(kase, setProgress).catch((e) => toast('err', e.message))}><IconDownload /> export case bundle (.remn.json)</button><span className="small dim">{progress}</span></div>
                <Dropzone compact multiple={false} onFiles={(f) => importCaseBundle(f[0], setProgress).then((id) => toast('ok', `case imported (#${id}) - switch to it from the case selector`)).catch((e) => toast('err', e.message, 0))}><div className="big">drop a bundle to import</div></Dropzone>
                <div className="hint">The bundle contains every row of the case and a SHA-256 of its content, verified at import.</div>
              </div>
            </div>
          </div>
        </div>
        <div className="panel">
          <div className="panel-h">preview</div>
          <div className="panel-b"><iframe title="report preview" sandbox="" srcDoc={html()} style={{ width: '100%', height: 560, background: '#fff', border: '1px solid var(--line-2)', borderRadius: 4 }} /></div>
        </div>
      </div>
    </div>
  )
}
