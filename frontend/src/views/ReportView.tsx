import { useEffect, useState } from 'react'
import { runAgent } from '../ai/chat'
import { getSource } from '../data/source'
import { getDb, type Evidence, type Finding, type Ioc } from '../db/schema'
import { toast, useStore } from '../state/store'
import { defang, escapeHtml, fmtBytes, fmtNum, fmtTs, renderMarkdown } from '../util/format'
import { downloadBlob, exportCaseBundle, importCaseBundle } from '../util/export'
import { Badge, Spinner } from '../components/ui'
import { Dropzone } from '../components/Dropzone'
import { IconAi, IconDownload } from '../components/Icons'

const ORDER = ['critical', 'high', 'medium', 'low', 'info']

export function ReportView() {
  const kase = useStore((s) => s.currentCase)
  const rulesVersion = useStore((s) => s.rulesVersion)
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [iocs, setIocs] = useState<Ioc[]>([])
  const [summary, setSummary] = useState<string>('')
  const [busy, setBusy] = useState(false)
  const [progress, setProgress] = useState('')
  const [includeFp, setIncludeFp] = useState(false)
  useEffect(() => {
    if (!kase?.id) return
    const db = getDb()
    db.evidence.where('caseId').equals(kase.id).toArray().then(setEvidence)
    db.findings.where('caseId').equals(kase.id).toArray().then((f) => setFindings(f.sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity) || (a.ts ?? 0) - (b.ts ?? 0))))
    getSource(kase).listIocs({ onlyBad: true, limit: 500 }).then((r) => setIocs(r.rows)).catch(() => setIocs([]))
    db.kv.get(`report-summary-${kase.id}`).then((k) => setSummary((k?.value as string) ?? ''))
  }, [kase, rulesVersion])
  if (!kase) return null
  const shown = findings.filter((f) => includeFp || f.status !== 'false_positive')
  const bySev = shown.reduce((acc, f) => ((acc[f.severity] = (acc[f.severity] ?? 0) + 1), acc), {} as Record<string, number>)
  const generateSummary = async () => {
    if (useStore.getState().aiStatus.reachable !== true) return toast('err', 'Ollama is not reachable (check the AI section in Settings)')
    setBusy(true)
    try {
      const data = { case: { name: kase.name, analyst: kase.analyst, settings: { internalDomains: kase.settings.internalDomains } }, summary: await getSource(kase).summary(), findings: shown.slice(0, 60).map((f) => ({ severity: f.severity, title: f.title, entities: f.entities, count: f.count, first: f.ts ? new Date(f.ts).toISOString() : null, last: f.tsEnd ? new Date(f.tsEnd).toISOString() : null, attack: f.attack, status: f.status, notes: f.notes })), iocs: iocs.slice(0, 40).map((i) => ({ kind: i.kind, value: i.value, verdict: i.verdict, tags: i.tags })) }
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
    const rows = (xs: string[][]) => xs.map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`).join('')
    return `<!doctype html><html><head><meta charset="utf-8"><title>REMN report - ${escapeHtml(kase.name)}</title>
<style>body{font:13px/1.5 Segoe UI,Arial,sans-serif;color:#111;margin:40px;max-width:1100px}h1{font-size:22px;border-bottom:2px solid #222;padding-bottom:6px}h2{font-size:16px;margin-top:28px;border-bottom:1px solid #ccc}table{border-collapse:collapse;width:100%;font-size:12px}td,th{border:1px solid #ccc;padding:4px 6px;text-align:left;vertical-align:top}th{background:#eee}code,.mono{font-family:Consolas,monospace;font-size:11px}.sev-critical{color:#b00035;font-weight:bold}.sev-high{color:#c4471b;font-weight:bold}.sev-medium{color:#9a6b00}.sev-low{color:#1f5fb0}.sev-info{color:#666}.muted{color:#666}</style></head><body>
<h1>Forensic analysis report — ${escapeHtml(kase.name)}</h1>
<p class="muted">Generated ${new Date().toISOString()} by REMN${kase.analyst ? ` · analyst ${escapeHtml(kase.analyst)}` : ''}. All timestamps UTC.</p>
${summary ? `<h2>Executive summary</h2><div>${renderMarkdown(summary)}</div>` : ''}
<h2>Evidence &amp; chain of custody</h2>
<table><tr><th>file</th><th>kind</th><th>size</th><th>rows</th><th>SHA-256</th><th>integrity</th><th>added</th></tr>${rows(evidence.map((e) => [escapeHtml(e.name), e.format || e.kind, fmtBytes(e.size), fmtNum(e.count), `<code>${e.sha256Client ?? ''}</code>`, e.integrity, fmtTs(e.addedAt)]))}</table>
<h2>Findings (${shown.length})</h2>
<p>${ORDER.map((s) => `<span class="sev-${s}">${s}: ${bySev[s] ?? 0}</span>`).join(' · ')}</p>
<table><tr><th>severity</th><th>finding</th><th>entities</th><th>count</th><th>first</th><th>last</th><th>ATT&amp;CK</th><th>status</th><th>notes</th></tr>${rows(shown.map((f) => [`<span class="sev-${f.severity}">${f.severity}</span>`, escapeHtml(f.title) + (f.escalation ? `<br><span class="muted">${escapeHtml(f.escalation)}</span>` : ''), `<code>${escapeHtml(Object.entries(f.entities).map(([k, v]) => `${k}=${v}`).join('; '))}</code>`, String(f.count), fmtTs(f.ts), fmtTs(f.tsEnd ?? null), f.attack.join(' '), f.status, escapeHtml(f.notes ?? '')]))}</table>
<h2>Indicators of compromise (flagged by reputation)</h2>
${iocs.length ? `<table><tr><th>kind</th><th>indicator (defanged)</th><th>verdict</th><th>tags</th><th>seen</th></tr>${rows(iocs.map((i) => [i.kind, `<code>${escapeHtml(defang(i.value))}</code>`, i.verdict ?? '', (i.tags ?? []).join(' '), `${i.count} (${i.sources.join(', ')})`]))}</table>` : '<p class="muted">No indicator flagged (reputation checks not run, or nothing malicious).</p>'}
<h2>Timeline of findings</h2>
<table><tr><th>time (UTC)</th><th>severity</th><th>finding</th><th>entities</th></tr>${rows([...shown].filter((f) => f.ts).sort((a, b) => (a.ts ?? 0) - (b.ts ?? 0)).map((f) => [fmtTs(f.ts), `<span class="sev-${f.severity}">${f.severity}</span>`, escapeHtml(f.title), `<code>${escapeHtml(Object.values(f.entities).slice(0, 3).join(' · '))}</code>`]))}</table>
<h2>Case settings</h2>
<p class="mono">internal domains: ${escapeHtml(kase.settings.internalDomains.join(', ') || '—')} · VIPs: ${escapeHtml(kase.settings.vipNames.join(', ') || '—')} · business hours ${kase.settings.businessHours.start}h–${kase.settings.businessHours.end}h (${escapeHtml(kase.settings.businessHours.tz)}) · external lookups ${kase.settings.networkAllowed ? 'enabled' : 'disabled'}</p>
</body></html>`
  }
  return (
    <div className="view">
      <div className="view-header">
        <h1>Report</h1>
        <span className="sub">{shown.length} finding(s) · {iocs.length} flagged IOC(s) · {evidence.length} evidence file(s)</span>
        <span className="spacer" />
        <label className="checkbox small"><input type="checkbox" checked={includeFp} onChange={(e) => setIncludeFp(e.target.checked)} /> include false positives</label>
        <button className="btn sm" onClick={generateSummary} disabled={busy}>{busy ? <Spinner /> : <IconAi />} AI executive summary</button>
        <button className="btn sm primary" onClick={() => downloadBlob(`${kase.name.replace(/[^a-z0-9_-]+/gi, '_')}-report.html`, new Blob([html()], { type: 'text/html' }))}><IconDownload /> download HTML</button>
        <button className="btn sm" onClick={() => { const w = window.open('', '_blank'); if (w) { w.document.write(html()); w.document.close(); w.focus(); setTimeout(() => w.print(), 300) } }}>print / PDF</button>
      </div>
      <div className="view-body col" style={{ gap: 14 }}>
        <div className="grid-2">
          <div className="panel">
            <div className="panel-h">executive summary</div>
            <div className="panel-b">
              {summary ? <div className="md" dangerouslySetInnerHTML={{ __html: renderMarkdown(summary) }} /> : <div className="muted small">Click "AI executive summary" to have the local model draft it from the findings, or write your own below.</div>}
              <textarea className="textarea" style={{ marginTop: 8, minHeight: 120 }} value={summary} onChange={(e) => setSummary(e.target.value)} onBlur={() => getDb().kv.put({ key: `report-summary-${kase.id}`, value: summary })} placeholder="edit the summary…" />
            </div>
          </div>
          <div className="col">
            <div className="panel">
              <div className="panel-h">findings by severity</div>
              <div className="panel-b row wrap" style={{ gap: 8 }}>{ORDER.map((s) => <Badge key={s} sev={s}>{s} {bySev[s] ?? 0}</Badge>)}</div>
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
          <div className="panel-b"><iframe title="report preview" sandbox="" srcDoc={html()} style={{ width: '100%', height: 520, background: '#fff', border: '1px solid var(--line-2)', borderRadius: 4 }} /></div>
        </div>
      </div>
    </div>
  )
}
