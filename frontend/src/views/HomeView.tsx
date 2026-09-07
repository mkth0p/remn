import { useStore } from '../state/store'
import { fmtNum } from '../util/format'

/** Intro page behind the wordmark: one sentence, three lines, one button. */
export function HomeView() {
  const setView = useStore((s) => s.setView)
  const meta = useStore((s) => s.meta)
  const health = useStore((s) => s.health)
  const kase = useStore((s) => s.currentCase)
  const counts = useStore((s) => s.counts)
  const bundled = meta?.rules.filter((r) => !r.error).length ?? 0
  const packs = meta?.packs?.length ?? 0
  const hasEvidence = counts.events + counts.mails > 0

  return (
    <div className="view">
      <div className="view-body intro">
        <div className="wordmark">REMN</div>
        <p className="lead">Forensic analysis of Windows event logs, mailboxes and Microsoft 365 exports.</p>
        <dl>
          <dt>in</dt>
          <dd>.evtx, .pst / .ost, .mbox, .eml, .msg, Unified Audit Log and Entra sign-in exports</dd>
          <dt>out</dt>
          <dd>scored mails, findings grouped into incidents, attack chains across mail, cloud and host, a report</dd>
          <dt>where</dt>
          <dd>in this browser, or in a DuckDB store on your server for large cases; the analyst model is your own Ollama, or Claude through a Claude Code sign-in on the server</dd>
        </dl>
        <div className="row" style={{ gap: 8 }}>
          {hasEvidence ? (
            <button className="btn primary" onClick={() => setView('findings')}>
              open the findings
            </button>
          ) : (
            <button className="btn primary" onClick={() => setView('evidence')}>
              add evidence
            </button>
          )}
          <button className="btn ghost" onClick={() => setView('settings')}>
            settings
          </button>
        </div>
        <div className="foot mono">
          {health ? `v${health.version}` : 'server offline'} · {fmtNum(bundled)} rules, {packs} community pack{packs === 1 ? '' : 's'}
          {kase && hasEvidence ? ` · ${kase.name}: ${fmtNum(counts.events)} events, ${fmtNum(counts.mails)} mails, ${fmtNum(counts.findings)} findings` : ''}
          <br />j / k move, / searches, Esc closes · type in Gulax by Velvetyne · rules from SigmaHQ and Sublime
        </div>
      </div>
    </div>
  )
}
