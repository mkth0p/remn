import { useStore } from '../state/store'
import { fmtNum } from '../util/format'
import { IconAi, IconEvents, IconEvidence, IconFindings, IconLink, IconMail, IconReport, IconRules, IconSettings } from '../components/Icons'

/**
 * Product sheet, reached from the wordmark: what REMN reads, what it produces, how a case
 * flows, where the data lives, shortcuts and licences. Live numbers come from what the
 * app already loaded (rules, packs, server health); nothing here is fetched.
 */
export function HomeView() {
  const setView = useStore((s) => s.setView)
  const meta = useStore((s) => s.meta)
  const health = useStore((s) => s.health)
  const kase = useStore((s) => s.currentCase)
  const counts = useStore((s) => s.counts)
  const bundled = meta?.rules.filter((r) => !r.error).length ?? 0
  const packs = meta?.packs ?? []
  const packRules = packs.reduce((s, p) => s + (p.counts?.converted ?? 0), 0)
  const go = (v: Parameters<typeof setView>[0]) => () => setView(v)

  return (
    <div className="view">
      <div className="view-body home">
        <section className="home-hero">
          <div className="wordmark">REMN</div>
          <p className="lead">Forensic analysis of Windows event logs, mailboxes and Microsoft 365 exports. Evidence is parsed and scored on this machine, rules and cross-source correlation run over it, and the result is a triage queue, attack chains and a report.</p>
          <div className="row wrap" style={{ gap: 8 }}>
            <button className="btn primary" onClick={go('evidence')}><IconEvidence /> add evidence</button>
            <button className="btn" onClick={go('findings')}><IconFindings /> findings</button>
            <button className="btn" onClick={go('chains')}><IconLink /> chains</button>
            <button className="btn" onClick={go('report')}><IconReport /> report</button>
            <button className="btn ghost" onClick={go('settings')}><IconSettings /> settings</button>
          </div>
          <div className="small muted mono" style={{ marginTop: 6 }}>
            server {health ? `v${health.version}` : 'offline'} · {fmtNum(bundled)} bundled rules · {packs.length} community pack{packs.length === 1 ? '' : 's'} ({fmtNum(packRules)} rules) · PST {health?.optional.pst ? 'supported' : 'needs libpff-python'} · YARA {health?.optional.yara ? `${fmtNum(health.optional.yaraRules)} rules` : 'not installed'}
            {kase ? ` · current case "${kase.name}": ${fmtNum(counts.events)} events, ${fmtNum(counts.mails)} mails, ${fmtNum(counts.findings)} findings` : ''}
          </div>
        </section>

        <div className="grid-3 home-grid">
          <section className="card">
            <h3><IconEvidence /> What it reads</h3>
            <ul>
              <li><b>Windows event logs</b>: .evtx (Security, System, Sysmon, PowerShell, Defender, any channel), single files or archives.</li>
              <li><b>Mailboxes</b>: .pst and .ost exports, .mbox, .eml (single or zipped), .msg; deleted and orphaned items are recovered and tagged.</li>
              <li><b>Microsoft 365 / Entra</b>: Unified Audit Log exports (CSV or JSON, including Splunk exports) and sign-in logs.</li>
              <li>Attachments are analysed statically (Office macros, PDF, archives, HTML smuggling, disguised executables), never opened.</li>
            </ul>
          </section>
          <section className="card">
            <h3><IconFindings /> What it produces</h3>
            <ul>
              <li><b>Mail risk</b>: every message scored from authentication, sender identity, links, wording and attachments, with the reasons kept on the row.</li>
              <li><b>Findings</b>: {fmtNum(bundled)} bundled rules plus the SigmaHQ and Sublime collections, grouped into <b>incidents</b> per mail or per user, host and IP.</li>
              <li><b>Attack chains</b>: what a recipient did after a suspicious mail across the mailbox, the cloud audit trail and the host, scored and explained step by step.</li>
              <li><b>Entity pages</b> for any user, host, IP, sender or domain; a curated case timeline, tasks and notes; an HTML report.</li>
            </ul>
          </section>
          <section className="card">
            <h3><IconLink /> How a case flows</h3>
            <ol>
              <li>Create a case, set the internal domains, VIP names and business hours in Settings.</li>
              <li>Drop the evidence. Files are hashed, parsed and scored; the rules run when the ingest finishes.</li>
              <li>Work the Findings queue by incident, open the rows behind a finding, pivot on entities.</li>
              <li>Build the chains, read them as stories, pin what matters to the case timeline.</li>
              <li>Ask the local analyst model with the evidence as its only source, then export the report.</li>
            </ol>
          </section>
          <section className="card">
            <h3><IconEvents /> Where the data lives</h3>
            <ul>
              <li><b>Browser store</b> (default): rows stay in this browser's IndexedDB; the server only parses uploads in temporary files it deletes at the end of each request.</li>
              <li><b>Server store</b>: for GB-scale cases, rows go to a DuckDB file under the server's case directory; findings, chains and notes stay in the browser.</li>
              <li>Nothing leaves the machine unless a case enables reputation lookups. The analyst model is your own Ollama, reached from the browser or through the server.</li>
              <li>A case exports as one bundle with a content hash and imports on another machine.</li>
            </ul>
          </section>
          <section className="card">
            <h3><IconAi /> Keyboard</h3>
            <table className="table compact keys">
              <tbody>
                <tr><td><kbd>j</kbd> <kbd>k</kbd></td><td className="sans">next / previous incident, mail or chain step</td></tr>
                <tr><td><kbd>/</kbd></td><td className="sans">focus the search of the page</td></tr>
                <tr><td><kbd>Esc</kbd></td><td className="sans">close the flyout or the message pane</td></tr>
                <tr><td><kbd>Enter</kbd></td><td className="sans">apply a search, send a question, add a task or note</td></tr>
              </tbody>
            </table>
            <div className="small muted" style={{ marginTop: 8 }}>Alt-click a facet to exclude it. Click a cell value in the Events or Mails tables to filter on it. Drag on the Timeline chart to select a range.</div>
          </section>
          <section className="card">
            <h3><IconRules /> Credits</h3>
            <ul>
              <li>Detection content: <b>SigmaHQ</b> rules (Detection Rule License) and <b>Sublime Security</b> rules (see the pack cards on the Rules page for versions and licences).</li>
              <li>Wordmark and titles set in <b>Gulax</b> by Morgan Gilbert, Velvetyne (SIL Open Font License 1.1).</li>
              <li>Built on Django, DuckDB, React, Dexie, ECharts, DOMPurify, libpff, pyevtx-rs and Ollama.</li>
              <li>Validation numbers on public corpora and the security model are in the README.</li>
            </ul>
          </section>
        </div>
        <div className="small muted" style={{ padding: '4px 2px' }}>
          <IconMail /> Findings only reflect the last rule run: the Findings page says when the evidence is ahead of it.
        </div>
      </div>
    </div>
  )
}
