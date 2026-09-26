import { useEffect, useRef, useState, type ReactNode } from 'react'
import '@fontsource/ibm-plex-sans/400.css'
import '@fontsource/ibm-plex-sans/500.css'
import '@fontsource/ibm-plex-sans/600.css'
import '@fontsource/ibm-plex-mono/400.css'
import '@fontsource/ibm-plex-mono/500.css'
import '../ui/landing.css'
import { toast, useStore } from '../state/store'
import { RemnMark } from '../components/RemnMark'
import { deployment } from '../data/deployment'
import { openDemoCase } from '../data/demoCase'
import { requestIngest } from '../data/ingest'
import { startCase } from '../data/cases'
import { EXAMPLE_RULE, HEAD_TO_HEAD, HELD_OUT, liveFigures, MAIL_CORPORA, type LiveFigures } from '../data/landingFigures'
import { fmtNum } from '../util/format'

type Level = 'info' | 'medium' | 'high'
type Section = 'coverage' | 'baseline' | 'mail' | 'method' | 'modules' | 'data'
const SECTIONS: [Section, string][] = [
  ['coverage', 'Coverage'],
  ['baseline', 'Baseline'],
  ['mail', 'Mail'],
  ['method', 'Method'],
  ['modules', 'Modules'],
  ['data', 'Data handling'],
]
const LEVELS: [Level, string][] = [
  ['info', '≥ info'],
  ['medium', '≥ medium'],
  ['high', '≥ high'],
]

/**
 * The page REMN opens on until a case holds evidence, and behind the wordmark after that: what the
 * tool reads, how its rules are measured and what the measures show, and where a case starts.
 */
export function HomeView() {
  const meta = useStore((s) => s.meta)
  const health = useStore((s) => s.health)
  const kase = useStore((s) => s.currentCase)
  const counts = useStore((s) => s.counts)
  const setView = useStore((s) => s.setView)
  const live = liveFigures(meta)
  const dep = deployment(health)
  const browserOnly = health?.mode === 'browser-only'
  const [newCase, setNewCase] = useState(false)
  const [demo, setDemo] = useState<string | null>(null)
  const refs = useRef<Partial<Record<Section, HTMLElement | null>>>({})
  const hasEvidence = counts.evidence > 0

  const jump = (s: Section) => refs.current[s]?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  const openDemo = () => {
    setDemo('Opening…')
    openDemoCase(setDemo)
      .then((c) => {
        const s = useStore.getState()
        s.setCurrentCase(c)
        s.bumpCases()
        s.setView('stories')
        toast('ok', `${c.name}: synthetic evidence, restored in this browser; nothing was uploaded`)
      })
      .catch((e: Error) => toast('err', e.message, 0))
      .finally(() => setDemo(null))
  }
  const where =
    dep.tier === 'this-machine'
      ? 'Evidence is parsed on this machine and kept in this browser (IndexedDB) or in a DuckDB file on this machine.'
      : dep.tier === 'uploaded-not-kept'
        ? `Files are parsed on ${dep.host}, which keeps nothing; the case stays in this browser (IndexedDB).`
        : `Files are parsed on ${dep.host}; the case is kept in this browser (IndexedDB) or on ${dep.host} (DuckDB).`

  return (
    <div className="landing">
      <header className="ld-hero">
        <div className="ld-wrap">
          <nav className="ld-nav" aria-label="Home">
            <span className="ld-logo">
              <RemnMark size={34} />
              <span>REMN</span>
            </span>
            <div className="ld-links">
              {SECTIONS.map(([id, label]) => (
                <button key={id} type="button" onClick={() => jump(id)}>
                  {label}
                </button>
              ))}
              <a href={dep.source} target="_blank" rel="noreferrer noopener">
                Source
              </a>
            </div>
            <div className="ld-nav-cta">
              {kase && (
                <button type="button" className="ld-btn ld-btn-ghost" onClick={() => setView('dashboard')} title={`Open ${kase.name}`}>
                  Open case <span className="ld-case">{kase.name}</span>
                </button>
              )}
              <button type="button" className="ld-btn ld-btn-primary" onClick={() => setNewCase(true)}>
                New case
              </button>
            </div>
          </nav>

          <div className="ld-hero-grid">
            <div>
              <span className="ld-kicker">EVTX · PST/OST · MBOX · EML/MSG · M365 UAL · Entra</span>
              <h1>Detection and investigation for Windows event logs, mailboxes and Microsoft 365.</h1>
              <p className="ld-lede">
                {live
                  ? `${fmtNum(live.rules)} detection rules, each scored against ${fmtNum(live.recordings)} public attack recordings${live.baseline ? ` and ${fmtNum(live.baseline.events)} events from ${fmtNum(live.baseline.machines)} clean hosts` : ''}. Every finding reports its rule's measured detection and false-positive counts.`
                  : "Detection rules scored against public attack recordings and clean hosts. Every finding reports its rule's measured detection and false-positive counts."}
              </p>
              <div className="ld-ctas">
                <button type="button" className="ld-btn ld-btn-primary" onClick={() => setNewCase(true)}>
                  New case
                </button>
                <button type="button" className="ld-btn ld-btn-ghost" onClick={openDemo} disabled={!!demo}>
                  {demo ?? 'Open demo case'}
                </button>
              </div>
              <p className="ld-fine">Apache-2.0. {where}</p>
            </div>
            <ExampleFinding live={live} />
          </div>
        </div>
      </header>

      <div className="ld-formats">
        <div className="ld-wrap">
          <small>Input</small>
          {['.evtx', 'event XML', '.pst / .ost', '.mbox', '.eml / .msg', 'UAL export', 'Entra sign-in logs', 'host packages'].map((f) => (
            <span key={f}>{f}</span>
          ))}
        </div>
      </div>

      <main className="ld-wrap">
        <Coverage ref={(el) => void (refs.current.coverage = el)} />
        <Baseline ref={(el) => void (refs.current.baseline = el)} live={live} />
        <Mail ref={(el) => void (refs.current.mail = el)} />
        <Method ref={(el) => void (refs.current.method = el)} live={live} />
        <Modules ref={(el) => void (refs.current.modules = el)} />
        <section className="ld-blk" ref={(el) => void (refs.current.data = el)}>
          <div className="ld-eyebrow">Data handling</div>
          <h2>Storage and network</h2>
          <dl className="ld-spec">
            <dt>This instance</dt>
            <dd>{dep.parsing}</dd>
            <dt>Browser store</dt>
            <dd>Evidence hashed (SHA-256) on import; the case is stored in this browser's IndexedDB.</dd>
            <dt>Server store</dt>
            <dd>{browserOnly ? 'Not offered here: this server keeps nothing.' : 'A DuckDB file on the REMN server, for multi-gigabyte cases.'}</dd>
            <dt>Agent</dt>
            <dd>Runs only when opened. Uses a local model endpoint (Ollama, LM Studio, llama.cpp, vLLM, Jan) or the provider configured on the server.</dd>
          </dl>
          <div className="ld-final">
            <div>
              <h2>New case</h2>
              <p>Create a case, then import evidence. Parsing, detection and story building run on import.</p>
            </div>
            <div className="ld-ctas">
              <button type="button" className="ld-btn ld-btn-primary" onClick={() => setNewCase(true)}>
                New case
              </button>
              {hasEvidence && kase ? (
                <button type="button" className="ld-btn ld-btn-ghost" onClick={() => setView('dashboard')}>
                  Open {kase.name}
                </button>
              ) : (
                <button type="button" className="ld-btn ld-btn-ghost" onClick={openDemo} disabled={!!demo}>
                  {demo ?? 'Open demo case'}
                </button>
              )}
            </div>
          </div>
        </section>
      </main>

      <footer className="ld-wrap ld-footer">
        <span className="ld-logo">
          <RemnMark size={26} />
          <span>REMN</span>
        </span>
        <span>
          {live ? `Measured ${live.measured}` : 'Measures'} · rules/measures.json · sources: EVTX-to-MITRE-Attack, splunk/attack_data, EVTX-ATTACK-SAMPLES, SigmaHQ, NextronSystems/evtx-baseline
        </span>
      </footer>

      {newCase && <NewCaseDialog browserOnly={browserOnly} onClose={() => setNewCase(false)} />}
    </div>
  )
}

function ExampleFinding({ live }: { live: LiveFigures | null }) {
  const ex = live?.example
  return (
    <div className="ld-shot" aria-label="Example finding">
      <span className="ld-example">example finding</span>
      <div className="ld-finding">
        <div className="ld-bar">
          <i />
          <i />
          <i />
          <span>findings · WS-FIN-07</span>
        </div>
        <div className="ld-finding-body">
          <span className="ld-sevtag">HIGH · T1003.001</span>
          <h3>LSASS memory read by unsigned process</h3>
          <dl className="ld-kv">
            <dt>rule</dt>
            <dd>{EXAMPLE_RULE}</dd>
            <dt>image</dt>
            <dd>C:\Users\Public\rundll32.exe</dd>
            <dt>source</dt>
            <dd>Sysmon 10 · GrantedAccess 0x1010 · 3 events</dd>
          </dl>
          {ex && (
            <div className="ld-measured">
              <div className="ld-ring" style={{ ['--p' as string]: Math.round((ex.hits / ex.of) * 100) }}>
                <span>
                  {ex.hits}/{ex.of}
                </span>
              </div>
              <div>
                <b>Rule record</b>
                <p>
                  Detects {fmtNum(ex.hits)} of {fmtNum(ex.of)} recordings of what it looks for. {fmtNum(ex.cleanFindings)} finding{ex.cleanFindings === 1 ? '' : 's'} on the clean baseline
                  {live?.baseline ? ` (${fmtNum(live.baseline.machines)} hosts, ${fmtNum(live.baseline.events)} events)` : ''}.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

type SectionRef = (el: HTMLElement | null) => void

function Table({ head, children, numeric }: { head: string[]; children: ReactNode; numeric?: number }) {
  // columns from `numeric` on are right-aligned figures
  const from = numeric ?? 1
  return (
    <div className="ld-tw">
      <table className="ld-t">
        <thead>
          <tr>
            {head.map((h, i) => (
              <th key={h} className={i >= from ? 'n' : undefined}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  )
}

function Coverage({ ref }: { ref: SectionRef }) {
  const [level, setLevel] = useState<Level>('medium')
  const h = HEAD_TO_HEAD
  const files = h.library.files
  const values = h.detected[level]
  const ticks = [0, 0.25, 0.5, 0.75, 1]
  return (
    <section className="ld-blk" ref={ref}>
      <div className="ld-eyebrow">
        Coverage · {h.library.name} @ {h.library.sha}
      </div>
      <h2>Detection on held-out recordings</h2>
      <p className="ld-intro">
        {files} technique-labelled logs ({fmtNum(h.library.events)} events) that no REMN rule was written against. A file counts as detected when a rule tagged with its ATT&amp;CK v19 technique,
        parent or sub-technique fires on it. Same scorer for all three tools, all shipped rules enabled.
      </p>
      <div className="ld-proof">
        <div className="ld-panel">
          <div className="ld-chart-head">
            <div>
              <div className="ld-chart-t">Files detected / {files}</div>
              <div className="ld-chart-s">level {LEVELS.find(([l]) => l === level)![1]}</div>
            </div>
            <div className="ld-seg" role="group" aria-label="Minimum level">
              {LEVELS.map(([l, label]) => (
                <button key={l} type="button" aria-pressed={l === level} onClick={() => setLevel(l)}>
                  {label}
                </button>
              ))}
            </div>
          </div>
          <div className="ld-bars">
            {h.tools.map((tool, i) => (
              <div key={tool} className={i === 0 ? 'ld-row ld-us' : 'ld-row'}>
                <span className="ld-who">{tool}</span>
                <div className="ld-track">
                  <div className="ld-fill" style={{ width: `${(values[i] / files) * 100}%` }} />
                </div>
                <span className="ld-v">
                  {values[i]}
                  <small>{Math.round((values[i] / files) * 100)}%</small>
                </span>
              </div>
            ))}
          </div>
          <div className="ld-ticks" aria-hidden="true">
            <span />
            <div>
              {ticks.map((t) => (
                <span key={t} style={{ left: `${t * 100}%` }}>
                  {Math.round(t * files)}
                </span>
              ))}
            </div>
            <span />
          </div>
          <p className="ld-note">
            {h.versions} Run {h.date}.
          </p>
        </div>
        <div className="ld-side">
          <Table head={['Scoring variant, ≥ medium', ...h.tools]}>
            <tr>
              <td>Title map for untagged rules</td>
              {h.detected.medium.map((v, i) => (
                <td key={i} className={i === 0 ? 'n b' : 'n'}>
                  {v}
                </td>
              ))}
            </tr>
            <tr>
              <td>Author tags only</td>
              {h.authorTags.map((v, i) => (
                <td key={i} className={i === 0 ? 'n b' : 'n'}>
                  {v}
                </td>
              ))}
            </tr>
            <tr>
              <td>Union of the three</td>
              <td className="n" colSpan={3}>
                {h.union}
              </td>
            </tr>
          </Table>
          <Table head={[`attack_data @ ${HELD_OUT.attackData.sha}, ${HELD_OUT.attackData.recordings} recordings`, '≥ med', '≥ high']}>
            {HELD_OUT.attackData.rows.map(([set, med, high], i, all) => (
              <tr key={set} className={i === all.length - 1 ? 'sum' : undefined}>
                <td>{set}</td>
                <td className="n">{med}</td>
                <td className="n">{high}</td>
              </tr>
            ))}
          </Table>
        </div>
      </div>
      <div className="ld-gap" />
      <Table head={['Tactic, ≥ medium', 'Files', ...h.tools]}>
        {h.tactics.map(([tactic, n, ...v]) => {
          const top = Math.max(...v)
          return (
            <tr key={tactic}>
              <td>{tactic}</td>
              <td className="n">{n}</td>
              {v.map((x, i) => (
                <td key={i} className={x === top && x > 0 ? 'n b' : 'n'}>
                  {x}
                </td>
              ))}
            </tr>
          )
        })}
      </Table>
      <p className="ld-note">
        Per-tactic counts with each tool's threat-hunting rules enabled. {h.onlyRemn} files are detected by REMN only, {h.onlyRemnOwnRules} of them by REMN-authored rules.
      </p>
    </section>
  )
}

function Baseline({ ref, live }: { ref: SectionRef; live: LiveFigures | null }) {
  const c = HELD_OUT.clean
  const b = live?.baseline
  return (
    <section className="ld-blk" ref={ref}>
      <div className="ld-eyebrow">False positives · evtx-baseline {b?.tag ?? 'v0.8.4'}</div>
      <h2>Findings on clean hosts</h2>
      <p className="ld-intro">
        {b ? `${fmtNum(b.machines)} Windows hosts with no attack activity, ${fmtNum(b.events)} events.` : 'Windows hosts with no attack activity.'} Every finding here is either a false positive or
        benign activity the rule describes correctly.
      </p>
      <div className="ld-gap" />
      <Table head={['Rule set', 'Rules firing', 'High + critical findings', 'Events covered', '≥ medium findings']}>
        <tr>
          <td>REMN rules</td>
          <td className="n">{c.own.rules}</td>
          <td className="n b">{fmtNum(c.own.highCritical)}</td>
          <td className="n">{fmtNum(c.own.events)}</td>
          <td className="n">{fmtNum(c.own.mediumUp)}</td>
        </tr>
        <tr>
          <td>REMN + SigmaHQ default packs</td>
          <td className="n">–</td>
          <td className="n">{fmtNum(c.withPacks.highCritical)}</td>
          <td className="n">{fmtNum(c.withPacks.events)}</td>
          <td className="n">–</td>
        </tr>
      </Table>
      <p className="ld-note">
        {c.critical.logCleared} of the {c.critical.of} critical findings are Security log clears (1102) that occurred before export. {fmtNum(c.twoFindingsEvents)} of the {fmtNum(c.own.events)} events
        belong to two grouped findings: an AV installer reading LSASS and one process reading TeamViewer memory. Findings are grouped per image and host. Run {HELD_OUT.date}.
      </p>
    </section>
  )
}

function Mail({ ref }: { ref: SectionRef }) {
  return (
    <section className="ld-blk" ref={ref}>
      <div className="ld-eyebrow">Mail scoring · public corpora</div>
      <h2>Risk bands on phishing and legitimate mail</h2>
      <p className="ld-intro">Default settings, no sender baseline, no internal domains configured. Run {MAIL_CORPORA.date}.</p>
      <div className="ld-gap" />
      <Table head={['Corpus', 'Class', 'Mails', '≥ high', '≥ medium']} numeric={2}>
        {MAIL_CORPORA.rows.map(([corpus, kind, mails, high, medium]) => (
          <tr key={corpus}>
            <td>{corpus}</td>
            <td className="m">{kind}</td>
            <td className="n">{fmtNum(mails)}</td>
            <td className={kind === 'legitimate' && high === 0 ? 'n b' : 'n'}>{high}%</td>
            <td className={(kind === 'phishing' && medium >= 90) || (kind === 'legitimate' && medium <= 2) ? 'n b' : 'n'}>{medium}%</td>
          </tr>
        ))}
      </Table>
    </section>
  )
}

function Method({ ref, live }: { ref: SectionRef; live: LiveFigures | null }) {
  return (
    <section className="ld-blk" ref={ref}>
      <div className="ld-eyebrow">Method</div>
      <h2>How rules are measured</h2>
      <dl className="ld-spec">
        <dt>Rule corpus</dt>
        <dd>
          {live
            ? `${fmtNum(live.rules)} event rules measured: REMN's own and SigmaHQ's converted packs. ${fmtNum(live.detect)} have fired on a recording of what they look for; the rest are marked as leads.`
            : "REMN's own event rules and SigmaHQ's converted packs. Rules seen to fire on a recording of what they look for are marked as detecting; the rest as leads."}
        </dd>
        <dt>Recordings</dt>
        <dd>
          {live
            ? `${fmtNum(live.recordings)}: ${live.libraries.map((l) => `${l.name} ${fmtNum(l.recordings)} (${l.ref})`).join(', ')}.`
            : 'Public libraries of recorded attacks, each pinned to a commit.'}
        </dd>
        <dt>Clean hosts</dt>
        <dd>
          {live?.baseline
            ? `evtx-baseline ${live.baseline.tag}: ${fmtNum(live.baseline.machines)} Windows machines, ${fmtNum(live.baseline.events)} events.`
            : 'evtx-baseline: clean Windows machines.'}
        </dd>
        <dt>Detection</dt>
        <dd>A rule tagged with the recording's technique (ATT&amp;CK v19, revoked ids mapped to successors) raises a finding at or above the level cut.</dd>
        <dt>Held-out</dt>
        <dd>
          Rules written after studying a library are listed in <code>WRITTEN_AGAINST</code> and not scored on it.
        </dd>
        <dt>Engines</dt>
        <dd>Browser and SQL engines produce identical findings on every file of EVTX-ATTACK-SAMPLES.</dd>
        <dt>CI gate</dt>
        <dd>Weekly and on pull requests. A change that removes a measured detection fails the build.</dd>
        <dt>Output</dt>
        <dd>
          <code>rules/measures.json</code>
          {live ? `, measured ${live.measured}` : ''}. Each finding shows its rule's measure.
        </dd>
      </dl>
    </section>
  )
}

const MODULES: { id: string; name: string; text: string; cap: string; rows: [string, string, string, 'h' | 'm' | 'n'][] }[] = [
  {
    id: 'detect',
    name: 'Detection',
    text: 'YAML rules plus SigmaHQ and Sublime packs over events and mail. Findings grouped into incidents, sorted by level and rule record.',
    cap: 'example findings',
    rows: [
      ['LSASS memory read by unsigned process', 'WS-FIN-07 · T1003.001', 'high', 'h'],
      ['Service installed after ADMIN$ write', 'DC01 · 5145 → 7045 within 60 s · T1569.002', 'high', 'h'],
      ['Kerberos pre-auth failure burst', '4771 · 38 accounts · 1 source · T1110.003', 'medium', 'm'],
      ['Run key value under Program Files', 'Sysmon 13 · lead, no measured detection', 'low', 'n'],
    ],
  },
  {
    id: 'stories',
    name: 'Stories',
    text: 'Per-account and per-host sequences ordered by ATT&CK phase: logon sessions, RDP, admin-share, WMI and WinRM hops, process trees, DNS/DHCP address-to-host, Entra device-to-host.',
    cap: 'example story',
    rows: [
      ['Initial access · T1566.002', 'Mail delivered to m.durand, URL clicked', '09:12Z', 'm'],
      ['Valid accounts · T1078.004', 'Entra sign-in, new ASN, device WS-FIN-07', '09:31Z', 'm'],
      ['Remote services · T1021.001', '4624 type 10, WS-FIN-07 → FS02, svc-backup', '10:04Z', 'h'],
      ['Archive collected data · T1560.001', '7z.exe on FS02, 2.1 GB output', '10:22Z', 'h'],
    ],
  },
  {
    id: 'mail',
    name: 'Mail',
    text: 'Header, authentication, link and attachment indicators combined into a risk band. Recipients linked to their later host and cloud activity.',
    cap: 'example mail',
    rows: [
      ['Overdue invoice #44817', 'billing@acme-invoices.co → m.durand', 'band: high', 'h'],
      ['Password field, form posts to look-alike domain', 'content', 'strong', 'h'],
      ['X-MS-Exchange SCL 5', 'gateway verdict', 'strong', 'm'],
      ['DMARC fail, first message from sender', 'authentication · sender history', '', 'm'],
    ],
  },
  {
    id: 'agent',
    name: 'Agent (optional)',
    text: 'Local model via Ollama, LM Studio, llama.cpp, vLLM or Jan. Read-only tools, row citations, analyst approval for every change, hash-chained ledger.',
    cap: 'example exchange',
    rows: [
      ['Logons by svc-backup after 10:04Z', 'question', '', 'n'],
      ['logons_by_account', '2 hosts, 5 sessions', 'read-only', 'n'],
      ['BKP01, 4624 type 3 at 10:41Z', 'cites 3 rows', 'cited', 'n'],
      ['Add BKP01 to story', 'requires analyst approval', 'pending', 'm'],
    ],
  },
  {
    id: 'report',
    name: 'Report',
    text: 'Single self-contained HTML file: stories, chain of custody with file hashes, graphs, analyst decisions. Exports in STIX, CSV and JSON.',
    cap: 'example report',
    rows: [
      ['Summary and timeline', 'report.html', '§1', 'n'],
      ['Stories with cited events', '', '§2', 'n'],
      ['Chain of custody, SHA-256', '', '§3', 'n'],
      ['Analyst decisions', '', '§4', 'n'],
    ],
  },
]

function Modules({ ref }: { ref: SectionRef }) {
  const [tab, setTab] = useState(MODULES[0].id)
  const m = MODULES.find((x) => x.id === tab)!
  return (
    <section className="ld-blk" ref={ref}>
      <div className="ld-eyebrow">Modules</div>
      <h2>Case workflow</h2>
      <div className="ld-feat">
        <div className="ld-tablist" role="tablist" aria-label="Modules">
          {MODULES.map((x) => (
            <button key={x.id} type="button" role="tab" aria-selected={x.id === tab} aria-controls="ld-stage" onClick={() => setTab(x.id)}>
              <b>{x.name}</b>
              <span>{x.text}</span>
            </button>
          ))}
        </div>
        <div className="ld-stage" id="ld-stage" role="tabpanel">
          <div className="ld-card">
            {m.rows.map(([title, sub, tag, tone]) => (
              <div key={title} className="ld-ln">
                <i className={`ld-dot ld-dot-${tone}`} />
                <div>
                  <b>{title}</b>
                  {sub && <p>{sub}</p>}
                </div>
                <em>{tag}</em>
              </div>
            ))}
          </div>
          <span className="ld-cap">{m.cap}</span>
        </div>
      </div>
    </section>
  )
}

function NewCaseDialog({ browserOnly, onClose }: { browserOnly: boolean; onClose: () => void }) {
  const [name, setName] = useState('')
  const [storage, setStorage] = useState<'browser' | 'server'>('browser')
  const [files, setFiles] = useState<File[]>([])
  const [busy, setBusy] = useState(false)
  const [over, setOver] = useState(false)
  useEffect(() => {
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', esc)
    return () => window.removeEventListener('keydown', esc)
  }, [onClose])
  const create = async () => {
    setBusy(true)
    try {
      const c = await startCase(name, browserOnly ? 'browser' : storage)
      const s = useStore.getState()
      s.setCurrentCase(c)
      s.bumpCases()
      s.setView('evidence')
      if (files.length) requestIngest(files, c)
    } catch (e) {
      toast('err', `the case was not created: ${(e as Error).message}`, 0)
      setBusy(false)
    }
  }
  return (
    <div className="ld-scrim" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="ld-modal" role="dialog" aria-modal="true" aria-labelledby="ld-new-title">
        <div className="ld-mh">
          <div className="ld-mh-t">
            <RemnMark size={38} />
            <div>
              <h2 id="ld-new-title">New case</h2>
              <p>Evidence can be added after creation.</p>
            </div>
          </div>
          <button type="button" className="ld-x" aria-label="Close" onClick={onClose}>
            ×
          </button>
        </div>
        <form
          className="ld-form"
          onSubmit={(e) => {
            e.preventDefault()
            if (!busy) void create()
          }}
        >
          <label className="ld-f">
            <span>Case name</span>
            <input type="text" autoFocus value={name} placeholder="e.g. Finance laptop, suspicious sign-ins" onChange={(e) => setName(e.target.value)} />
          </label>
          <div className="ld-f">
            <span>Storage</span>
            <div className="ld-choice">
              <label>
                <input type="radio" name="ld-storage" checked={browserOnly || storage === 'browser'} onChange={() => setStorage('browser')} />
                <span>
                  <b>Browser</b>IndexedDB, in this browser
                </span>
              </label>
              {!browserOnly && (
                <label>
                  <input type="radio" name="ld-storage" checked={storage === 'server'} onChange={() => setStorage('server')} />
                  <span>
                    <b>Server</b>DuckDB, multi-gigabyte cases
                  </span>
                </label>
              )}
            </div>
          </div>
          <label
            className={over ? 'ld-dz over' : 'ld-dz'}
            onDragOver={(e) => {
              e.preventDefault()
              setOver(true)
            }}
            onDragLeave={() => setOver(false)}
            onDrop={(e) => {
              e.preventDefault()
              e.stopPropagation()
              setOver(false)
              setFiles([...files, ...Array.from(e.dataTransfer.files)])
            }}
          >
            <input type="file" multiple onChange={(e) => setFiles([...files, ...Array.from(e.target.files ?? [])])} />
            <b>{files.length ? `${files.length} file${files.length === 1 ? '' : 's'} to import` : 'Import evidence'}</b>
            {files.length ? files.map((f) => f.name).join(', ') : '.evtx, .pst, .ost, .mbox, .eml, .msg, UAL, Entra, archives'}
          </label>
          <div className="ld-mf">
            <button type="button" className="ld-btn ld-btn-line" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="ld-btn ld-btn-primary" disabled={busy}>
              {files.length ? 'Create case and import' : 'Create case'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
