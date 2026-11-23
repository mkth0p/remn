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
import { DEFAULT_DETECTION_LEVEL, type DetectionLevel } from '../data/detectionLevel'
import { DetectionLevelPicker } from '../components/DetectionLevelPicker'
import { useDialogFocus } from '../components/dialogFocus'
import { DETECTION_LEVELS, BEFORE_LEVELS, MEASURED_ON } from '../data/detectionLevel'
import { EXAMPLE_RULE, exampleMeasure, LIBRARY_MEASURES, MAIL_CORPORA, type Cut, type ExampleMeasure } from '../data/landingFigures'
import measure from 'virtual:rule-measure'
import { fmtNum } from '../util/format'

type Section = 'libraries' | 'baseline' | 'intrusion' | 'mail' | 'method' | 'modules' | 'data'
const SECTIONS: [Section, string][] = [
  ['libraries', 'Libraries'],
  ['baseline', 'Baseline'],
  ['intrusion', 'APT29'],
  ['mail', 'Mail'],
  ['method', 'Method'],
  ['modules', 'Modules'],
  ['data', 'Data handling'],
]
const CUTS: [Cut, string][] = [
  ['any', 'any level'],
  ['medium', '≥ medium'],
  ['high', '≥ high'],
]
const pct = (n: number, of: number) => (of ? `${Math.round((n / of) * 100)}%` : '–')
/** recorded attacks in the committed measure, every library together */
const RECORDINGS = measure.libraries.reduce((n, l) => n + l.recordings, 0)
/** the libraries no rule had been written against when they were first measured, together */
const HELD = measure.libraries.filter((l) => l.heldOut)
const HELD_DETECTED = HELD.reduce((n, l) => n + l.detected, 0)
const HELD_RECORDINGS = HELD.reduce((n, l) => n + l.recordings, 0)

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
  const example = exampleMeasure(meta)
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
              {SECTIONS.filter(([id]) => id !== 'modules' && id !== 'data').map(([id, label]) => (
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
                {fmtNum(measure.rules)} detection rules, each scored against {fmtNum(RECORDINGS)} public attack recordings and {fmtNum(measure.baseline.events)} events from{' '}
                {fmtNum(measure.baseline.machines)} clean hosts. Every finding reports its rule's measured detection and false-positive counts.
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
            <ExampleFinding example={example} />
          </div>
          <HeroFigures />
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
        <Libraries ref={(el) => void (refs.current.libraries = el)} />
        <Baseline ref={(el) => void (refs.current.baseline = el)} />
        <Intrusion ref={(el) => void (refs.current.intrusion = el)} />
        <Mail ref={(el) => void (refs.current.mail = el)} />
        <Method ref={(el) => void (refs.current.method = el)} />
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
          Measured {measure.measured} · rules/measures.json · tools/library_measures.py at {LIBRARY_MEASURES.commit} · sources: EVTX-to-MITRE-Attack, splunk/attack_data, OTRF Security-Datasets,
          EVTX-ATTACK-SAMPLES, SigmaHQ, NextronSystems/evtx-baseline
        </span>
      </footer>

      {newCase && <NewCaseDialog browserOnly={browserOnly} onClose={() => setNewCase(false)} />}
    </div>
  )
}

function ExampleFinding({ example: ex }: { example: ExampleMeasure | null }) {
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
                  {` (${fmtNum(measure.baseline.machines)} hosts, ${fmtNum(measure.baseline.events)} events)`}.
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

function HeroFigures() {
  const b = measure.baseline
  const tiles: [string, string][] = [
    [fmtNum(RECORDINGS), `recorded attacks in ${measure.libraries.length} public libraries, each at a pinned commit`],
    [pct(HELD_DETECTED, HELD_RECORDINGS), `of ${fmtNum(HELD_RECORDINGS)} held-out recordings detected, at any severity, by the rules a new case enables`],
    [`${fmtNum(measure.detect)} / ${fmtNum(measure.rules)}`, 'event rules seen to fire on a recording of what they look for'],
    [`${(b.events / 1e6).toFixed(1)}M`, `events from ${b.machines} clean Windows hosts, scored for false positives`],
  ]
  return (
    <dl className="ld-figs" aria-label="Measured figures">
      {tiles.map(([v, t]) => (
        <div key={t}>
          <dt>{t}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  )
}

const SHORT: Record<string, string> = { evtxToMitre: 'EVTX-to-MITRE', attackDataWindows: 'attack_data', securityDatasets: 'Security-Datasets', all: 'All held-out' }

function PctTicks() {
  return (
    <div className="ld-ticks ld-lticks" aria-hidden="true">
      <span />
      <div>
        {[0, 0.25, 0.5, 0.75, 1].map((t) => (
          <span key={t} style={{ left: `${t * 100}%` }}>
            {t * 100}%
          </span>
        ))}
      </div>
      <span />
    </div>
  )
}

function Libraries({ ref }: { ref: SectionRef }) {
  const w = measure.attackDataWindows
  return (
    <section className="ld-blk" ref={ref}>
      <div className="ld-eyebrow">
        Libraries · {measure.libraries.length} public corpora · rule measure of {measure.measured}
      </div>
      <h2>Detection by library</h2>
      <p className="ld-intro">
        Every event rule run on every recording of each library by <code>tools/measure_rules.py</code>, the committed measure (<code>rules/measures.json</code>). A recording counts as detected when a
        rule a new case enables, tagged with its ATT&amp;CK technique (the same id, its parent or a sub-technique), raises a finding of any severity anywhere in the file; whether the finding is on the
        attack's own events is not checked. Held out: no rule was written against the library before it was first measured, and a rule written since after studying it is not counted on it.
      </p>
      <div className="ld-panel ld-mt">
        <div className="ld-chart-head">
          <div>
            <div className="ld-chart-t">Recordings detected, share of each library</div>
            <div className="ld-chart-s">
              held out together: {fmtNum(HELD_DETECTED)} of {fmtNum(HELD_RECORDINGS)} ({pct(HELD_DETECTED, HELD_RECORDINGS)})
            </div>
          </div>
        </div>
        <div className="ld-bars">
          {measure.libraries.map((l) => (
            <div key={l.key} className={l.heldOut ? 'ld-lrow ld-us' : 'ld-lrow'}>
              <div className="ld-lname">
                <b>{l.name}</b>
                <span>
                  {fmtNum(l.recordings)} recordings at {l.ref} · {l.heldOut ? 'held out' : l.note}
                </span>
              </div>
              <div className="ld-track" title={`${l.name}: ${fmtNum(l.detected)} of ${fmtNum(l.recordings)} recordings detected`}>
                <div className="ld-fill" style={{ width: `${(l.detected / l.recordings) * 100}%` }} />
              </div>
              <span className="ld-v">
                {pct(l.detected, l.recordings)}
                <small>
                  {fmtNum(l.detected)}/{fmtNum(l.recordings)}
                </small>
              </span>
            </div>
          ))}
        </div>
        <PctTicks />
        <p className="ld-note">
          Gray: libraries that are not held out, shown for reference. attack_data (Windows): its datasets up to {w.maxMb} MB; the {w.overSize} larger ones and the {w.missing} missing at the pinned
          commit are not measured. REMN's own rules alone detect {HELD.map((l) => `${fmtNum(l.own)} (${l.name})`).join(' and ')}; the other detections come from SigmaHQ's packs. Rules added or changed
          since the measure have none until it is taken again.
        </p>
      </div>
      <div className="ld-gap" />
      <TacticMap />
    </section>
  )
}

function TacticMap() {
  const [cut, setCut] = useState<Cut>('any')
  const m = LIBRARY_MEASURES
  const cols = [...m.libraries.filter((l) => !l.practice && l.read > 0).map((l) => l.key), 'all']
  const at = { any: 1, medium: 2, high: 3 }[cut]
  return (
    <>
      <div className="ld-chart-head">
        <div>
          <div className="ld-chart-t">Held-out recordings detected, by tactic ({CUTS.find(([c]) => c === cut)![1]})</div>
          <div className="ld-chart-s">
            A separate run of every rule on every library, OTRF Security-Datasets added, by <code>tools/library_measures.py</code> on {m.measured} with the rules at {m.commit}; its counts differ from
            the measure above, taken with other versions of the rules. Tactic of each recording's technique, ATT&amp;CK v19. Rule levels were changed on 2026-09-26, after the measure's results on
            EVTX-to-MITRE-Attack and attack_data were known, so their counts at medium and above are not held out.
          </div>
        </div>
        <div className="ld-scale" aria-hidden="true">
          <span>0%</span>
          <i />
          <span>100%</span>
        </div>
        <div className="ld-seg" role="group" aria-label="Level cut">
          {CUTS.map(([c, label]) => (
            <button key={c} type="button" aria-pressed={c === cut} onClick={() => setCut(c)}>
              {label}
            </button>
          ))}
        </div>
      </div>
      <div className="ld-tw ld-mt-s">
        <table className="ld-t ld-hm">
          <thead>
            <tr>
              <th>Tactic</th>
              {cols.map((c) => (
                <th key={c} className="n">
                  {SHORT[c] ?? c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {m.tactics.map((t) => (
              <tr key={t.id}>
                <td>{t.label}</td>
                {cols.map((c) => {
                  const cell = t.cells[c]
                  if (!cell || !cell[0])
                    return (
                      <td key={c} className="n ld-hc ld-na">
                        –
                      </td>
                    )
                  const r = cell[at] / cell[0]
                  return (
                    <td
                      key={c}
                      className={r >= 0.55 ? 'n ld-hc ld-hc-d' : 'n ld-hc'}
                      style={{ ['--r' as string]: r.toFixed(3) }}
                      title={`${t.label}, ${SHORT[c] ?? c}: ${cell[at]} of ${cell[0]} recordings (${pct(cell[at], cell[0])})`}
                    >
                      {cell[at]}/{cell[0]}
                    </td>
                  )
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}

function Levels() {
  const max = Math.max(...DETECTION_LEVELS.map((l) => l.measured.perCleanMachine))
  const rows: [string, number, boolean][] = [
    ...DETECTION_LEVELS.map((l): [string, number, boolean] => [`${l.level} · ${l.label}`, l.measured.perCleanMachine, l.level === 2]),
    ['≥ medium, no levels', BEFORE_LEVELS.perCleanMachine, false],
  ]
  return (
    <div className="ld-panel">
      <div className="ld-chart-t">Lines to read per clean host, by detection level</div>
      <div className="ld-chart-s">Findings on their own, plus one line per rule and host for the findings folded below the level. Level 2 is a new case's.</div>
      <div className="ld-bars">
        {rows.map(([label, v, us]) => (
          <div key={label} className={us ? 'ld-row ld-lvl ld-us' : 'ld-row ld-lvl'}>
            <span className="ld-who">{label}</span>
            <div className="ld-track" title={`${label}: ${v} lines per clean host`}>
              <div className="ld-fill" style={{ width: `${(v / max) * 100}%` }} />
            </div>
            <span className="ld-v">{v}</span>
          </div>
        ))}
      </div>
      <p className="ld-note">
        No level drops a finding, so every level detects the same recordings: at any severity, those under Libraries. Lines counted on the {MEASURED_ON.cleanMachines} clean hosts of the rule measure
        of {MEASURED_ON.date}, for the rules a new case enables at their current severities, each host under rule noise taken from the other hosts.
      </p>
    </div>
  )
}

function Intrusion({ ref }: { ref: SectionRef }) {
  const days = (['day1', 'day2'] as const).filter((d) => LIBRARY_MEASURES.apt29[d])
  if (!days.length) return null
  return (
    <section className="ld-blk" ref={ref}>
      <div className="ld-eyebrow">Intrusion replay · APT29 emulation · recorded by OTRF Security-Datasets</div>
      <h2>Findings per host on an emulated intrusion</h2>
      <p className="ld-intro">
        Two days of an emulated APT29 intrusion as OTRF Security-Datasets recorded them: Sysmon, Security and PowerShell logs of the lab's hosts, loaded as a case with a new case's settings and the
        default rule set. REMN took no part in the emulation or in any evaluation of products on it. On day 1 the operator works on SCRANTON and NASHUA; NEWYORK, the domain controller, and UTICA are
        left alone.
      </p>
      <div className="ld-proof">
        {days.map((d) => {
          const day = LIBRARY_MEASURES.apt29[d]!
          const hosts = Object.entries(day.hosts).sort((a, b) => b[1].medium - a[1].medium)
          const max = Math.max(1, ...hosts.map(([, v]) => v.medium))
          return (
            <div key={d} className="ld-panel">
              <div className="ld-chart-t">Day {d.slice(3)}</div>
              <div className="ld-chart-s">{fmtNum(day.events)} events · findings at medium and above</div>
              <div className="ld-legend" aria-hidden="true">
                <span>
                  <i className="ld-k-high" />
                  high and critical
                </span>
                <span>
                  <i className="ld-k-med" />
                  medium
                </span>
              </div>
              <div className="ld-bars">
                {hosts.map(([host, v]) => (
                  <div key={host} className="ld-row ld-host">
                    <span className="ld-who">
                      {host.toUpperCase()}
                      {v.attacked != null && <small>{v.attacked ? 'attacked' : 'not attacked'}</small>}
                    </span>
                    <div className="ld-track ld-stack" title={`${host.toUpperCase()}: ${v.high} high and critical, ${v.medium - v.high} medium`}>
                      {v.high > 0 && <div className="ld-seg-h" style={{ width: `${(v.high / max) * 100}%` }} />}
                      {v.medium > v.high && <div className="ld-seg-m" style={{ width: `${((v.medium - v.high) / max) * 100}%` }} />}
                    </div>
                    <span className="ld-v">{fmtNum(v.medium)}</span>
                  </div>
                ))}
              </div>
            </div>
          )
        })}
      </div>
      <p className="ld-note">
        Findings are counted before folding: at a case's default detection level the analyst reads fewer lines. Run {LIBRARY_MEASURES.measured}, rules at {LIBRARY_MEASURES.commit}.
      </p>
    </section>
  )
}

function Baseline({ ref }: { ref: SectionRef }) {
  const b = measure.baseline
  const { own, defaults } = measure.clean
  return (
    <section className="ld-blk" ref={ref}>
      <div className="ld-eyebrow">False positives · evtx-baseline {b.tag}</div>
      <h2>Findings on clean hosts</h2>
      <p className="ld-intro">
        {fmtNum(b.machines)} Windows hosts with no attack activity, {fmtNum(b.events)} events. Every finding here is either a false positive or benign activity the rule describes correctly.
      </p>
      <div className="ld-proof">
        <Levels />
        <div className="ld-side">
          {LIBRARY_MEASURES.clean.length > 0 && (
            <Table head={['Clean host, every finding', 'Events', '≥ med', '≥ high', 'Crit']}>
              {LIBRARY_MEASURES.clean.map((m) => (
                <tr key={m.machine}>
                  <td>{m.machine}</td>
                  <td className="n">{fmtNum(m.events)}</td>
                  <td className="n">{fmtNum(m.medium)}</td>
                  <td className="n">{fmtNum(m.high)}</td>
                  <td className="n">{fmtNum(m.critical)}</td>
                </tr>
              ))}
            </Table>
          )}
          <Table head={[`Rule set, measure of ${measure.measured}`, 'Rules firing', 'High + crit', '≥ medium']}>
            <tr>
              <td>REMN rules</td>
              <td className="n">{fmtNum(own.rules)}</td>
              <td className="n b">{fmtNum(own.highCritical)}</td>
              <td className="n">{fmtNum(own.mediumUp)}</td>
            </tr>
            <tr>
              <td>REMN + SigmaHQ default packs</td>
              <td className="n">{fmtNum(defaults.rules)}</td>
              <td className="n">{fmtNum(defaults.highCritical)}</td>
              <td className="n">{fmtNum(defaults.mediumUp)}</td>
            </tr>
          </Table>
        </div>
      </div>
      <p className="ld-note">
        Every finding of each rule on the {fmtNum(b.machines)} hosts, at the severity the rule had when it was measured; levels changed since are not applied (<code>rules/measures-detail.json</code>).
      </p>
    </section>
  )
}

function Mail({ ref }: { ref: SectionRef }) {
  return (
    <section className="ld-blk" ref={ref}>
      <div className="ld-eyebrow">Mail scoring · public corpora</div>
      <h2>Risk bands on phishing and legitimate mail</h2>
      <p className="ld-intro">
        Default settings, no sender baseline, no internal domains configured. The score's weights were adjusted on these same corpora, so the rates are not a held-out measure. Run {MAIL_CORPORA.date}.
      </p>
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

function Method({ ref }: { ref: SectionRef }) {
  return (
    <section className="ld-blk" ref={ref}>
      <div className="ld-eyebrow">Method</div>
      <h2>How rules are measured</h2>
      <dl className="ld-spec">
        <dt>Rule corpus</dt>
        <dd>
          {fmtNum(measure.rules)} event rules measured: REMN's own and SigmaHQ's converted packs. {fmtNum(measure.detect)} have fired on a recording of what they look for; the rest are marked as
          leads.
        </dd>
        <dt>Recordings</dt>
        <dd>
          {fmtNum(RECORDINGS)}: {measure.libraries.map((l) => `${l.name} ${fmtNum(l.recordings)} (${l.ref})`).join(', ')}.
        </dd>
        <dt>Also run</dt>
        <dd>
          OTRF Security-Datasets (atomic Windows datasets, labelled by their metadata) and the APT29 emulation OTRF recorded, with every rule, by <code>tools/library_measures.py</code>. They are
          scored on this page, not yet in the per-rule measure.
        </dd>
        <dt>Clean hosts</dt>
        <dd>
          evtx-baseline {measure.baseline.tag}: {fmtNum(measure.baseline.machines)} Windows machines, {fmtNum(measure.baseline.events)} events.
        </dd>
        <dt>Detection</dt>
        <dd>A rule tagged with the recording's technique (ATT&amp;CK v19, revoked ids mapped to successors) raises a finding on it, of any severity in the rule measure.</dd>
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
          <code>rules/measures.json</code> and <code>rules/measures-detail.json</code>, measured {measure.measured}. Each finding shows its rule's measure.
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
  const [level, setLevel] = useState<DetectionLevel>(DEFAULT_DETECTION_LEVEL)
  const [files, setFiles] = useState<File[]>([])
  const [busy, setBusy] = useState(false)
  const [over, setOver] = useState(false)
  const dialog = useRef<HTMLDivElement>(null)
  useDialogFocus(dialog)
  useEffect(() => {
    const esc = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', esc)
    return () => window.removeEventListener('keydown', esc)
  }, [onClose])
  const create = async () => {
    setBusy(true)
    try {
      const c = await startCase(name, browserOnly ? 'browser' : storage, level)
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
      <div className="ld-modal" ref={dialog} role="dialog" aria-modal="true" aria-labelledby="ld-new-title" tabIndex={-1}>
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
          <div className="ld-f">
            <span>Detection level</span>
            <DetectionLevelPicker value={level} onChange={setLevel} compact />
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
