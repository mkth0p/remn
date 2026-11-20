import { Dot } from '../../components/ui'
import { type GapStatement } from '../../data/evidenceGaps'
import { type Hop, HOP_LABEL, type Identity, type Process, type Session, type Story, storyGaps, type StoryResult } from '../../data/stories'
import { fmtNum, fmtTs } from '../../util/format'
import { CONFIDENCE_SEV } from './model'

export function SessionLine({ s }: { s: Session }) {
  return (
    <div className="small">
      <strong>{s.account || 'an account'}</strong> on {s.host}, logon {s.logonId} ({s.typeName}){s.ip || s.workstation ? ` from ${[s.workstation, s.ip].filter(Boolean).join(' / ')}` : ''}
      {s.from ? `, the host ${s.from}` : ''} · {fmtTs(s.start)}
      {s.end ? ` → ${fmtTs(s.end)}` : ' · no logoff recorded'}
      {s.privileged ? ' · special privileges' : ''}
      {!s.logonSeen ? ' · its logon is not in the evidence' : ''} · {fmtNum(s.activity)} record(s) in it
      {Object.keys(s.actions ?? {}).length ? ` · ${Object.keys(s.actions).join(', ')}` : ''}
    </div>
  )
}

export function HopLine({ h }: { h: Hop }) {
  const from = [h.from.host, h.from.workstation && h.from.workstation.toLowerCase() !== h.from.host ? h.from.workstation : null, h.from.ip].filter(Boolean).join(' / ')
  return (
    <div className="small">
      <Dot sev={CONFIDENCE_SEV[h.confidence]} /> <strong>{HOP_LABEL[h.kind] ?? h.kind}</strong> {from || 'an unknown source'}
      {h.from.external ? ' (outside)' : ''} → <strong>{h.to}</strong>
      {h.account ? ` as ${h.account}` : ''} · {fmtTs(h.ts)}
      {h.count > 1 ? ` · ${h.count} times` : ''}
      <div className="muted" style={{ paddingLeft: 18 }}>
        {h.basis}
        {h.evidence.length ? ` · ${h.evidence.join('; ')}` : ''}
        {h.from.basis ? ` · the source host is known from ${h.from.basis}` : ''}
      </div>
    </div>
  )
}

/** The processes of a story as trees: each root with what it started, as far as the evidence goes. */
export function ProcessTrees({ processes, highlight }: { processes: Process[]; highlight?: string | null }) {
  const byId = new Map(processes.map((p) => [p.id, p]))
  const roots = processes.filter((p) => !p.parent || !byId.has(p.parent))
  const render = (p: Process, depth: number): React.ReactNode => (
    <div key={p.id}>
      <div className={'small mono proc' + (highlight === p.id ? ' active' : '')} style={{ paddingLeft: depth * 16 }} title={p.commandLine ?? ''}>
        {depth ? '└ ' : ''}
        {p.name || p.image} {p.pid != null ? `(${p.pid})` : ''}{' '}
        <span className="muted">
          {p.host} · {fmtTs(p.ts)} · {p.source === 'both' ? 'Sysmon and 4688' : p.source === 'sysmon' ? 'Sysmon' : '4688'}
          {!p.parent && p.parentImage ? ` · started by ${p.parentImage.split('\\').pop()} (not in the evidence)` : ''}
        </span>
      </div>
      {p.children.filter((c) => byId.has(c)).map((c) => render(byId.get(c)!, depth + 1))}
    </div>
  )
  if (!processes.length) return <div className="small muted">No process of this story is in the evidence.</div>
  return <>{roots.map((r) => render(r, 0))}</>
}

export function LineagePanel({ story, highlight }: { story: Story; highlight?: string | null }) {
  const { sessions, hops, processes, devices = [] } = story.lineage
  return (
    <div className="view-body col" style={{ gap: 14 }}>
      <div className="section">
        <h3>How the accounts got in</h3>
        {hops.length ? (
          hops.map((h) => <HopLine key={h.id} h={h} />)
        ) : (
          <div className="small muted">No hop of this story is in the evidence: no RDP logon, admin share, remote service, WMI or WinRM execution or explicit credentials towards its hosts.</div>
        )}
      </div>
      {devices.length > 0 && (
        <div className="section">
          <h3>The devices its sign-ins came from</h3>
          {devices.map((d) => (
            <div key={d.key} className="small">
              <strong>{d.name}</strong>
              {d.trustTypes.length ? ` · ${d.trustTypes.join(', ')}` : ' · not joined'}
              {d.host ? ` · the host ${d.host} of this case` : ' · a device the case has no logs of'} · {d.signIns} sign-in(s)
              {d.accounts.length ? ` by ${d.accounts.join(', ')}` : ''}
            </div>
          ))}
        </div>
      )}
      <div className="section">
        <h3>Logon sessions</h3>
        {sessions.length ? sessions.map((s) => <SessionLine key={s.id} s={s} />) : <div className="small muted">No logon session of this story is in the evidence.</div>}
      </div>
      <div className="section">
        <h3>What ran</h3>
        <ProcessTrees processes={processes} highlight={highlight} />
      </div>
    </div>
  )
}

export function IdentityPanel({ identity }: { identity: Identity | undefined }) {
  if (!identity) return <div className="view-body muted">This story is about a host; its accounts are named on each step.</div>
  return (
    <div className="view-body col" style={{ gap: 14 }}>
      <div className="section">
        <h3>
          {identity.label}{' '}
          <span className="muted small">
            · {identity.kind}
            {identity.org ? ` · ${identity.org}` : ''}
          </span>
        </h3>
        <p className="small muted" style={{ margin: 0 }}>
          The forms the evidence names this account by, and how surely each is the same account: strong when one record states both, medium when the organisation's naming rules join them.
        </p>
        <table className="table compact" style={{ marginTop: 8 }}>
          <thead>
            <tr>
              <th>form</th>
              <th>value</th>
              <th>records</th>
              <th>confidence</th>
            </tr>
          </thead>
          <tbody>
            {identity.forms.map((f) => (
              <tr key={f.kind + f.value}>
                <td>{f.kind}</td>
                <td className="mono" style={{ overflowWrap: 'anywhere' }}>
                  {f.value}
                </td>
                <td>{fmtNum(f.seen)}</td>
                <td>
                  <Dot sev={CONFIDENCE_SEV[f.confidence]} /> {f.confidence}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {identity.joins.length > 0 && (
        <div className="section">
          <h3>Why they are one account</h3>
          {identity.joins.map((j, i) => (
            <div key={i} className="small">
              <Dot sev={CONFIDENCE_SEV[j.confidence]} /> <span className="mono">{j.a}</span> = <span className="mono">{j.b}</span>: {j.basis}
              {j.count > 1 ? ` (${fmtNum(j.count)} records)` : ''}
            </div>
          ))}
        </div>
      )}
      {(identity.namesakes.length > 0 || identity.possibly.length > 0 || identity.conflicts.length > 0 || identity.notes.length > 0) && (
        <div className="section">
          <h3>Kept apart</h3>
          {identity.namesakes.map((n) => (
            <div key={'n' + n.id} className="small">
              Namesake <span className="mono">{n.label}</span>: {n.basis}.
            </div>
          ))}
          {identity.possibly.map((n) => (
            <div key={'p' + n.id} className="small">
              Possibly <span className="mono">{n.label}</span>, never joined without a record that says so: {n.basis}.
            </div>
          ))}
          {identity.conflicts.map((c, i) => (
            <div key={'c' + i} className="small">
              Not joined, <span className="mono">{c.a}</span> and <span className="mono">{c.b}</span>: {c.why}.
            </div>
          ))}
          {identity.notes.map((n, i) => (
            <div key={'x' + i} className="small">
              {n}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export function GapsPanel({ story, stats, caseGaps }: { story: Story; stats: StoryResult['stats'] | undefined; caseGaps: GapStatement[] }) {
  const gaps = storyGaps(story, stats)
  return (
    <div className="view-body col" style={{ gap: 14 }}>
      <div className="section">
        <h3>Where this story stops</h3>
        {gaps.length ? (
          gaps.map((g, i) => (
            <div key={i} className="small">
              · {g}
            </div>
          ))
        ) : (
          <div className="small muted">Every host of the story logs its logons and what ran.</div>
        )}
      </div>
      <div className="section">
        <h3>Where the case's files stop</h3>
        {caseGaps.length ? (
          caseGaps.map((g, i) => (
            <div key={i} className="small">
              <Dot sev={g.severity} /> {g.text}
            </div>
          ))
        ) : (
          <div className="small muted">The files record no hole, no clock set back, no damaged chunk and no log that starts after the first finding.</div>
        )}
      </div>
    </div>
  )
}
