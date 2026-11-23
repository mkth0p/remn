import { useEffect, useMemo, useState } from 'react'
import { getDb, type Case, type Evidence } from '../db/schema'
import { toast, useStore } from '../state/store'
import { fmtBytes, fmtNum, fmtTs } from '../util/format'
import { Dropzone } from '../components/Dropzone'
import { Badge, CopyButton, JsonView, Modal } from '../components/ui'
import { confirmAction } from '../components/confirm'
import { hashOnly, readAgain, refreshCounts, requestIngest } from '../data/ingest'
import { dateSetting, datesRead, describeDates, zoneError } from '../data/dateSetting'
import { getSource } from '../data/source'
import { Jobs } from '../components/ConsolePanel'
import { IconTrash } from '../components/Icons'
import { PackageCoverage } from '../components/PackageCoverage'
import { coverageMembers } from '../data/packageCoverage'
import { packageCoverageIssues } from '../data/packageCoverage'
import { evidenceGaps } from '../data/evidenceGaps'
import { viewerReason } from '../data/access'
import { pressableRow } from '../components/pressable'

export function EvidenceView() {
  const kase = useStore((s) => s.currentCase)
  const jobs = useStore((s) => s.jobs)
  const threshold = useStore((s) => s.storeThresholdMb)
  const health = useStore((s) => s.health)
  const [items, setItems] = useState<Evidence[]>([])
  const [detail, setDetail] = useState<Evidence | null>(null)
  const [verify, setVerify] = useState<{ ev: Evidence; result?: string; progress?: number } | null>(null)
  const ds = useMemo(() => (kase ? getSource(kase) : null), [kase])
  const reload = () => kase?.id && getDb().evidence.where('caseId').equals(kase.id).reverse().sortBy('addedAt').then(setItems)
  useEffect(() => {
    reload()
    const t = setInterval(reload, 1500)
    return () => clearInterval(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kase?.id, jobs.length])
  if (!kase || !ds) return null
  const isServer = kase.storage === 'server'
  // a viewer changes nothing on the server; a case kept in this browser stays its own
  const viewer = isServer ? viewerReason(health) : null
  const remove = async (e: Evidence) => {
    if (!(await confirmAction(`Remove "${e.name}" and all its rows from ${isServer ? 'the server store' : 'this browser'}?`, { title: 'Remove the evidence', action: 'Remove', danger: true }))) return
    try {
      const cleared = await ds.deleteEvidence(e.id!)
      toast(
        'ok',
        `${e.name} removed: rows, bodies, attachments, indicators and facets deleted${cleared.findings ? `, ${cleared.findings} finding(s)${cleared.chains ? ` and ${cleared.chains} chain(s)` : ''} cleared` : ''} - run the rules again (analyst decisions are kept)`,
        9000,
      )
    } catch (err) {
      toast('err', `remove failed: ${(err as Error).message}`, 0)
    }
    refreshCounts(kase)
    reload()
  }
  const doVerify = async (file: File) => {
    if (!verify) return
    const h = await hashOnly(file, (p) => setVerify((v) => (v ? { ...v, progress: p } : v)))
    const ok = h === verify.ev.sha256Client
    setVerify({ ...verify, result: ok ? `MATCH — ${h}` : `MISMATCH — file is ${h}, evidence was ${verify.ev.sha256Client}` })
    toast(ok ? 'ok' : 'err', ok ? 'integrity verified' : 'hash mismatch!', 0)
  }
  return (
    <div className="view">
      <div className="view-header">
        <h1>Evidence</h1>
        <span className="sub">{items.length} item(s) · chain of custody</span>
        <Badge sev={isServer ? 'accent' : 'info'}>{isServer ? 'server store (GB-scale)' : `browser store (files over ${threshold} MB will ask to switch)`}</Badge>
      </div>
      <div className="view-body col" style={{ gap: 14 }}>
        {viewer ? (
          <div className="hint">{viewer} Evidence is added by an analyst who owns the case or is a member of it.</div>
        ) : (
          <Dropzone onFiles={(files) => requestIngest(files, kase)} allowFolders />
        )}
        {isServer && health?.accounts && (
          <div className="hint">This list holds the files added from this browser. The rows of every file in the case, whoever added it, are on the Events and Mails pages.</div>
        )}
        <Jobs />
        <table className="table">
          <thead>
            <tr>
              <th>name</th>
              <th>kind</th>
              <th>size</th>
              <th>rows</th>
              <th>sha-256 (browser)</th>
              <th>integrity</th>
              <th>status</th>
              <th>added</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {items.map((e) => (
              <tr {...pressableRow} key={e.id} onClick={() => setDetail(e)} style={{ cursor: 'pointer' }}>
                <td className="mono ellipsis" style={{ maxWidth: 260 }} title={e.name}>
                  {e.name}
                </td>
                <td>
                  <Badge sev="accent">{e.format || e.kind}</Badge>
                  {e.parsedIn === 'browser' && (
                    <Badge sev="ok" title="parsed in this browser: the file was never uploaded">
                      parsed in this browser
                    </Badge>
                  )}
                </td>
                <td>{fmtBytes(e.size)}</td>
                <td>{fmtNum(e.count)}</td>
                <td className="mono small" title={e.sha256Client}>
                  {e.sha256Client ? e.sha256Client.slice(0, 16) + '…' : '…'}
                </td>
                <td>
                  <Badge sev={e.integrity === 'verified' ? 'ok' : e.integrity === 'mismatch' ? 'critical' : 'info'}>{e.integrity}</Badge>
                </td>
                <td>
                  <Badge sev={e.status === 'done' ? 'ok' : e.status === 'error' ? 'critical' : 'medium'}>{e.status}</Badge>
                  {packageCoverageIssues(e).length > 0 && <Badge sev="medium">partial coverage</Badge>}
                  {evidenceGaps({ evidence: [e] }).some((g) => g.severity === 'high') && (
                    <Badge sev="high" title="the file records gaps in itself: see its detail">
                      gaps
                    </Badge>
                  )}
                  {e.error && (
                    <span className="small" style={{ color: 'var(--danger)', marginLeft: 6 }}>
                      {e.error.slice(0, 60)}
                    </span>
                  )}
                </td>
                <td className="nowrap">{fmtTs(e.addedAt)}</td>
                <td className="row" onClick={(ev) => ev.stopPropagation()}>
                  <button className="btn xs" onClick={() => setVerify({ ev: e })} title="re-hash a copy of the file and compare">
                    verify
                  </button>
                  <button className="btn xs danger" onClick={() => remove(e)} disabled={!!viewer} title={viewer ?? 'remove'} aria-label="remove">
                    <IconTrash />
                  </button>
                </td>
              </tr>
            ))}
            {!items.length && (
              <tr>
                <td colSpan={9} className="muted">
                  no evidence yet
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {detail && (
        <Modal title={detail.name} onClose={() => setDetail(null)} wide>
          <div className="kv">
            <div className="k">sha-256 browser</div>
            <div className="v">
              {detail.sha256Client} {detail.sha256Client && <CopyButton text={detail.sha256Client} />}
            </div>
            <div className="k">sha-256 server</div>
            <div className="v">{detail.parsedIn === 'browser' ? 'never uploaded: parsed in this browser, from the bytes this digest identifies' : (detail.sha256Server ?? '—')}</div>
            <div className="k">integrity</div>
            <div className="v">{detail.integrity}</div>
            <div className="k">size</div>
            <div className="v">
              {fmtBytes(detail.size)} ({fmtNum(detail.size)} bytes)
            </div>
            <div className="k">file modified</div>
            <div className="v">{fmtTs(detail.lastModified)}</div>
            <div className="k">added</div>
            <div className="v">
              {fmtTs(detail.addedAt)} {detail.analyst ? `by ${detail.analyst}` : ''}
            </div>
            <div className="k">rows</div>
            <div className="v">
              {fmtNum(detail.count)}
              {Number(detail.stats?.duplicates ?? 0) > 0 && (
                <span className="small muted">
                  {' '}
                  · {fmtNum(Number(detail.stats!.duplicates))} repeated record(s) not added: the same audit or sign-in record (by its id) was already read, in this file or in earlier evidence
                </span>
              )}
            </div>
            <div className="k">store</div>
            <div className="v">{isServer ? `server (DuckDB ${kase.serverKey?.slice(0, 8)}…)` : 'browser (IndexedDB)'}</div>
          </div>
          <label className="field">
            <span>analyst note</span>
            <textarea
              className="textarea"
              defaultValue={detail.note ?? ''}
              onBlur={(e) => {
                getDb().evidence.update(detail.id!, { note: e.target.value })
                toast('ok', 'note saved')
              }}
            />
          </label>
          <FileGaps evidence={detail} />
          <EvidenceDates key={detail.id} evidence={detail} kase={kase} onRead={() => setDetail(null)} />
          {detail.kind === 'package' && detail.stats && <PackageCoverage stats={detail.stats} />}
          {detail.kind !== 'package' && coverageMembers(detail.stats).length > 0 && <PackageCoverage stats={detail.stats!} archive />}
          {detail.stats && (
            <details open={detail.kind !== 'package'}>
              <summary className="small dim" style={{ cursor: 'pointer' }}>
                parser statistics
              </summary>
              <JsonView value={detail.stats} />
            </details>
          )}
        </Modal>
      )}
      {verify && (
        <Modal title={`Verify integrity of ${verify.ev.name}`} onClose={() => setVerify(null)}>
          <div className="hint">Drop the original file again. It is hashed in the browser (never uploaded) and compared with the SHA-256 recorded at ingestion.</div>
          <Dropzone multiple={false} onFiles={(f) => doVerify(f[0])} compact>
            <div className="big">drop file to re-hash</div>
          </Dropzone>
          {verify.progress != null && !verify.result && (
            <div className="progress">
              <div style={{ width: `${verify.progress * 100}%` }} />
            </div>
          )}
          {verify.result && (
            <div className="mono small" style={{ color: verify.result.startsWith('MATCH') ? 'var(--ok)' : 'var(--danger)', wordBreak: 'break-all' }}>
              {verify.result}
            </div>
          )}
        </Modal>
      )}
    </div>
  )
}

/** What the file records about gaps in itself: holes in its record numbering, times that run backwards, failed checksums, an export cut at a service limit. */
function FileGaps({ evidence }: { evidence: Evidence }) {
  const gaps = evidenceGaps({ evidence: [evidence] })
  if (!gaps.length) return null
  return (
    <div className="col" style={{ gap: 4 }}>
      <div className="small dim">what this file cannot show</div>
      {gaps.map((g, i) => (
        <div key={i} className="small">
          <Badge sev={g.severity === 'high' ? 'high' : 'medium'}>{g.kind.replace(/-/g, ' ')}</Badge> {g.text}
        </div>
      ))}
    </div>
  )
}

/**
 * How the file's dates were read, for a Microsoft 365 or Entra export whose dates or times did not
 * say all: the order and zone used, what was guessed, and a way to read the file again with an
 * order and a zone set for this evidence.
 */
function EvidenceDates({ evidence, kase, onRead }: { evidence: Evidence; kase: Case; onRead: () => void }) {
  const [order, setOrder] = useState<string>(evidence.dates?.order ?? '')
  const [zone, setZone] = useState(evidence.dates?.zone ?? '')
  const read = datesRead(evidence)
  if (!read || evidence.kind === 'mail') return null
  const error = zoneError(zone)
  const setting = dateSetting(order, zone)
  const again = async (file: File) => {
    if (error) return toast('err', error)
    const question = `Import ${file.name} again with ${describeDates(setting)}, and replace evidence #${evidence.id} with it once it is read? If the read fails, the evidence stays as it is. Its findings are cleared until the rules run again; your decisions are kept.`
    if (!(await confirmAction(question, { title: 'Read the file again', action: 'Read again', danger: true }))) return
    onRead()
    readAgain(evidence, file, kase, setting).catch((e: Error) => toast('err', `${file.name} not read again: ${e.message}`, 0))
  }
  return (
    <div className="col" style={{ gap: 6 }}>
      <div className="small dim">dates</div>
      <div className="small">read with {read.setting}</div>
      {read.counts.map((c) => (
        <div key={c} className="small">
          {c}
        </div>
      ))}
      <div className="row" style={{ gap: 10, flexWrap: 'wrap' }}>
        <label className="field">
          <span>date order</span>
          <select className="select" value={order} onChange={(e) => setOrder(e.target.value)}>
            <option value="">as the file shows (month first when it cannot)</option>
            <option value="day-first">day first (01/09/2026 is 1 September)</option>
            <option value="month-first">month first (01/09/2026 is 9 January)</option>
          </select>
        </label>
        <label className="field">
          <span>time zone of times that give none</span>
          <input className="input" value={zone} onChange={(e) => setZone(e.target.value)} placeholder="UTC, +02:00 or Europe/Paris" />
        </label>
      </div>
      {error && (
        <div className="small" style={{ color: 'var(--danger)' }}>
          {error}
        </div>
      )}
      <div className="hint">
        To read the file with this setting, drop the original file again. Its SHA-256 is checked against the one recorded at import; the file is then imported again, and the evidence is replaced by
        the new read once it succeeds. A read that fails leaves the evidence as it was. Its findings are cleared until the rules run again.
      </div>
      <Dropzone multiple={false} onFiles={(f) => again(f[0])} compact>
        <div className="big">drop the file to read it again</div>
      </Dropzone>
    </div>
  )
}
