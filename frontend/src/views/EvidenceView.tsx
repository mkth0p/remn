import { useEffect, useMemo, useState } from 'react'
import { getDb, type Evidence } from '../db/schema'
import { toast, useStore } from '../state/store'
import { fmtBytes, fmtNum, fmtTs } from '../util/format'
import { Dropzone } from '../components/Dropzone'
import { Badge, CopyButton, JsonView, Modal } from '../components/ui'
import { hashOnly, refreshCounts, requestIngest } from '../data/ingest'
import { getSource } from '../data/source'
import { Jobs } from '../components/ConsolePanel'
import { IconTrash } from '../components/Icons'

export function EvidenceView() {
  const kase = useStore((s) => s.currentCase)
  const jobs = useStore((s) => s.jobs)
  const threshold = useStore((s) => s.storeThresholdMb)
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
  const remove = async (e: Evidence) => {
    if (!confirm(`Remove "${e.name}" and all its rows from ${isServer ? 'the server store' : 'this browser'}?`)) return
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
        <Dropzone onFiles={(files) => requestIngest(files, kase)} />
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
              <tr key={e.id} onClick={() => setDetail(e)} style={{ cursor: 'pointer' }}>
                <td className="mono ellipsis" style={{ maxWidth: 260 }} title={e.name}>
                  {e.name}
                </td>
                <td>
                  <Badge sev="accent">{e.format || e.kind}</Badge>
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
                  <button className="btn xs danger" onClick={() => remove(e)} title="remove">
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
            <div className="v">{detail.sha256Server ?? '—'}</div>
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
            <div className="v">{fmtNum(detail.count)}</div>
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
          {detail.stats && (
            <details open>
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
