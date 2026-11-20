import { useEffect, useState } from 'react'
import { Badge, Progress, Toggle } from '../../components/ui'
import { refreshCounts } from '../../data/ingest'
import { migrateCaseToServer } from '../../data/migrate'
import type { DataSource } from '../../data/source'
import { getDb, type Case, type CaseSettings } from '../../db/schema'
import { toast, useStore } from '../../state/store'
import { fmtBytes } from '../../util/format'

/**
 * Where the case's rows live: the browser store, or the server store with its size; the move of a
 * browser case to the server; the size from which an import suggests the server store; and, on the
 * server store, how much of each mail ingestion keeps.
 */
export function StoragePanel({
  kase,
  ds,
  patch,
  browserOnly,
  viewer,
}: {
  kase: Case
  ds: DataSource
  patch: (p: Partial<CaseSettings>) => void
  browserOnly: boolean
  /** why the signed-in account may change nothing, when it may not */
  viewer: string | null
}) {
  const counts = useStore((s) => s.counts)
  const threshold = useStore((s) => s.storeThresholdMb)
  const setThreshold = useStore((s) => s.setStoreThresholdMb)
  const [migrating, setMigrating] = useState<string | null>(null)
  const [storeSize, setStoreSize] = useState<number | null>(null)
  useEffect(() => {
    if (ds.kind === 'server')
      ds.summary()
        .then((s) => setStoreSize((s as { sizeBytes?: number }).sizeBytes ?? null))
        .catch(() => setStoreSize(null))
    else setStoreSize(null)
  }, [ds])
  const s = kase.settings
  const isServer = kase.storage === 'server'
  const migrate = async () => {
    const total = counts.events + counts.mails
    if (
      !confirm(
        `Move this case to the server store (DuckDB on this machine)? ${total.toLocaleString('en-US')} rows will be transferred and removed from the browser. Findings will be cleared (re-run the rules afterwards).`,
      )
    )
      return
    setMigrating('starting…')
    try {
      await migrateCaseToServer(kase, setMigrating)
      await refreshCounts(kase)
    } catch (e) {
      toast('err', `migration failed: ${(e as Error).message}`, 0)
    } finally {
      setMigrating(null)
    }
  }
  return (
    <div className="panel">
      <div className="panel-h">storage</div>
      <div className="panel-b col">
        <div className="row">
          <Badge sev={isServer ? 'accent' : 'info'}>{isServer ? 'server store (DuckDB)' : 'browser store (IndexedDB)'}</Badge>
          {isServer && (
            <span className="mono small dim">
              {kase.serverKey} · {storeSize != null ? fmtBytes(storeSize) : '…'}
            </span>
          )}
        </div>
        <div className="hint">
          {isServer
            ? 'Rows live in a DuckDB file under the server data folder on this machine; the browser keeps cases, findings, notes and AI sessions. Suited to gigabytes of logs and mailboxes.'
            : 'Rows live in this browser only (portable, zero server state). Suited to cases under a few hundred MB.'}
        </div>
        {!isServer && !browserOnly && (
          <div className="col">
            <button className="btn primary sm" onClick={migrate} disabled={!!migrating || !!viewer} title={viewer ?? undefined}>
              convert this case to the server store
            </button>
            {migrating && (
              <>
                <Progress indeterminate />
                <div className="small dim mono">{migrating}</div>
              </>
            )}
          </div>
        )}
        <label className="field">
          <span>suggest the server store for files larger than (MB)</span>
          <input
            type="number"
            className="input mono"
            min={10}
            value={threshold}
            onChange={(e) => {
              const v = Number(e.target.value) || 150
              setThreshold(v)
              getDb().kv.put({ key: 'storeThresholdMb', value: v })
            }}
          />
        </label>
        {isServer && (
          <>
            <Toggle on={s.deepAttachments !== false} onChange={(v) => patch({ deepAttachments: v })} label="deep attachment analysis at ingestion (macros, PDF, archives) - slower on huge mailboxes" />
            <Toggle on={s.keepBodies !== false} onChange={(v) => patch({ keepBodies: v })} label="keep mail bodies and raw headers (needed for body regex and previews)" />
          </>
        )}
      </div>
    </div>
  )
}
