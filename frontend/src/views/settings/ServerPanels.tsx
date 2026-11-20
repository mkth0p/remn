import type { Health } from '../../api/client'
import { Badge, Toggle } from '../../components/ui'
import { confirmAction } from '../../components/confirm'
import { removeCase, wipeCase } from '../../data/caseState'
import { refreshCounts } from '../../data/ingest'
import type { Case, CaseSettings } from '../../db/schema'
import { toast, useStore } from '../../state/store'

type Patch = (p: Partial<CaseSettings>) => void

/** The reputation lookups: off by default, and only through the providers the server has a key or a list for. */
export function LookupsPanel({ s, patch, health }: { s: CaseSettings; patch: Patch; health: Health | null }) {
  const providers = health?.providers ?? []
  return (
    <div className="panel">
      <div className="panel-h">external lookups (opt-in)</div>
      <div className="panel-b col">
        {health?.mode === 'browser-only' ? (
          <div className="hint">Reputation lookups are switched off on this server (browser-only mode): it contacts no third party on your behalf.</div>
        ) : (
          <Toggle on={s.networkAllowed} onChange={(v) => patch({ networkAllowed: v })} label="allow reputation lookups - every checked indicator is disclosed to the provider" />
        )}
        <div className="col" style={{ gap: 4 }}>
          {providers.map((p) => (
            <label key={p.name} className="checkbox small" title={p.description}>
              <input
                type="checkbox"
                disabled={!p.configured}
                checked={!s.providers.length ? p.configured : s.providers.includes(p.name)}
                onChange={(e) => {
                  const base = s.providers.length ? s.providers : providers.filter((x) => x.configured).map((x) => x.name)
                  patch({ providers: e.target.checked ? Array.from(new Set([...base, p.name])) : base.filter((x) => x !== p.name) })
                }}
              />
              <span className="mono">{p.name}</span> <Badge sev={p.configured ? 'ok' : 'info'}>{p.configured ? 'configured' : p.needsKey ? `needs ${p.needsKey} key` : 'unavailable'}</Badge>{' '}
              <span className="muted">{p.kinds.join(', ')}</span>
            </label>
          ))}
        </div>
        <div className="hint">
          Keys are read by the server from <code>.env</code> (see <code>.env.example</code>). Offline block lists go to <code>backend/data/lists</code>, YARA rules to <code>backend/data/yara</code>,
          GeoLite2 databases to <code>backend/data/geoip</code>.
        </div>
      </div>
    </div>
  )
}

/**
 * What ingestion reads and keeps, what the server offers, and the end of the case: emptied, deleted,
 * or, for a member of a shared case who may do neither, removed from this browser only.
 */
export function IngestionPanel({
  kase,
  patch,
  health,
  shared,
  mayOwn,
  ownReason,
  settled,
}: {
  kase: Case
  patch: Patch
  health: Health | null
  /** a server case on a server with accounts */
  shared: boolean
  /** whether this account may empty or delete it */
  mayOwn: boolean
  /** why it may not, when it may not */
  ownReason: string | undefined
  /** whether who may change the case is known yet */
  settled: boolean
}) {
  const setCurrentCase = useStore((st) => st.setCurrentCase)
  const s = kase.settings
  const isServer = kase.storage === 'server'
  const wipe = async () => {
    if (
      !(await confirmAction(`Delete ALL data of case "${kase.name}" (${isServer ? 'server store + ' : ''}browser records: evidence rows, findings, sessions)? The case itself is kept.`, {
        title: 'Delete the case data',
        action: 'Delete',
        danger: true,
      }))
    )
      return
    try {
      await wipeCase(kase)
    } catch (e) {
      toast('err', `case data not deleted: ${(e as Error).message}`, 0)
      return
    }
    await refreshCounts(kase)
    toast('ok', 'case data deleted')
  }
  const destroy = async () => {
    if (
      !(await confirmAction(
        `Delete case "${kase.name}" entirely: ${isServer ? 'server store, ' : ''}evidence rows, findings, notes, sessions, custom rules, settings and the case itself? This cannot be undone.`,
        { title: 'Delete the case', action: 'Delete', danger: true },
      ))
    )
      return
    try {
      const { next, serverCleared } = await removeCase(kase)
      setCurrentCase(next)
      useStore.getState().bumpCases()
      useStore.getState().setView('dashboard')
      toast('ok', `case "${kase.name}" deleted`)
      if (!serverCleared) toast('warn', 'the server store could not be removed (server unreachable); delete its folder under backend/data/cases', 0)
    } catch (e) {
      toast('err', `delete failed: ${(e as Error).message}`, 0)
    }
  }
  const leave = async () => {
    if (
      !(await confirmAction(`Remove case "${kase.name}" from this browser? Its evidence stays on the server for its owner and members; this browser's findings, notes and sessions of it go.`, {
        title: 'Remove from this browser',
        action: 'Remove',
        danger: true,
      }))
    )
      return
    try {
      const { next } = await removeCase(kase, { keepServer: true })
      setCurrentCase(next)
      useStore.getState().bumpCases()
      useStore.getState().setView('dashboard')
      toast('ok', `case "${kase.name}" removed from this browser`)
    } catch (e) {
      toast('err', `not removed: ${(e as Error).message}`, 0)
    }
  }
  return (
    <div className="panel">
      <div className="panel-h">ingestion &amp; storage</div>
      <div className="panel-b col">
        <Toggle on={s.includeRaw !== false} onChange={(v) => patch({ includeRaw: v })} label="store the raw event JSON (enables regex over the whole record; ~2x storage)" />
        <Toggle
          on={s.readFileSystem === true}
          onChange={(v) => patch({ readFileSystem: v })}
          label="read the $MFT and USN journal of a drive-layout collection (KAPE, Velociraptor, acquire): up to 500,000 records each, and less time left for Hayabusa"
        />
        {!isServer && (
          <Toggle
            on={s.parseEvtxInBrowser === true}
            onChange={(v) => patch({ parseEvtxInBrowser: v })}
            label="parse .evtx files in this browser: the file is never uploaded (server engines such as Hayabusa then do not run on it)"
          />
        )}
        <Toggle
          on={s.autoRunRules !== false}
          onChange={(v) => patch({ autoRunRules: v })}
          label="run the enabled rules automatically when an ingest finishes (the Findings page otherwise lags the evidence until you run them)"
        />
        <div className="kv small">
          <div className="k">server</div>
          <div className="v">
            {health?.name} v{health?.version} · python {health?.python} · multipart limit {health?.limits.maxUploadMb} MB · chunked uploads up to {health?.limits.maxChunkedGb ?? '?'} GB
          </div>
          <div className="k">case stores</div>
          <div className="v">{health?.store?.casesDir ?? '—'}</div>
          <div className="k">ollama</div>
          <div className="v">
            {health?.ollama.host} · {health?.ollama.reachable ? `${health.ollama.models.length} model(s)` : health?.ollama.error}
          </div>
          <div className="k">optional</div>
          <div className="v">
            PST/OST {health?.optional.pst ? 'yes' : 'no (pip install libpff-python)'} · YARA {health?.optional.yara ? `yes (${health.optional.yaraRules} rule file(s))` : 'no'} · Hayabusa{' '}
            {health?.engines?.includes('hayabusa') ? 'yes (runs on every event log ingested; findings under engine:hayabusa)' : 'no (binary or its rules not found on the server)'}
          </div>
        </div>
        <div className="divider" />
        <div className="row">
          <button className="btn danger sm" onClick={wipe} disabled={!mayOwn} title={ownReason}>
            delete all case data{isServer ? ' (browser + server store)' : ' from this browser'}
          </button>
          <button className="btn danger sm" onClick={destroy} disabled={!mayOwn} title={ownReason}>
            delete this case
          </button>
          {shared && !mayOwn && settled && (
            <button className="btn sm" onClick={leave}>
              remove this case from this browser
            </button>
          )}
        </div>
        <div className="hint">
          The first empties the case and keeps it; the second removes the case itself and switches to another one.
          {ownReason && settled ? ` ${ownReason}` : ''}
        </div>
      </div>
    </div>
  )
}
