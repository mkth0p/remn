import { useEffect, useState } from 'react'
import { getDb, type Case } from '../db/schema'
import { listSharedCases, openSharedCase, OWNER_REASON, setCaseMembers, type CaseAccess, type SharedCase } from '../data/access'
import { toast, useStore } from '../state/store'
import { fmtBytes } from '../util/format'

/** The owner and members of a server case. Its owner, or an admin, adds and removes members by account name. */
export function CaseAccessPanel({ kase, access, onChange }: { kase: Case; access: CaseAccess | null; onChange: (a: CaseAccess) => void }) {
  const [draft, setDraft] = useState('')
  const [busy, setBusy] = useState(false)
  if (!access || !kase.serverKey) return null
  const key = kase.serverKey
  const own = access.may.own
  const save = async (members: string[]) => {
    setBusy(true)
    try {
      onChange(await setCaseMembers(key, members, kase.name))
      setDraft('')
    } catch (e) {
      toast('err', `members not changed: ${(e as Error).message}`, 0)
    } finally {
      setBusy(false)
    }
  }
  const add = () => {
    const names = draft
      .split(/[\s,]+/)
      .map((n) => n.trim().toLowerCase())
      .filter(Boolean)
    if (names.length) save(Array.from(new Set([...access.members, ...names])))
  }
  return (
    <div className="panel">
      <div className="panel-h">case access</div>
      <div className="panel-b col">
        <div className="small">
          owner <b className="mono">{access.owner ?? 'none: only an admin opens it'}</b>
        </div>
        <div className="row" style={{ flexWrap: 'wrap', gap: 6 }}>
          {access.members.length ? (
            access.members.map((m) => (
              <span key={m} className="badge mono">
                {m}{' '}
                <button
                  className="btn ghost xs"
                  disabled={!own || busy}
                  title={own ? `remove ${m}` : OWNER_REASON}
                  aria-label={`remove ${m}`}
                  onClick={() => save(access.members.filter((x) => x !== m))}
                >
                  ×
                </button>
              </span>
            ))
          ) : (
            <span className="muted small">no members</span>
          )}
        </div>
        <div className="row">
          <input
            className="input mono"
            style={{ flex: 1 }}
            placeholder="account name(s)"
            value={draft}
            disabled={!own || busy}
            title={own ? undefined : OWNER_REASON}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && add()}
          />
          <button className="btn sm" disabled={!own || busy || !draft.trim()} title={own ? undefined : OWNER_REASON} onClick={add}>
            add member
          </button>
        </div>
        <div className="hint">
          {own ? '' : `${OWNER_REASON} `}A member opens the case from "+ case" in their own browser. An analyst member adds and removes evidence; a viewer reads. Findings, notes and decisions stay in
          each browser.
        </div>
      </div>
    </div>
  )
}

/** The server cases this account may read that this browser does not hold yet, each opened as a case of this browser. */
export function SharedCases({ onOpen }: { onOpen: (id: number) => void }) {
  const [list, setList] = useState<SharedCase[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    let alive = true
    Promise.all([listSharedCases(), getDb().cases.toArray()])
      .then(([stores, local]) => {
        const held = new Set(local.map((c) => c.serverKey).filter(Boolean))
        if (alive) setList(stores.filter((s) => !held.has(s.key)))
      })
      .catch((e: Error) => alive && setError(e.message))
    return () => {
      alive = false
    }
  }, [])
  const open = async (s: SharedCase) => {
    const id = await openSharedCase(s)
    useStore.getState().bumpCases()
    onOpen(id)
  }
  return (
    <div className="col" style={{ gap: 4 }}>
      <b className="small">Cases shared with you</b>
      {error && <div className="small muted">{error}</div>}
      {list && !list.length && <div className="small muted">none that this browser does not already hold</div>}
      {list?.map((s) => (
        <div key={s.key} className="row small">
          <span style={{ flex: 1 }}>
            {s.name || <span className="mono">{s.key.slice(0, 8)}…</span>} <span className="muted">· owner {s.owner ?? 'none'}</span>
            <span className="muted"> · {s.stored ? fmtBytes(s.sizeBytes) : 'no evidence yet'}</span>
          </span>
          <button className="btn xs" onClick={() => open(s)}>
            open
          </button>
        </div>
      ))}
      <div className="hint">The evidence is read from the server. Findings, notes and decisions are kept per browser: run the rules after opening.</div>
    </div>
  )
}
