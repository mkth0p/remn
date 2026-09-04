import { useState } from 'react'
import { getHealth, setApiToken } from '../api/client'
import { getDb } from '../db/schema'
import { useStore } from '../state/store'
import { Modal } from './ui'

/**
 * Shown when the server requires an access token (FORENSIC_AUTH_TOKEN set on a
 * remote/home-server deployment) and ours is missing or wrong.
 */
export function TokenGate() {
  const setAuthRequired = useStore((s) => s.setAuthRequired)
  const setHealth = useStore((s) => s.setHealth)
  const [token, setToken] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const submit = async () => {
    const t = token.trim()
    if (!t || busy) return
    setBusy(true)
    setErr(null)
    setApiToken(t)
    try {
      const h = await getHealth()
      await getDb().kv.put({ key: 'apiToken', value: t })
      setHealth(h)
      setAuthRequired(false)
    } catch (e) {
      const status = (e as { status?: number }).status
      setErr(status === 401 ? 'wrong token' : `server error: ${(e as Error).message}`)
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal title="Access token required" onClose={() => undefined} footer={<button className="btn primary" disabled={busy || !token.trim()} onClick={submit}>{busy ? 'checking…' : 'unlock'}</button>}>
      <div className="small muted">This REMN server is protected by a shared access token (set by whoever runs it, in the server's environment as FORENSIC_AUTH_TOKEN).</div>
      <input className="input mono" type="password" autoFocus placeholder="access token" value={token} onChange={(e) => setToken(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && submit()} />
      {err && <div className="small" style={{ color: 'var(--red, #e5534b)' }}>{err}</div>}
      <div className="hint">The token is kept in this browser only (IndexedDB) and sent with every API request. It never goes to Ollama or any third party.</div>
    </Modal>
  )
}
