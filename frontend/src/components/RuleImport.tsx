import { useRef, useState } from 'react'
import { apiPostForm } from '../api/client'
import { getDb } from '../db/schema'
import { toast, useStore } from '../state/store'
import { Modal, Spinner } from './ui'

interface ConvertedRule {
  ok: boolean
  id: string
  title: string
  file?: string
  yaml?: string
  error?: string
  warnings: string[]
}
interface ConvertResponse {
  rules: ConvertedRule[]
  summary: { total: number; converted: number; skipped: number; reasons: [string, number][] }
}

const KINDS = {
  sigma: {
    label: 'import Sigma',
    title: 'Sigma import',
    endpoint: '/api/rules/convert/sigma',
    hint: 'SigmaHQ / Chainsaw / Hayabusa rules: one .yml or a .zip of the rules folder',
    blurb: 'A skipped rule is one whose detection cannot be expressed without changing what it matches (base64 / utf16 modifiers, aggregations, non-Windows sources).',
  },
  sublime: {
    label: 'import Sublime',
    title: 'Sublime rules import',
    endpoint: '/api/rules/convert/sublime',
    hint: 'Sublime Security detection rules (MQL): one .yml or a .zip of the sublime-rules repository',
    blurb:
      'Rules relying on Sublime-only features (ML classifiers, link analysis, sender profiles, file explosion, screenshots) are skipped rather than weakened; approximations are listed as warnings.',
  },
} as const

/** "Import Sigma" / "Import Sublime" buttons: convert through the backend, keep the exact translations as custom rules. */
export function RuleImport({ kind }: { kind: keyof typeof KINDS }) {
  const cfg = KINDS[kind]
  const fileRef = useRef<HTMLInputElement>(null)
  const [busy, setBusy] = useState(false)
  const [res, setRes] = useState<ConvertResponse | null>(null)
  const [showSkipped, setShowSkipped] = useState(false)

  const pick = async (file: File | undefined) => {
    if (!file) return
    setBusy(true)
    try {
      const form = new FormData()
      form.append('file', file, file.name)
      setRes(await apiPostForm<ConvertResponse>(cfg.endpoint, form))
      setShowSkipped(false)
    } catch (e) {
      toast('err', `${cfg.title}: ${(e as Error).message}`, 0)
    } finally {
      setBusy(false)
      if (fileRef.current) fileRef.current.value = ''
    }
  }

  const add = async () => {
    if (!res) return
    const db = getDb()
    const existing = new Set((await db.customRules.toArray()).map((r) => r.ruleId))
    const now = Date.now()
    const rows = res.rules.filter((r) => r.ok && r.yaml && !existing.has(r.id)).map((r) => ({ caseId: null, ruleId: r.id, yaml: r.yaml!, enabled: true, updatedAt: now }))
    if (rows.length) await db.customRules.bulkAdd(rows)
    const dup = res.rules.filter((r) => r.ok && existing.has(r.id)).length
    toast('ok', `${rows.length} rule(s) added as custom rules${dup ? ` (${dup} already present)` : ''}`)
    setRes(null)
    useStore.getState().bumpRules()
  }

  const listed = res ? res.rules.filter((r) => (showSkipped ? !r.ok : r.ok)).slice(0, 300) : []
  return (
    <>
      <input ref={fileRef} type="file" accept=".yml,.yaml,.zip" data-import={kind} style={{ display: 'none' }} onChange={(e) => pick(e.target.files?.[0])} />
      <button className="btn sm" onClick={() => fileRef.current?.click()} disabled={busy} title={cfg.hint}>
        {busy ? <Spinner /> : null} {cfg.label}
      </button>
      {res && (
        <Modal title={cfg.title} onClose={() => setRes(null)} wide>
          <p className="muted" style={{ marginTop: 0 }}>
            {res.summary.converted} of {res.summary.total} rule(s) translate to the REMN DSL; {res.summary.skipped} skipped. {cfg.blurb}
          </p>
          {res.summary.reasons.length > 0 && (
            <div className="muted mono" style={{ fontSize: 12, marginBottom: 8 }}>
              {res.summary.reasons.map(([why, n]) => (
                <div key={why}>
                  {n} × {why}
                </div>
              ))}
            </div>
          )}
          <div className="row" style={{ gap: 8, marginBottom: 8 }}>
            <button className={`btn xs${showSkipped ? '' : ' primary'}`} onClick={() => setShowSkipped(false)}>
              converted ({res.summary.converted})
            </button>
            <button className={`btn xs${showSkipped ? ' primary' : ''}`} onClick={() => setShowSkipped(true)}>
              skipped ({res.summary.skipped})
            </button>
          </div>
          <div style={{ maxHeight: 360, overflow: 'auto', border: '1px solid var(--line)', borderRadius: 6 }}>
            <table className="table compact">
              <tbody>
                {listed.map((r) => (
                  <tr key={r.id + (r.file ?? '')}>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {r.id}
                    </td>
                    <td>{r.title}</td>
                    <td className="muted" style={{ fontSize: 12 }}>
                      {r.ok ? r.warnings.join('; ') : r.error}
                    </td>
                  </tr>
                ))}
                {listed.length === 0 && (
                  <tr>
                    <td className="muted">nothing here</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <div className="row" style={{ marginTop: 12, gap: 8 }}>
            <span className="spacer" />
            <button className="btn" onClick={() => setRes(null)}>
              cancel
            </button>
            <button className="btn primary" onClick={add} disabled={!res.summary.converted}>
              add {res.summary.converted} rule(s) as custom rules
            </button>
          </div>
        </Modal>
      )}
    </>
  )
}
