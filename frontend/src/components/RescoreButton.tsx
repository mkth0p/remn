import { useEffect, useState } from 'react'
import { rescoreMails } from '../data/enrich'
import { loadRules, runRulesFor } from '../data/rules'
import { refreshCounts } from '../data/ingest'
import { getDb } from '../db/schema'
import { toast, useStore } from '../state/store'
import { Spinner } from './ui'

export function RescoreButton() {
  const kase = useStore((s) => s.currentCase)
  const [busy, setBusy] = useState(false)
  const [progress, setProgress] = useState('')
  const [notice, setNotice] = useState('')
  useEffect(() => {
    let alive = true
    if (kase?.id)
      getDb()
        .kv.get(`mail-calibration-${kase.id}`)
        .then((r) => {
          const state = (r?.value as { state?: string })?.state
          if (alive) setNotice(state && state !== 'done' ? 'Previous refresh is incomplete. Rescore again to finish.' : '')
        })
    return () => {
      alive = false
    }
  }, [kase?.id])
  if (!kase) return null
  const run = async () => {
    if (useStore.getState().jobs.some((j) => j.phase !== 'done' && j.phase !== 'error')) return toast('warn', 'Wait for evidence ingestion to finish before rescoring')
    setBusy(true)
    setNotice('')
    try {
      const summary = await rescoreMails(kase, setProgress)
      setProgress('Refreshing mail findings…')
      const rules = (await loadRules(kase.id!, true)).filter((r) => r.enabled && !r.error && r.rule.source === 'mails').map((r) => r.rule)
      const result = await runRulesFor(kase, rules)
      if (result.errors.length) throw new Error(`Scores updated; ${result.errors.length} rule(s) failed. See Rules diagnostics and retry.`)
      await getDb().kv.put({ key: `mail-calibration-${kase.id}`, value: { state: 'done', at: Date.now(), summary } })
      if (useStore.getState().currentCase?.id === kase.id) await refreshCounts(kase)
      toast(
        'ok',
        `${summary.mails} mails rescored: high/critical ${summary.highBefore} → ${summary.highAfter}. Findings refreshed.${summary.limited ? ` ${summary.limited} need original evidence for full attachment analysis.` : ''}`,
        12000,
      )
      setNotice(summary.limited ? `${summary.limited} messages have incomplete attachment analysis; see message details.` : '')
    } catch (e) {
      setNotice((e as Error).message)
      toast('err', `Mail refresh incomplete: ${(e as Error).message}`, 0)
    } finally {
      setBusy(false)
      setProgress('')
      useStore.getState().bumpRules()
    }
  }
  return (
    <span className="row small" style={{ gap: 6 }}>
      <button
        className="btn xs"
        disabled={busy}
        onClick={run}
        title="Update sender history, recalibrate retained mail and attachment facts, then refresh enabled mail rules. Evidence IDs and raw records are preserved."
      >
        {busy ? <Spinner /> : null} rescore + refresh findings
      </button>
      {progress && <span role="status">{progress}</span>}
      {notice && (
        <span className="muted" role="status">
          {notice}
        </span>
      )}
    </span>
  )
}
