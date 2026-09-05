import { useState } from 'react'
import { baselineSenders } from '../data/enrich'
import { toast, useStore } from '../state/store'
import { Spinner } from './ui'

/** Runs the sender-baseline / campaign enrichment for the current case and reports the summary. */
export function BaselineButton() {
  const kase = useStore((s) => s.currentCase)
  const bump = useStore((s) => s.bumpRules)
  const [busy, setBusy] = useState(false)
  if (!kase) return null
  const run = async () => {
    setBusy(true)
    try {
      const s = await baselineSenders(kase)
      toast('ok', `baseline: ${s.newSenders} first-contact sender(s), ${s.unsolicitedNew} unsolicited, ${s.authRegressions} auth regression(s), ${s.campaigns} campaign(s) (largest ${s.largestCampaign})`, 8000)
      bump()
    } catch (e) {
      toast('err', `baseline: ${(e as Error).message}`, 0)
    } finally {
      setBusy(false)
    }
  }
  return (
    <button className="btn xs" onClick={run} disabled={busy} title="sender prevalence / first contact / solicited / auth regression / campaign clusters - feeds the baseline rules and the AI">
      {busy ? <Spinner /> : null} baseline senders
    </button>
  )
}
