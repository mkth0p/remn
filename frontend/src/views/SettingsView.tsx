import { useMemo, useState } from 'react'
import { CaseAccessPanel } from '../components/CaseAccess'
import { OWNER_REASON, useCaseAccess, viewerReason } from '../data/access'
import { getSource } from '../data/source'
import { suggestTrustedSenders, type TrustedSuggestion } from '../data/trusted'
import { getDb, type CaseSettings } from '../db/schema'
import { toast, useStore } from '../state/store'
import { AiPanel } from './settings/AiPanel'
import { CasePanel } from './settings/CasePanel'
import { OrganisationPanel, TimePanel, WindowsPanel } from './settings/ContextPanels'
import { IngestionPanel, LookupsPanel } from './settings/ServerPanels'
import { StoragePanel } from './settings/StoragePanel'
import { TrustedSuggestions } from './settings/TrustedSuggestions'

/**
 * Settings: the case (name, storage, who may change it), the analyst model, the context the rules
 * read (the organisation, Windows, time), the reputation lookups, what ingestion keeps, and the
 * end of the case.
 */
export function SettingsView() {
  const kase = useStore((s) => s.currentCase)
  const updateSettings = useStore((s) => s.updateSettings)
  const health = useStore((s) => s.health)
  const meta = useStore((st) => st.meta)
  const [suggesting, setSuggesting] = useState(false)
  const [suggestions, setSuggestions] = useState<TrustedSuggestion[] | null>(null)
  const ds = useMemo(() => (kase ? getSource(kase) : null), [kase])
  const [access, setAccess, accessError] = useCaseAccess(kase)
  if (!kase || !ds) return null
  const s = kase.settings
  const isServer = kase.storage === 'server'
  // on a server with accounts, emptying or deleting a server case is its owner's (or an admin's)
  const viewer = viewerReason(health)
  const shared = isServer && health?.accounts === true
  const mayOwn = !shared || access?.may.own === true
  const ownReason = mayOwn ? undefined : (viewer ?? (access ? OWNER_REASON : accessError ? `who may change this case is not known: ${accessError}` : 'checking who may change this case…'))
  const settled = access != null || accessError != null
  const patch = async (p: Partial<CaseSettings>) => {
    updateSettings(p)
    await getDb().cases.update(kase.id!, { settings: { ...s, ...p }, updatedAt: Date.now() })
  }
  const runSuggest = async () => {
    setSuggesting(true)
    try {
      const found = await suggestTrustedSenders(kase, meta?.mailStrongFlags ?? [])
      if (!found.length) {
        toast('info', 'no candidates: needs senders with 5+ mails, passing auth and no strong indicator')
      } else {
        setSuggestions(found)
      }
    } catch (e) {
      toast('err', `scan failed: ${(e as Error).message}`)
    } finally {
      setSuggesting(false)
    }
  }
  const addTrusted = async (add: string[]) => {
    await patch({ trustedSenders: Array.from(new Set([...(s.trustedSenders ?? []), ...add])) })
    setSuggestions(null)
    toast('ok', `${add.length} trusted sender(s) added. Use Mails → rescore + refresh findings to apply the changes.`)
  }
  return (
    <div className="view">
      <div className="view-header">
        <h1>Settings</h1>
        <span className="sub">case-level context used by the rules and the AI</span>
      </div>
      <div className="view-body col" style={{ gap: 14, maxWidth: 1100 }}>
        <div className="grid-2">
          <CasePanel kase={kase} />
          <StoragePanel kase={kase} ds={ds} patch={patch} browserOnly={health?.mode === 'browser-only'} viewer={viewer} />
          {shared && <CaseAccessPanel kase={kase} access={access} onChange={setAccess} />}
          <AiPanel health={health} />
          <OrganisationPanel s={s} patch={patch} suggesting={suggesting} onSuggest={runSuggest} />
          <WindowsPanel s={s} patch={patch} />
          <TimePanel s={s} patch={patch} />
          <LookupsPanel s={s} patch={patch} health={health} />
          <IngestionPanel kase={kase} patch={patch} health={health} shared={shared} mayOwn={mayOwn} ownReason={ownReason} settled={settled} />
        </div>
      </div>
      {suggestions && <TrustedSuggestions suggestions={suggestions} onClose={() => setSuggestions(null)} onAdd={addTrusted} />}
    </div>
  )
}
