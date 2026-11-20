/**
 * Accounts on the server (docs/security.md, "Accounts, roles and the audit log"): what the signed-in
 * account may change, who may open a server case, and the server cases shared with this account.
 * The server decides; the page only disables what it would refuse, and says why.
 */
import { useEffect, useState } from 'react'
import { apiGet, apiPost, setApiToken, type Health } from '../api/client'
import { defaultSettings, getDb, type Case } from '../db/schema'
import { useStore } from '../state/store'
import { DEFAULT_DETECTION_LEVEL } from './detectionLevel'

/** A server case as the access route describes it, with what the signed-in account may do with it. */
export interface CaseAccess {
  key: string
  name: string
  owner: string | null
  members: string[]
  may: { read: boolean; write: boolean; own: boolean }
}

/** A server case this account may read, from the case listing. */
export interface SharedCase extends CaseAccess {
  sizeBytes: number
  modified: number | null
  /** whether the server holds a store for it yet */
  stored: boolean
}

export const VIEWER_REASON = 'Your account is a viewer: it reads the cases it is a member of and changes nothing.'
export const OWNER_REASON = "Only the case's owner or an admin may do this."

/** Why the signed-in account may change nothing on the server, or null: no accounts, or an analyst or an admin. */
export function viewerReason(health: Health | null | undefined): string | null {
  return health?.accounts && health.account?.role === 'viewer' ? VIEWER_REASON : null
}

export const getCaseAccess = (key: string) => apiGet<CaseAccess>(`/api/store/${key}/access`)

/** Replace the members of a case. The case's name in this browser goes with it, for the listing of the others. */
export const setCaseMembers = (key: string, members: string[], name: string) => apiPost<CaseAccess>(`/api/store/${key}/access`, { members, name })

export const listSharedCases = () => apiGet<{ stores: SharedCase[] }>('/api/store').then((r) => r.stores)

/** Add a server case shared with this account to this browser's cases; returns its id here. */
export async function openSharedCase(s: SharedCase): Promise<number> {
  const now = Date.now()
  return getDb().cases.add({
    name: s.name || `shared case ${s.key.slice(0, 8)}`,
    createdAt: now,
    updatedAt: now,
    settings: { ...defaultSettings(), detectionLevel: DEFAULT_DETECTION_LEVEL },
    storage: 'server',
    serverKey: s.key,
  })
}

/**
 * Who may open a server case and what this account may do with it, on a server with accounts; null
 * otherwise or until it is known. The third value is why it could not be read: a case this account
 * is no longer a member of reads as not found.
 */
export function useCaseAccess(kase: Case | null): [CaseAccess | null, (a: CaseAccess) => void, string | null] {
  const accounts = useStore((s) => s.health?.accounts === true)
  const [access, setAccess] = useState<CaseAccess | null>(null)
  const [error, setError] = useState<string | null>(null)
  const key = kase?.storage === 'server' ? kase.serverKey : undefined
  useEffect(() => {
    setAccess(null)
    setError(null)
    if (!accounts || !key) return
    let alive = true
    getCaseAccess(key)
      .then((a) => alive && setAccess(a))
      .catch((e: Error) => alive && setError(e.message))
    return () => {
      alive = false
    }
  }, [accounts, key])
  return [access, setAccess, error]
}

/** Forget this browser's token and ask for one again. */
export async function signOut(): Promise<void> {
  await getDb().kv.delete('apiToken')
  setApiToken(null)
  useStore.getState().setHealth(null)
  useStore.getState().setAuthRequired(true, true)
}
