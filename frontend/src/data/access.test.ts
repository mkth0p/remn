import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { API_HEADERS, setApiToken, type Health } from '../api/client'
import { RemnDB, setDb } from '../db/schema'
import { useStore } from '../state/store'
import { openSharedCase, signOut, viewerReason, VIEWER_REASON } from './access'

// every account name and case key here is invented
const health = (extra: Partial<Health>) => ({ mode: 'full', ...extra }) as Health
let db: RemnDB

beforeEach(() => {
  db = new RemnDB(`access-${Math.random()}`)
  setDb(db)
})
afterEach(async () => {
  setApiToken(null)
  vi.unstubAllGlobals()
  await db.delete()
})

describe('what the page disables for the signed-in account', () => {
  it('disables nothing without accounts, or for an analyst or an admin', () => {
    expect(viewerReason(null)).toBeNull()
    expect(viewerReason(health({}))).toBeNull()
    expect(viewerReason(health({ accounts: true, account: { name: 'ana', role: 'analyst' } }))).toBeNull()
    expect(viewerReason(health({ accounts: true, account: { name: 'root', role: 'admin' } }))).toBeNull()
  })

  it('gives a viewer the reason its controls are disabled', () => {
    expect(viewerReason(health({ accounts: true, account: { name: 'vic', role: 'viewer' } }))).toBe(VIEWER_REASON)
  })
})

describe('signing out', () => {
  it("forgets this browser's token and asks for a personal one again", async () => {
    await db.kv.put({ key: 'apiToken', value: 'remn_0123456789_invented' })
    setApiToken('remn_0123456789_invented')
    useStore.setState({ authRequired: false, authAccounts: false, health: health({ accounts: true, account: { name: 'ana', role: 'analyst' } }) } as never)
    await signOut()
    expect(await db.kv.get('apiToken')).toBeUndefined()
    expect(API_HEADERS['X-Forensic-Client']).toBe('remn')
    expect(useStore.getState()).toMatchObject({ authRequired: true, authAccounts: true, health: null })
  })
})

describe('opening a case shared with this account', () => {
  it('adds it as a server case of this browser under its name, or its key when it has none', async () => {
    const may = { read: true, write: false, own: false }
    const base = { owner: 'ana', members: ['vic'], may, sizeBytes: 0, modified: null, stored: true }
    const named = await openSharedCase({ ...base, key: '11111111-2222-4333-8444-555555555555', name: 'invented intrusion' })
    const unnamed = await openSharedCase({ ...base, key: '66666666-7777-4888-8999-aaaaaaaaaaaa', name: '' })
    expect(await db.cases.get(named)).toMatchObject({ name: 'invented intrusion', storage: 'server', serverKey: '11111111-2222-4333-8444-555555555555' })
    expect((await db.cases.get(unnamed))?.name).toBe('shared case 66666666')
  })
})
