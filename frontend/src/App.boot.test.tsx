// @vitest-environment jsdom
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case } from './db/schema'
import { caseRef } from './state/route'
import { useStore } from './state/store'
import App from './App'

vi.mock('./api/client', async (original) => ({
  ...(await original<typeof import('./api/client')>()),
  getHealth: vi.fn(() => new Promise(() => undefined)),
  getMeta: vi.fn(() => new Promise(() => undefined)),
}))

/** A database the browser refuses to open, as Dexie reports it. */
function unopenable(name: string, message: string): RemnDB {
  const fail = () => Promise.reject(Object.assign(new Error(message), { name }))
  return { kv: { get: fail, put: fail }, cases: { count: fail, toArray: fail }, on: () => ({ unsubscribe: () => undefined }) } as unknown as RemnDB
}

let opened: RemnDB | null = null
afterEach(async () => {
  cleanup()
  // what the start set going (counts, the check for interrupted imports) ends before its database goes
  await new Promise((r) => setTimeout(r, 100))
  await opened?.delete()
  opened = null
  setDb(null)
  history.replaceState(null, '', '/')
})

// invented cases, both holding evidence, the second the one this browser opened last
const lab: Case = { id: 1, name: 'Lab', createdAt: 1_700_000_000_000, updatedAt: 1, settings: defaultSettings(), storage: 'browser' }
const second: Case = { id: 2, name: 'Second', createdAt: 1_700_000_500_000, updatedAt: 1, settings: defaultSettings(), storage: 'browser' }
async function twoCases(): Promise<RemnDB> {
  const db = (opened = new RemnDB(`boot-${Math.random()}`))
  setDb(db)
  await db.cases.bulkAdd([lab, second])
  for (const caseId of [1, 2]) await db.evidence.add({ caseId, name: 'box.mbox', kind: 'mail', size: 1, addedAt: 1, status: 'done', count: 1, integrity: 'verified' })
  await db.kv.put({ key: 'lastCase', value: 2 })
  useStore.setState({ view: 'dashboard', currentCase: null, toasts: [] })
  return db
}
const title = () => document.querySelector('.topbar .title')?.textContent

describe('starting the application', () => {
  it('says why when the browser database cannot be opened, instead of booting for ever', async () => {
    setDb(unopenable('OpenFailedError', 'InvalidStateError A mutation operation was attempted on a database that did not allow mutations.'))
    render(<App />)
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('REMN could not open its database in this browser')
    expect(alert.textContent).toContain('A mutation operation was attempted')
    expect(screen.queryByText(/booting/)).toBeNull()
  })

  it('names the likely cause when the storage is full', async () => {
    setDb(unopenable('QuotaExceededError', 'The quota has been exceeded.'))
    render(<App />)
    expect((await screen.findByRole('alert')).textContent).toContain('storage for this site is full')
  })

  it('says that another tab holds the database while an upgrade waits for it, and starts once it lets go', async () => {
    const name = `blocked-${Math.random()}`
    // a tab of an older version that keeps its connection open and never answers the upgrade request
    const older = await new Promise<IDBDatabase>((resolve, reject) => {
      const req = indexedDB.open(name, 1)
      req.onsuccess = () => resolve(req.result)
      req.onerror = () => reject(req.error)
    })
    const db = new RemnDB(name)
    setDb(db)
    render(<App />)
    const status = await screen.findByText(/Another REMN tab/, undefined, { timeout: 5000 })
    expect(status.textContent).toContain('close the other REMN tabs')
    older.close()
    await waitFor(() => expect(screen.queryByText(/Another REMN tab/)).toBeNull(), { timeout: 8000 })
    db.close()
  }, 15_000)

  it('opens the case and the page the address names, so a reload keeps the place', async () => {
    await twoCases()
    history.replaceState(null, '', `/case/${caseRef(lab)}/case`)
    render(<App />)
    await waitFor(() => expect(title()).toBe('Case notes'), { timeout: 8000 })
    // the page's own script is fetched when it is first opened
    expect(await screen.findByText('Tasks', undefined, { timeout: 8000 })).toBeTruthy()
    expect(useStore.getState().currentCase?.id).toBe(1)
    expect((document.querySelector('.topbar select') as HTMLSelectElement).value).toBe('1')
    expect(location.pathname).toBe(`/case/${caseRef(lab)}/case`)
    expect(document.title).toBe('Case notes · REMN')
  }, 15_000)

  it('does not open a case of another browser that has the same number, and says why', async () => {
    await twoCases()
    history.replaceState(null, '', `/case/${caseRef({ id: 1, createdAt: 1_600_000_000_000 })}/case`)
    render(<App />)
    await waitFor(() => expect(title()).toBe('Dashboard'), { timeout: 8000 })
    // the start goes on as without a link: the case opened last, on its dashboard
    expect(useStore.getState().currentCase?.id).toBe(2)
    expect(
      useStore
        .getState()
        .toasts.map((t) => t.text)
        .join('\n'),
    ).toContain('does not hold')
    expect(location.pathname).toBe(`/case/${caseRef(second)}/dashboard`)
  }, 15_000)
})
