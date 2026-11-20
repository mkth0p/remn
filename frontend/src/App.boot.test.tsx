// @vitest-environment jsdom
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { RemnDB, setDb } from './db/schema'
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

afterEach(() => {
  cleanup()
  setDb(null)
})

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
})
