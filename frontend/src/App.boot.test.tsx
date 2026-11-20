// @vitest-environment jsdom
import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { setDb, type RemnDB } from './db/schema'
import App from './App'

vi.mock('./api/client', async (original) => ({
  ...(await original<typeof import('./api/client')>()),
  getHealth: vi.fn(() => new Promise(() => undefined)),
  getMeta: vi.fn(() => new Promise(() => undefined)),
}))

/** A database the browser refuses to open, as Dexie reports it. */
function unopenable(name: string, message: string): RemnDB {
  const fail = () => Promise.reject(Object.assign(new Error(message), { name }))
  return { kv: { get: fail, put: fail }, cases: { count: fail, toArray: fail }, on: () => undefined } as unknown as RemnDB
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
})
