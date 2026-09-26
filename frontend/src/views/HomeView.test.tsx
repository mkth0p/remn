// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case } from '../db/schema'
import { FIRST_CASE_NAME } from '../data/cases'
import { useStore } from '../state/store'
import type { Health } from '../api/client'
import { HomeView } from './HomeView'

let db: RemnDB
let first: Case
beforeEach(async () => {
  db = new RemnDB(`homeview-${Math.random()}`)
  setDb(db)
  first = { name: FIRST_CASE_NAME, storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
  first.id = await db.cases.add(first)
  useStore.setState({ currentCase: first, view: 'home', health: null, meta: null })
})
afterEach(async () => {
  cleanup()
  await db.delete()
})

describe('HomeView', () => {
  it('starts a case from the dialog and opens its evidence', async () => {
    render(<HomeView />)
    fireEvent.click(screen.getAllByRole('button', { name: 'New case' })[0])
    fireEvent.change(screen.getByLabelText('Case name'), { target: { value: 'Finance laptop' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create case' }))
    await waitFor(() => expect(useStore.getState().view).toBe('evidence'))
    expect(useStore.getState().currentCase).toMatchObject({ id: first.id, name: 'Finance laptop', storage: 'browser' })
    expect(await db.cases.count()).toBe(1)
  })

  it('opens the current case', () => {
    render(<HomeView />)
    fireEvent.click(screen.getByRole('button', { name: /^Open case/ }))
    expect(useStore.getState().view).toBe('dashboard')
  })

  it('offers no server store where the server keeps nothing', () => {
    useStore.setState({ health: { mode: 'browser-only' } as Health })
    render(<HomeView />)
    fireEvent.click(screen.getAllByRole('button', { name: 'New case' })[0])
    expect(screen.getByRole('radio', { name: /Browser/ })).toBeTruthy()
    expect(screen.queryByRole('radio', { name: /Server/ })).toBeNull()
  })
})
