// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case } from '../db/schema'
import { FIRST_CASE_NAME } from '../data/cases'
import { useStore } from '../state/store'
import type { Health } from '../api/client'
import measure from 'virtual:rule-measure'
import levels from '../data/detectionLevels.gen.json'
import { fmtNum } from '../util/format'
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

  it('keeps the focus in the new case dialog and gives it back to the button that opened it', () => {
    render(<HomeView />)
    const opener = screen.getAllByRole('button', { name: 'New case' })[0]
    opener.focus()
    fireEvent.click(opener)
    const dialog = screen.getByRole('dialog', { name: 'New case' })
    expect(document.activeElement).toBe(screen.getByLabelText('Case name'))
    const close = screen.getByRole('button', { name: 'Close' })
    close.focus()
    fireEvent.keyDown(close, { key: 'Tab', shiftKey: true })
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'Create case' }))
    fireEvent.keyDown(document.activeElement!, { key: 'Tab' })
    expect(document.activeElement).toBe(close)
    expect(dialog.contains(document.activeElement)).toBe(true)
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(document.activeElement).toBe(opener)
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

  it('quotes the committed rule measure, without a server to ask', () => {
    const { container } = render(<HomeView />)
    const page = container.textContent ?? ''
    expect(page).toContain(`${fmtNum(measure.rules)} detection rules`)
    for (const l of measure.libraries) {
      const bar = screen.getByTitle(`${l.name}: ${fmtNum(l.detected)} of ${fmtNum(l.recordings)} recordings detected`)
      expect(bar).toBeTruthy()
    }
    expect(page).toContain(`${fmtNum(measure.detect)} have fired on a recording of what they look for`)
    expect(page).toContain(`Measured ${measure.measured}`)
    expect(screen.getByRole('cell', { name: fmtNum(measure.clean.own.highCritical) })).toBeTruthy()
  })

  it('draws the lines of each detection level from the figures the committed measure gives', () => {
    render(<HomeView />)
    for (const l of levels.levels) expect(screen.getByTitle(new RegExp(`^${l.level} · .*: ${l.lines} lines per clean host$`))).toBeTruthy()
    expect(screen.getByTitle(`≥ medium, no levels: ${levels.mediumUp} lines per clean host`)).toBeTruthy()
    expect(document.body.textContent).toContain(`Lines counted on the ${levels.machines} clean hosts of the rule measure of ${levels.measured}`)
  })

  it('names no evaluation REMN did not take part in, and no comparison the committed measure does not hold', () => {
    const { container } = render(<HomeView />)
    const page = container.textContent ?? ''
    expect(page).not.toMatch(/ATT&CK Evaluations|MITRE's APT29 evaluation/)
    expect(page).not.toMatch(/Hayabusa|Chainsaw|Head-to-head/)
    expect(page).toContain('APT29')
  })
})
