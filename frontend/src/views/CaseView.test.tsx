// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case } from '../db/schema'
import { addTimelineEntry } from '../data/caseNotes'
import { useStore } from '../state/store'
import { CaseView } from './CaseView'

const kase: Case = { id: 1, name: 'Lab', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
let db: RemnDB
beforeEach(() => {
  db = new RemnDB(`caseview-${Math.random()}`)
  setDb(db)
  useStore.setState({ currentCase: kase, view: 'case' })
})
afterEach(async () => {
  cleanup()
  await db.delete()
})

describe('CaseView', () => {
  it('adds a task from the input and reflects the open count', async () => {
    render(<CaseView />)
    fireEvent.click(screen.getByText('Tasks'))
    const input = screen.getByPlaceholderText(/task to do/i)
    fireEvent.change(input, { target: { value: 'Reset the credentials' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    await waitFor(() => expect(screen.getByText('Reset the credentials')).toBeTruthy())
    expect(await db.caseNotes.where('caseId').equals(1).count()).toBe(1)
    expect(screen.getByText(/1 open task/)).toBeTruthy()
  })

  it('lists timeline entries in time order with their link and dedupes by link', async () => {
    await addTimelineEntry(1, { ts: 2000, text: 'later', link: { source: 'mails', id: 7, label: 'S01' }, severity: 'high' })
    await addTimelineEntry(1, { ts: 1000, text: 'earlier', severity: 'info' })
    expect(await addTimelineEntry(1, { ts: 2000, text: 'later again', link: { source: 'mails', id: 7 } })).toBe('exists')
    await act(async () => {
      render(<CaseView />)
    })
    await waitFor(() => expect(screen.getByText('later')).toBeTruthy())
    const titles = Array.from(document.querySelectorAll('.story .step .title')).map((el) => el.textContent)
    expect(titles).toEqual(['earlier', 'later'])
    expect(screen.getByText('mails S01')).toBeTruthy()
    expect(screen.getByText(/2 timeline entries/)).toBeTruthy()
  })
})
