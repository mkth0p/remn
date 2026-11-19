// @vitest-environment jsdom
import { act, cleanup, render } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case } from '../db/schema'
import { useStore, type IngestJob } from '../state/store'
import { EventsView } from './EventsView'
import { MailsView } from './MailsView'

// a data source that answers every query with nothing and counts the searches
const searches = vi.hoisted(() => ({ events: 0, mails: 0 }))
vi.mock('../data/source', () => {
  const answers: Record<string, unknown> = {
    searchEvents: { rows: [], truncated: false },
    searchMails: { rows: [], truncated: false },
    countEvents: 0,
    countMails: 0,
    timelineEvents: [],
    timelineMails: [],
    facets: [],
  }
  const ds = new Proxy(
    { kind: 'browser' },
    {
      get: (target, key: string) => {
        if (key in target) return (target as Record<string, unknown>)[key]
        return async () => {
          if (key === 'searchEvents') searches.events++
          if (key === 'searchMails') searches.mails++
          return answers[key] ?? {}
        }
      },
    },
  )
  return { getSource: () => ds }
})

const kase: Case = { id: 1, name: 'Lab', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
const job = (phase: IngestJob['phase']): IngestJob => ({ id: 1, evidenceId: 1, name: 'a.evtx', kind: 'evtx', phase, progress: 0, rows: 0, bytes: 0, startedAt: 0 })
const settle = () => act(() => new Promise((r) => setTimeout(r, 50)))
let db: RemnDB

beforeEach(() => {
  db = new RemnDB(`events-view-${Math.random()}`)
  setDb(db)
  searches.events = searches.mails = 0
  useStore.setState({ currentCase: kase, jobs: [] })
})
afterEach(async () => {
  cleanup()
  await db.delete()
})

describe('the Events and Mails pages', () => {
  it('search once when they open, and again once an import finishes', async () => {
    render(<EventsView />)
    await settle()
    expect(searches.events).toBe(1)
    act(() => useStore.setState({ jobs: [job('parsing')] }))
    await settle()
    expect(searches.events).toBe(1)
    act(() => useStore.setState({ jobs: [job('done')] }))
    await settle()
    expect(searches.events).toBe(2)
    // the finished job leaving the list is no new data
    act(() => useStore.setState({ jobs: [] }))
    await settle()
    expect(searches.events).toBe(2)
  })

  it('the Mails page searches once when it opens', async () => {
    render(<MailsView />)
    await settle()
    expect(searches.mails).toBe(1)
  })
})
