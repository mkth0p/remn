// @vitest-environment jsdom
import { act, cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case } from '../db/schema'
import { useStore } from '../state/store'
import { Dashboard } from './Dashboard'

// an invented case summary: events without an event-log time range, as a cloud audit export gives
vi.mock('../data/source', () => ({ getSource: () => ({ kind: 'browser', summary: async () => ({ eventsTimeRange: { firstIso: null, lastIso: null } }) }) }))
vi.mock('../data/ingest', () => ({ requestIngest: vi.fn(), refreshCounts: vi.fn() }))

const kase = (over: Partial<Case['settings']> = {}): Case => ({ id: 1, name: 'Lab', storage: 'browser', createdAt: 1, updatedAt: 1, settings: { ...defaultSettings(), ...over } })
const settle = () => act(() => new Promise((r) => setTimeout(r, 30)))
const counts = (events: number, evidence: number) => ({ events, mails: 0, findings: 0, iocs: 0, evidence })
let db: RemnDB

beforeEach(() => {
  db = new RemnDB(`dashboard-${Math.random()}`)
  setDb(db)
  useStore.setState({ currentCase: kase(), counts: counts(0, 0), aiStatus: { reachable: null, checkedAt: 0 } })
})
afterEach(async () => {
  cleanup()
  await db.delete()
})

describe('the Dashboard', () => {
  it('does not say no event log is loaded when the case holds events from another source', async () => {
    useStore.setState({ counts: counts(120, 1) })
    render(<Dashboard />)
    await settle()
    expect(screen.queryByText(/no EVTX/)).toBeNull()
    expect(screen.getByText('events')).toBeTruthy()
  })

  it('says so when the case holds no events', async () => {
    render(<Dashboard />)
    await settle()
    expect(screen.getByText('events · none loaded')).toBeTruthy()
  })

  it('tells that the rules run on their own after an import, unless the case turned that off', async () => {
    render(<Dashboard />)
    await settle()
    expect(screen.getByText('No findings yet. Load evidence: the rules run on their own once an import finishes.')).toBeTruthy()
    cleanup()
    useStore.setState({ currentCase: kase({ autoRunRules: false }), counts: counts(120, 1) })
    render(<Dashboard />)
    await settle()
    expect(screen.getByText('No findings yet. Run the rules from the Findings view: this case does not run them on its own.')).toBeTruthy()
  })

  it('names the AI connection that could not be reached', async () => {
    useStore.setState({ aiStatus: { reachable: false, error: 'not signed in', checkedAt: 1 } })
    useStore.getState().setAiConfig({ transport: 'claude' })
    render(<Dashboard />)
    await settle()
    expect(screen.queryByText('Ollama unreachable')).toBeNull()
    expect(screen.getByText('Claude Code unavailable')).toBeTruthy()
    cleanup()
    useStore.getState().setAiConfig({ transport: 'openai' })
    render(<Dashboard />)
    await settle()
    expect(screen.getByText('model server unreachable')).toBeTruthy()
    cleanup()
    useStore.getState().setAiConfig({ transport: 'browser' })
    render(<Dashboard />)
    await settle()
    expect(screen.getByText('Ollama unreachable')).toBeTruthy()
  })
})
