// @vitest-environment jsdom
import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case } from '../db/schema'
import { useStore } from '../state/store'
import { IocsView } from './IocsView'

const kase: Case = { id: 1, name: 'Lab', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
let db: RemnDB
beforeEach(() => {
  db = new RemnDB(`iocsview-${Math.random()}`)
  setDb(db)
  useStore.setState({ currentCase: kase, view: 'iocs', health: null, jobs: [] })
})
afterEach(async () => {
  cleanup()
  await db.delete()
})

describe('the Indicators page', () => {
  it('says which import stopped collecting indicators at the limit', async () => {
    await db.kv.put({ key: 'iocs-capped-1', value: { limit: 50_000, files: ['proxy-export.csv'] } })
    render(<IocsView />)
    expect(await screen.findByText('Indicator collection stopped at 50,000 distinct values in proxy-export.csv: indicators first seen later in that file are not listed.')).toBeTruthy()
  })

  it('says nothing of a limit when none was reached', async () => {
    await db.iocs.add({ caseId: 1, kind: 'domain', value: 'files.example.test', sources: ['mail-url'], firstSeen: 1, lastSeen: 1, count: 1 })
    render(<IocsView />)
    expect(await screen.findByText(/1 unique/)).toBeTruthy()
    expect(screen.queryByText(/Indicator collection stopped/)).toBeNull()
  })
})
