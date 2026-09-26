import { readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { beforeAll, describe, expect, it } from 'vitest'
import { RemnDB, setDb, type EventRow } from '../db/schema'
import type { Filter, SettingsLike } from '../rules/filter'
import { stackEvents, type Stack } from './queries'

/**
 * Stacking parity: the browser store must stack the fixture's events exactly as the server store
 * did. The fixture (rows + the DuckDB stacks) is written by tools/parity_fixture.py.
 */
const FIX = resolve(__dirname, '../../../tests/fixtures/parity')

describe('stacking parity with the server store', () => {
  const events = JSON.parse(readFileSync(join(FIX, 'events.json'), 'utf-8')) as EventRow[]
  const fixture = JSON.parse(readFileSync(join(FIX, 'stacks.json'), 'utf-8')) as {
    settings: SettingsLike
    stacks: { field: string; filter: Filter | null; order: 'rare' | 'common'; stack: Stack }[]
  }

  beforeAll(async () => {
    const db = new RemnDB('test-stack-parity')
    setDb(db)
    await db.events.bulkAdd(events.map((r) => ({ ...r, caseId: 1, evidenceId: 1 })))
  })

  it('records a stack for several fields', () => {
    expect(fixture.stacks.length).toBeGreaterThan(5)
    expect(fixture.stacks.some((s) => s.stack.hosts > 1)).toBe(true)
  })

  for (const s of fixture.stacks) {
    it(`stacks ${s.field} (${s.order}${s.filter ? ', filtered' : ''}) as DuckDB does`, async () => {
      const got = await stackEvents(1, s.filter ?? {}, s.field, s.order, 500, fixture.settings)
      expect(got).toEqual(s.stack)
    })
  }
})
