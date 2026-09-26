import { describe, expect, it } from 'vitest'
import type { EventRow } from '../db/schema'
import type { Filter } from '../rules/filter'
import { timelineRows } from './timelineRows'

// a store that answers like the real ones: sorted by time, from the range's start, at most `limit` rows
const store = (all: EventRow[]) => ({
  calls: 0,
  async searchEvents(filter: Filter, limit: number) {
    this.calls++
    const from = filter.timeRange?.from == null ? -Infinity : Number(filter.timeRange.from)
    const hit = all.filter((r) => typeof r.ts === 'number' && r.ts >= from && r.eventId === 4625).sort((a, b) => a.ts! - b.ts!)
    return { rows: hit.slice(0, limit), truncated: hit.length > limit }
  },
})

const ev = (id: number, ts: number | null, eventId = 4625) => ({ id, ts, eventId }) as unknown as EventRow
const filter: Filter = { conditions: [{ field: 'eventId', op: 'eq', value: 4625 }] }

describe('timelineRows', () => {
  it('pages through every match in time order, well past one page', async () => {
    const all = Array.from({ length: 95 }, (_, i) => ev(i + 1, 1000 + Math.floor(i / 3)))
    all.push(ev(500, null), ev(501, 5000, 4624))
    const ds = store(all)
    const { rows, cut } = await timelineRows(ds, filter, { page: 10 })
    expect(cut).toBeNull()
    expect(rows.map((r) => r.id)).toEqual(Array.from({ length: 95 }, (_, i) => i + 1))
    expect(ds.calls).toBeGreaterThan(9)
  })

  it('says where it stopped when the export reaches its ceiling', async () => {
    const all = Array.from({ length: 30 }, (_, i) => ev(i + 1, 1000 + i))
    const { rows, cut } = await timelineRows(store(all), filter, { page: 10, max: 25 })
    expect(rows).toHaveLength(25)
    expect(cut).toMatch(/stopped at 25 rows/)
  })

  it('stops, and says so, when more rows share one instant than a page holds', async () => {
    const all = Array.from({ length: 30 }, (_, i) => ev(i + 1, 1000))
    const { rows, cut } = await timelineRows(store(all), filter, { page: 10 })
    expect(rows).toHaveLength(10)
    expect(cut).toMatch(/share the time/)
  })
})
