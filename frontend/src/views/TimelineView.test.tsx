// @vitest-environment jsdom
import { act, cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case } from '../db/schema'
import { useStore } from '../state/store'
import { TimelineView } from './TimelineView'

// the chart library draws on a canvas, which this test environment does not have
const drawn = vi.hoisted(() => ({ options: [] as unknown[] }))
vi.mock('echarts/core', () => ({
  use: () => undefined,
  init: () => ({ setOption: (o: unknown) => drawn.options.push(o), dispatchAction: () => undefined, on: () => undefined, off: () => undefined, resize: () => undefined, dispose: () => undefined }),
}))
vi.mock('echarts/charts', () => ({ BarChart: {}, ScatterChart: {} }))
vi.mock('echarts/components', () => ({
  BrushComponent: {},
  DataZoomComponent: {},
  GridComponent: {},
  LegendComponent: {},
  MarkLineComponent: {},
  ToolboxComponent: {},
  TooltipComponent: {},
}))
vi.mock('echarts/renderers', () => ({ CanvasRenderer: {} }))

// invented answers: the events histogram fails, the mails histogram has one bucket
const answers = vi.hoisted(() => ({ events: null as Error | null }))
vi.mock('../data/source', () => ({
  getSource: () => ({
    kind: 'browser',
    timelineEvents: async () => {
      if (answers.events) throw answers.events
      return [{ t: 0, count: 3 }]
    },
    timelineMails: async () => [{ t: 0, count: 2 }],
  }),
}))

const kase: Case = { id: 1, name: 'Lab', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
const settle = () => act(() => new Promise((r) => setTimeout(r, 50)))
let db: RemnDB

beforeEach(() => {
  db = new RemnDB(`timeline-view-${Math.random()}`)
  setDb(db)
  drawn.options = []
  answers.events = null
  useStore.setState({ currentCase: kase, jobs: [] })
})
afterEach(async () => {
  cleanup()
  await db.delete()
})

describe('the Timeline page', () => {
  it('says which histogram could not be read instead of drawing it as empty', async () => {
    answers.events = new Error('the query worker stopped')
    render(<TimelineView />)
    await settle()
    expect(screen.getByRole('alert').textContent).toContain('events could not be read: the query worker stopped')
    // what could be read is still drawn
    expect(drawn.options).toHaveLength(1)
    expect(screen.getByText(/2 mails/)).toBeTruthy()
  })

  it('shows no error when every query answered', async () => {
    render(<TimelineView />)
    await settle()
    expect(screen.queryByRole('alert')).toBeNull()
    expect(screen.getByText(/3 events/)).toBeTruthy()
  })
})
