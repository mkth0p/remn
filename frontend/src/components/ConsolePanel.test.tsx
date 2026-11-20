// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { useStore, type IngestJob } from '../state/store'
import { cancelImport } from '../data/ingest'
import { Jobs, Toasts } from './ConsolePanel'

vi.mock('../data/ingest', () => ({ cancelImport: vi.fn() }))

const job = (id: number, phase: IngestJob['phase'], extra: Partial<IngestJob> = {}): IngestJob => ({
  id,
  evidenceId: id,
  name: `file-${id}.evtx`,
  kind: 'evtx',
  phase,
  progress: 0.5,
  rows: 0,
  bytes: 0,
  startedAt: 0,
  ...extra,
})

afterEach(() => {
  cleanup()
  useStore.setState({ jobs: [], toasts: [] })
})

describe('the jobs panel', () => {
  it('offers to cancel a running import, and only a running one', () => {
    useStore.setState({ jobs: [job(1, 'uploading'), job(2, 'done')] })
    render(<Jobs />)
    const buttons = screen.getAllByRole('button', { name: 'cancel' })
    expect(buttons).toHaveLength(1)
    fireEvent.click(buttons[0])
    expect(cancelImport).toHaveBeenCalledWith(1)
  })

  it('shows a cancel in progress and does not offer it twice', () => {
    useStore.setState({ jobs: [job(3, 'parsing', { cancelling: true })] })
    render(<Jobs />)
    expect((screen.getByRole('button', { name: 'cancelling…' }) as HTMLButtonElement).disabled).toBe(true)
  })
})

describe('the messages', () => {
  it('are read out as they come: in a live region, an error at once', () => {
    render(<Toasts />)
    const region = screen.getByRole('log', { name: 'Messages' })
    expect(region.getAttribute('aria-live')).toBe('polite')
    act(() => {
      useStore.getState().toast('ok', '3 finding(s) from 2 rule(s)')
      useStore.getState().toast('err', 'rule engine error: out of memory', 0)
    })
    expect(within(region).getByText('3 finding(s) from 2 rule(s)')).toBeTruthy()
    expect(screen.getByRole('alert').textContent).toContain('rule engine error: out of memory')
  })

  it('each have a dismiss button the keyboard reaches, so an error that stays can be closed', async () => {
    const user = userEvent.setup()
    render(<Toasts />)
    act(() => useStore.getState().toast('err', 'migration failed', 0))
    await user.tab()
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'dismiss' }))
    await user.keyboard('{Enter}')
    expect(screen.queryByRole('alert')).toBeNull()
    expect(useStore.getState().toasts).toEqual([])
  })
})
