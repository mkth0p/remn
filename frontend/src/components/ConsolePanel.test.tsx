// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { useStore, type IngestJob } from '../state/store'
import { cancelImport } from '../data/ingest'
import { Jobs } from './ConsolePanel'

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
  useStore.setState({ jobs: [] })
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
