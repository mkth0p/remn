import { beforeEach, describe, expect, it, vi } from 'vitest'
import { useStore } from '../state/store'
import type { Case } from '../db/schema'

vi.mock('./upload', () => ({ chunkedUpload: vi.fn() }))

const kase = { id: 1, name: 'c', createdAt: 0, updatedAt: 0, storage: 'browser', settings: {} } as unknown as Case
const file = (name: string, mb: number) => ({ name, size: mb * 1024 * 1024, webkitRelativePath: '' }) as unknown as File

describe('requestIngest', () => {
  beforeEach(() => {
    useStore.setState({ pendingIngest: null, dataNotice: 'unknown', toasts: [] } as never)
  })

  it('refuses a file over the public server limit before hashing it', async () => {
    const { requestIngest } = await import('./ingest')
    useStore.setState({ health: { mode: 'browser-only', limits: { maxUploadMb: 512 } } } as never)
    requestIngest([file('huge.pst', 700)], kase)
    expect(useStore.getState().pendingIngest).toBeNull()
    expect(JSON.stringify(useStore.getState())).toContain('above this server')
  })

  it('shows where the evidence goes before the first upload to a remote parser', async () => {
    const { requestIngest } = await import('./ingest')
    useStore.setState({ health: { mode: 'browser-only', limits: { maxUploadMb: 512 } }, dataNotice: 'required' } as never)
    requestIngest([file('a.evtx', 1)], kase)
    expect(useStore.getState().pendingIngest?.reason).toBe('notice')
  })
})
