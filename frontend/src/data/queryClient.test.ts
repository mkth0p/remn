import { afterEach, beforeEach, expect, it, vi } from 'vitest'

/** A worker that answers only when the test says so, so a query can be caught while it runs. */
class FakeWorker {
  static all: FakeWorker[] = []
  terminated = false
  onmessage: ((ev: { data: unknown }) => void) | null = null
  onerror: ((ev: { message: string }) => void) | null = null
  inbox: { id: number; op: string; args: unknown[] }[] = []
  constructor() {
    FakeWorker.all.push(this)
  }
  postMessage(m: { id: number; op: string; args: unknown[] }) {
    this.inbox.push(m)
  }
  terminate() {
    this.terminated = true
  }
  answer(result: unknown) {
    const m = this.inbox.shift()!
    this.onmessage?.({ data: { id: m.id, result } })
  }
}

async function client() {
  vi.resetModules()
  return import('./queryClient')
}
const tick = () => new Promise((r) => setTimeout(r, 0))

beforeEach(() => {
  FakeWorker.all = []
  vi.stubGlobal('Worker', FakeWorker)
})
afterEach(() => vi.unstubAllGlobals())

it('runs a query in a worker and keeps the worker for the next one', async () => {
  const { runQuery } = await client()
  const first = runQuery('countEvents', [1, {}])
  expect(FakeWorker.all).toHaveLength(1)
  expect(FakeWorker.all[0].inbox[0]).toMatchObject({ op: 'countEvents', args: [1, {}] })
  FakeWorker.all[0].answer(42)
  expect(await first).toBe(42)
  const second = runQuery('countMails', [1, {}])
  expect(FakeWorker.all).toHaveLength(1)
  FakeWorker.all[0].answer(7)
  expect(await second).toBe(7)
})

it('a query no longer wanted is stopped where it stands, and the next gets a fresh worker', async () => {
  const { runQuery, isAbort } = await client()
  const ac = new AbortController()
  const stale = runQuery('searchEvents', [1, {}, { limit: 10 }], ac.signal)
  ac.abort()
  await expect(stale).rejects.toSatisfy(isAbort)
  expect(FakeWorker.all[0].terminated).toBe(true)
  const fresh = runQuery('countEvents', [1, {}])
  expect(FakeWorker.all).toHaveLength(2)
  FakeWorker.all[1].answer(3)
  expect(await fresh).toBe(3)
  // a signal already aborted never starts anything
  await expect(runQuery('countEvents', [1, {}], AbortSignal.abort())).rejects.toSatisfy(isAbort)
  expect(FakeWorker.all).toHaveLength(2)
})

it('runs three at a time; a waiting query starts when one ends, or leaves the line when dropped', async () => {
  const { runQuery, isAbort } = await client()
  const running = [0, 1, 2].map((i) => runQuery('countEvents', [i, {}]))
  const dropped = new AbortController()
  const waitingDropped = runQuery('countEvents', [3, {}], dropped.signal)
  const waiting = runQuery('countEvents', [4, {}])
  expect(FakeWorker.all).toHaveLength(3)
  dropped.abort()
  await expect(waitingDropped).rejects.toSatisfy(isAbort)
  FakeWorker.all[0].answer(0)
  await tick()
  // the freed worker takes the next query still wanted, not the dropped one
  expect(FakeWorker.all).toHaveLength(3)
  expect(FakeWorker.all[0].inbox[0]).toMatchObject({ args: [4, {}] })
  FakeWorker.all[0].answer(4)
  FakeWorker.all[1].answer(1)
  FakeWorker.all[2].answer(2)
  expect(await Promise.all([...running, waiting])).toEqual([0, 1, 2, 4])
})

it('without workers the query runs in place', async () => {
  vi.unstubAllGlobals()
  vi.stubGlobal('Worker', undefined)
  const { runQuery } = await client()
  expect(await runQuery('countEvents', [987654, {}])).toBe(0)
})
