import { afterEach, expect, it } from 'vitest'
import { defaultSettings, getDb, type Evidence } from '../db/schema'
import { stopInterruptedImports, whileImporting, type Locks } from './interruptedImports'

/** The browser's lock manager, in memory: a name is held until its callback settles. */
function memoryLocks() {
  const held = new Set<string>()
  const locks = {
    held,
    request(name: string, a: unknown, b?: unknown) {
      const opts = (typeof a === 'function' ? {} : a) as LockOptions
      const cb = (typeof a === 'function' ? a : b) as (lock: Lock | null) => unknown
      if (held.has(name)) {
        if (opts.ifAvailable) return Promise.resolve(cb(null))
        return Promise.reject(new Error('the test never waits on a held lock'))
      }
      held.add(name)
      return Promise.resolve()
        .then(() => cb({ name, mode: 'exclusive' } as Lock))
        .finally(() => held.delete(name))
    },
  }
  return locks as unknown as Locks & { held: Set<string> }
}

afterEach(async () => {
  for (const table of getDb().tables) await table.clear()
})

async function importing(caseId: number, extra: Partial<Evidence> = {}) {
  const db = getDb()
  const id = await db.evidence.add({ caseId, name: 'Security.evtx', kind: 'evtx', size: 1, status: 'parsing', integrity: 'pending', count: 0, addedAt: 1_000, ...extra })
  await db.events.bulkAdd([1, 2, 3].map((i) => ({ caseId, evidenceId: id, ts: i, eventId: 4625 })))
  return id
}

async function aCase(storage: 'browser' | 'server' = 'browser') {
  return getDb().cases.add({ name: 'c', createdAt: 1, updatedAt: 1, settings: defaultSettings(), storage })
}

it('stops an import no tab is running: its partial rows go and the evidence says why', async () => {
  const caseId = await aCase()
  const kept = await getDb().evidence.add({ caseId, name: 'done.evtx', kind: 'evtx', size: 1, status: 'done', integrity: 'verified', count: 1, addedAt: 1 })
  await getDb().events.add({ caseId, evidenceId: kept, ts: 9, eventId: 4624 })
  const id = await importing(caseId, { importLock: 'remn-import-gone' })
  const stopped = await stopInterruptedImports(memoryLocks())
  expect(stopped.map((s) => [s.evidenceId, s.rows])).toEqual([[id, 3]])
  const ev = await getDb().evidence.get(id)
  expect(ev).toMatchObject({ status: 'error', count: 0 })
  expect(ev?.error).toMatch(/stopped before it finished.*3 row\(s\).*removed.*Add the file again/)
  // only its own rows: the finished evidence keeps everything
  expect((await getDb().events.toArray()).map((e) => e.evidenceId)).toEqual([kept])
})

it('leaves alone an import another tab is running, a server-store import, and everything without locks', async () => {
  const locks = memoryLocks()
  const caseId = await aCase()
  const live = await importing(caseId, { importLock: 'remn-import-live' })
  locks.held.add('remn-import-live')
  const server = await importing(await aCase('server'), { importLock: 'remn-import-server' })
  expect(await stopInterruptedImports(locks)).toEqual([])
  expect(await stopInterruptedImports(null)).toEqual([])
  for (const id of [live, server]) expect((await getDb().evidence.get(id))?.status).toBe('parsing')
  expect(await getDb().events.count()).toBe(6)
})

it('an import from before the locks is stopped only once it is hours old', async () => {
  const caseId = await aCase()
  const id = await importing(caseId)
  expect(await stopInterruptedImports(memoryLocks(), 1_000 + 60_000)).toEqual([])
  expect((await stopInterruptedImports(memoryLocks(), 1_000 + 7 * 3600_000)).map((s) => s.evidenceId)).toEqual([id])
})

it('holds the lock for exactly as long as the import runs', async () => {
  const locks = memoryLocks()
  let during: string | undefined
  const out = await whileImporting(async (lock) => {
    during = lock
    expect(locks.held.has(lock!)).toBe(true)
    return 7
  }, locks)
  expect(out).toBe(7)
  expect(during).toMatch(/^remn-import-/)
  expect(locks.held.size).toBe(0)
  // without locks the import still runs, with no name to store
  expect(await whileImporting(async (lock) => lock ?? 'none', null)).toBe('none')
})
