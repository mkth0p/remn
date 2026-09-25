import { QUERY_OPS, type QueryOp } from './queryOps'

/**
 * Runs the read queries of a browser-store case in workers (workers/query.worker.ts), a few at a
 * time, so the page stays responsive while they scan. A query whose signal aborts is stopped
 * where it stands: its worker is ended, which ends the scan, and a fresh one takes its place for
 * the next query. Where workers do not exist (the unit tests) the query runs in place.
 */
const MAX_WORKERS = 3

type Run<O extends QueryOp> = Awaited<ReturnType<(typeof QUERY_OPS)[O]>>

interface Job {
  start: () => void
}

const idle: Worker[] = []
let running = 0
const waiting: Job[] = []
let seq = 0

export function abortError(): Error {
  try {
    return new DOMException('the query was cancelled', 'AbortError')
  } catch {
    const e = new Error('the query was cancelled')
    e.name = 'AbortError'
    return e
  }
}

export function isAbort(e: unknown): boolean {
  return (e as { name?: string } | null)?.name === 'AbortError'
}

function spawn(): Worker {
  return new Worker(new URL('../workers/query.worker.ts', import.meta.url), { type: 'module' })
}

function next(): void {
  running--
  const job = waiting.shift()
  if (job) job.start()
}

export function runQuery<O extends QueryOp>(op: O, args: Parameters<(typeof QUERY_OPS)[O]>, signal?: AbortSignal): Promise<Run<O>> {
  if (signal?.aborted) return Promise.reject(abortError())
  if (typeof Worker === 'undefined') return (QUERY_OPS[op] as (...a: unknown[]) => Promise<Run<O>>)(...args)
  return new Promise<Run<O>>((resolve, reject) => {
    let settled = false
    const job: Job = {
      start: () => {
        running++
        if (signal?.aborted) {
          settled = true
          next()
          return reject(abortError())
        }
        const id = ++seq
        const worker = idle.pop() ?? spawn()
        const finish = (keep: boolean) => {
          settled = true
          signal?.removeEventListener('abort', onAbort)
          worker.onmessage = null
          worker.onerror = null
          if (keep) idle.push(worker)
          else worker.terminate()
          next()
        }
        const onAbort = () => {
          if (settled) return
          finish(false) // ends the scan; the worker is not reused
          reject(abortError())
        }
        signal?.addEventListener('abort', onAbort, { once: true })
        worker.onmessage = (ev: MessageEvent<{ id: number; result?: Run<O>; error?: string }>) => {
          if (ev.data.id !== id || settled) return
          finish(true)
          if (ev.data.error !== undefined) reject(new Error(ev.data.error))
          else resolve(ev.data.result as Run<O>)
        }
        worker.onerror = (ev) => {
          if (settled) return
          finish(false)
          reject(new Error(ev.message || 'the query worker failed'))
        }
        worker.postMessage({ id, op, args })
      },
    }
    if (running < MAX_WORKERS) job.start()
    else {
      waiting.push(job)
      // a query still waiting for a worker is dropped from the line when it is no longer wanted
      signal?.addEventListener(
        'abort',
        () => {
          const i = waiting.indexOf(job)
          if (i >= 0 && !settled) {
            waiting.splice(i, 1)
            settled = true
            reject(abortError())
          }
        },
        { once: true },
      )
    }
  })
}
