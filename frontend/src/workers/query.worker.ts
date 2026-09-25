/// <reference lib="webworker" />
/**
 * Read queries over a browser-store case, off the page's thread. Search, count, aggregate,
 * timeline and pivot walk IndexedDB and test every row against the filter; on the page's thread
 * that froze the whole app for seconds on a large case, and a query nobody wanted any more (the
 * filter changed, the view closed) ran to its end regardless. Here a query runs in a worker the
 * page ends when the answer is no longer wanted (data/queryClient.ts).
 */
import { QUERY_OPS, type QueryOp } from '../data/queryOps'

export interface QueryRequest {
  id: number
  op: QueryOp
  args: unknown[]
}

const ctx = self as unknown as DedicatedWorkerGlobalScope

ctx.onmessage = async (ev: MessageEvent<QueryRequest>) => {
  const { id, op, args } = ev.data
  try {
    const run = QUERY_OPS[op] as (...a: unknown[]) => Promise<unknown>
    ctx.postMessage({ id, result: await run(...args) })
  } catch (e) {
    ctx.postMessage({ id, error: (e as Error)?.message || String(e) })
  }
}
