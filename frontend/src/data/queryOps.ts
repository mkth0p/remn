import * as q from './queries'
import { compileRegex } from '../rules/filter'

/**
 * A regular expression the model wrote, tried on a sample string. It runs here, in a query worker,
 * because a pattern with catastrophic backtracking would otherwise freeze the page; the caller's
 * timeout ends the worker.
 */
async function regexSample(pattern: string, flags: string, sample: string): Promise<{ matches: string[]; count: number } | { error: string }> {
  const re = compileRegex(pattern, flags)
  if (!re) return { error: 'invalid regular expression' }
  const m = sample.match(new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g'))
  return { matches: m ? m.slice(0, 50) : [], count: m ? m.length : 0 }
}

/** The read queries a query worker runs, by name (workers/query.worker.ts, data/queryClient.ts). */
export const QUERY_OPS = {
  searchEvents: q.searchEvents,
  countEvents: q.countEvents,
  aggregateEvents: q.aggregateEvents,
  stackEvents: q.stackEvents,
  timelineEvents: q.timelineEvents,
  searchMails: q.searchMails,
  countMails: q.countMails,
  aggregateMails: q.aggregateMails,
  timelineMails: q.timelineMails,
  pivot: q.pivot,
  caseSummary: q.caseSummary,
  regexSample,
}

export type QueryOp = keyof typeof QUERY_OPS
