import * as q from './queries'

/** The read queries a query worker runs, by name (workers/query.worker.ts, data/queryClient.ts). */
export const QUERY_OPS = {
  searchEvents: q.searchEvents,
  countEvents: q.countEvents,
  aggregateEvents: q.aggregateEvents,
  timelineEvents: q.timelineEvents,
  searchMails: q.searchMails,
  countMails: q.countMails,
  aggregateMails: q.aggregateMails,
  timelineMails: q.timelineMails,
  pivot: q.pivot,
  caseSummary: q.caseSummary,
}

export type QueryOp = keyof typeof QUERY_OPS
