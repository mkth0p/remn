/// <reference lib="webworker" />
import type { Finding, RowMark } from '../db/schema'
import { buildStories, type StoryOptions } from '../data/relationshipStories'
import { reviewedRelationships, type RelationshipReview } from '../data/relationshipReviews'
import type { RelationshipResult } from '../data/relationships'

/**
 * Stories off the main thread. The graph is sent once per build of it and kept here; every
 * later request (rules ran, a mark or a review changed, the window moved) carries only the
 * findings, marks and reviews, so a 100,000-node graph is not cloned on each keystroke.
 */

type In =
  | { type: 'graph'; graphId: number; result: RelationshipResult }
  | { type: 'build'; jobId: number; graphId: number; findings: Finding[]; marks: RowMark[]; reviews: Record<string, RelationshipReview>; options: StoryOptions }

let held: { graphId: number; result: RelationshipResult } | null = null

self.onmessage = (e: MessageEvent<In>) => {
  const msg = e.data
  if (msg.type === 'graph') {
    held = { graphId: msg.graphId, result: msg.result }
    return
  }
  if (!held || held.graphId !== msg.graphId) {
    self.postMessage({ type: 'error', jobId: msg.jobId, message: 'graph not loaded' })
    return
  }
  try {
    const stories = buildStories(reviewedRelationships(held.result, msg.reviews), msg.findings, msg.marks, msg.options)
    self.postMessage({ type: 'stories', jobId: msg.jobId, stories })
  } catch (err) {
    self.postMessage({ type: 'error', jobId: msg.jobId, message: (err as Error).message })
  }
}
