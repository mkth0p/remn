import type { Finding, RowMark } from '../db/schema'
import { buildStories, type StoryOptions, type StoryResult } from './relationshipStories'
import { reviewedRelationships, type RelationshipReview } from './relationshipReviews'
import type { RelationshipResult } from './relationships'

/**
 * Builds stories in a worker so a large graph does not freeze the tab, sending the graph over
 * once per graph object and only the small inputs afterwards. Without Worker support (tests,
 * old runtimes) it builds on the calling thread. A request superseded by a newer one resolves
 * with the newer result's arrival; callers compare job ids through the returned promise only.
 */
export class StoriesClient {
  private worker: Worker | null = null
  private graphId = 0
  private sent: RelationshipResult | null = null
  private jobId = 0
  private pending = new Map<number, { resolve: (r: StoryResult) => void; reject: (e: Error) => void }>()

  private ensure(): Worker | null {
    if (typeof Worker === 'undefined') return null
    if (!this.worker) {
      this.worker = new Worker(new URL('../workers/stories.worker.ts', import.meta.url), { type: 'module' })
      this.worker.onmessage = (e: MessageEvent<{ type: 'stories' | 'error'; jobId: number; stories?: StoryResult; message?: string }>) => {
        const job = this.pending.get(e.data.jobId)
        if (!job) return
        this.pending.delete(e.data.jobId)
        if (e.data.type === 'stories' && e.data.stories) job.resolve(e.data.stories)
        else job.reject(new Error(e.data.message ?? 'story build failed'))
      }
      this.worker.onerror = (e) => {
        for (const job of this.pending.values()) job.reject(new Error(e.message || 'story worker failed'))
        this.pending.clear()
        this.worker?.terminate()
        this.worker = null
        this.sent = null
      }
    }
    return this.worker
  }

  build(result: RelationshipResult, findings: Finding[], marks: RowMark[], reviews: Record<string, RelationshipReview>, options: StoryOptions): Promise<StoryResult> {
    const worker = this.ensure()
    if (!worker) return Promise.resolve(buildStories(reviewedRelationships(result, reviews), findings, marks, options))
    if (this.sent !== result) {
      this.graphId++
      this.sent = result
      worker.postMessage({ type: 'graph', graphId: this.graphId, result })
    }
    const jobId = ++this.jobId
    return new Promise((resolve, reject) => {
      this.pending.set(jobId, { resolve, reject })
      worker.postMessage({ type: 'build', jobId, graphId: this.graphId, findings, marks, reviews, options })
    })
  }

  dispose(): void {
    this.worker?.terminate()
    this.worker = null
    this.sent = null
    for (const job of this.pending.values()) job.reject(new Error('disposed'))
    this.pending.clear()
  }
}
