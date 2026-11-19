import { apiGet, API_HEADERS } from '../api/client'

export interface JobInfo {
  id: string
  kind: string
  label: string
  status: 'queued' | 'running' | 'done' | 'error' | 'cancelled'
  progress: Record<string, unknown>
  error: string | null
  result?: Record<string, unknown>
  log: string[]
}

/** Poll a server job until it finishes. The server answers about a job only to a request that presents the key of its case. */
export async function waitForJob(jobId: string, caseKey: string, onProgress?: (job: JobInfo) => void, signal?: AbortSignal, intervalMs = 700): Promise<JobInfo> {
  const path = `/api/jobs/${jobId}?case=${encodeURIComponent(caseKey)}`
  for (;;) {
    if (signal?.aborted) {
      await fetch(path, { method: 'DELETE', headers: API_HEADERS }).catch(() => undefined)
      throw new Error('cancelled')
    }
    const job = await apiGet<JobInfo>(path)
    onProgress?.(job)
    if (job.status === 'done') return job
    if (job.status === 'error') throw new Error(job.error || 'job failed')
    if (job.status === 'cancelled') throw new Error('cancelled')
    await new Promise((r) => setTimeout(r, intervalMs))
  }
}
