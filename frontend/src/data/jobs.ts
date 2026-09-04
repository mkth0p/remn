import { apiGet, API_HEADERS } from '../api/client'

export interface JobInfo {
  id: string
  kind: string
  caseKey: string | null
  label: string
  status: 'queued' | 'running' | 'done' | 'error' | 'cancelled'
  progress: Record<string, unknown>
  error: string | null
  result?: Record<string, unknown>
  log: string[]
}

/** Poll a server job until it finishes. */
export async function waitForJob(jobId: string, onProgress?: (job: JobInfo) => void, signal?: AbortSignal, intervalMs = 700): Promise<JobInfo> {
  for (;;) {
    if (signal?.aborted) {
      await fetch(`/api/jobs/${jobId}`, { method: 'DELETE', headers: API_HEADERS }).catch(() => undefined)
      throw new Error('cancelled')
    }
    const job = await apiGet<JobInfo>(`/api/jobs/${jobId}`)
    onProgress?.(job)
    if (job.status === 'done') return job
    if (job.status === 'error') throw new Error(job.error || 'job failed')
    if (job.status === 'cancelled') throw new Error('cancelled')
    await new Promise((r) => setTimeout(r, intervalMs))
  }
}
