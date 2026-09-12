/**
 * API client. Every request carries the X-Forensic-Client header required by
 * the server (cookie-less CSRF protection). Works in the main thread and in
 * web workers.
 */
export const API_HEADERS: Record<string, string> = { 'X-Forensic-Client': 'remn' }

/** Set the shared access token for remote deployments (FORENSIC_AUTH_TOKEN on the server). Mutated in place so every module (and worker) sharing this instance picks it up. */
export function setApiToken(token: string | null): void {
  API_HEADERS['X-Forensic-Client'] = token?.trim() || 'remn'
}

let authErrorHandler: (() => void) | null = null
/** Called once per 401 with code "auth" - the app shows the token gate. */
export function onAuthError(fn: (() => void) | null): void {
  authErrorHandler = fn
}

export class ApiError extends Error {
  status: number
  body: unknown
  constructor(status: number, message: string, body?: unknown) {
    super(message)
    this.status = status
    this.body = body
  }
}

async function handle(resp: Response): Promise<unknown> {
  const ct = resp.headers.get('content-type') || ''
  const body = ct.includes('application/json') ? await resp.json().catch(() => null) : await resp.text().catch(() => '')
  if (!resp.ok) {
    const msg = (body && typeof body === 'object' && 'error' in body && String((body as { error: unknown }).error)) || `${resp.status} ${resp.statusText}`
    if (resp.status === 401 && body && typeof body === 'object' && (body as { code?: string }).code === 'auth') authErrorHandler?.()
    throw new ApiError(resp.status, msg, body)
  }
  return body
}

export async function apiGet<T = unknown>(path: string, signal?: AbortSignal): Promise<T> {
  const resp = await fetch(path, { headers: API_HEADERS, signal })
  return (await handle(resp)) as T
}

export async function apiPost<T = unknown>(path: string, body: unknown, signal?: AbortSignal): Promise<T> {
  const resp = await fetch(path, {
    method: 'POST',
    headers: { ...API_HEADERS, 'Content-Type': 'application/json' },
    body: JSON.stringify(body ?? {}),
    signal,
  })
  return (await handle(resp)) as T
}

export async function apiPostForm<T = unknown>(path: string, form: FormData, signal?: AbortSignal): Promise<T> {
  const resp = await fetch(path, { method: 'POST', headers: API_HEADERS, body: form, signal })
  return (await handle(resp)) as T
}

/** Read an NDJSON body line by line (shared by evidence ingestion and the browser Ollama transport). */
export async function readNdjsonBody(resp: Response, onRow: (row: Record<string, unknown>) => void | Promise<void>, onBytes?: (n: number) => void): Promise<void> {
  if (!resp.body) throw new ApiError(500, 'no response body')
  const reader = resp.body.getReader()
  const decoder = new TextDecoder('utf-8')
  let buffer = ''
  let received = 0
  for (;;) {
    const { value, done } = await reader.read()
    if (done) break
    received += value.byteLength
    onBytes?.(received)
    buffer += decoder.decode(value, { stream: true })
    let idx: number
    while ((idx = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, idx).trim()
      buffer = buffer.slice(idx + 1)
      if (!line) continue
      let obj: Record<string, unknown>
      try {
        obj = JSON.parse(line)
      } catch {
        continue
      }
      await onRow(obj)
    }
  }
  buffer += decoder.decode()
  const rest = buffer.trim()
  if (rest) {
    try {
      await onRow(JSON.parse(rest))
    } catch {
      /* ignore trailing garbage */
    }
  }
}

/** Stream an NDJSON response line by line. */
export async function streamNdjson(
  path: string,
  form: FormData,
  onRow: (row: Record<string, unknown>) => void | Promise<void>,
  opts: { signal?: AbortSignal; onBytes?: (n: number) => void } = {},
): Promise<void> {
  const resp = await fetch(path, { method: 'POST', headers: API_HEADERS, body: form, signal: opts.signal })
  if (!resp.ok) {
    await handle(resp)
    return
  }
  await readNdjsonBody(resp, onRow, opts.onBytes)
}

/** Consume a Server-Sent-Events POST response. */
export async function streamSse(path: string, body: unknown, onEvent: (event: Record<string, unknown>) => void, signal?: AbortSignal): Promise<void> {
  const resp = await fetch(path, {
    method: 'POST',
    headers: { ...API_HEADERS, 'Content-Type': 'application/json', Accept: 'text/event-stream' },
    body: JSON.stringify(body ?? {}),
    signal,
  })
  if (!resp.ok) {
    await handle(resp)
    return
  }
  if (!resp.body) throw new ApiError(500, 'no response body')
  const reader = resp.body.getReader()
  const decoder = new TextDecoder('utf-8')
  let buffer = ''
  for (;;) {
    const { value, done } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    let idx: number
    while ((idx = buffer.indexOf('\n\n')) >= 0) {
      const chunk = buffer.slice(0, idx)
      buffer = buffer.slice(idx + 2)
      const data = chunk
        .split('\n')
        .filter((l) => l.startsWith('data:'))
        .map((l) => l.slice(5).trim())
        .join('\n')
      if (!data) continue
      try {
        onEvent(JSON.parse(data))
      } catch {
        /* ignore malformed chunk */
      }
    }
  }
}

// ---- typed helpers -------------------------------------------------------
export interface Health {
  ok: boolean
  name: string
  version: string
  stateless: boolean
  /** browser-only: the server parses and returns rows and keeps nothing; no server store, lookups or server-side models */
  mode?: 'full' | 'browser-only'
  python?: string
  platform?: string
  limits: { maxUploadMb: number; inMemoryMb: number; maxChunkedGb?: number; chunkMb?: number }
  store?: { thresholdMb: number; casesDir: string }
  ollama: {
    reachable: boolean
    host: string
    models: { name: string; size?: number; family?: string; parameterSize?: string }[]
    defaultModel: string
    defaultAvailable?: boolean
    capabilities?: string[]
    error?: string
    numCtx?: number
  }
  optional: { pst: boolean; yara: boolean; yaraRules: number; claudeCode?: boolean; hayabusa?: boolean }
  providers: ProviderInfo[]
}
export interface ProviderInfo {
  name: string
  kinds: string[]
  configured: boolean
  needsKey: string | null
  description: string
  homepage: string
  files?: number
}
export interface Meta {
  events: { provider: string; eventId: number; description: string; category: string }[]
  notes: Record<string, string>
  logonTypes: Record<string, string>
  statusCodes: Record<string, string>
  kerberosFailures: Record<string, string>
  ticketEncryption: Record<string, string>
  flags: Record<string, string>
  mailWeights?: Record<string, number>
  mailStrongFlags?: string[]
  dangerousExtensions: Record<string, string>
  rules: { file: string; yaml: string; rule?: Record<string, unknown>; error?: string }[]
  packs?: PackInfo[]
}
/** Manifest of a community rule pack (rules/community/<id>/pack.json). */
export interface PackInfo {
  id: string
  name: string
  description: string
  source: 'events' | 'mails'
  defaultEnabled: boolean
  license: { name: string; spdx?: string; url?: string; file?: string }
  upstream: { repo: string; ref: string; sha: string; url: string; paths?: string[]; fetched: string }
  counts: { upstream: number; converted: number; skipped: number; warnings?: number }
  skipReasons?: [string, number][]
  files?: Record<string, number>
  hash?: string
  licenseText?: boolean
}
export interface PackRules {
  pack: PackInfo
  rules: { file: string; rule?: Record<string, unknown>; error?: string; yaml?: string }[]
}
export const getHealth = () => apiGet<Health>('/api/health')
export const getMeta = () => apiGet<Meta>('/api/meta')
export interface Verdict {
  provider: string
  kind: string
  value: string
  verdict: string
  score: number | null
  tags: string[]
  details: Record<string, unknown>
  link: string | null
  cached: boolean
}
export interface LookupResponse {
  results: Verdict[]
  summary: Record<
    string,
    {
      kind: string
      value: string
      verdict: string
      providers: string[]
      malicious: number
      suspicious: number
      clean: number
      tags: string[]
      geo: { country?: string; city?: string; org?: string } | null
      asn: string | null
    }
  >
}
export const lookupReputation = (items: { kind: string; value: string }[], providers?: string[]) =>
  apiPost<LookupResponse>('/api/reputation/lookup', { items, providers: providers && providers.length ? providers : undefined })
export const aiQuery = (question: string, context: Record<string, unknown>, model?: string) =>
  apiPost<{ query: Record<string, unknown> | null; raw: string; model: string }>('/api/ai/query', { question, context, model })
