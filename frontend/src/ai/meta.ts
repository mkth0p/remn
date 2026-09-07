/**
 * AI meta (system prompts, tool schemas, defaults) fetched once from the
 * backend, plus the TypeScript mirror of prompts.compose_system(). Parity with
 * the Python implementation is locked by tests/fixtures/ai_system_compose.json.
 */
import { apiGet } from '../api/client'

export interface AiMeta {
  prompts: Record<'analyst' | 'query' | 'explain' | 'rule' | 'report' | 'triage' | 'free', string>
  tools: Record<string, unknown>[]
  querySchema: Record<string, unknown>
  schemaDoc: string
  numCtx: number
  defaultModel: string
  limits: { maxMessages: number; maxMessageChars: number }
  version: string
}

let cached: Promise<AiMeta> | null = null

export function fetchAiMeta(): Promise<AiMeta> {
  if (!cached) {
    cached = apiGet<AiMeta>('/api/ai/meta').catch((e) => {
      cached = null // allow retry after a failure
      throw e
    })
  }
  return cached
}

export function resetAiMetaCache(): void {
  cached = null
}

/**
 * Serialize exactly like Python's json.dumps(obj, ensure_ascii=False):
 * ", " between items and ": " after keys. Needed so the browser-composed
 * system message is byte-identical to the server-composed one.
 */
export function pyJson(value: unknown): string {
  if (value === null || value === undefined) return 'null'
  if (typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : 'NaN'
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (Array.isArray(value)) return '[' + value.map(pyJson).join(', ') + ']'
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).filter(([, v]) => v !== undefined)
    return '{' + entries.map(([k, v]) => JSON.stringify(k) + ': ' + pyJson(v)).join(', ') + '}'
  }
  return 'null'
}

/** TS mirror of backend/services/ai/prompts.py compose_system(). */
export function composeSystem(mode: string, context: Record<string, unknown>, meta: AiMeta): string {
  const prompts = meta.prompts as Record<string, string>
  const system = mode in prompts && mode !== 'query' ? prompts[mode] : mode === 'free' ? '' : prompts.analyst
  const ctx = context || {}
  const extra: string[] = []
  if (ctx.caseSettings) extra.push('Case settings: ' + pyJson(ctx.caseSettings).slice(0, 3000))
  if (ctx.now) extra.push(`Current time (UTC): ${ctx.now}`)
  if (ctx.networkAllowed !== undefined && ctx.networkAllowed !== null) {
    extra.push('External reputation lookups are ' + (ctx.networkAllowed ? 'ENABLED' : 'DISABLED (lookup_ioc will return a notice)'))
  }
  if (ctx.storage === 'server') {
    extra.push('This case is stored server-side in DuckDB: the `sql` tool is available and preferred for aggregations, joins and window functions.\n' + meta.schemaDoc)
  } else {
    extra.push('This case is stored in the browser: the `sql` tool is NOT available; use the search/aggregate tools.')
  }
  return (system + '\n\n' + extra.join('\n')).trim()
}
