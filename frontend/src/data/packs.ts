import yaml from 'js-yaml'
import { apiGet, type PackInfo, type PackRules } from '../api/client'
import { getDb } from '../db/schema'

/**
 * Community rule packs (rules/community/<id>, SigmaHQ + Sublime). The manifests travel with
 * /api/meta; the rules themselves are fetched once per session when a pack is enabled.
 */

const inflight = new Map<string, Promise<PackRules>>()

export function getPackRules(id: string): Promise<PackRules> {
  let p = inflight.get(id)
  if (!p) {
    p = apiGet<PackRules>(`/api/rules/packs/${encodeURIComponent(id)}`).catch((e) => {
      inflight.delete(id)
      throw e
    })
    inflight.set(id, p)
  }
  return p
}

/** Per-analyst overrides of the manifests' defaultEnabled, kept in the kv table. */
export async function packOverrides(): Promise<Record<string, boolean>> {
  try {
    return ((await getDb().kv.get('packOverrides'))?.value as Record<string, boolean>) ?? {}
  } catch {
    return {}
  }
}

export async function enabledPackIds(packs: PackInfo[]): Promise<Set<string>> {
  const ov = await packOverrides()
  return new Set(packs.filter((p) => ov[p.id] ?? p.defaultEnabled).map((p) => p.id))
}

export async function setPackEnabled(id: string, on: boolean): Promise<void> {
  const ov = await packOverrides()
  ov[id] = on
  await getDb().kv.put({ key: 'packOverrides', value: ov })
}

/** YAML for a pack rule (the server does not ship the text; the rule object is authoritative). */
export function ruleYaml(rule: Record<string, unknown>): string {
  return yaml.dump(rule, { noRefs: true, lineWidth: 120, sortKeys: false })
}

export function shortSha(sha?: string): string {
  return sha && sha !== 'unknown' ? sha.slice(0, 10) : ''
}
