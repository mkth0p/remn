/**
 * "Suggest trusted senders": scan the case for sender domains that look like
 * legitimate notification traffic (several mails, passing auth, no strong
 * indicator) so the analyst can whitelist them in one click.
 */
import type { Case } from '../db/schema'
import { getSource } from './source'

export interface TrustedSuggestion {
  registrable: string
  count: number
  sample: string
}

const MIN_MAILS = 5
const SCAN_LIMIT = 5000

export async function suggestTrustedSenders(kase: Case, strongFlags: string[]): Promise<TrustedSuggestion[]> {
  const ds = getSource(kase)
  const res = await ds.searchMails({ conditions: [{ field: 'risk', op: 'lte', value: 45 }] }, SCAN_LIMIT)
  const strong = new Set(strongFlags)
  const already = new Set((kase.settings.trustedSenders ?? []).map((x) => x.toLowerCase().replace(/^@/, '')))
  const internal = (kase.settings.internalDomains ?? []).map((d) => d.toLowerCase().replace(/^@/, ''))
  const groups = new Map<string, { count: number; sample: string }>()
  for (const r of res.rows as Record<string, unknown>[]) {
    const reg = String(r.fromRegistrable ?? '').toLowerCase()
    if (!reg || already.has(reg)) continue
    if (internal.some((d) => reg === d || reg.endsWith('.' + d))) continue
    const auth = (r.auth ?? {}) as Record<string, unknown>
    const spf = r.spf ?? auth.spf
    const dkim = r.dkim ?? auth.dkim
    if (spf !== 'pass' && dkim !== 'pass') continue
    const flags = Array.isArray(r.flags) ? (r.flags as string[]) : []
    if (flags.some((f) => strong.has(f))) continue
    const g = groups.get(reg) ?? { count: 0, sample: String(r.fromAddr ?? '') }
    g.count++
    groups.set(reg, g)
  }
  return [...groups.entries()]
    .filter(([, g]) => g.count >= MIN_MAILS)
    .map(([registrable, g]) => ({ registrable, count: g.count, sample: g.sample }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 40)
}
