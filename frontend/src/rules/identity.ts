/**
 * One person, one key, for grouping findings into incidents. The same account appears as
 * `daniel.roy` (a Windows event), `NORTHSTAR\daniel.roy` and `daniel.roy@northstar.example`
 * (Microsoft 365); grouped by the raw string, one person was three incidents.
 *
 * The resolution is conservative, because a wrong merge is worse than a split:
 * - `DOMAIN\user` and `user@domain` resolve to user@realm. A NetBIOS domain is the DNS domain
 *   whose first label it is, when that domain is internal or appears in the case
 *   (NORTHSTAR -> northstar.example).
 * - A bare name joins a realm only when one realm has that name, or, when several do, the only
 *   internal one. The other-tenant alice.martin@other-tenant.example never joins the internal one.
 * - Machine accounts, SIDs and well-known service names are left as they are.
 */

export interface ResolvedIdentity {
  /** the grouping key */
  key: string
  /** the most descriptive spelling, for the incident title */
  label: string
}

interface Parsed {
  name: string
  realm: string
  kind: 'dns' | 'netbios' | 'none'
  raw: string
}

const SKIP = /^(s-1-|-$|system$|anonymous logon$|local service$|network service$|dwm-|umfd-)/i

function parse(raw: string): Parsed | null {
  const v = raw.trim().replace(/^["']|["']$/g, '')
  if (!v || SKIP.test(v) || v.endsWith('$')) return null
  const low = v.toLowerCase()
  const bs = low.lastIndexOf('\\')
  if (bs > 0) return { name: low.slice(bs + 1), realm: low.slice(0, bs), kind: 'netbios', raw: v }
  const at = low.indexOf('@')
  if (at > 0) return { name: low.slice(0, at), realm: low.slice(at + 1), kind: 'dns', raw: v }
  return { name: low, realm: '', kind: 'none', raw: v }
}

/** Resolves every user value of a case at once, since whether a bare name is ambiguous depends on the others. */
export function resolveUsers(values: Iterable<string>, internalDomains: string[] = []): Map<string, ResolvedIdentity> {
  const internal = new Set(internalDomains.map((d) => d.trim().toLowerCase()).filter(Boolean))
  const parsed = new Map<string, Parsed>()
  for (const v of values) {
    const p = parse(v)
    if (p) parsed.set(v.toLowerCase(), p)
  }
  const dnsRealms = new Set([...internal, ...[...parsed.values()].filter((p) => p.kind === 'dns').map((p) => p.realm)])
  // NetBIOS name -> DNS realm, when exactly one known DNS realm starts with that label
  const netbiosTo = new Map<string, string>()
  for (const p of parsed.values()) {
    if (p.kind !== 'netbios' || netbiosTo.has(p.realm)) continue
    const matches = [...dnsRealms].filter((d) => d.split('.')[0] === p.realm)
    if (matches.length === 1) netbiosTo.set(p.realm, matches[0])
  }
  const realmOf = (p: Parsed) => (p.kind === 'dns' ? p.realm : p.kind === 'netbios' ? (netbiosTo.get(p.realm) ?? `netbios:${p.realm}`) : '')
  const isInternal = (realm: string) => internal.has(realm) || [...internal].some((d) => realm.endsWith(`.${d}`))
  // the realms each name is seen in, and the best label for each resolved identity
  const realmsByName = new Map<string, Set<string>>()
  for (const p of parsed.values()) {
    const r = realmOf(p)
    if (!r) continue
    const set = realmsByName.get(p.name) ?? new Set<string>()
    set.add(r)
    realmsByName.set(p.name, set)
  }
  const out = new Map<string, ResolvedIdentity>()
  for (const [low, p] of parsed) {
    let realm = realmOf(p)
    if (!realm) {
      const candidates = [...(realmsByName.get(p.name) ?? [])]
      const inside = candidates.filter(isInternal)
      realm = candidates.length === 1 ? candidates[0] : inside.length === 1 ? inside[0] : ''
    }
    const key = realm ? `${p.name}@${realm}` : p.name
    const label = realm && !realm.startsWith('netbios:') ? `${p.name}@${realm}` : p.raw
    out.set(low, { key, label })
  }
  return out
}
