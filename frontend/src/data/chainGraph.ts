import type { Chain, ChainStep } from './chains'

/**
 * Graph models for the Chains page.
 *
 * `buildChainGraph` lays one chain out as a time-ordered swimlane graph: the seed mail and its
 * infrastructure (sender, link domains, attachments) on top, the recipient identity, then the
 * steps by source (mailbox, cloud, host) in time order, and the machines / IPs they touched at
 * the bottom. Runs of routine steps (weight 1, no artifact, no finding) collapse into one node so
 * a 40-sign-in window reads as one line; every artifact that ties a step back to the mail becomes
 * a labelled edge from the seed's domain / attachment / sender node to that step.
 *
 * `buildCampaignGraph` draws every chain of the case against the infrastructure they share
 * (sender addresses, link domains, IPs, hosts): an entity touching several chains is the
 * campaign signal an analyst looks for.
 */

export type Lane = 'attacker' | 'mail' | 'identity' | 'cloud' | 'host' | 'infra'
export const LANES: Lane[] = ['attacker', 'mail', 'identity', 'cloud', 'host', 'infra']
export const LANE_LABEL: Record<Lane, string> = { attacker: 'attacker side', mail: 'mailbox', identity: 'identity', cloud: 'Microsoft 365', host: 'host', infra: 'machines & IPs' }

export type NodeKind = 'seed' | 'step' | 'routine' | 'user' | 'address' | 'domain' | 'attachment' | 'ip' | 'host' | 'chain'
export type EdgeKind = 'sequence' | 'artifact' | 'entity' | 'recipient'

export interface GNode {
  id: string
  label: string
  sub?: string
  lane: Lane
  kind: NodeKind
  /** column in time order (seed = 0); entity nodes take the mean column of their neighbours */
  x: number
  severity?: string
  weight: number
  /** tied to the seed mail by an artifact or carrying a finding */
  linked: boolean
  stepIdx?: number
  stepIdxs?: number[]
  entity?: { kind: 'user' | 'host' | 'ip' | 'address' | 'domain'; value: string }
  ts?: number
  /** tooltip detail lines */
  detail?: string[]
  /** campaign graph: number of chains the entity touches */
  degree?: number
  score?: number
  chainId?: string
}

export interface GEdge {
  source: string
  target: string
  kind: EdgeKind
  label?: string
}

export interface Graph {
  nodes: GNode[]
  edges: GEdge[]
  columns: number
}

const ORDER = ['critical', 'high', 'medium', 'low', 'info']
const worstSeverity = (fs: { severity: string }[]): string | undefined => ORDER.find((s) => fs.some((f) => f.severity === s))
export const riskSeverity = (risk: number) => (risk >= 80 ? 'critical' : risk >= 60 ? 'high' : risk >= 40 ? 'medium' : 'low')
const isRoutine = (s: ChainStep) => s.weight <= 1 && !s.artifacts.length && !s.findings.length
/** widest graph before adjacent unpinned steps are folded together */
export const MAX_COLUMNS = 14
/** "sign-in from NL via Other clients" and "sign-in from FR via Browser" fold together; numbers and IPs are wildcards */
const titleKey = (t: string) => t.toLowerCase().replace(/\s*×\d+$/, '').replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, '#').replace(/\d+/g, '#').replace(/ (?:from|on|by|via|to) .*$/, '').slice(0, 48)
const laneOf = (s: ChainStep): Lane => (s.kind === 'mail' ? 'mail' : s.origin === 'm365' ? 'cloud' : 'host')

function offset(min: number): string {
  const a = Math.abs(min)
  const txt = a < 90 ? `${Math.round(a)} min` : a < 48 * 60 ? `${(a / 60).toFixed(1)} h` : `${(a / 1440).toFixed(1)} d`
  return (min < 0 ? '-' : '+') + txt
}

/** "sign-ins, mailbox reads" for a run of routine steps, from the words their titles start with. */
function routineSummary(steps: ChainStep[]): string {
  const heads = new Map<string, number>()
  for (const s of steps) {
    const h = s.title.replace(/\s*×\d+$/, '').split(/ (?:from|on|by|via|to) /)[0].slice(0, 28)
    heads.set(h, (heads.get(h) ?? 0) + 1)
  }
  return Array.from(heads.entries()).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([h, n]) => (n > 1 ? `${h} ×${n}` : h)).join(', ')
}

export function buildChainGraph(chain: Chain): Graph {
  const nodes: GNode[] = []
  const edges: GEdge[] = []
  const byId = new Map<string, GNode>()
  const add = (n: GNode) => {
    byId.set(n.id, n)
    nodes.push(n)
    return n
  }
  const ensure = (id: string, make: () => GNode) => byId.get(id) ?? add(make())
  const seedRisk = chain.seed.risk
  add({ id: 'seed', label: chain.seed.subject || '(no subject)', sub: `seed mail · risk ${seedRisk}`, lane: 'mail', kind: 'seed', x: 0, severity: riskSeverity(seedRisk), weight: 6, linked: true, ts: chain.seed.ts, detail: chain.seed.findings.map((f) => `${f.severity}: ${f.title}`) })
  add({ id: 'victim', label: chain.identityLabel, sub: 'recipient', lane: 'identity', kind: 'user', x: 0, weight: 5, linked: true, entity: { kind: 'user', value: chain.entities.user || chain.identityLabel } })
  edges.push({ source: 'seed', target: 'victim', kind: 'recipient', label: 'delivered to' })
  if (chain.seed.fromAddr) {
    const id = `address:${chain.seed.fromAddr}`
    ensure(id, () => ({ id, label: chain.seed.fromAddr!, sub: 'sender', lane: 'attacker', kind: 'address', x: 0, weight: 3, linked: true, entity: { kind: 'address', value: chain.seed.fromAddr! } }))
    edges.push({ source: id, target: 'seed', kind: 'entity', label: 'from' })
  }
  for (const d of chain.seed.urlDomains) {
    const id = `domain:${d}`
    ensure(id, () => ({ id, label: d, sub: 'link domain', lane: 'attacker', kind: 'domain', x: 0, weight: 2, linked: false, entity: { kind: 'domain', value: d } }))
    edges.push({ source: id, target: 'seed', kind: 'entity', label: 'link' })
  }
  for (const a of chain.seed.attachments) {
    const id = `attachment:${a}`
    ensure(id, () => ({ id, label: a, sub: 'attachment', lane: 'attacker', kind: 'attachment', x: 0, weight: 2, linked: false }))
    edges.push({ source: id, target: 'seed', kind: 'entity', label: 'attached' })
  }

  // --- steps: fold what repeats, keep what ties to the mail
  const ordered = chain.steps.map((s, i) => ({ s, i })).sort((a, b) => a.s.ts - b.s.ts || a.i - b.i)
  const hasArtifact = (st: ChainStep) => st.artifacts.some((a) => a.startsWith('mail ') || a === 'victim engaged with the sender' || a === 'forwarding rule' || a === 'mailbox forwarding' || a === 'same thread')
  type Group = { items: { s: ChainStep; i: number }[]; lane: Lane; key: string; pinned: boolean; routine: boolean }
  const groups: Group[] = []
  for (const it of ordered) {
    const lane = laneOf(it.s)
    const key = titleKey(it.s.title)
    const pinned = hasArtifact(it.s)
    const routine = isRoutine(it.s)
    const last = groups[groups.length - 1]
    // routine steps fold together whatever they are; steps with findings fold only with the same action on the same lane
    const joins = !!last && !last.pinned && !pinned && (routine ? last.routine : !last.routine && last.lane === lane && last.key === key)
    if (joins) last.items.push(it)
    else groups.push({ items: [it], lane, key, pinned, routine })
  }
  const majorityLane = (g: Group): Lane => { const lanes = g.items.map((x) => laneOf(x.s)); return LANES.find((l) => lanes.filter((x) => x === l).length >= lanes.length / 2) ?? g.lane }
  for (const g of groups) if (g.routine) g.lane = majorityLane(g)
  // still too wide: merge adjacent unpinned groups (same lane first, then any) until it fits
  const mergeOnce = (sameLane: boolean): boolean => {
    for (let g = 0; g < groups.length - 1; g++) {
      const a = groups[g]
      const b = groups[g + 1]
      if (a.pinned || b.pinned || (sameLane && a.lane !== b.lane)) continue
      a.items.push(...b.items)
      a.key = a.key === b.key ? a.key : '*'
      a.routine = a.routine && b.routine
      if (!sameLane) a.lane = majorityLane(a)
      groups.splice(g + 1, 1)
      return true
    }
    return false
  }
  while (groups.length > MAX_COLUMNS && (mergeOnce(true) || mergeOnce(false))) { /* fold */ }

  let col = 1
  let prev = 'victim'
  for (const g of groups) {
    const first = g.items[0].s
    const n = g.items.length
    const allRoutine = g.items.every((x) => isRoutine(x.s))
    const findings = g.items.flatMap((x) => x.s.findings)
    const artifacts = Array.from(new Set(g.items.flatMap((x) => x.s.artifacts)))
    const rows = g.items.reduce((t, x) => t + x.s.count, 0)
    const id = n === 1 ? `step:${g.items[0].i}` : allRoutine ? `routine:${g.items[0].i}` : `group:${g.items[0].i}`
    const titles = Array.from(new Set(g.items.map((x) => x.s.title.replace(/\s*×\d+$/, ''))))
    const label = allRoutine && n > 1 ? `${n} routine steps` : n === 1 ? titles[0] : g.key !== '*' ? `${titles[0]} ×${n}` : `${n} steps: ${routineSummary(g.items.map((x) => x.s))}`
    const last = g.items[n - 1].s
    const sub = allRoutine && n > 1 ? `${routineSummary(g.items.map((x) => x.s))} · ${offset(first.offsetMin)} → ${offset(last.offsetMin)}` : n === 1 ? `${offset(first.offsetMin)}${first.count > 1 ? ` · ×${first.count}` : ''}` : `${offset(first.offsetMin)} → ${offset(last.offsetMin)} · ${rows} row${rows === 1 ? '' : 's'}`
    const sev = worstSeverity(findings) ?? (artifacts.some((a) => a.startsWith('mail ') || a === 'victim engaged with the sender') ? 'high' : undefined)
    add({ id, label, sub, lane: g.lane, kind: allRoutine ? 'routine' : 'step', x: col++, severity: allRoutine ? undefined : sev, weight: Math.max(...g.items.map((x) => x.s.weight)), linked: g.pinned || findings.length > 0, stepIdx: n === 1 ? g.items[0].i : undefined, stepIdxs: n > 1 ? g.items.map((x) => x.i) : undefined, ts: first.ts, detail: n === 1 ? [...first.artifacts, ...first.findings.map((f) => `${f.severity}: ${f.title}`)] : [...titles.slice(0, 6).map((t) => (n > 1 ? `${g.items.filter((x) => x.s.title.replace(/\s*×\d+$/, '') === t).length}× ${t}` : t)), ...Array.from(new Set(findings.map((f) => `${f.severity}: ${f.title}`))).slice(0, 6)] })
    edges.push({ source: prev, target: id, kind: 'sequence' })
    prev = id
    for (const a of artifacts) {
      if (a.startsWith('mail URL domain ')) {
        const d = a.slice('mail URL domain '.length)
        const did = `domain:${d}`
        ensure(did, () => ({ id: did, label: d, sub: 'link domain', lane: 'attacker', kind: 'domain', x: 0, weight: 2, linked: true, entity: { kind: 'domain', value: d } }))
        byId.get(did)!.linked = true
        edges.push({ source: did, target: id, kind: 'artifact', label: 'link' })
      } else if (a.startsWith('mail attachment ')) {
        const nm = a.slice('mail attachment '.length)
        const match = chain.seed.attachments.find((x) => x.toLowerCase().startsWith(nm.toLowerCase().slice(0, 12))) ?? nm
        const aid = `attachment:${match}`
        ensure(aid, () => ({ id: aid, label: match, sub: 'attachment', lane: 'attacker', kind: 'attachment', x: 0, weight: 2, linked: true }))
        byId.get(aid)!.linked = true
        edges.push({ source: aid, target: id, kind: 'artifact', label: 'attachment' })
      } else if (a === 'victim engaged with the sender' && chain.seed.fromAddr) {
        edges.push({ source: id, target: `address:${chain.seed.fromAddr}`, kind: 'artifact', label: 'replied' })
      } else if (a === 'forwarding rule' || a === 'mailbox forwarding') {
        for (const x of g.items) {
          const m = /forward(?:ing)? to ([^\s,]+)/i.exec(x.s.title)
          if (!m) continue
          const addr = m[1].replace(/^smtp:/i, '')
          const fid = `address:${addr}`
          ensure(fid, () => ({ id: fid, label: addr, sub: 'forward target', lane: 'attacker', kind: 'address', x: 0, weight: 3, linked: true, entity: { kind: 'address', value: addr } }))
          if (!edges.some((e) => e.source === id && e.target === fid)) edges.push({ source: id, target: fid, kind: 'artifact', label: 'forwards to' })
        }
      }
    }
    const ips = Array.from(new Set(g.items.map((x) => x.s.ipAddress).filter(Boolean).map(String))).slice(0, 3)
    for (const ip of ips) {
      const iid = `ip:${ip}`
      ensure(iid, () => ({ id: iid, label: ip, sub: 'source ip', lane: 'infra', kind: 'ip', x: 0, weight: 2, linked: false, entity: { kind: 'ip', value: ip } }))
      edges.push({ source: id, target: iid, kind: 'entity' })
    }
    const hosts = Array.from(new Set(g.items.filter((x) => x.s.computer && x.s.origin !== 'm365').map((x) => String(x.s.computer)))).slice(0, 3)
    for (const host of hosts) {
      const hid = `host:${host}`
      ensure(hid, () => ({ id: hid, label: host.split('.')[0], sub: 'host', lane: 'infra', kind: 'host', x: 0, weight: 3, linked: false, entity: { kind: 'host', value: host } }))
      edges.push({ source: id, target: hid, kind: 'entity' })
    }
  }
  // entity nodes sit under / above the mean column of the steps they connect to
  for (const n of nodes) {
    if (n.kind === 'ip' || n.kind === 'host' || ((n.kind === 'domain' || n.kind === 'attachment' || n.kind === 'address') && n.linked)) {
      const cols = edges.filter((e) => e.source === n.id || e.target === n.id).map((e) => byId.get(e.source === n.id ? e.target : e.source)?.x ?? 0)
      if (cols.length) n.x = cols.reduce((a, b) => a + b, 0) / cols.length
    }
  }
  // spread entity nodes that landed on the same lane and column
  const taken = new Map<string, number>()
  for (const n of nodes.filter((n) => n.kind === 'ip' || n.kind === 'host' || n.lane === 'attacker').sort((a, b) => a.x - b.x)) {
    let x = Math.round(n.x * 2) / 2
    let key = `${n.lane}:${x}`
    while (taken.has(key)) {
      x += 0.5
      key = `${n.lane}:${x}`
    }
    taken.set(key, 1)
    n.x = x
  }
  return { nodes, edges, columns: col }
}

export interface CampaignInsight {
  text: string
  entity?: GNode['entity']
}

/** All chains of the case against the sender addresses, link domains, IPs and hosts they share. */
export function buildCampaignGraph(chains: Chain[]): Graph & { insights: CampaignInsight[] } {
  const nodes: GNode[] = []
  const edges: GEdge[] = []
  const byId = new Map<string, GNode>()
  const touch = new Map<string, Set<string>>()
  const add = (n: GNode) => {
    byId.set(n.id, n)
    nodes.push(n)
    return n
  }
  const link = (chainId: string, id: string, make: () => GNode, label?: string) => {
    if (!byId.has(id)) add(make())
    const set = touch.get(id) ?? new Set<string>()
    set.add(chainId)
    touch.set(id, set)
    edges.push({ source: `chain:${chainId}`, target: id, kind: 'entity', label })
  }
  for (const c of chains) {
    add({ id: `chain:${c.id}`, label: c.identityLabel, sub: `${c.severity} · score ${c.score} · ${c.steps.length} steps`, lane: 'identity', kind: 'chain', x: 0, severity: c.severity, weight: 4 + Math.round(c.score / 25), linked: true, score: c.score, chainId: c.id, entity: { kind: 'user', value: c.entities.user || c.identityLabel } })
    if (c.seed.fromAddr) link(c.id, `address:${c.seed.fromAddr}`, () => ({ id: `address:${c.seed.fromAddr}`, label: c.seed.fromAddr!, sub: 'sender', lane: 'attacker', kind: 'address', x: 0, weight: 3, linked: true, entity: { kind: 'address', value: c.seed.fromAddr! } }), 'seed from')
    for (const a of c.entities.attackerAddresses) if (a !== c.seed.fromAddr) link(c.id, `address:${a}`, () => ({ id: `address:${a}`, label: a, sub: 'attacker address', lane: 'attacker', kind: 'address', x: 0, weight: 3, linked: true, entity: { kind: 'address', value: a } }))
    for (const d of c.entities.domains) link(c.id, `domain:${d}`, () => ({ id: `domain:${d}`, label: d, sub: 'link domain', lane: 'attacker', kind: 'domain', x: 0, weight: 2, linked: false, entity: { kind: 'domain', value: d } }))
    for (const ip of c.entities.ips) link(c.id, `ip:${ip}`, () => ({ id: `ip:${ip}`, label: ip, sub: 'ip', lane: 'infra', kind: 'ip', x: 0, weight: 2, linked: false, entity: { kind: 'ip', value: ip } }))
    for (const h of c.entities.hosts) link(c.id, `host:${h}`, () => ({ id: `host:${h}`, label: h.split('.')[0], sub: 'host', lane: 'infra', kind: 'host', x: 0, weight: 3, linked: false, entity: { kind: 'host', value: h } }))
  }
  const insights: CampaignInsight[] = []
  for (const n of nodes) {
    const deg = touch.get(n.id)?.size ?? 0
    n.degree = deg
    if (deg >= 2) {
      n.linked = true
      insights.push({ text: `${n.sub ?? n.kind} ${n.label} appears in ${deg} chains`, entity: n.entity })
    }
  }
  insights.sort((a, b) => Number(/appears in (\d+)/.exec(b.text)?.[1]) - Number(/appears in (\d+)/.exec(a.text)?.[1]))
  return { nodes, edges, columns: chains.length, insights }
}
