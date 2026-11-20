import { useCallback, useMemo } from 'react'
import type { LoadedRule } from '../../data/rules'
import { readMeasure, ruleTrust, type MeasureReading } from '../../data/ruleMeasures'
import { byPriority, scoreFindings, type PastDecision } from '../../data/findingPriority'
import type { Finding, Severity } from '../../db/schema'
import { buildIncidents, chainMembership, effectiveSeverity, sevCounts } from '../../rules/incidents'
import type { Chain } from '../../data/chains'
import { chainSeverity, type ChainReview } from '../../data/review'
import { ORDER, type Group, type Sort } from './model'

export interface QueueFilters {
  sev: string
  status: string
  source: string
  q: string
  showFp: boolean
  group: Group
  sort: Sort
}

/**
 * The queue as the filters cut it: the findings in their order, the incidents they form, the groups
 * of the other groupings, the counts of the severity tiles, and the techniques of the ATT&CK tab.
 */
export function useFindingsQueue(
  { all, chains, chainReviews, rules, memory }: { all: Finding[]; chains: Chain[]; chainReviews: Record<string, ChainReview>; rules: LoadedRule[]; memory: PastDecision[] },
  { sev, status, source, q, showFp, group, sort }: QueueFilters,
) {
  // false positives leave the queue and the counts unless asked for (status filter or the toggle)
  const active = useMemo(() => all.filter((f) => f.status !== 'false_positive'), [all])
  const fpCount = all.length - active.length
  // what to look at first (data/findingPriority.ts): read from the whole case, the rules' measures and past decisions
  const trust = useMemo(() => new Map(rules.map((r) => [r.rule.id, ruleTrust(r.measured)])), [rules])
  const scores = useMemo(() => scoreFindings(all, { trust: (id) => trust.get(id), memory }), [all, trust, memory])
  const sortFindings = useCallback(
    (fs: Finding[]) => (sort === 'priority' ? [...fs].sort(byPriority(scores)) : sort === 'time' ? [...fs].sort((a, b) => (b.ts ?? 0) - (a.ts ?? 0)) : fs),
    [sort, scores],
  )
  const rows = useMemo(() => {
    const needle = q.toLowerCase()
    const base = status === 'false_positive' || showFp ? all : active
    const matching = base.filter(
      (f) =>
        (group === 'incident' || !sev || effectiveSeverity(f) === sev) &&
        (!status || f.status === status) &&
        (!source || f.source === source) &&
        (!needle || `${f.title} ${f.ruleId} ${JSON.stringify(f.entities)} ${f.attack.join(' ')}`.toLowerCase().includes(needle)),
    )
    return sortFindings(matching)
  }, [all, active, sev, status, source, q, showFp, group, sortFindings])
  const incidentOpts = useMemo(() => ({ chains, severityOf: (c: Chain) => chainSeverity(c, chainReviews[c.id]) }), [chains, chainReviews])
  const incidents = useMemo(() => {
    if (group !== 'incident') return []
    const built = buildIncidents(rows, incidentOpts).filter((i) => !sev || i.severity === sev)
    if (sort === 'time') return built.sort((a, b) => (b.ts ?? 0) - (a.ts ?? 0))
    if (sort !== 'priority') return built
    // an incident ranks by its first finding to look at
    const first = byPriority(scores)
    const top = new Map(built.map((i) => [i.id, [...i.findings].sort(first)[0]]))
    return built.sort((a, b) => first(top.get(a.id)!, top.get(b.id)!))
  }, [rows, group, incidentOpts, sev, sort, scores])
  const shownRows = useMemo(() => (group === 'incident' ? [...new Map(incidents.flatMap((i) => i.findings).map((f) => [f.id, f])).values()] : rows), [group, incidents, rows])
  const allIncidents = useMemo(() => buildIncidents(active, incidentOpts), [active, incidentOpts])
  const membership = useMemo(() => chainMembership(all, chains), [all, chains])
  // how far each rule's finding can be taken as a detection (rules/measures.json)
  const readings = useMemo(() => new Map<string, MeasureReading>(rules.map((r) => [r.rule.id, readMeasure(r.measured, r.origin)])), [rules])
  const counts = useMemo(() => (group === 'incident' ? sevCounts(allIncidents) : sevCounts(active)), [active, allIncidents, group])
  const groups = useMemo(() => {
    if (!group || group === 'incident') return []
    const m = new Map<string, { key: string; label: string; items: Finding[] }>()
    for (const f of rows) {
      const key = group === 'ruleId' ? f.ruleId : group === 'source' ? f.source : (Object.values(f.entities)[0] ?? '(no entity)')
      const label = group === 'ruleId' ? f.title : key
      const g = m.get(key) ?? { key, label, items: [] }
      g.items.push(f)
      m.set(key, g)
    }
    return Array.from(m.values()).sort((a, b) => b.items.length - a.items.length)
  }, [rows, group])
  const attack = useMemo(() => {
    const m = new Map<string, { id: string; findings: number; rules: Set<string>; worst: Severity }>()
    for (const f of active) {
      for (const t of f.attack) {
        const e = m.get(t) ?? { id: t, findings: 0, rules: new Set<string>(), worst: 'info' as Severity }
        e.findings++
        e.rules.add(f.ruleId)
        if (ORDER.indexOf(effectiveSeverity(f)) < ORDER.indexOf(e.worst)) e.worst = effectiveSeverity(f)
        m.set(t, e)
      }
    }
    const enabledByTechnique = new Map<string, number>()
    for (const r of rules) if (r.enabled) for (const t of r.rule.attack ?? []) enabledByTechnique.set(t, (enabledByTechnique.get(t) ?? 0) + 1)
    return { hits: Array.from(m.values()).sort((a, b) => b.findings - a.findings), enabledByTechnique }
  }, [active, rules])

  return { active, fpCount, scores, sortFindings, rows, incidentOpts, incidents, shownRows, allIncidents, membership, readings, counts, groups, attack }
}

export type FindingsQueue = ReturnType<typeof useFindingsQueue>
export type TechniqueHits = FindingsQueue['attack']
