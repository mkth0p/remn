import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { buildRelationships, GRAPH_CACHE_VERSION, scanRelationships, type RelationshipAliases, type RelationshipEdge, type RelationshipResult } from '../data/relationships'
import { loadRelationshipReviews, saveRelationshipReview, type RelationshipReview } from '../data/relationshipReviews'
import { getDb, type Case, type Evidence } from '../db/schema'
import { fmtNum } from '../util/format'

/**
 * The relationship graph of a case for Explore and the story steps: the cached graph, its link
 * reviews and aliases, and the build that scans the evidence page by page.
 */

/** Nodes plus edges a cached graph may hold; past it only the cursor and options are kept. */
const CACHE_BUDGET = 20_000

function fingerprint(rows: Evidence[]): string {
  return JSON.stringify(rows.map((e) => [e.id, e.sha256Client, e.count, e.status]).sort((a, b) => Number(a[0]) - Number(b[0])))
}

/** The graph of a case, its reviews and aliases, and the build that scans the evidence page by page. */
export function useRelationshipGraph(kase: Case | null) {
  const [result, setResult] = useState<RelationshipResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [progress, setProgress] = useState('')
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [evidenceId, setEvidenceId] = useState('')
  const [aliasesText, setAliasesText] = useState('{}')
  const [aliases, setAliases] = useState<RelationshipAliases>({})
  const [reviews, setReviews] = useState<Record<string, RelationshipReview>>({})
  const alive = useRef(true)
  const stopped = useRef(false)
  const generation = useRef(0)
  useEffect(() => {
    alive.current = true
    const current = ++generation.current
    setBusy(false)
    setResult(null)
    setError('')
    if (kase?.id)
      getDb()
        .evidence.where('caseId')
        .equals(kase.id)
        .toArray()
        .then(async (rows) => {
          const [saved, savedAliases, cache] = await Promise.all([
            loadRelationshipReviews(kase.id!),
            getDb().kv.get(`relationship-aliases-${kase.id}`),
            getDb().kv.get(`relationship-cache-${kase.id}`),
          ])
          if (!alive.current || current !== generation.current) return
          setEvidence(rows)
          setReviews(saved)
          setAliasesText(JSON.stringify(savedAliases?.value ?? {}, null, 2))
          const cached = cache?.value as { version?: number; fingerprint: string; result?: RelationshipResult; aliases: RelationshipAliases; scope: string; tooLarge?: number } | undefined
          if (cached?.version === GRAPH_CACHE_VERSION && cached.fingerprint === fingerprint(rows) && cached.result) {
            setResult(cached.result)
            setAliases(cached.aliases)
            setEvidenceId(cached.scope)
          } else if (cached?.tooLarge) setError('The previous graph was too large to keep. Build it again to explore; your saved link reviews are retained.')
        })
    return () => {
      alive.current = false
    }
  }, [kase?.id])

  const build = useCallback(
    async (append = false) => {
      if (!kase) return
      setBusy(true)
      setError('')
      stopped.current = false
      const current = generation.current
      setProgress('Scanning evidence…')
      try {
        const next_aliases = append ? aliases : (JSON.parse(aliasesText) as RelationshipAliases)
        if (!next_aliases || Array.isArray(next_aliases) || typeof next_aliases !== 'object') throw new Error('Aliases must be a JSON object containing hosts and/or accounts maps')
        const next = await scanRelationships(
          append ? result : null,
          (previous) => buildRelationships(kase, evidenceId ? Number(evidenceId) : undefined, previous?.cursor ?? undefined, next_aliases, previous?.processContext, previous?.processContextTruncated),
          () => stopped.current || !alive.current || generation.current !== current,
          (partial) => {
            if (alive.current && generation.current === current) setProgress(`Scanned ${fmtNum(partial.stats.events + partial.stats.mails)} records…`)
          },
        )
        if (!next || !alive.current || generation.current !== current) return
        // cache only what a reload needs to resume: the whole graph of a large case is too big a row to rewrite on each build
        const cacheable = next.nodes.length + next.edges.length <= CACHE_BUDGET
        await getDb().kv.bulkPut([
          { key: `relationship-aliases-${kase.id}`, value: next_aliases },
          {
            key: `relationship-cache-${kase.id}`,
            value: cacheable
              ? { version: GRAPH_CACHE_VERSION, fingerprint: fingerprint(evidence), result: next, aliases: next_aliases, scope: evidenceId }
              : { version: GRAPH_CACHE_VERSION, fingerprint: fingerprint(evidence), aliases: next_aliases, scope: evidenceId, cursor: next.cursor, tooLarge: next.nodes.length + next.edges.length },
          },
        ])
        if (!alive.current || generation.current !== current) return
        setResult(next)
        setAliases(next_aliases)
      } catch (e) {
        if (alive.current && generation.current === current) setError((e as Error).message)
      } finally {
        if (alive.current && generation.current === current) {
          setBusy(false)
          setProgress('')
        }
      }
    },
    [kase, aliases, aliasesText, result, evidenceId, evidence],
  )
  const save = useCallback(
    async (review: RelationshipReview) => {
      if (!kase) return
      try {
        await saveRelationshipReview(kase.id!, review)
        setReviews((old) => ({ ...old, [review.key]: review }))
      } catch (e) {
        setError(`Could not save review: ${(e as Error).message}`)
        throw e
      }
    },
    [kase],
  )
  const nodes = useMemo(() => new Map(result?.nodes.map((n) => [n.id, n]) ?? []), [result])
  return {
    result,
    nodes,
    busy,
    error,
    progress,
    evidence,
    evidenceId,
    setEvidenceId: (v: string) => {
      setEvidenceId(v)
      setResult(null)
    },
    aliasesText,
    setAliasesText,
    aliases,
    reviews,
    build,
    stop: () => {
      stopped.current = true
    },
    save,
  }
}
export type RelationshipGraph = ReturnType<typeof useRelationshipGraph>

/** The links of the graph that the given records support: what each record names, and the process and logon links it shows. */
export function recordLinks(graph: RelationshipResult | null, refs: { source: 'events' | 'mails'; id: number }[]): RelationshipEdge[] {
  if (!graph || !refs.length) return []
  const want = new Set(refs.map((r) => `${r.source}:${r.id}`))
  return graph.edges.filter((e) => e.refs.some((r) => r.id != null && want.has(`${r.source}:${r.id}`)))
}
