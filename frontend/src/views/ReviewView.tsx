import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { runAgent } from '../ai/chat'
import { AddToTimeline } from '../components/AddToTimeline'
import { entityKind } from '../components/EntityPanel'
import { IconAi, IconArrowLeft, IconCheck, IconReport, IconStop } from '../components/Icons'
import { Badge, Dot, Modal, Progress, Sev, Spinner, Toggle } from '../components/ui'
import { VerdictBar } from '../components/VerdictBar'
import {
  applySuggestion,
  loadSuggestions,
  loadTriageRun,
  removeSuggestion,
  runTriage,
  suggestionsFor,
  undoEntry,
  type Suggestion,
  type TriageEntry,
  type TriageProgress,
  type TriageRun,
} from '../data/aiReview'
import { loadChains, type Chain } from '../data/chains'
import { computeConfidence, computeVerdict, groupByRule, threatProfile, type ReportData } from '../data/reportHtml'
import {
  applyChainVerdict,
  chainIncluded,
  chainSeverity,
  loadChainReviews,
  loadReportSettings,
  overridesForIncident,
  reviewQueue,
  saveChainReview,
  saveReportSettings,
  selectForReport,
  setChainUnlinked,
  SEVERITIES,
  stepVisible,
  type ChainReview,
  type ReportSettings,
  type ReviewItem,
  type Verdict,
  unprintedConfirmed,
} from '../data/review'
import { getDb, type Evidence, type Finding, type Severity } from '../db/schema'
import { buildIncidents, type Incident } from '../rules/incidents'
import { toast, useStore } from '../state/store'
import { classNames, fmtNum, fmtTs, tzLabel } from '../util/format'

type Status = 'new' | 'reviewed' | 'escalated' | 'false_positive'
const STATUS_LABEL: Record<Status, string> = { new: 'not reviewed', reviewed: 'reviewed', escalated: 'confirmed', false_positive: 'false positive' }
const STATUS_SEV: Record<Status, string> = { new: 'accent', reviewed: 'ok', escalated: 'critical', false_positive: 'info' }
const DECISIONS: { id: Exclude<Status, 'new'>; label: string; key: string; tone: string }[] = [
  { id: 'escalated', label: 'confirmed', key: 'e', tone: 'confirm' },
  { id: 'reviewed', label: 'reviewed', key: 'r', tone: 'review' },
  { id: 'false_positive', label: 'false positive', key: 'f', tone: 'dismiss' },
]
const VERDICTS: { id: Verdict; label: string; key: string; tone: string }[] = [
  { id: 'confirmed', label: 'confirmed', key: 'e', tone: 'confirm' },
  { id: 'unsure', label: 'unsure', key: 'r', tone: 'review' },
  { id: 'benign', label: 'benign', key: 'f', tone: 'dismiss' },
]
const DECISION_LABEL: Record<string, string> = { ...STATUS_LABEL, confirmed: 'confirmed', benign: 'benign', unsure: 'unsure' }
const DECISION_SEV: Record<string, string> = { ...STATUS_SEV, confirmed: 'critical', benign: 'ok', unsure: 'medium' }
/** the log's summary counts chains and incidents apart, since both have a "confirmed" */
const SUMMARY_LABEL: Record<string, string> = {
  confirmed: 'chains confirmed',
  escalated: 'incidents confirmed',
  unsure: 'chains unsure',
  reviewed: 'incidents reviewed',
  benign: 'chains benign',
  false_positive: 'false positives',
}
const chainDecision = (r?: ChainReview) => (r?.verdict === 'confirmed' ? 'critical' : r?.verdict === 'benign' ? 'ok' : 'medium')
const trim = (s: string, n: number) => (s.length > n ? s.slice(0, n - 1) + '…' : s)

/** The facts behind an item, the way the report prints them: one line per rule with count, span and the values matched. */
function Facts({ findings, said, onUnlink }: { findings: Finding[]; said: Record<string, string>; onUnlink?: (ids: number[]) => void }) {
  const groups = useMemo(() => groupByRule(findings, said), [findings, said])
  if (!groups.length) return <div className="small muted">no finding</div>
  const idsOf = (ruleId: string) => findings.filter((f) => f.ruleId === ruleId && f.id != null).map((f) => f.id!)
  return (
    <table className="table compact facts">
      <thead>
        <tr>
          <th>severity</th>
          <th>finding</th>
          <th>findings · rows</th>
          <th>when ({tzLabel()})</th>
          <th>what matched</th>
          <th>status</th>
          {onUnlink && <th></th>}
        </tr>
      </thead>
      <tbody>
        {groups.map((g) => (
          <tr key={g.ruleId}>
            <td style={{ width: 96 }}>
              <Sev sev={g.severity} />
              {g.severity !== g.ruleSeverity && <div className="small muted">rule {g.ruleSeverity}</div>}
            </td>
            <td className="sans">
              {g.title}
              <div className="small muted mono">
                {g.ruleId}
                {g.escalations.length ? ` · ${g.escalations.slice(0, 2).join(' · ')}` : ''}
                {g.attack.length ? ` · ${g.attack.slice(0, 4).join(' ')}` : ''}
              </div>
            </td>
            <td className="nowrap" style={{ width: 90 }}>
              {fmtNum(g.findings)} · {fmtNum(g.rows)}
            </td>
            <td className="nowrap small" style={{ width: 150 }}>
              {fmtTs(g.first)}
              {g.last && g.first && g.last !== g.first ? <div className="muted">to {fmtTs(g.last)}</div> : null}
            </td>
            <td className="vals">
              {g.values.length ? (
                <>
                  {g.values.slice(0, 5).map((v) => (
                    <code key={v} title={v}>
                      {trim(v, 110)}
                    </code>
                  ))}
                  {g.values.length > 5 && <span className="small muted">+{g.values.length - 5} more</span>}
                </>
              ) : (
                <span className="muted">–</span>
              )}
            </td>
            <td style={{ width: 110 }}>
              {Object.entries(g.statuses).map(([s, c]) => (
                <span key={s} style={{ marginRight: 4 }}>
                  <Badge sev={STATUS_SEV[s as Status]}>{STATUS_LABEL[s as Status]}</Badge>
                  {c > 1 ? <span className="small muted"> ×{c}</span> : null}
                </span>
              ))}
            </td>
            {onUnlink && (
              <td style={{ width: 60 }}>
                <button className="btn link small" onClick={() => onUnlink(idsOf(g.ruleId))}>
                  unlink
                </button>
              </td>
            )}
          </tr>
        ))}
      </tbody>
    </table>
  )
}

/**
 * Review: the case's verdict, live, and the queue that decides it. The verdict bar at the top is
 * the report's cover computed from the decisions so far. The rail groups the queue into what is
 * still to decide, what was confirmed, and the rest. Each item opens on its facts, one line per
 * rule with the values it matched, so the decision rests on what was seen; the decision bar says
 * what each choice does to the verdict before it is made. Chains and the findings whose rows are
 * their steps are one item. The model can propose per item or triage the queue; every decision
 * is logged and undoable. Decisions live on the findings and in the case's kv; the Report page
 * prints them.
 */
export function ReviewView() {
  const kase = useStore((s) => s.currentCase)
  const rulesVersion = useStore((s) => s.rulesVersion)
  const aiCfg = useStore((s) => s.aiConfig)
  const setView = useStore((s) => s.setView)
  const setFocus = useStore((s) => s.setFocus)
  const setFocusChain = useStore((s) => s.setFocusChain)
  const setEntity = useStore((s) => s.setEntity)
  const setEventsFilter = useStore((s) => s.setEventsFilter)
  const setMailsFilter = useStore((s) => s.setMailsFilter)
  const [findings, setFindings] = useState<Finding[]>([])
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [chains, setChains] = useState<Chain[]>([])
  const [reviews, setReviews] = useState<Record<string, ChainReview>>({})
  const [settings, setSettings] = useState<ReportSettings | null>(null)
  const [suggestions, setSuggestions] = useState<Record<string, Suggestion>>({})
  const [lastRun, setLastRun] = useState<TriageRun | null>(null)
  const [showRun, setShowRun] = useState(false)
  const [askTriage, setAskTriage] = useState(false)
  const [triageDecided, setTriageDecided] = useState(false)
  const [triage, setTriage] = useState<TriageProgress | null>(null)
  const triageAbort = useRef<AbortController | null>(null)
  const [suggesting, setSuggesting] = useState(false)
  const [idx, setIdx] = useState(0)
  const [showDone, setShowDone] = useState(true)
  const [drafting, setDrafting] = useState(false)
  const [note, setNote] = useState('')
  const [narrative, setNarrative] = useState('')
  const caseId = kase?.id

  const reload = useCallback(() => {
    if (!caseId) return
    getDb().findings.where('caseId').equals(caseId).toArray().then(setFindings)
    loadSuggestions(caseId).then(setSuggestions)
  }, [caseId])
  useEffect(() => {
    if (!caseId) return
    reload()
    getDb().evidence.where('caseId').equals(caseId).toArray().then(setEvidence)
    loadChains(caseId).then((r) => setChains(r?.chains ?? []))
    loadChainReviews(caseId).then(setReviews)
    loadReportSettings(caseId).then(setSettings)
    loadTriageRun(caseId).then(setLastRun)
    setIdx(0)
  }, [caseId, rulesVersion, reload])

  const incidents = useMemo(() => buildIncidents(findings, { chains, severityOf: (c) => chainSeverity(c, reviews[c.id]) }), [findings, chains, reviews])
  const queue = useMemo(() => reviewQueue(incidents, chains, reviews), [incidents, chains, reviews])
  const done = queue.filter((i) => i.done).length
  const undecided = queue.length - done
  const aiDecided = queue.filter((it) => (it.kind === 'chain' ? reviews[it.chain!.id]?.by === 'ai' : it.incident!.lead.decidedBy === 'ai')).length
  const confirmedOf = (it: ReviewItem) => (it.kind === 'chain' ? reviews[it.chain!.id]?.verdict === 'confirmed' : it.incident!.status === 'escalated')
  // the rail: what is still to decide, what was confirmed, the rest
  const groups = useMemo(() => {
    const todo = queue.filter((i) => !i.done)
    const confirmed = queue.filter((i) => i.done && confirmedOf(i))
    const rest = queue.filter((i) => i.done && !confirmedOf(i))
    return [
      { id: 'todo', label: 'to decide', items: todo },
      { id: 'confirmed', label: 'confirmed', items: showDone ? confirmed : [] },
      { id: 'rest', label: 'reviewed, benign, false positive', items: showDone ? rest : [] },
    ]
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [queue, showDone, reviews])
  const visible = useMemo(() => groups.flatMap((g) => g.items), [groups])
  const current: ReviewItem | undefined = visible[Math.min(idx, Math.max(0, visible.length - 1))]
  const pending = useMemo(() => (current ? suggestionsFor(current, suggestions) : []), [current, suggestions])
  // editable text follows the current item
  useEffect(() => {
    setNote(current?.incident?.lead.notes ?? '')
    setNarrative(current?.chain ? (reviews[current.chain.id]?.narrative ?? '') : '')
  }, [current?.id, current?.incident?.lead.notes, current?.chain, reviews])

  // the report's cover, live: the same selection and the same functions the Report page uses
  const report = useMemo(() => {
    if (!kase || !settings) return null
    const selection = selectForReport(findings, chains, reviews, settings)
    const grouped = buildIncidents(selection.findings, { chains: selection.chains, severityOf: (c) => chainSeverity(c, reviews[c.id]) })
    const membersOf = new Map(grouped.filter((i) => i.kind === 'chain' && i.chain).map((i) => [i.chain!.id, i.findings.filter((f) => f.ruleId !== 'chain')]))
    const data: ReportData = {
      kase,
      generatedAt: 0,
      settings,
      summary: '',
      evidence,
      chains: selection.chains,
      reviews,
      membersOf,
      graphs: {},
      campaignInsights: [],
      incidents: grouped.filter((i) => i.kind !== 'chain'),
      findings: selection.findings,
      iocs: [],
      timeline: [],
      tasks: [],
      notes: [],
      undecided,
      unprintedConfirmed: unprintedConfirmed(findings, chains, reviews, selection),
    }
    return { data, verdict: computeVerdict(data), confidence: computeConfidence(data), profile: threatProfile(data) }
  }, [kase, settings, findings, chains, reviews, evidence, undecided])
  /** what the verdict becomes if the current incident gets this status, or the current chain this verdict */
  const effectOf = useCallback(
    (decision: string): string | null => {
      if (!report || !current) return null
      const d = report.data
      let next: ReportData
      if (current.kind === 'chain' && current.chain) {
        const c = current.chain
        const r: ChainReview = { ...(reviews[c.id] ?? {}), verdict: decision as Verdict }
        next = { ...d, reviews: { ...reviews, [c.id]: r }, undecided: d.undecided - (reviews[c.id]?.verdict ? 0 : 1) }
      } else if (current.incident) {
        const inc = current.incident
        next = {
          ...d,
          incidents: d.incidents.map((i) => (i.id === inc.id ? { ...i, status: decision as Status } : i)),
          undecided: d.undecided - (inc.status === 'new' ? 1 : 0),
        }
        if (!d.incidents.some((i) => i.id === inc.id) && decision === 'escalated') next.incidents = [...next.incidents, { ...inc, status: 'escalated' }]
      } else return null
      const v = computeVerdict(next)
      return v.label === report.verdict.label ? null : v.label
    },
    [report, current, reviews],
  )

  const go = useCallback((d: number) => setIdx((i) => Math.max(0, Math.min(visible.length - 1, i + d))), [visible.length])

  const setStatus = useCallback(
    async (inc: Incident, s: Status) => {
      const db = getDb()
      await Promise.all(inc.findings.map((f) => db.findings.update(f.id!, { status: s, decidedBy: 'analyst' })))
      reload()
    },
    [reload],
  )
  const rescore = useCallback(
    async (inc: Incident, sev: Severity | null) => {
      const db = getDb()
      await Promise.all(overridesForIncident(inc, sev).map((o) => db.findings.update(o.id, { severityOverride: o.severityOverride })))
      reload()
    },
    [reload],
  )
  const exclude = useCallback(
    async (inc: Incident, on: boolean) => {
      const db = getDb()
      await Promise.all(inc.findings.map((f) => db.findings.update(f.id!, { reportExclude: on || undefined })))
      reload()
    },
    [reload],
  )
  const saveNote = async (inc: Incident) => {
    if (note === (inc.lead.notes ?? '')) return
    await getDb().findings.update(inc.lead.id!, { notes: note, notesBy: note ? 'analyst' : undefined })
    reload()
  }
  /** A verdict writes the status of the chain's linked findings; the other fields only touch the chain review. */
  const chainPatch = useCallback(
    async (c: Chain, patch: Partial<ChainReview>) => {
      if (!caseId) return
      const { verdict, ...rest } = patch
      if (verdict) {
        const members = incidents.find((i) => i.kind === 'chain' && i.chain?.id === c.id)?.findings ?? []
        setReviews(await applyChainVerdict(caseId, c, members, verdict, 'analyst'))
        reload()
      }
      if (Object.keys(rest).length) setReviews(await saveChainReview(caseId, c.id, rest))
    },
    [caseId, incidents, reload],
  )
  const unlink = async (ids: number[], on: boolean) => {
    if (!ids.length) return
    await setChainUnlinked(ids, on)
    reload()
    toast(
      'ok',
      on
        ? `${ids.length} finding${ids.length === 1 ? '' : 's'} unlinked from the chain: now in the queue on ${ids.length === 1 ? 'its' : 'their'} own`
        : `${ids.length} finding${ids.length === 1 ? '' : 's'} linked back to the chain`,
    )
  }
  const saveSettings = async (patch: Partial<ReportSettings>) => {
    if (!caseId || !settings) return
    const next = { ...settings, ...patch }
    setSettings(next)
    await saveReportSettings(caseId, next)
  }
  const openRows = (inc: Incident) => {
    if (inc.source === 'mixed' || !inc.refs.length) return
    if (inc.source === 'events') setEventsFilter({ conditions: [{ field: 'id', op: 'in', value: inc.refs.slice(0, 2000) }], sort: { field: 'ts', dir: 'asc' } })
    else setMailsFilter({ conditions: [{ field: 'id', op: 'in', value: inc.refs.slice(0, 2000) }] })
    setView(inc.source)
  }
  const modelReady = () => {
    if (useStore.getState().aiStatus.reachable === true) return true
    toast('err', 'the analyst model is not reachable (see the AI section in Settings)')
    return false
  }
  const draft = async (c: Chain) => {
    if (!kase || !modelReady()) return
    setDrafting(true)
    try {
      const steps = c.steps
        .filter((s) => stepVisible(s, 'weighted'))
        .slice(0, 40)
        .map(
          (s) =>
            `${fmtTs(s.ts)} (+${Math.round(s.offsetMin)} min) [${s.kind === 'mail' ? 'mail' : s.origin}] ${s.title}${s.artifacts.length ? ' | ties: ' + s.artifacts.join('; ') : ''}${s.findings.length ? ' | findings: ' + s.findings.map((f) => f.title).join('; ') : ''}`,
        )
      const prompt = `Write the narrative of this attack chain for an incident report: 4 to 7 sentences, past tense, factual, no speculation beyond what the steps show, name the recipient, the seed mail, what tied the activity to it, and the impact. End with one sentence on what to verify or contain.\n\nRecipient: ${c.identityLabel}\nSeed ${c.seed.source ?? 'mails'}: "${c.seed.subject}" from ${c.seed.fromAddr} at ${fmtTs(c.seed.ts)} (risk ${c.seed.risk}; findings: ${c.seed.findings.map((f) => f.title).join(', ') || 'none'})\nScore ${c.score} (${c.severity}), ${c.steps.length} steps over ${fmtTs(c.start)} to ${fmtTs(c.end)}, ${c.artifactLinks} artifact link(s)\nSteps:\n${steps.join('\n')}`
      const msgs = await runAgent([{ role: 'user', content: prompt }], kase, { mode: 'report', tools: false, think: false, maxIterations: 1 })
      const text = msgs
        .filter((m) => m.role === 'assistant')
        .map((m) => m.content)
        .join('\n')
        .trim()
      if (!text) throw new Error('the model returned nothing')
      setNarrative(text)
      await chainPatch(c, { narrative: text, narrativeBy: 'ai' })
    } catch (e) {
      toast('err', `narrative: ${(e as Error).message}`)
    } finally {
      setDrafting(false)
    }
  }

  // ---- the model's proposals
  const suggestOne = async (it: ReviewItem) => {
    if (!kase || !modelReady()) return
    setSuggesting(true)
    try {
      const run = await runTriage(kase, [it], reviews, { apply: false })
      if (run.errors.length) toast('err', run.errors.join('; '), 0)
      else if (!run.entries.length) toast('err', `the model gave no usable decision${run.rejected.length ? `: ${run.rejected[0]}` : ''}`, 0)
      reload()
    } finally {
      setSuggesting(false)
    }
  }
  const accept = async (it: ReviewItem, s: Suggestion) => {
    if (!caseId) return
    await applySuggestion(caseId, it, s, reviews)
    setReviews(await loadChainReviews(caseId))
    reload()
  }
  const dismiss = async (target: string) => {
    if (!caseId) return
    setSuggestions(await removeSuggestion(caseId, target))
  }
  const startTriage = async () => {
    if (!kase || !modelReady()) return
    const items = triageDecided ? queue : queue.filter((it) => !it.done)
    setAskTriage(false)
    if (!items.length) return toast('ok', 'nothing to triage')
    const controller = new AbortController()
    triageAbort.current = controller
    setTriage({ done: 0, total: items.length, batch: 0, batches: 0 })
    try {
      // The model proposes; the analyst decides. Text in the evidence (a mail subject becomes an
      // incident title) can steer a model, and a pass that wrote its answers straight away could
      // take a critical incident out of the report with nobody looking. Each proposal waits on its
      // item, with its reason, for the analyst to apply or dismiss.
      const run = await runTriage(kase, items, reviews, {
        apply: false,
        signal: controller.signal,
        onProgress: setTriage,
      })
      setSuggestions(await loadSuggestions(kase.id!))
      setLastRun(run)
      setShowRun(true)
      setReviews(await loadChainReviews(kase.id!))
      reload()
    } catch (e) {
      toast('err', `triage: ${(e as Error).message}`, 0)
    } finally {
      triageAbort.current = null
      setTriage(null)
    }
  }
  const undo = async (entry: TriageEntry) => {
    if (!caseId || !lastRun) return
    await undoEntry(caseId, entry)
    const run = { ...lastRun, entries: lastRun.entries.map((e) => (e.id === entry.id ? { ...e, undone: true } : e)) }
    setLastRun(run)
    await getDb().kv.put({ key: `ai-triage-${caseId}`, value: run })
    setReviews(await loadChainReviews(caseId))
    reload()
  }
  const undoAll = async () => {
    if (!caseId || !lastRun) return
    for (const e of lastRun.entries) if (!e.undone) await undoEntry(caseId, e)
    const run = { ...lastRun, entries: lastRun.entries.map((e) => ({ ...e, undone: true })) }
    setLastRun(run)
    await getDb().kv.put({ key: `ai-triage-${caseId}`, value: run })
    setReviews(await loadChainReviews(caseId))
    reload()
  }

  // keyboard: j / k or arrows move; r reviewed, e confirmed, f false positive, x toggles report exclusion
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement | null
      if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable)) return
      if (showRun || askTriage) return
      if (e.key === 'j' || e.key === 'ArrowRight') return go(1)
      if (e.key === 'k' || e.key === 'ArrowLeft') return go(-1)
      if (!current) return
      if (current.kind === 'chain' && current.chain) {
        if (e.key === 'r') void chainPatch(current.chain, { verdict: 'unsure' })
        if (e.key === 'e') void chainPatch(current.chain, { verdict: 'confirmed' })
        if (e.key === 'f') void chainPatch(current.chain, { verdict: 'benign' })
        if (e.key === 'x') void chainPatch(current.chain, { include: !chainIncluded(current.chain, reviews[current.chain.id]) })
      } else if (current.incident) {
        if (e.key === 'r') void setStatus(current.incident, 'reviewed')
        if (e.key === 'e') void setStatus(current.incident, 'escalated')
        if (e.key === 'f') void setStatus(current.incident, 'false_positive')
        if (e.key === 'x') void exclude(current.incident, !current.incident.findings.every((f) => f.reportExclude))
      }
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [current, go, setStatus, exclude, chainPatch, reviews, showRun, askTriage])

  if (!kase || !settings) return null
  const ch = current?.kind === 'chain' ? current.chain : undefined
  const inc = current?.kind === 'chain' ? undefined : current?.incident
  const chainInc = current?.kind === 'chain' ? current.incident : undefined
  const chRev = ch ? reviews[ch.id] : undefined
  const members = (chainInc?.findings ?? []).filter((f) => f.ruleId !== 'chain')
  const excluded = inc ? inc.findings.length > 0 && inc.findings.every((f) => f.reportExclude) : false
  const willPrint = (sev: Severity) => SEVERITIES.indexOf(sev) <= SEVERITIES.indexOf(settings.minSeverity)
  const aiTag = (it: ReviewItem) => (it.kind === 'chain' ? reviews[it.chain!.id]?.by === 'ai' : it.incident!.lead.decidedBy === 'ai')
  const modelName = aiCfg.transport === 'claude' ? `Claude (${aiCfg.claudeModel})` : aiCfg.model || 'the default model'
  /** what the rail says under an item: the rules and the first values they matched */
  const factsLine = (it: ReviewItem) => {
    if (it.kind === 'chain' || !it.incident) return it.sub
    const gs = groupByRule(it.incident.findings, it.incident.entities)
    const values = gs.flatMap((g) => g.values).slice(0, 2)
    return `${gs.length} rule${gs.length === 1 ? '' : 's'} · ${fmtNum(it.incident.refs.length)} rows${values.length ? ' · ' + values.map((v) => trim(v, 40)).join(' · ') : ''}`
  }
  const effectLine = (options: { id: string; label: string }[]) => {
    const parts = options.map((o) => ({ ...o, to: effectOf(o.id) })).filter((o) => o.to)
    return parts.length ? <div className="effect">{parts.map((o) => `${o.label} → ${o.to}`).join(' · ')}</div> : null
  }

  const suggestionBox = (it: ReviewItem, s: Suggestion) => (
    <div className="suggestion" key={s.target}>
      <div className="row" style={{ gap: 8, alignItems: 'baseline' }}>
        <b>the model proposes</b>
        <span className="small muted">
          {s.by === 'chat' ? 'from the AI analyst chat' : 'asked from this page'}
          {s.model ? ` · ${s.model}` : ''} · {fmtTs(s.at)}
          {s.target.startsWith('finding:') ? ` · on finding #${s.target.slice(8)}` : ''}
        </span>
      </div>
      <div className="row wrap" style={{ gap: 10 }}>
        {s.decision && <Badge sev={DECISION_SEV[s.decision]}>{DECISION_LABEL[s.decision] ?? s.decision}</Badge>}
        {s.severity && (
          <span className="row" style={{ gap: 4 }}>
            <span className="small muted">severity</span>
            <Sev sev={s.severity} />
          </span>
        )}
        {s.include !== undefined && <span className="small">{s.include ? 'in the report' : 'not in the report'}</span>}
        {s.unlink?.length ? (
          <span className="small">
            unlink {s.unlink.length} finding{s.unlink.length === 1 ? '' : 's'}: {s.unlink.map((id) => members.find((f) => f.id === id)?.title ?? `#${id}`).join('; ')}
          </span>
        ) : null}
      </div>
      <div className="small">{s.reason}</div>
      {(s.narrative || s.note) && (
        <div className="small muted" style={{ whiteSpace: 'pre-wrap' }}>
          <b>{s.narrative ? 'narrative' : 'note'}:</b> {(s.narrative ?? s.note ?? '').slice(0, 600)}
          {(s.narrative ?? s.note ?? '').length > 600 ? '…' : ''}
        </div>
      )}
      <div className="row" style={{ gap: 6 }}>
        <button className="btn sm primary" onClick={() => accept(it, s)}>
          apply
        </button>
        <button className="btn sm ghost" onClick={() => dismiss(s.target)}>
          dismiss
        </button>
      </div>
    </div>
  )

  return (
    <div className="view">
      <div className="view-header">
        <div className="desc">
          <h1>Review</h1>
          <span className="sub">
            {fmtNum(done)} of {fmtNum(queue.length)} decided{aiDecided ? ` (${aiDecided} by the model)` : ''} · {chains.length} chain{chains.length === 1 ? '' : 's'},{' '}
            {incidents.filter((i) => i.kind !== 'chain').length} other incident{incidents.filter((i) => i.kind !== 'chain').length === 1 ? '' : 's'} · j / k move · e confirmed · r reviewed · f false
            positive · x in / out of the report
          </span>
        </div>
        <span className="spacer" />
        <button
          className={classNames('pill', !showDone && 'active')}
          onClick={() => {
            setShowDone(!showDone)
            setIdx(0)
          }}
        >
          {showDone ? 'hide decided' : 'showing undecided only'}
        </button>
        {lastRun && (
          <button className="btn ghost sm" onClick={() => setShowRun(true)}>
            last AI triage
          </button>
        )}
        <button className="btn sm" disabled={!!triage} onClick={() => setAskTriage(true)}>
          <IconAi /> triage with the model
        </button>
      </div>
      {report && <VerdictBar verdict={report.verdict} confidence={report.confidence} profile={report.profile} done={done} total={queue.length} onReport={() => setView('report')} />}
      {triage && (
        <div className="bulkbar">
          <Spinner />
          <span>
            AI triage · {triage.batches ? `batch ${triage.batch} of ${triage.batches} · ` : ''}
            {triage.done} of {triage.total} items · {modelName}
          </span>
          <span style={{ flex: 1, minWidth: 120 }}>
            <Progress value={triage.total ? triage.done / triage.total : 0} />
          </span>
          <button className="btn xs danger" onClick={() => triageAbort.current?.abort()}>
            <IconStop /> stop
          </button>
        </div>
      )}
      <details className="report-contents">
        <summary>
          report contents · from {settings.minSeverity} up · chain steps {settings.chainDetail}
          {settings.onlyReviewed ? ' · reviewed items only' : ''}
          {settings.includeFp ? ' · false positives included' : ''}
        </summary>
        <div className="row wrap" style={{ gap: 12, padding: '8px 0' }}>
          <label className="pill active">
            from{' '}
            <select value={settings.minSeverity} onChange={(e) => saveSettings({ minSeverity: e.target.value as Severity })}>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>{' '}
            up
          </label>
          <label className="pill active">
            chain steps{' '}
            <select value={settings.chainDetail} onChange={(e) => saveSettings({ chainDetail: e.target.value as ReportSettings['chainDetail'] })}>
              <option value="linked">tied to the mail or with a finding</option>
              <option value="weighted">plus weighted steps</option>
              <option value="all">every step</option>
            </select>
          </label>
          <Toggle on={settings.includeChains} onChange={(v) => saveSettings({ includeChains: v })} label="chains" />
          <Toggle on={settings.includeGraphs} onChange={(v) => saveSettings({ includeGraphs: v })} label="chain graphs" />
          <Toggle on={settings.includeTimeline} onChange={(v) => saveSettings({ includeTimeline: v })} label="case timeline" />
          <Toggle on={settings.includeTasks} onChange={(v) => saveSettings({ includeTasks: v })} label="tasks" />
          <Toggle on={settings.includeNotes} onChange={(v) => saveSettings({ includeNotes: v })} label="notes" />
          <Toggle on={settings.includeIocs} onChange={(v) => saveSettings({ includeIocs: v })} label="indicators" />
          <Toggle on={settings.includeEvidence} onChange={(v) => saveSettings({ includeEvidence: v })} label="evidence" />
          <Toggle on={settings.onlyReviewed} onChange={(v) => saveSettings({ onlyReviewed: v })} label="only what was reviewed" />
          <Toggle on={settings.includeFp} onChange={(v) => saveSettings({ includeFp: v })} label="false positives" />
        </div>
      </details>
      <div className="split" style={{ gridTemplateColumns: '340px 1fr' }}>
        <div className="left review-rail">
          {!visible.length && (
            <div className="muted small" style={{ padding: 14 }}>
              {queue.length ? 'everything is decided' : 'run the rules and build the chains first'}
            </div>
          )}
          {groups.map((g) => {
            if (!g.items.length) return null
            const start = visible.indexOf(g.items[0])
            return (
              <div key={g.id} className="group">
                <div className="group-head">
                  <span>{g.label}</span>
                  <span className="mono">{g.items.length}</span>
                </div>
                {g.items.map((it, j) => {
                  const i = start + j
                  return (
                    <div key={it.id} className={classNames('item', i === idx && 'active', it.done && 'done')} onClick={() => setIdx(i)}>
                      <Dot sev={it.severity} />
                      <div style={{ minWidth: 0 }}>
                        <div className="title ellipsis">{it.title}</div>
                        <div className="sub ellipsis" title={factsLine(it)}>
                          {factsLine(it)}
                        </div>
                      </div>
                      <div className="col" style={{ alignItems: 'flex-end', gap: 2 }}>
                        {it.done ? (
                          <Badge sev={it.kind === 'chain' ? chainDecision(reviews[it.chain!.id]) : STATUS_SEV[it.incident!.status as Status]}>
                            {it.kind === 'chain' ? reviews[it.chain!.id]?.verdict : STATUS_LABEL[it.incident!.status as Status]}
                          </Badge>
                        ) : (
                          <span className="small muted">{i === idx ? 'now' : ''}</span>
                        )}
                        {aiTag(it) && (
                          <span className="ai-tag" title="decided by the model; open the item for its reason">
                            AI
                          </span>
                        )}
                        {suggestionsFor(it, suggestions).length > 0 && !it.done && (
                          <span className="ai-tag proposal" title="the model proposed a decision">
                            proposal
                          </span>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            )
          })}
        </div>
        <div className="right" style={{ overflow: 'auto', padding: 16 }}>
          {!undecided && queue.length > 0 && report && (
            <div className="review-done">
              <IconCheck />
              <span>
                Every item is decided. The report will open on <b>{report.verdict.label}</b>
                {report.verdict.severity ? ` (${report.verdict.severity})` : ''}, confidence {report.confidence.level}.
              </span>
              <button className="btn sm primary" onClick={() => setView('report')}>
                <IconReport /> print the report
              </button>
            </div>
          )}
          {!current && <div className="muted">Nothing to review{showDone ? '' : ' that is still undecided'}.</div>}

          {inc && current && (
            <div className="review-card">
              <div className="head">
                <Sev sev={inc.severity} />
                <div className="col" style={{ gap: 4, flex: 1 }}>
                  <h2>{inc.title}</h2>
                  <div className="small muted">
                    {inc.subtitle} · {inc.kind} · {fmtTs(inc.ts)}
                    {inc.tsEnd && inc.tsEnd !== inc.ts ? ` → ${fmtTs(inc.tsEnd)}` : ''} · {fmtNum(inc.refs.length)} row(s)
                  </div>
                </div>
                <span className={`stamp st-${inc.status}`}>{STATUS_LABEL[inc.status as Status]}</span>
              </div>
              <div className="section">
                <h3>
                  What was seen <span className="muted">· one line per rule, with the values it matched</span>
                </h3>
                <Facts findings={inc.findings} said={inc.entities} />
                <div className="row wrap" style={{ gap: 6, marginTop: 6 }}>
                  {Object.entries(inc.entities)
                    .slice(0, 8)
                    .map(([k, v]) => {
                      const kind = entityKind(k)
                      return (
                        <span key={k} className={classNames('pill', kind && 'click')} onClick={() => kind && setEntity({ kind, value: String(v) })} title={kind ? 'open the entity page' : k}>
                          <span className="muted">{k}</span> {String(v)}
                        </span>
                      )
                    })}
                  {inc.kind === 'mail' && (
                    <span
                      className="pill click"
                      onClick={() => {
                        setFocus({ source: 'mails', id: inc.refs[0] })
                        setView('mails')
                      }}
                    >
                      open the mail
                    </span>
                  )}
                </div>
              </div>
              <div className="decide">
                <div className="choices">
                  {DECISIONS.map((d) => (
                    <button key={d.id} className={classNames('choice', d.tone, inc.status === d.id && 'active')} onClick={() => setStatus(inc, d.id)}>
                      {d.label} <kbd>{d.key}</kbd>
                    </button>
                  ))}
                </div>
                {effectLine(DECISIONS)}
                <div className="controls">
                  <span>
                    <span className="lbl">severity</span>
                    <span className="segmented">
                      {SEVERITIES.map((s) => (
                        <button
                          key={s}
                          className={classNames(inc.severity === s && 'active')}
                          onClick={() => rescore(inc, s)}
                          title={inc.lead.severityOverride ? `rule severity ${inc.lead.severity}` : 'rescore the incident'}
                        >
                          {s}
                        </button>
                      ))}
                    </span>
                    {inc.findings.some((f) => f.severityOverride) && (
                      <button className="btn link small" onClick={() => rescore(inc, null)}>
                        reset
                      </button>
                    )}
                  </span>
                  <Toggle
                    on={!excluded}
                    onChange={(v) => exclude(inc, !v)}
                    label={willPrint(inc.severity) && !excluded && (inc.status !== 'false_positive' || settings.includeFp) ? 'in the report' : 'not in the report'}
                  />
                </div>
              </div>
              {inc.lead.decidedBy === 'ai' && inc.lead.aiReason && (
                <div className="ai-note">
                  <b>decided by the model:</b> {inc.lead.aiReason} <span className="muted">· change the decision above to make it yours</span>
                </div>
              )}
              {inc.findings.some((f) => f.chainUnlinked) && (
                <div className="ai-note">
                  <b>unlinked from its attack chain</b> · decided here on its own.{' '}
                  <button
                    className="btn link small"
                    onClick={() =>
                      unlink(
                        inc.findings.filter((f) => f.chainUnlinked).map((f) => f.id!),
                        false,
                      )
                    }
                  >
                    link back to the chain
                  </button>
                </div>
              )}
              {pending.map((s) => suggestionBox(current, s))}
              <div className="section">
                <h3>
                  Analyst note <span className="muted">(printed with the incident)</span>
                </h3>
                <textarea
                  className="textarea"
                  style={{ minHeight: 80 }}
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  onBlur={() => saveNote(inc)}
                  placeholder="what this is, what was checked, what was decided…"
                />
                {inc.lead.notesBy === 'ai' && inc.lead.notes && <div className="small muted">written by the model during triage; edit it to make it yours (the next triage then leaves it alone)</div>}
              </div>
              <div className="row wrap" style={{ gap: 6 }}>
                <button className="btn sm ghost" onClick={() => go(-1)}>
                  <IconArrowLeft /> previous
                </button>
                <button className="btn sm" onClick={() => openRows(inc)} disabled={inc.source === 'mixed'}>
                  open the rows
                </button>
                <AddToTimeline ts={inc.ts} text={`${inc.title}: ${inc.lead.title}`} link={{ source: 'findings', id: inc.lead.id!, label: inc.lead.ruleId }} severity={inc.severity} />
                <button className="btn sm" disabled={suggesting} onClick={() => suggestOne(current)}>
                  {suggesting ? <Spinner /> : <IconAi />} ask the model to decide
                </button>
                <button
                  className="btn sm"
                  onClick={() => {
                    useStore
                      .getState()
                      .setAiPrompt(
                        `Assess this incident for the report and record your proposal with suggest_review. "${inc.title}" (${inc.severity}), findings: ${inc.findings.map((f) => `#${f.id} ${f.severity} ${f.title}`).join('; ')}. Entities: ${JSON.stringify(inc.entities)}. Referenced ${inc.source} rows: ${inc.refs.slice(0, 20).join(', ')}.`,
                      )
                    setView('ai')
                  }}
                >
                  <IconAi /> ask the analyst
                </button>
                <span className="spacer" />
                <button
                  className="btn sm primary"
                  onClick={() => {
                    if (inc.status === 'new') void setStatus(inc, 'reviewed')
                    go(1)
                  }}
                >
                  <IconCheck /> {inc.status === 'new' ? 'mark reviewed and next' : 'next'}
                </button>
              </div>
            </div>
          )}

          {ch && current && (
            <div className="review-card">
              <div className="head">
                <Sev sev={chainSeverity(ch, chRev)} />
                <div className="col" style={{ gap: 4, flex: 1 }}>
                  <h2>Attack chain · {ch.identityLabel}</h2>
                  <div className="small muted">
                    score {ch.score} · {ch.steps.length} steps · {ch.artifactLinks} artifact link(s) · {fmtTs(ch.start)} → {fmtTs(ch.end)} · seed "{ch.seed.subject}" from {ch.seed.fromAddr}
                  </div>
                </div>
                {chRev?.verdict && (
                  <span className={`stamp ${chRev.verdict === 'confirmed' ? 'st-escalated' : chRev.verdict === 'benign' ? 'st-false_positive' : 'st-reviewed'}`}>{chRev.verdict}</span>
                )}
              </div>
              <div className="section">
                <h3>
                  What was seen <span className="muted">· the findings whose rows are steps of this chain; the verdict sets their status, unlink one to decide on it separately</span>
                </h3>
                {members.length ? (
                  <Facts findings={members} said={{}} onUnlink={(ids) => unlink(ids, true)} />
                ) : (
                  <div className="small muted">
                    no finding has its rows among the chain's steps{findings.some((f) => f.chainUnlinked) ? ' (some were unlinked and sit in the queue on their own)' : ''}
                  </div>
                )}
                <div className="small" style={{ marginTop: 6 }}>
                  {ch.summary}
                </div>
                {ch.scoreBreakdown && (
                  <div className="small mono muted">
                    score {ch.score} = seed {ch.scoreBreakdown.seed} + links {ch.scoreBreakdown.links} + steps {ch.scoreBreakdown.steps} + findings {ch.scoreBreakdown.findings} + sources{' '}
                    {ch.scoreBreakdown.sources}
                    {ch.scoreBreakdown.cap ? ` · capped at ${ch.scoreBreakdown.cap}` : ''} · the report prints {ch.steps.filter((s) => stepVisible(s, settings.chainDetail)).length} of{' '}
                    {ch.steps.length} steps at the "{settings.chainDetail}" level
                  </div>
                )}
              </div>
              <div className="decide">
                <div className="choices">
                  {VERDICTS.map((v) => (
                    <button key={v.id} className={classNames('choice', v.tone, chRev?.verdict === v.id && 'active')} onClick={() => chainPatch(ch, { verdict: v.id })}>
                      {v.label} <kbd>{v.key}</kbd>
                    </button>
                  ))}
                </div>
                {effectLine(VERDICTS)}
                <div className="controls">
                  <span>
                    <span className="lbl">severity</span>
                    <span className="segmented">
                      {SEVERITIES.map((s) => (
                        <button key={s} className={classNames(chainSeverity(ch, chRev) === s && 'active')} onClick={() => chainPatch(ch, { severityOverride: s === ch.severity ? undefined : s })}>
                          {s}
                        </button>
                      ))}
                    </span>
                  </span>
                  <Toggle
                    on={chainIncluded(ch, chRev)}
                    onChange={(v) => chainPatch(ch, { include: v })}
                    label={chainIncluded(ch, chRev) && willPrint(chainSeverity(ch, chRev)) && settings.includeChains ? 'in the report' : 'not in the report'}
                  />
                </div>
              </div>
              {chRev?.by === 'ai' && chRev.aiReason && (
                <div className="ai-note">
                  <b>decided by the model:</b> {chRev.aiReason} <span className="muted">· set the verdict above to make it yours</span>
                </div>
              )}
              {pending.map((s) => suggestionBox(current, s))}
              {members.length > 1 && (
                <div className="row">
                  <button
                    className="btn sm ghost"
                    onClick={() =>
                      unlink(
                        members.map((f) => f.id!),
                        true,
                      )
                    }
                  >
                    unlink all {members.length}
                  </button>
                </div>
              )}
              <div className="section">
                <h3>
                  Narrative <span className="muted">(replaces the automatic summary in the report)</span>
                </h3>
                <textarea
                  className="textarea"
                  style={{ minHeight: 140 }}
                  value={narrative}
                  onChange={(e) => setNarrative(e.target.value)}
                  onBlur={() => {
                    if (narrative !== (chRev?.narrative ?? '')) void chainPatch(ch, { narrative, narrativeBy: narrative ? 'analyst' : undefined })
                  }}
                  placeholder="what happened, in order, and what tied it to the mail…"
                />
                {chRev?.narrativeBy === 'ai' && chRev.narrative && (
                  <div className="small muted">written by the model during triage; edit it to make it yours (the next triage then leaves it alone)</div>
                )}
                <div className="row" style={{ gap: 6 }}>
                  <button className="btn sm" disabled={drafting} onClick={() => draft(ch)}>
                    {drafting ? <Spinner /> : <IconAi />} draft with the analyst
                  </button>
                  <span className="small muted">the model only sees the chain's steps; edit before you keep it</span>
                </div>
              </div>
              <div className="row wrap" style={{ gap: 6 }}>
                <button className="btn sm ghost" onClick={() => go(-1)}>
                  <IconArrowLeft /> previous
                </button>
                <button
                  className="btn sm"
                  onClick={() => {
                    setFocusChain(ch.id)
                    setView('chains')
                  }}
                >
                  open the chain
                </button>
                <AddToTimeline
                  ts={ch.start}
                  text={`Attack chain ${ch.identityLabel}: ${chRev?.narrative?.slice(0, 200) || ch.summary}`}
                  link={{ source: 'chains', id: ch.id, label: ch.identityLabel }}
                  severity={chainSeverity(ch, chRev)}
                />
                <button className="btn sm" disabled={suggesting} onClick={() => suggestOne(current)}>
                  {suggesting ? <Spinner /> : <IconAi />} ask the model to decide
                </button>
                <span className="spacer" />
                <button
                  className="btn sm primary"
                  onClick={() => {
                    if (!chRev?.verdict) void chainPatch(ch, { verdict: 'unsure' })
                    go(1)
                  }}
                >
                  <IconCheck /> {chRev?.verdict ? 'next' : 'mark unsure and next'}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {askTriage && (
        <Modal
          title="Triage with the model"
          onClose={() => setAskTriage(false)}
          footer={
            <>
              <button className="btn ghost sm" onClick={() => setAskTriage(false)}>
                cancel
              </button>
              <button className="btn primary sm" onClick={startTriage}>
                <IconAi /> start
              </button>
            </>
          }
        >
          <div className="col" style={{ gap: 10 }}>
            <div>
              The model proposes a decision on every item in the queue: a verdict or decision, a severity, whether the report carries it, and a reason. Nothing is written. Each proposal waits on its
              item, tagged "AI", until you apply or dismiss it. Text in the evidence can try to steer a model, so a proposal to lower a severity or leave an item out of the report deserves a second
              look.
            </div>
            <div className="small muted">
              {modelName} ·{' '}
              {aiCfg.transport === 'claude'
                ? 'Claude Code on the server machine: the items (findings, entities, chain steps) leave for Anthropic'
                : aiCfg.transport === 'browser'
                  ? 'your local Ollama: nothing leaves this machine'
                  : "the server's Ollama"}{' '}
              · {aiCfg.transport === 'claude' ? 8 : 4} items per call
            </div>
            <Toggle on={triageDecided} onChange={setTriageDecided} label={`re-triage the ${done} item${done === 1 ? '' : 's'} already decided too`} />
            <div>
              <b>{fmtNum(triageDecided ? queue.length : undecided)}</b> item{(triageDecided ? queue.length : undecided) === 1 ? '' : 's'} will be sent.
            </div>
          </div>
        </Modal>
      )}

      {showRun && lastRun && (
        <Modal
          wide
          title={
            <span>
              AI triage · {lastRun.entries.filter((e) => !e.undone).length} {lastRun.proposed ? 'proposal' : 'decision'}
              {lastRun.entries.filter((e) => !e.undone).length === 1 ? '' : 's'}{' '}
              <span className="muted small">
                · {fmtTs(lastRun.at)}
                {lastRun.model ? ` · ${lastRun.model}` : ''}
              </span>
            </span>
          }
          onClose={() => setShowRun(false)}
          footer={
            <>
              {lastRun.proposed ? (
                <span className="small muted">nothing was written: apply or dismiss each proposal on its item</span>
              ) : (
                <button className="btn ghost sm" disabled={lastRun.entries.every((e) => e.undone)} onClick={undoAll}>
                  undo all
                </button>
              )}
              <span className="spacer" />
              <button className="btn primary sm" onClick={() => setShowRun(false)}>
                close
              </button>
            </>
          }
        >
          <div className="col" style={{ gap: 10 }}>
            <div className="small">
              {(['confirmed', 'escalated', 'unsure', 'reviewed', 'benign', 'false_positive'] as const).map((d) => {
                const n = lastRun.entries.filter((e) => e.decision === d && !e.undone).length
                return n ? (
                  <span key={d} style={{ marginRight: 12 }}>
                    <Badge sev={DECISION_SEV[d]}>{SUMMARY_LABEL[d]}</Badge> {n}
                  </span>
                ) : null
              })}
              {lastRun.entries.some((e) => e.severityBefore !== e.severityAfter && !e.undone) && (
                <span style={{ marginRight: 12 }}>rescored {lastRun.entries.filter((e) => e.severityBefore !== e.severityAfter && !e.undone).length}</span>
              )}
              {lastRun.entries.some((e) => e.unlinked.length && !e.undone) && (
                <span>unlinked {lastRun.entries.reduce((n, e) => n + (e.undone ? 0 : e.unlinked.length), 0)} finding(s), now in the queue on their own</span>
              )}
              {lastRun.entries.some((e) => e.wrote && !e.undone) && (
                <span style={{ marginRight: 12 }}>
                  wrote {lastRun.entries.filter((e) => e.wrote === 'narrative' && !e.undone).length} narrative(s), {lastRun.entries.filter((e) => e.wrote === 'note' && !e.undone).length} note(s)
                </span>
              )}
              {lastRun.summaryDrafted && <span style={{ marginRight: 12 }}>executive summary drafted</span>}
              {lastRun.asked > lastRun.entries.length && (
                <span className="muted">
                  {' '}
                  · {lastRun.asked - lastRun.entries.length} of {lastRun.asked} item(s) got no decision
                </span>
              )}
            </div>
            {lastRun.errors.length > 0 && (
              <div className="small" style={{ color: 'var(--sev-high)' }}>
                {lastRun.errors.join(' · ')}
              </div>
            )}
            {lastRun.rejected.length > 0 && (
              <div className="small muted">
                not applied: {lastRun.rejected.slice(0, 6).join(' · ')}
                {lastRun.rejected.length > 6 ? ` · +${lastRun.rejected.length - 6}` : ''}
              </div>
            )}
            <table className="table compact triage-table">
              <thead>
                <tr>
                  <th>item</th>
                  <th>decision</th>
                  <th>severity</th>
                  <th>report</th>
                  <th>reason</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {lastRun.entries.map((e) => (
                  <tr key={e.id} className={classNames(e.undone && 'undone')}>
                    <td className="sans">
                      <span className="muted">{e.kind === 'chain' ? 'chain · ' : ''}</span>
                      {e.title}
                      {e.unlinked.length ? <div className="small muted">unlinked: {e.unlinked.map((u) => u.title).join('; ')}</div> : null}
                    </td>
                    <td>
                      <Badge sev={DECISION_SEV[e.decision]}>{DECISION_LABEL[e.decision] ?? e.decision}</Badge>
                    </td>
                    <td className="nowrap">
                      {e.severityBefore !== e.severityAfter ? (
                        <span>
                          <Sev sev={e.severityBefore} /> → <Sev sev={e.severityAfter} />
                        </span>
                      ) : (
                        <Sev sev={e.severityAfter} />
                      )}
                    </td>
                    <td className="nowrap">
                      {e.includeAfter ? 'in' : 'out'}
                      {e.includeBefore !== e.includeAfter ? <span className="muted"> (was {e.includeBefore ? 'in' : 'out'})</span> : null}
                    </td>
                    <td className="sans small">
                      {e.reason}
                      {e.wrote && !e.undone ? <span className="muted"> · {e.wrote} written</span> : null}
                    </td>
                    <td className="nowrap">
                      {lastRun.proposed ? (
                        <span className="small muted">proposed</span>
                      ) : e.undone ? (
                        <span className="small muted">undone</span>
                      ) : (
                        <button className="btn link small" onClick={() => undo(e)}>
                          undo
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Modal>
      )}
    </div>
  )
}
