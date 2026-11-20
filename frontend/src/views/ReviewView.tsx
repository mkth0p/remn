import { useCallback, useEffect, useMemo, useState } from 'react'
import { runAgent } from '../ai/chat'
import { IconAi, IconCheck, IconReport } from '../components/Icons'
import { VerdictBar } from '../components/VerdictBar'
import { suggestionsFor } from '../data/aiReview'
import type { Chain } from '../data/chains'
import {
  applyChainVerdict,
  chainIncluded,
  chainSeverity,
  overridesForIncident,
  reviewQueue,
  saveChainReview,
  saveReportSettings,
  setChainUnlinked,
  stepVisible,
  type ChainReview,
  type ReportSettings,
  type ReviewItem,
} from '../data/review'
import { getDb, type Severity } from '../db/schema'
import { buildIncidents, type Incident } from '../rules/incidents'
import { toast, useStore } from '../state/store'
import { classNames, fmtNum, fmtTs } from '../util/format'
import { ChainCard } from './review/ChainCard'
import { IncidentCard } from './review/IncidentCard'
import { DECISIONS, modelNameOf, VERDICTS, type Status } from './review/model'
import { ReportContents } from './review/ReportContents'
import { ReviewRail } from './review/ReviewRail'
import { SuggestionBox } from './review/SuggestionBox'
import { AskTriageModal, TriageProgressBar, TriageRunModal } from './review/TriageDialogs'
import { useReviewData } from './review/useReviewData'
import { useReviewReport } from './review/useReviewReport'
import { modelReady, useReviewTriage } from './review/useReviewTriage'

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
  const setEventsFilter = useStore((s) => s.setEventsFilter)
  const setMailsFilter = useStore((s) => s.setMailsFilter)
  const caseId = kase?.id
  const { findings, evidence, chains, reviews, setReviews, settings, setSettings, stories, suggestions, setSuggestions, lastRun, setLastRun, reload } = useReviewData(caseId)
  const [idx, setIdx] = useState(0)
  const [showDone, setShowDone] = useState(true)
  const [drafting, setDrafting] = useState(false)
  const [note, setNote] = useState('')
  const [narrative, setNarrative] = useState('')
  // a case change or a rule run starts the queue over
  useEffect(() => setIdx(0), [caseId, rulesVersion])

  const incidents = useMemo(() => buildIncidents(findings, { chains, severityOf: (c) => chainSeverity(c, reviews[c.id]) }), [findings, chains, reviews])
  const queue = useMemo(() => reviewQueue(incidents, chains, reviews), [incidents, chains, reviews])
  const done = queue.filter((i) => i.done).length
  const undecided = queue.length - done
  const aiDecided = queue.filter((it) => (it.kind === 'chain' ? reviews[it.chain!.id]?.by === 'ai' : it.incident!.lead.decidedBy === 'ai')).length
  // the rail: what is still to decide, what was confirmed, the rest
  const groups = useMemo(() => {
    const confirmedOf = (it: ReviewItem) => (it.kind === 'chain' ? reviews[it.chain!.id]?.verdict === 'confirmed' : it.incident!.status === 'escalated')
    const todo = queue.filter((i) => !i.done)
    const confirmed = queue.filter((i) => i.done && confirmedOf(i))
    const rest = queue.filter((i) => i.done && !confirmedOf(i))
    return [
      { id: 'todo', label: 'to decide', items: todo },
      { id: 'confirmed', label: 'confirmed', items: showDone ? confirmed : [] },
      { id: 'rest', label: 'reviewed, benign, false positive', items: showDone ? rest : [] },
    ]
  }, [queue, showDone, reviews])
  const visible = useMemo(() => groups.flatMap((g) => g.items), [groups])
  const current: ReviewItem | undefined = visible[Math.min(idx, Math.max(0, visible.length - 1))]
  const pending = useMemo(() => (current ? suggestionsFor(current, suggestions) : []), [current, suggestions])
  // editable text follows the current item
  useEffect(() => {
    setNote(current?.incident?.lead.notes ?? '')
    setNarrative(current?.chain ? (reviews[current.chain.id]?.narrative ?? '') : '')
  }, [current?.id, current?.incident?.lead.notes, current?.chain, reviews])
  const { report, effectOf } = useReviewReport({ kase, settings, findings, chains, reviews, evidence, undecided, stories, current })
  const { showRun, setShowRun, askTriage, setAskTriage, triageDecided, setTriageDecided, triage, stop, suggesting, suggestOne, accept, dismiss, startTriage, undo, undoAll } = useReviewTriage({
    kase,
    queue,
    reviews,
    setReviews,
    setSuggestions,
    lastRun,
    setLastRun,
    reload,
  })

  const go = useCallback((d: number) => setIdx((i) => Math.max(0, Math.min(visible.length - 1, i + d))), [visible.length])

  const setStatus = useCallback(
    async (inc: Incident, s: Status) => {
      const db = getDb()
      await Promise.all(inc.findings.map((f) => db.findings.update(f.id!, { status: s, decidedBy: 'analyst', decidedAt: Date.now() })))
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
    [caseId, incidents, reload, setReviews],
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
      const msgs = await runAgent([{ role: 'user', content: prompt }], kase, { mode: 'narrative', tools: false, think: false, maxIterations: 1 })
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
  const modelName = modelNameOf(aiCfg)
  const effectLine = (options: { id: string; label: string }[]) => {
    const parts = options.map((o) => ({ ...o, to: effectOf(o.id) })).filter((o) => o.to)
    return parts.length ? <div className="effect">{parts.map((o) => `${o.label} → ${o.to}`).join(' · ')}</div> : null
  }
  const proposals = (it: ReviewItem) => pending.map((s) => <SuggestionBox key={s.target} s={s} members={members} onApply={() => accept(it, s)} onDismiss={() => dismiss(s.target)} />)

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
      {triage && <TriageProgressBar triage={triage} modelName={modelName} onStop={stop} />}
      <ReportContents settings={settings} save={saveSettings} />
      <div className="split" style={{ gridTemplateColumns: '340px 1fr' }}>
        <ReviewRail groups={groups} visible={visible} idx={idx} setIdx={setIdx} queued={queue.length} reviews={reviews} suggestions={suggestions} />
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
            <IncidentCard
              inc={inc}
              settings={settings}
              effect={effectLine(DECISIONS)}
              proposals={proposals(current)}
              note={note}
              setNote={setNote}
              suggesting={suggesting}
              onStatus={(s) => setStatus(inc, s)}
              onRescore={(sev) => rescore(inc, sev)}
              onExclude={(on) => exclude(inc, on)}
              onSaveNote={() => saveNote(inc)}
              onLinkBack={(ids) => unlink(ids, false)}
              onOpenRows={() => openRows(inc)}
              onSuggest={() => suggestOne(current)}
              onPrevious={() => go(-1)}
              onNext={() => {
                if (inc.status === 'new') void setStatus(inc, 'reviewed')
                go(1)
              }}
            />
          )}

          {ch && current && (
            <ChainCard
              ch={ch}
              chRev={chRev}
              members={members}
              anyUnlinked={findings.some((f) => f.chainUnlinked)}
              settings={settings}
              effect={effectLine(VERDICTS)}
              proposals={proposals(current)}
              narrative={narrative}
              setNarrative={setNarrative}
              drafting={drafting}
              suggesting={suggesting}
              onPatch={(patch) => void chainPatch(ch, patch)}
              onUnlink={(ids) => unlink(ids, true)}
              onDraft={() => draft(ch)}
              onSuggest={() => suggestOne(current)}
              onPrevious={() => go(-1)}
              onNext={() => {
                if (!chRev?.verdict) void chainPatch(ch, { verdict: 'unsure' })
                go(1)
              }}
            />
          )}
        </div>
      </div>

      {askTriage && (
        <AskTriageModal
          aiCfg={aiCfg}
          decided={done}
          queued={queue.length}
          undecided={undecided}
          triageDecided={triageDecided}
          setTriageDecided={setTriageDecided}
          onClose={() => setAskTriage(false)}
          onStart={startTriage}
        />
      )}

      {showRun && lastRun && <TriageRunModal run={lastRun} onClose={() => setShowRun(false)} onUndo={undo} onUndoAll={undoAll} />}
    </div>
  )
}
