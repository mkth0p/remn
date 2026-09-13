import { useEffect, useMemo, useRef, useState } from 'react'
import type { Case } from '../db/schema'
import { useStore } from '../state/store'
import { getSource } from '../data/source'
import type { Story } from '../data/relationshipStories'
import { assessStory, type InvestigationStep } from '../data/relationshipIntelligence'
import { adviceFingerprint, advicePacket, loadHypothesisDecisions, reviewStory, saveHypothesisDecision, type RelationshipAdvice, type HypothesisDecision } from '../data/relationshipAssistant'
import type { RelationshipReview } from '../data/relationshipReviews'

export function RelationshipInvestigation({
  kase,
  story,
  partial,
  reviews,
  onOpen,
}: {
  kase: Case
  story: Story
  partial: boolean
  reviews: Record<string, RelationshipReview>
  onOpen: (source: 'events' | 'mails', id: number | null) => void
}) {
  const assessment = useMemo(() => assessStory(story, partial), [story, partial])
  const packet = useMemo(() => advicePacket(story, assessment), [story, assessment])
  const config = useStore((s) => s.aiConfig)
  const [advice, setAdvice] = useState<RelationshipAdvice | null>(null)
  const [decisions, setDecisions] = useState<HypothesisDecision[]>([])
  const [notes, setNotes] = useState('')
  const [fingerprint, setFingerprint] = useState('')
  const [busy, setBusy] = useState(false)
  const [status, setStatus] = useState('')
  const [error, setError] = useState('')
  const [search, setSearch] = useState<{ step: InvestigationStep; rows: { id: number | null; title: string }[]; truncated: boolean } | null>(null)
  const [searchBusy, setSearchBusy] = useState(false)
  const controller = useRef<AbortController | null>(null)
  const generation = useRef(0)
  useEffect(() => {
    const current = ++generation.current
    controller.current?.abort()
    setAdvice(null)
    setBusy(false)
    setSearchBusy(false)
    setSearch(null)
    setStatus('')
    setError('')
    setFingerprint('')
    setDecisions([])
    adviceFingerprint(story, assessment, reviews, config)
      .then(async (key) => {
        const saved = await loadHypothesisDecisions(kase.id!, key)
        if (current === generation.current) {
          setFingerprint(key)
          setDecisions(saved)
        }
      })
      .catch((e) => {
        if (current === generation.current) setError((e as Error).message)
      })
    return () => {
      generation.current = current + 1
      controller.current?.abort()
    }
  }, [story, assessment, reviews, config, kase.id])
  const ask = async () => {
    const current = generation.current,
      abort = new AbortController()
    controller.current = abort
    setBusy(true)
    setError('')
    setStatus('Reviewing this story…')
    try {
      const result = await reviewStory(kase, packet, fingerprint, abort.signal)
      if (current === generation.current) {
        setAdvice(result.advice)
        setStatus(result.cached ? 'Cached review · no new model request' : 'Review complete · one model request')
      }
    } catch (e) {
      if (current === generation.current) {
        setStatus('')
        setError(abort.signal.aborted ? 'Review cancelled.' : (e as Error).message)
      }
    } finally {
      if (current === generation.current) setBusy(false)
    }
  }
  const run = async (step: InvestigationStep) => {
    const current = generation.current
    setSearchBusy(true)
    setError('')
    try {
      const ds = getSource(kase)
      const result = step.source === 'events' ? await ds.searchEvents(step.filter, 50) : await ds.searchMails(step.filter, 50)
      if (current === generation.current)
        setSearch({ step, rows: result.rows.map((r) => ({ id: r.id ?? null, title: String(r.summary || r.subject || `${step.source} #${r.id}`) })), truncated: result.truncated })
    } catch (e) {
      if (current === generation.current) setError((e as Error).message)
    } finally {
      if (current === generation.current) setSearchBusy(false)
    }
  }
  const citations = (ids: string[]) =>
    ids.map((id) => {
      const r = story.records.find((record) => record.nodeId === id)
      return (
        r && (
          <button className="btn xs" key={id} disabled={r.id == null} onClick={() => onOpen(r.source, r.id)}>
            Open {r.source} #{r.id}
          </button>
        )
      )
    })
  return (
    <div className="view-body col" style={{ gap: 14, overflow: 'auto' }}>
      <div className="card">
        <strong>Association confidence: {assessment.confidence}</strong>
        <p>
          Severity: {story.severity} · based on findings. Priority score: {story.score}/100 · not a probability.
        </p>
        <p>
          Coverage: {assessment.coverage.uniqueRecords} unique records · {assessment.coverage.sources} source contents · {assessment.coverage.timed} event times · {assessment.coverage.snapshots}{' '}
          snapshots · {assessment.coverage.partial ? 'partial scan or reference sample' : 'current scan'}
        </p>
        <p className="small muted">
          Telemetry represented: {assessment.coverage.families.join(', ')}. Coverage describes imported evidence; it does not establish that all relevant telemetry was collected.
        </p>
        {assessment.reasons.map((reason) => (
          <div className="small" key={reason}>
            {reason}
          </div>
        ))}
      </div>
      <div className="card">
        <strong>Contradictions, alternatives and gaps</strong>
        {!assessment.issues.length && <p>No contradiction detected in the available fields. This does not prove a causal chain.</p>}
        {assessment.issues.map((issue) => (
          <div key={issue.id} style={{ marginTop: 10 }}>
            <b>{issue.kind}</b>: {issue.message}
            <div className="row wrap">
              {citations(issue.records)}
              {issue.related && (
                <button className="btn xs" disabled={issue.related.id == null} onClick={() => onOpen(issue.related!.source, issue.related!.id)}>
                  Open excluded record #{issue.related.id}
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
      <div className="card">
        <strong>Next useful checks</strong>
        <p className="small muted">Ranked by the uncertainty they can resolve. Each search reads up to 50 matching records and makes no AI request.</p>
        {assessment.steps.map((step) => (
          <details key={step.id} style={{ marginTop: 10 }}>
            <summary>{step.title}</summary>
            <p>{step.purpose}</p>
            <button className="btn sm" disabled={searchBusy} onClick={() => run(step)}>
              Search evidence
            </button>
            <p className="small muted">If unavailable: {step.collect}</p>
            <pre className="small">{JSON.stringify(step.filter, null, 2)}</pre>
          </details>
        ))}
        {search && (
          <div role="status">
            <p>
              {search.step.title}: {search.rows.length} matches{search.truncated ? ' (result limit reached)' : ''}.
            </p>
            {!search.rows.length && <p>No match in the searched evidence; this is not proof the activity did not happen. {search.step.collect}</p>}
            {search.rows.map((r, i) => (
              <div key={`${r.id}:${i}`}>
                <button className="btn xs" onClick={() => onOpen(search.step.source, r.id)}>
                  Open #{r.id}
                </button>{' '}
                {r.title}
              </div>
            ))}
          </div>
        )}
      </div>
      <div className="card">
        <strong>Evidence-bound AI review</strong>
        <p className="small muted">
          Uses your configured AI connection. One request, up to 30 records and 40 links; matching cached reviews are reused. AI explanations remain annotations. Hypotheses never become observed links
          automatically.
        </p>
        <button className="btn sm" disabled={busy || !fingerprint} onClick={ask}>
          Review selected story with AI
        </button>
        {busy && (
          <button className="btn sm" onClick={() => controller.current?.abort()}>
            Cancel review
          </button>
        )}
        <div role="status">{status}</div>
        {error && <p role="alert">{error}</p>}
        {advice?.claims.map((claim, i) => (
          <div key={i} style={{ marginTop: 12 }}>
            <b>{packet.edges.find((e) => e.id === claim.edgeId)?.assertion} link · AI annotation</b>
            <p>{claim.explanation}</p>
            <div className="row wrap">{citations(claim.citations)}</div>
          </div>
        ))}
        {advice?.hypotheses.map((hypothesis, i) => {
          const decision = decisions.find((d) => d.text === hypothesis.text && JSON.stringify(d.citations) === JSON.stringify(hypothesis.citations))
          return (
            <div key={i} className="card" style={{ marginTop: 12 }}>
              <b>Hypothesized · {decision?.status ?? 'unreviewed'}</b>
              <p>{hypothesis.text}</p>
              <div className="row wrap">{citations(hypothesis.citations)}</div>
              <p>Validate with: {assessment.steps.find((s) => s.id === hypothesis.checkId)?.title}</p>
              {decision?.notes && <p>Analyst: {decision.notes}</p>}
              {(['accepted', 'rejected'] as const).map((value) => (
                <button
                  key={value}
                  className="btn xs"
                  onClick={async () => {
                    const current = generation.current
                    try {
                      await saveHypothesisDecision(kase.id!, fingerprint, hypothesis, { status: value, notes })
                      const saved = await loadHypothesisDecisions(kase.id!, fingerprint)
                      if (current === generation.current) setDecisions(saved)
                    } catch (e) {
                      if (current === generation.current) setError((e as Error).message)
                    }
                  }}
                >
                  {value === 'accepted' ? 'Keep hypothesis' : 'Reject hypothesis'}
                </button>
              ))}
            </div>
          )
        })}
        {!!advice?.hypotheses.length && (
          <label>
            Analyst notes
            <textarea className="input" value={notes} onChange={(e) => setNotes(e.target.value)} maxLength={2000} />
          </label>
        )}
        {!!advice?.nextStepIds.length && <p>AI check order: {advice.nextStepIds.map((id) => assessment.steps.find((step) => step.id === id)?.title).join(' → ')}</p>}
      </div>
    </div>
  )
}
