import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Badge, Dot, Empty } from '../components/ui'
import { IconClose, IconExternal, IconQuestion } from '../components/Icons'
import { getDb, type Evidence, type Finding, type QuestionAnswer, type QuestionCitation } from '../db/schema'
import { loadEvidenceGaps } from '../data/evidenceGaps'
import { loadRules, type LoadedRule } from '../data/rules'
import { getSource } from '../data/source'
import {
  ANSWER_LABEL,
  ANSWER_STATUSES,
  addCitation,
  citationId,
  findingCitation,
  loadAnswers,
  loadScenarioChoice,
  removeCitation,
  resolveCitation,
  saveScenarioChoice,
  setAnswer,
  updateAnswer,
  type AnswerStatus,
} from '../data/questions/answers'
import { CATALOG, questionsOf, relatedRules, scenarioViews, type Question, type QuestionSearch } from '../data/questions/catalog'
import { activitySpan, coverage, loadEvidenceProfile, type EvidenceProfile } from '../data/questions/coverage'
import { effectiveSeverity } from '../rules/incidents'
import { isAbort } from '../data/queryClient'
import { toast, useStore } from '../state/store'
import { fmtNum, fmtTs } from '../util/format'

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
const STATUS_SEV: Record<AnswerStatus, string> = { open: 'medium', answered: 'ok', cannot: 'info' }

/**
 * Questions (docs/questions.md): the case read as the questions an investigation has to answer.
 * The analyst picks scenarios (DFIQ's, and REMN's own), and each of their questions shows what REMN
 * can answer it with (searches, related rules, whether the case holds the evidence) and takes the
 * analyst's answer, its status and the records and findings it cites. The report prints them.
 */
export function QuestionsView() {
  const kase = useStore((s) => s.currentCase)
  const mails = useStore((s) => s.counts.mails)
  const rulesVersion = useStore((s) => s.rulesVersion)
  const active = useStore((s) => s.activeQuestion)
  const setActive = useStore((s) => s.setActiveQuestion)
  const [scenarios, setScenarios] = useState<string[] | null>(null)
  const [answers, setAnswers] = useState<Map<string, QuestionAnswer>>(new Map())
  const [profile, setProfile] = useState<EvidenceProfile | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [rules, setRules] = useState<LoadedRule[]>([])
  const [picking, setPicking] = useState(false)
  const caseId = kase?.id
  useEffect(() => {
    if (!caseId) return
    loadScenarioChoice(caseId).then((s) => {
      setScenarios(s)
      setPicking(!s.length)
    })
    loadAnswers(caseId).then(setAnswers)
    getDb().evidence.where('caseId').equals(caseId).toArray().then(setEvidence)
  }, [caseId])
  useEffect(() => {
    if (!caseId) return
    getDb().findings.where('caseId').equals(caseId).toArray().then(setFindings)
    loadRules(caseId)
      .then(setRules)
      .catch(() => setRules([]))
  }, [caseId, rulesVersion])
  useEffect(() => {
    if (!kase) return
    loadEvidenceProfile(getSource(kase), mails)
      .then(setProfile)
      .catch(() => setProfile(null))
  }, [kase, mails])
  const views = useMemo(() => scenarioViews(scenarios ?? []), [scenarios])
  const questions = useMemo(() => questionsOf(scenarios ?? []), [scenarios])
  const selected = questions.find((q) => q.id === active) ?? questions[0] ?? null
  const toggleScenario = async (id: string) => {
    if (!caseId || !scenarios) return
    const next = scenarios.includes(id) ? scenarios.filter((s) => s !== id) : [...scenarios, id]
    await saveScenarioChoice(caseId, next)
    setScenarios(next)
  }
  const saved = (a: QuestionAnswer) => setAnswers((m) => new Map(m).set(a.questionId, a))
  if (!kase || !caseId || !scenarios) return null
  const counts = { open: 0, answered: 0, cannot: 0 } as Record<AnswerStatus, number>
  for (const q of questions) counts[answers.get(q.id)?.status ?? 'open']++
  return (
    <div className="view">
      <div className="view-header">
        <div className="desc">
          <h1>Questions</h1>
          <span className="sub">
            {questions.length
              ? `${fmtNum(questions.length)} question(s) · ${fmtNum(counts.answered)} answered · ${fmtNum(counts.cannot)} cannot be answered from this evidence · ${fmtNum(counts.open)} open`
              : 'pick the scenarios this case is about; their questions become its checklist'}
          </span>
        </div>
        <span className="spacer" />
        <button className={'btn sm' + (picking ? ' active' : '')} onClick={() => setPicking(!picking)}>
          scenarios ({scenarios.length})
        </button>
      </div>
      <div className="view-body col" style={{ gap: 12 }}>
        {picking && <ScenarioPicker chosen={scenarios} onToggle={toggleScenario} />}
        {!questions.length ? (
          !picking && <Empty title="No scenario chosen" hint="Choose one or more scenarios to get their questions." />
        ) : (
          <div className="qs-layout">
            <div className="qs-list" role="list" aria-label="Questions">
              {views.map((v) => (
                <div key={v.scenario.id} className="qs-scenario">
                  <div className="qs-scenario-h">
                    {v.scenario.name} <span className="dim mono">{v.scenario.id}</span>
                  </div>
                  {v.facets.map((f) => (
                    <div key={f.facet.id}>
                      <div className="qs-facet">{f.facet.name}</div>
                      {f.questions.map((q) => {
                        const status = answers.get(q.id)?.status ?? 'open'
                        const cov = profile ? coverage(q, profile) : null
                        return (
                          <button
                            key={q.id}
                            role="listitem"
                            className={'qs-item' + (selected?.id === q.id ? ' active' : '')}
                            onClick={() => setActive(q.id)}
                            title={`${ANSWER_LABEL[status]}${cov ? ` · ${cov.text}` : ''}`}
                          >
                            <Dot sev={STATUS_SEV[status]} />
                            <span className="mono dim">{q.id}</span>
                            <span className="qs-name">{q.name}</span>
                            {cov && !cov.covered && <span className="qs-gap">no evidence</span>}
                          </button>
                        )
                      })}
                    </div>
                  ))}
                </div>
              ))}
            </div>
            {selected && (
              <QuestionPanel key={selected.id} question={selected} answer={answers.get(selected.id)} profile={profile} findings={findings} evidence={evidence} rules={rules} onSaved={saved} />
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function ScenarioPicker({ chosen, onToggle }: { chosen: string[]; onToggle: (id: string) => void }) {
  return (
    <div className="panel">
      <div className="panel-h">
        scenarios <span className="muted">· DFIQ {CATALOG.dfiq.version} (dfiq.org) and REMN's own (ids starting with 0)</span>
      </div>
      <div className="panel-b qs-scenarios">
        {CATALOG.scenarios.map((s) => (
          <label key={s.id} className="checkbox qs-scenario-pick">
            <input type="checkbox" checked={chosen.includes(s.id)} onChange={() => onToggle(s.id)} />
            <span>
              <b>{s.name}</b> <span className="mono dim">{s.id}</span>
              <span className="small muted qs-desc">{s.description}</span>
            </span>
          </label>
        ))}
      </div>
    </div>
  )
}

function QuestionPanel({
  question: q,
  answer,
  profile,
  findings,
  evidence,
  rules,
  onSaved,
}: {
  question: Question
  answer?: QuestionAnswer
  profile: EvidenceProfile | null
  findings: Finding[]
  evidence: Evidence[]
  rules: LoadedRule[]
  onSaved: (a: QuestionAnswer) => void
}) {
  const kase = useStore((s) => s.currentCase)!
  const setView = useStore((s) => s.setView)
  const setActive = useStore((s) => s.setActiveQuestion)
  const [text, setText] = useState(answer?.text ?? '')
  const [counts, setCounts] = useState<(number | null)[]>([])
  const status = answer?.status ?? 'open'
  const cov = profile ? coverage(q, profile) : null
  const related = useMemo(() => relatedRules(q, rules), [q, rules])
  const byRule = useMemo(() => {
    const m = new Map<string, Finding[]>()
    for (const f of findings) if (f.status !== 'false_positive') m.set(f.ruleId, [...(m.get(f.ruleId) ?? []), f])
    return m
  }, [findings])
  const relatedFindings = useMemo(
    () => related.flatMap((r) => byRule.get(r.rule.id) ?? []).sort((a, b) => SEV_ORDER.indexOf(effectiveSeverity(a)) - SEV_ORDER.indexOf(effectiveSeverity(b)) || (a.ts ?? 0) - (b.ts ?? 0)),
    [related, byRule],
  )
  useEffect(() => {
    const ctl = new AbortController()
    const ds = getSource(kase)
    Promise.all(
      q.searches.map((s) =>
        (s.source === 'mails' ? ds.countMails(s.filter, ctl.signal) : ds.countEvents(s.filter, ctl.signal)).catch((e) => {
          if (!isAbort(e)) return null
          throw e
        }),
      ),
    )
      .then(setCounts)
      .catch(() => undefined)
    return () => ctl.abort()
  }, [q, kase])
  const openSearch = (s: QuestionSearch) => {
    setActive(q.id)
    if (s.source === 'mails') useStore.getState().setMailsFilter(s.filter)
    else useStore.getState().setEventsFilter(s.filter)
    setView(s.source)
  }
  const openFinding = (id: number) => {
    useStore.getState().setFocusFinding(id)
    setView('findings')
  }
  const save = async (patch: { status?: AnswerStatus; text?: string }) => onSaved(await setAnswer(kase.id!, q.id, patch))
  const cite = async (c: QuestionCitation) => onSaved(await addCitation(kase.id!, q.id, c))
  const uncite = async (id: string) => onSaved(await removeCitation(kase.id!, q.id, id))
  const cited = new Set((answer?.citations ?? []).map(citationId))
  return (
    <div className="panel qs-panel">
      <div className="panel-h">
        <IconQuestion />
        <span className="mono">{q.id}</span>
        <span className="spacer" />
        <Badge sev={q.origin === 'dfiq' ? 'accent' : 'info'}>{q.origin === 'dfiq' ? 'DFIQ' : 'REMN'}</Badge>
      </div>
      <div className="panel-b col" style={{ gap: 12 }}>
        <div>
          <div className="qs-title">{q.name}</div>
          {q.description && <div className="small muted">{q.description}</div>}
          {q.note && <div className="hint">{q.note}</div>}
        </div>
        <section className="qs-sec" aria-label="Evidence">
          <h3>evidence in this case</h3>
          {cov ? (
            <div className="row wrap small" style={{ gap: 6 }}>
              <Badge sev={cov.covered ? 'ok' : 'high'}>{cov.covered ? 'covered' : 'not covered'}</Badge>
              <span>{cov.text}</span>
            </div>
          ) : (
            <span className="small muted">reading what the case holds…</span>
          )}
        </section>
        {(q.searches.length > 0 || q.derived) && (
          <section className="qs-sec" aria-label="Searches">
            <h3>answer it with</h3>
            <div className="col" style={{ gap: 4 }}>
              {q.searches.map((s, i) => (
                <div key={i} className="row small" style={{ gap: 8 }}>
                  <button className="btn xs" onClick={() => openSearch(s)} title="open this search; a row opened from it can be cited for this question">
                    <IconExternal /> {s.source === 'mails' ? 'Mails' : 'Events'}
                  </button>
                  <span style={{ flex: 1 }}>{s.label}</span>
                  <span className="mono dim">{counts[i] == null ? '…' : `${fmtNum(counts[i])} row(s)`}</span>
                </div>
              ))}
              {q.derived && <DerivedFact kind={q.derived} findings={findings} onOpen={openFinding} />}
            </div>
          </section>
        )}
        {q.attack.length + q.ruleTags.length > 0 && (
          <section className="qs-sec" aria-label="Related rules">
            <h3>
              related rules <span className="dim">· {[...q.attack, ...q.ruleTags].join(' ')}</span>
            </h3>
            {related.length ? (
              <div className="col" style={{ gap: 3 }}>
                {related
                  .map((r) => ({ r, hits: byRule.get(r.rule.id) ?? [] }))
                  .sort((a, b) => b.hits.length - a.hits.length)
                  .slice(0, 12)
                  .map(({ r, hits }) => (
                    <div key={r.rule.id} className="row small" style={{ gap: 8 }}>
                      <Dot sev={hits.length ? effectiveSeverity(hits[0]) : undefined} />
                      <span style={{ flex: 1 }} className={r.enabled ? '' : 'dim'}>
                        {r.rule.title} <span className="mono dim">{r.rule.id}</span>
                        {!r.enabled && <span className="dim"> · disabled</span>}
                      </span>
                      {hits.length ? (
                        <button className="btn xs" onClick={() => openFinding(hits[0].id!)}>
                          {fmtNum(hits.length)} finding(s)
                        </button>
                      ) : (
                        <span className="dim">no finding</span>
                      )}
                    </div>
                  ))}
                {related.length > 12 && <span className="small dim">and {fmtNum(related.length - 12)} more</span>}
              </div>
            ) : (
              <span className="small muted">No loaded rule names these techniques or tags.</span>
            )}
          </section>
        )}
        {q.approaches.length > 0 && (
          <details className="qs-sec">
            <summary className="small">DFIQ approaches ({q.approaches.length})</summary>
            {q.approaches.map((a) => (
              <div key={a.id} className="small" style={{ marginTop: 6 }}>
                <b>{a.name}</b> <span className="mono dim">{a.id}</span>
                {a.summary && <div className="muted">{a.summary}</div>}
                {a.notCovered.length > 0 && <div className="muted">Does not cover: {a.notCovered.join('; ')}</div>}
              </div>
            ))}
          </details>
        )}
        <section className="qs-sec" aria-label="Answer">
          <h3>answer</h3>
          <div className="segmented" role="group" aria-label="Answer status">
            {ANSWER_STATUSES.map((s) => (
              <button key={s.id} className={status === s.id ? 'active' : ''} aria-pressed={status === s.id} onClick={() => save({ status: s.id })}>
                {s.label}
              </button>
            ))}
          </div>
          <textarea
            className="textarea"
            aria-label="Answer"
            placeholder={status === 'cannot' ? 'what is missing, and what would answer it' : 'the answer, as the report prints it (markdown)'}
            value={text}
            onChange={(e) => setText(e.target.value)}
            onBlur={() => text !== (answer?.text ?? '') && save({ text })}
            style={{ marginTop: 8 }}
          />
          <Citations
            answer={answer}
            evidence={evidence}
            findings={findings}
            onRemove={uncite}
            onMoved={(c, id) => updateAnswer(kase.id!, q.id, (a) => (a.citations = a.citations.map((x) => (citationId(x) === citationId(c) ? { ...x, rowId: id } : x)))).then(onSaved)}
          />
          <div className="row wrap small" style={{ gap: 6, marginTop: 6 }}>
            <select
              className="select small"
              aria-label="Cite a finding"
              value=""
              onChange={(e) => {
                const f = findings.find((x) => String(x.id) === e.target.value)
                if (f) cite(findingCitation(f)).catch((err: Error) => toast('err', err.message))
              }}
              style={{ maxWidth: 360 }}
            >
              <option value="">cite a finding…</option>
              {(relatedFindings.length ? relatedFindings : findings)
                .filter((f) => !cited.has(citationId(findingCitation(f))))
                .slice(0, 200)
                .map((f) => (
                  <option key={f.id} value={f.id}>
                    {effectiveSeverity(f)} · {f.title} · {fmtTs(f.ts)}
                  </option>
                ))}
            </select>
            <span className="muted">Rows: open a search above, then "cite for {q.id}" in the row's detail.</span>
          </div>
        </section>
      </div>
    </div>
  )
}

function Citations({
  answer,
  evidence,
  findings,
  onRemove,
  onMoved,
}: {
  answer?: QuestionAnswer
  evidence: Evidence[]
  findings: Finding[]
  onRemove: (id: string) => void
  onMoved: (c: QuestionCitation, id: number) => void
}) {
  const kase = useStore((s) => s.currentCase)!
  const setView = useStore((s) => s.setView)
  const setFocus = useStore((s) => s.setFocus)
  const [where, setWhere] = useState<Record<string, number | null>>({})
  const citations = useMemo(() => answer?.citations ?? [], [answer])
  const moved = useRef(onMoved)
  useEffect(() => {
    moved.current = onMoved
  })
  const resolve = useCallback(async () => {
    const ds = getSource(kase)
    const out: Record<string, number | null> = {}
    for (const c of citations) {
      const r = await resolveCitation(c, ds, evidence, findings)
      out[citationId(c)] = r.id
      if (r.moved && r.id != null) moved.current(c, r.id)
    }
    setWhere(out)
  }, [citations, evidence, findings, kase])
  useEffect(() => {
    resolve().catch(() => undefined)
  }, [resolve])
  if (!citations.length)
    return (
      <div className="small muted" style={{ marginTop: 6 }}>
        Nothing cited yet.
      </div>
    )
  const open = (c: QuestionCitation, id: number) => {
    if (c.source === 'findings') {
      useStore.getState().setFocusFinding(id)
      setView('findings')
    } else {
      setFocus({ source: c.source, id })
      setView(c.source)
    }
  }
  return (
    <ul className="qs-cites" aria-label="Citations">
      {citations.map((c) => {
        const id = citationId(c)
        const at = where[id]
        return (
          <li key={id} className="row small" style={{ gap: 6 }}>
            <Badge>{c.source === 'findings' ? 'finding' : c.source === 'mails' ? 'mail' : 'event'}</Badge>
            {at != null ? (
              <button className="btn link small" onClick={() => open(c, at)} title="open it">
                {c.label}
              </button>
            ) : (
              <span title={at === null ? 'no longer in this case: removed, or not added again' : undefined}>
                {c.label}
                {at === null && <span className="dim"> · not in the case now</span>}
              </span>
            )}
            {c.ts ? <span className="dim mono">{fmtTs(c.ts)}</span> : null}
            <span className="spacer" />
            <button className="btn ghost xs" aria-label={`remove ${c.label}`} onClick={() => onRemove(id)}>
              <IconClose />
            </button>
          </li>
        )
      })}
    </ul>
  )
}

/** What a question works out from the case itself: the first or last attacker activity, how far the logs reach back, the holes in them. */
function DerivedFact({ kind, findings, onOpen }: { kind: NonNullable<Question['derived']>; findings: Finding[]; onOpen: (id: number) => void }) {
  const kase = useStore((s) => s.currentCase)!
  const [lines, setLines] = useState<string[] | null>(null)
  const span = useMemo(() => activitySpan(findings), [findings])
  useEffect(() => {
    if (kind !== 'log-reach' && kind !== 'evidence-gaps') return
    let alive = true
    const ds = getSource(kase)
    if (kind === 'evidence-gaps')
      loadEvidenceGaps(kase.id!, ds)
        .then((g) => alive && setLines(g.length ? g.slice(0, 8).map((x) => x.text) : ['No hole found in the logs of this case.']))
        .catch(() => alive && setLines(['The evidence gaps could not be read.']))
    else
      ds.aggregateEvents({}, 'channel', 50)
        .then((a) => {
          if (!alive) return
          const first = span.first?.ts ?? null
          setLines(
            a.groups
              .filter((g) => g.first != null)
              .sort((x, y) => (x.first ?? 0) - (y.first ?? 0))
              .slice(0, 10)
              .map((g) => `${g.value}: from ${fmtTs(g.first)}${first != null && (g.first ?? 0) > first ? ', after the first attacker activity' : ''}`),
          )
        })
        .catch(() => alive && setLines(['The logs could not be read.']))
    return () => {
      alive = false
    }
  }, [kind, kase, span])
  if (kind === 'first-activity' || kind === 'last-activity') {
    const f = kind === 'first-activity' ? span.first : span.last
    return f ? (
      <div className="row small" style={{ gap: 8 }}>
        <button className="btn xs" onClick={() => onOpen(f.id!)}>
          <IconExternal /> Findings
        </button>
        <span style={{ flex: 1 }}>
          {kind === 'first-activity' ? 'earliest' : 'latest'} finding of medium severity or more: {f.title}
        </span>
        <span className="mono dim">{fmtTs(kind === 'first-activity' ? f.ts : (f.tsEnd ?? f.ts))}</span>
      </div>
    ) : (
      <span className="small muted">No finding of medium severity or more with a time.</span>
    )
  }
  return (
    <div className="col small" style={{ gap: 2 }}>
      {(lines ?? ['reading the logs…']).map((l, i) => (
        <span key={i}>{l}</span>
      ))}
    </div>
  )
}
