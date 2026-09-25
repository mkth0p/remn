import { useEffect, useState } from 'react'
import type { Case } from '../../db/schema'
import type { AiLedgerEntry } from '../../db/schema'
import { toast } from '../../state/store'
import { fmtTs } from '../../util/format'
import { Badge } from '../../components/ui'
import { addNote } from '../../data/caseNotes'
import type { AgentRun } from '../../ai/chat'
import { refKey } from '../../ai/evidence'
import { acceptProposals, loadInbox, rejectProposals, undoProposal, useInbox, type Proposal } from '../../ai/inbox'
import { loadBoard, recordHypothesis, removeHypothesis, useBoard, type Hypothesis, type HypothesisStatus } from '../../ai/hypotheses'
import { loadLedger, verifyLedger, type LedgerCheck } from '../../ai/ledger'
import type { PlanStep } from '../../ai/tools'
import { RefChips } from './refs'

type Tab = 'plan' | 'inbox' | 'board' | 'ledger'

export function AiSidePanel({ kase, run, plan, seenCount, busy }: { kase: Case; run: AgentRun | null; plan: PlanStep[]; seenCount: number; busy: boolean }) {
  const [tab, setTab] = useState<Tab>('plan')
  const inboxVersion = useInbox((s) => s.version)
  const [pending, setPending] = useState(0)
  useEffect(() => {
    loadInbox(kase.id!).then((items) => setPending(items.filter((p) => p.status === 'pending').length))
  }, [kase.id, inboxVersion])
  return (
    <div className="ai-side">
      <div className="tabs">
        <button className={`tab ${tab === 'plan' ? 'active' : ''}`} onClick={() => setTab('plan')}>
          plan
        </button>
        <button className={`tab ${tab === 'inbox' ? 'active' : ''}`} onClick={() => setTab('inbox')}>
          inbox{pending ? <span className="n ai-pending">{pending}</span> : null}
        </button>
        <button className={`tab ${tab === 'board' ? 'active' : ''}`} onClick={() => setTab('board')}>
          hypotheses
        </button>
        <button className={`tab ${tab === 'ledger' ? 'active' : ''}`} onClick={() => setTab('ledger')}>
          ledger
        </button>
      </div>
      <div className="ai-side-body">
        {tab === 'plan' && <PlanTab run={run} plan={plan} seenCount={seenCount} busy={busy} />}
        {tab === 'inbox' && <InboxTab kase={kase} />}
        {tab === 'board' && <BoardTab kase={kase} />}
        {tab === 'ledger' && <LedgerTab kase={kase} />}
      </div>
    </div>
  )
}

const STEP_ICON: Record<PlanStep['status'], string> = { todo: '○', doing: '◐', done: '●', skipped: '–' }

function PlanTab({ run, plan, seenCount, busy }: { run: AgentRun | null; plan: PlanStep[]; seenCount: number; busy: boolean }) {
  const used = run?.contextTokens ?? 0
  const win = run?.contextWindow ?? 0
  const pct = win ? Math.min(100, Math.round((used / win) * 100)) : 0
  return (
    <div className="col" style={{ gap: 10 }}>
      {run && (
        <div className="ai-run">
          <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
            <Badge sev={busy ? 'info' : 'ok'}>{busy ? (run.wrappingUp ? 'writing the answer' : 'investigating') : 'done'}</Badge>
            <span className="small">
              step {run.step} of {run.budget}
            </span>
            <span className="small dim">· {run.toolCalls} tool call(s)</span>
            <span className="small dim">· {seenCount} citable ref(s)</span>
          </div>
          {win > 0 && (
            <div title={`${used.toLocaleString()} of ${win.toLocaleString()} tokens in the last turn${run.omitted ? `; ${run.omitted} older message(s) left out to fit` : ''}`}>
              <div className="small dim">
                context {Math.round(used / 1000)}k / {Math.round(win / 1000)}k{run.omitted ? ` · ${run.omitted} older message(s) left out` : ''}
              </div>
              <div className="ai-meter">
                <span style={{ width: `${pct}%` }} className={pct > 85 ? 'hot' : ''} />
              </div>
            </div>
          )}
          {run.proposals.length > 0 && <div className="small">{run.proposals.length} proposal(s) queued in the inbox this run</div>}
          {run.suspects > 0 && <div className="small warn-inline">⚠ the evidence it read holds {run.suspects} place(s) addressed to a model: its proposals from then on are marked</div>}
        </div>
      )}
      {plan.length ? (
        <div className="ai-plan">
          {plan.map((s, i) => (
            <div key={i} className={`ai-plan-step ${s.status}`}>
              <span className="ai-plan-icon">{STEP_ICON[s.status]}</span>
              <span>{s.title}</span>
            </div>
          ))}
        </div>
      ) : (
        <div className="small dim">The agent writes its plan here when an investigation starts. Pick a playbook or ask a question.</div>
      )}
    </div>
  )
}

const KIND_LABEL: Record<Proposal['kind'], string> = { decision: 'decision', note: 'note', row_mark: 'row marks', rule: 'rule', summary: 'summary' }

function ProposalCard({ kase, p, onDone }: { kase: Case; p: Proposal; onDone: () => void }) {
  const [text, setText] = useState(p.note?.text ?? p.summary?.text ?? '')
  const [busy, setBusy] = useState(false)
  const editable = p.kind === 'note' || p.kind === 'summary'
  const accept = async () => {
    setBusy(true)
    const edits: Partial<Proposal> = editable && text !== (p.note?.text ?? p.summary?.text ?? '') ? (p.kind === 'note' ? { note: { ...p.note!, text } } : { summary: { text } }) : {}
    const r = await acceptProposals(kase, [p.id], Object.keys(edits).length ? { [p.id]: edits } : {})
    setBusy(false)
    if (r.failed.length) toast('err', `not applied: ${r.failed[0].error}`, 0)
    onDone()
  }
  const reject = async () => {
    await rejectProposals(kase.id!, [p.id])
    onDone()
  }
  return (
    <div className={`ai-card ${p.exposed ? 'exposed' : ''}`}>
      <div className="row" style={{ gap: 6 }}>
        <Badge sev="info">{KIND_LABEL[p.kind]}</Badge>
        {p.exposed && (
          <Badge sev="medium" title="proposed after the agent read evidence text addressed to a model: check it before accepting">
            read text aimed at AI
          </Badge>
        )}
        <span className="spacer" />
        <span className="dim small">{fmtTs(p.createdAt)}</span>
      </div>
      <div className="ai-card-title">{p.title}</div>
      {p.reason && <div className="small">{p.reason}</div>}
      {editable && <textarea className="textarea small" rows={p.kind === 'summary' ? 8 : 3} value={text} onChange={(e) => setText(e.target.value)} />}
      {p.kind === 'rule' && p.rule && (
        <details>
          <summary className="small">
            tested here: {p.rule.test.findings} finding(s){p.rule.test.errors.length ? ` · ${p.rule.test.errors.length} error(s)` : ''}
          </summary>
          <pre className="ai-step-body">{p.rule.yaml}</pre>
        </details>
      )}
      <RefChips refs={p.citations} />
      {p.error && <div className="small warn-inline">last attempt: {p.error}</div>}
      <div className="row" style={{ gap: 6 }}>
        <button className="btn xs primary" disabled={busy} onClick={accept}>
          accept
        </button>
        <button className="btn xs" disabled={busy} onClick={reject}>
          reject
        </button>
        {p.model && <span className="dim small">{p.model}</span>}
      </div>
    </div>
  )
}

function InboxTab({ kase }: { kase: Case }) {
  const version = useInbox((s) => s.version)
  const [items, setItems] = useState<Proposal[]>([])
  const [showDecided, setShowDecided] = useState(false)
  const reload = () => loadInbox(kase.id!).then(setItems)
  useEffect(() => {
    reload()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kase.id, version])
  const pending = items.filter((p) => p.status === 'pending').reverse()
  const clean = pending.filter((p) => !p.exposed)
  const decided = items.filter((p) => p.status !== 'pending').reverse()
  const acceptAll = async () => {
    const r = await acceptProposals(
      kase,
      clean.map((p) => p.id),
    )
    toast(r.failed.length ? 'warn' : 'ok', `${r.accepted} accepted${r.failed.length ? `, ${r.failed.length} not applied (see the cards)` : ''}`)
  }
  return (
    <div className="col" style={{ gap: 8 }}>
      <div className="small dim">
        What the agent proposes to change in the case waits here. Nothing is written until you accept it; an accepted proposal can be undone below. Decisions also show on the Review page.
      </div>
      {pending.length > 0 && (
        <div className="row" style={{ gap: 6 }}>
          <button className="btn xs primary" disabled={!clean.length} onClick={acceptAll} title="proposals made after the agent read text aimed at a model are left for one-by-one review">
            accept all {clean.length}
            {clean.length < pending.length ? ` of ${pending.length}` : ''}
          </button>
          <button
            className="btn xs"
            onClick={() =>
              rejectProposals(
                kase.id!,
                pending.map((p) => p.id),
              )
            }
          >
            reject all
          </button>
        </div>
      )}
      {!pending.length && <div className="small dim">No proposal waiting.</div>}
      {pending.map((p) => (
        <ProposalCard key={p.id} kase={kase} p={p} onDone={reload} />
      ))}
      {decided.length > 0 && (
        <button className="btn ghost xs" onClick={() => setShowDecided((v) => !v)}>
          {showDecided ? 'hide' : 'show'} {decided.length} decided
        </button>
      )}
      {showDecided &&
        decided.slice(0, 60).map((p) => (
          <div key={p.id} className="ai-card decided">
            <div className="row" style={{ gap: 6 }}>
              <Badge sev={p.status === 'accepted' ? 'ok' : 'info'}>{p.applied?.undone ? 'undone' : p.status}</Badge>
              <span className="small ellipsis" style={{ flex: 1 }}>
                {p.title}
              </span>
              {p.status === 'accepted' && !p.applied?.undone && (
                <button className="btn xs ghost" onClick={() => undoProposal(kase, p.id).then(reload)}>
                  undo
                </button>
              )}
            </div>
          </div>
        ))}
    </div>
  )
}

const STATUSES: HypothesisStatus[] = ['open', 'supported', 'refuted', 'inconclusive']

function BoardTab({ kase }: { kase: Case }) {
  const version = useBoard((s) => s.version)
  const [items, setItems] = useState<Hypothesis[]>([])
  useEffect(() => {
    loadBoard(kase.id!).then(setItems)
  }, [kase.id, version])
  const toNote = async (h: Hypothesis) => {
    const refs = [...h.support.map(refKey)].join(' ')
    await addNote(
      kase.id!,
      'note',
      `Hypothesis ${h.id} (${h.status}${h.confidence ? `, ${h.confidence} confidence` : ''}): ${h.statement}${refs ? `\nFor: ${refs}` : ''}${h.against.length ? `\nAgainst: ${h.against.map(refKey).join(' ')}` : ''}`,
    )
    toast('ok', 'added to the case notes')
  }
  if (!items.length)
    return (
      <div className="small dim">The agent records its hypotheses here, with the rows for and against each. They are its working theories, not conclusions: turn one into a case note to keep it.</div>
    )
  return (
    <div className="col" style={{ gap: 8 }}>
      {[...items].reverse().map((h) => (
        <div key={h.id} className={`ai-card hyp ${h.status}`}>
          <div className="row" style={{ gap: 6 }}>
            <b className="mono small">{h.id}</b>
            <select className="select xs" value={h.status} onChange={(e) => recordHypothesis(kase.id!, { id: h.id, status: e.target.value as HypothesisStatus }, 'analyst')}>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            {h.confidence && <span className="small dim">{h.confidence}</span>}
            <span className="spacer" />
            <button className="btn xs ghost" onClick={() => toNote(h)} title="add to the case notes">
              → note
            </button>
            <button className="btn xs ghost" onClick={() => removeHypothesis(kase.id!, h.id)}>
              ×
            </button>
          </div>
          <div className="small">{h.statement}</div>
          {h.support.length > 0 && (
            <div className="small">
              <span className="dim">for </span>
              <RefChips refs={h.support} />
            </div>
          )}
          {h.against.length > 0 && (
            <div className="small">
              <span className="dim">against </span>
              <RefChips refs={h.against} />
            </div>
          )}
          {h.next && <div className="small dim">next: {h.next}</div>}
        </div>
      ))}
    </div>
  )
}

function LedgerTab({ kase }: { kase: Case }) {
  const [entries, setEntries] = useState<AiLedgerEntry[]>([])
  const [check, setCheck] = useState<LedgerCheck | null>(null)
  const inboxVersion = useInbox((s) => s.version)
  useEffect(() => {
    loadLedger(kase.id!, 150).then((e) => setEntries(e.reverse()))
  }, [kase.id, inboxVersion])
  return (
    <div className="col" style={{ gap: 8 }}>
      <div className="small dim">
        Every run, tool call (with a hash of its result), proposal and your decision on it, chained by hash: an entry changed afterwards breaks the chain. The report prints the summary.
      </div>
      <div className="row" style={{ gap: 6 }}>
        <button className="btn xs" onClick={() => verifyLedger(kase.id!).then(setCheck)}>
          verify the chain
        </button>
        {check && (
          <span className={`small ${check.intact ? '' : 'warn-inline'}`}>
            {check.intact ? `✓ intact · ${check.entries} entries · head ${check.head?.slice(0, 12) ?? '—'}` : `✗ broken at entry ${check.brokenAt} of ${check.entries}`}
          </span>
        )}
      </div>
      {entries.map((e) => (
        <div key={e.seq} className="ai-ledger-row">
          <span className="dim mono">{e.seq}</span> <span className="dim">{fmtTs(e.at)}</span> <b>{e.kind}</b> <span className="ellipsis">{e.text}</span>
        </div>
      ))}
    </div>
  )
}
