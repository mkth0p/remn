import { transportLabel } from '../../ai/transport'
import { IconAi, IconStop } from '../../components/Icons'
import { Badge, Modal, Progress, Sev, Spinner, Toggle } from '../../components/ui'
import type { TriageEntry, TriageProgress, TriageRun } from '../../data/aiReview'
import { classNames, fmtNum, fmtTs } from '../../util/format'
import { DECISION_LABEL, DECISION_SEV, modelNameOf, SUMMARY_LABEL, type AiConfig } from './model'

/** A triage in progress: the batch, the items done, and a way to stop it. */
export function TriageProgressBar({ triage, modelName, onStop }: { triage: TriageProgress; modelName: string; onStop: () => void }) {
  return (
    <div className="bulkbar">
      <Spinner />
      <span>
        AI triage · {triage.batches ? `batch ${triage.batch} of ${triage.batches} · ` : ''}
        {triage.done} of {triage.total} items · {modelName}
      </span>
      <span style={{ flex: 1, minWidth: 120 }}>
        <Progress value={triage.total ? triage.done / triage.total : 0} />
      </span>
      <button className="btn xs danger" onClick={onStop}>
        <IconStop /> stop
      </button>
    </div>
  )
}

/** What a triage does and where the items go, asked before any is sent. */
export function AskTriageModal({
  aiCfg,
  decided,
  queued,
  undecided,
  triageDecided,
  setTriageDecided,
  onClose,
  onStart,
}: {
  aiCfg: AiConfig
  /** items already decided */
  decided: number
  queued: number
  undecided: number
  triageDecided: boolean
  setTriageDecided: (on: boolean) => void
  onClose: () => void
  onStart: () => void
}) {
  const sent = triageDecided ? queued : undecided
  return (
    <Modal
      title="Triage with the model"
      onClose={onClose}
      footer={
        <>
          <button className="btn ghost sm" onClick={onClose}>
            cancel
          </button>
          <button className="btn primary sm" onClick={onStart}>
            <IconAi /> start
          </button>
        </>
      }
    >
      <div className="col" style={{ gap: 10 }}>
        <div>
          The model proposes a decision on every item in the queue: a verdict or decision, a severity, whether the report carries it, and a reason. Nothing is written. Each proposal waits on its item,
          tagged "AI", until you apply or dismiss it. Text in the evidence can try to steer a model, so a proposal to lower a severity or leave an item out of the report deserves a second look.
        </div>
        <div className="small muted">
          {modelNameOf(aiCfg)} ·{' '}
          {aiCfg.transport === 'claude'
            ? 'Claude Code on the server machine: the items (findings, entities, chain steps) leave for Anthropic'
            : transportLabel(aiCfg).local
              ? `your local model (${transportLabel(aiCfg).where}): nothing leaves this machine`
              : "the server's Ollama"}{' '}
          · {aiCfg.transport === 'claude' ? 8 : 4} items per call
        </div>
        <Toggle on={triageDecided} onChange={setTriageDecided} label={`re-triage the ${decided} item${decided === 1 ? '' : 's'} already decided too`} />
        <div>
          <b>{fmtNum(sent)}</b> item{sent === 1 ? '' : 's'} will be sent.
        </div>
      </div>
    </Modal>
  )
}

/** The last triage: what it proposed or decided per item, with its reason, and the undo of what it wrote. */
export function TriageRunModal({ run, onClose, onUndo, onUndoAll }: { run: TriageRun; onClose: () => void; onUndo: (e: TriageEntry) => void; onUndoAll: () => void }) {
  const live = run.entries.filter((e) => !e.undone).length
  return (
    <Modal
      wide
      title={
        <span>
          AI triage · {live} {run.proposed ? 'proposal' : 'decision'}
          {live === 1 ? '' : 's'}{' '}
          <span className="muted small">
            · {fmtTs(run.at)}
            {run.model ? ` · ${run.model}` : ''}
          </span>
        </span>
      }
      onClose={onClose}
      footer={
        <>
          {run.proposed ? (
            <span className="small muted">nothing was written: apply or dismiss each proposal on its item</span>
          ) : (
            <button className="btn ghost sm" disabled={run.entries.every((e) => e.undone)} onClick={onUndoAll}>
              undo all
            </button>
          )}
          <span className="spacer" />
          <button className="btn primary sm" onClick={onClose}>
            close
          </button>
        </>
      }
    >
      <div className="col" style={{ gap: 10 }}>
        <div className="small">
          {(['confirmed', 'escalated', 'unsure', 'reviewed', 'benign', 'false_positive'] as const).map((d) => {
            const n = run.entries.filter((e) => e.decision === d && !e.undone).length
            return n ? (
              <span key={d} style={{ marginRight: 12 }}>
                <Badge sev={DECISION_SEV[d]}>{SUMMARY_LABEL[d]}</Badge> {n}
              </span>
            ) : null
          })}
          {run.entries.some((e) => e.severityBefore !== e.severityAfter && !e.undone) && (
            <span style={{ marginRight: 12 }}>rescored {run.entries.filter((e) => e.severityBefore !== e.severityAfter && !e.undone).length}</span>
          )}
          {run.entries.some((e) => e.unlinked.length && !e.undone) && (
            <span>unlinked {run.entries.reduce((n, e) => n + (e.undone ? 0 : e.unlinked.length), 0)} finding(s), now in the queue on their own</span>
          )}
          {run.entries.some((e) => e.wrote && !e.undone) && (
            <span style={{ marginRight: 12 }}>
              wrote {run.entries.filter((e) => e.wrote === 'narrative' && !e.undone).length} narrative(s), {run.entries.filter((e) => e.wrote === 'note' && !e.undone).length} note(s)
            </span>
          )}
          {run.summaryDrafted && <span style={{ marginRight: 12 }}>executive summary drafted</span>}
          {run.asked > run.entries.length && (
            <span className="muted">
              {' '}
              · {run.asked - run.entries.length} of {run.asked} item(s) got no decision
            </span>
          )}
        </div>
        {run.errors.length > 0 && (
          <div className="small" style={{ color: 'var(--sev-high)' }}>
            {run.errors.join(' · ')}
          </div>
        )}
        {run.rejected.length > 0 && (
          <div className="small muted">
            not applied: {run.rejected.slice(0, 6).join(' · ')}
            {run.rejected.length > 6 ? ` · +${run.rejected.length - 6}` : ''}
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
            {run.entries.map((e) => (
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
                  {run.proposed ? (
                    <span className="small muted">proposed</span>
                  ) : e.undone ? (
                    <span className="small muted">undone</span>
                  ) : (
                    <button className="btn link small" onClick={() => onUndo(e)}>
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
  )
}
