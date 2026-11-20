import type { ReactNode } from 'react'
import { AddToTimeline } from '../../components/AddToTimeline'
import { IconAi, IconArrowLeft, IconCheck } from '../../components/Icons'
import { Sev, Spinner, Toggle } from '../../components/ui'
import type { Chain } from '../../data/chains'
import { chainIncluded, chainSeverity, SEVERITIES, stepVisible, type ChainReview, type ReportSettings, type Verdict } from '../../data/review'
import type { Finding } from '../../db/schema'
import { useStore } from '../../state/store'
import { classNames, fmtTs } from '../../util/format'
import { Facts } from './Facts'
import { VERDICTS } from './model'

/**
 * An attack chain to decide: the findings whose rows are its steps (its verdict sets their status;
 * one can be unlinked to be decided on its own), the verdict and what it does, its severity, whether
 * the report carries it, and its narrative.
 */
export function ChainCard({
  ch,
  chRev,
  members,
  anyUnlinked,
  settings,
  effect,
  proposals,
  narrative,
  setNarrative,
  drafting,
  suggesting,
  onPatch,
  onUnlink,
  onDraft,
  onSuggest,
  onPrevious,
  onNext,
}: {
  ch: Chain
  chRev: ChainReview | undefined
  /** the findings whose rows are its steps */
  members: Finding[]
  /** some finding of the case was unlinked from a chain */
  anyUnlinked: boolean
  settings: ReportSettings
  effect: ReactNode
  proposals: ReactNode
  narrative: string
  setNarrative: (s: string) => void
  drafting: boolean
  suggesting: boolean
  onPatch: (patch: Partial<ChainReview>) => void
  onUnlink: (ids: number[]) => void
  onDraft: () => void
  onSuggest: () => void
  onPrevious: () => void
  onNext: () => void
}) {
  const setFocusChain = useStore((s) => s.setFocusChain)
  const setView = useStore((s) => s.setView)
  const willPrint = SEVERITIES.indexOf(chainSeverity(ch, chRev)) <= SEVERITIES.indexOf(settings.minSeverity)
  return (
    <div className="review-card">
      <div className="head">
        <Sev sev={chainSeverity(ch, chRev)} />
        <div className="col" style={{ gap: 4, flex: 1 }}>
          <h2>Attack chain · {ch.identityLabel}</h2>
          <div className="small muted">
            score {ch.score} · {ch.steps.length} steps · {ch.artifactLinks} artifact link(s) · {fmtTs(ch.start)} → {fmtTs(ch.end)} · seed "{ch.seed.subject}" from {ch.seed.fromAddr}
          </div>
        </div>
        {chRev?.verdict && <span className={`stamp ${chRev.verdict === 'confirmed' ? 'st-escalated' : chRev.verdict === 'benign' ? 'st-false_positive' : 'st-reviewed'}`}>{chRev.verdict}</span>}
      </div>
      <div className="section">
        <h3>
          What was seen <span className="muted">· the findings whose rows are steps of this chain; the verdict sets their status, unlink one to decide on it separately</span>
        </h3>
        {members.length ? (
          <Facts findings={members} said={{}} onUnlink={onUnlink} />
        ) : (
          <div className="small muted">no finding has its rows among the chain's steps{anyUnlinked ? ' (some were unlinked and sit in the queue on their own)' : ''}</div>
        )}
        <div className="small" style={{ marginTop: 6 }}>
          {ch.summary}
        </div>
        {ch.scoreBreakdown && (
          <div className="small mono muted">
            score {ch.score} = seed {ch.scoreBreakdown.seed} + links {ch.scoreBreakdown.links} + steps {ch.scoreBreakdown.steps} + findings {ch.scoreBreakdown.findings} + sources{' '}
            {ch.scoreBreakdown.sources}
            {ch.scoreBreakdown.cap ? ` · capped at ${ch.scoreBreakdown.cap}` : ''} · the report prints {ch.steps.filter((s) => stepVisible(s, settings.chainDetail)).length} of {ch.steps.length} steps
            at the "{settings.chainDetail}" level
          </div>
        )}
      </div>
      <div className="decide">
        <div className="choices">
          {VERDICTS.map((v) => (
            <button key={v.id} className={classNames('choice', v.tone, chRev?.verdict === v.id && 'active')} onClick={() => onPatch({ verdict: v.id as Verdict })}>
              {v.label} <kbd>{v.key}</kbd>
            </button>
          ))}
        </div>
        {effect}
        <div className="controls">
          <span>
            <span className="lbl">severity</span>
            <span className="segmented">
              {SEVERITIES.map((s) => (
                <button key={s} className={classNames(chainSeverity(ch, chRev) === s && 'active')} onClick={() => onPatch({ severityOverride: s === ch.severity ? undefined : s })}>
                  {s}
                </button>
              ))}
            </span>
          </span>
          <Toggle
            on={chainIncluded(ch, chRev)}
            onChange={(v) => onPatch({ include: v })}
            label={chainIncluded(ch, chRev) && willPrint && settings.includeChains ? 'in the report' : 'not in the report'}
          />
        </div>
      </div>
      {chRev?.by === 'ai' && chRev.aiReason && (
        <div className="ai-note">
          <b>decided by the model:</b> {chRev.aiReason} <span className="muted">· set the verdict above to make it yours</span>
        </div>
      )}
      {proposals}
      {members.length > 1 && (
        <div className="row">
          <button className="btn sm ghost" onClick={() => onUnlink(members.map((f) => f.id!))}>
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
            if (narrative !== (chRev?.narrative ?? '')) onPatch({ narrative, narrativeBy: narrative ? 'analyst' : undefined })
          }}
          placeholder="what happened, in order, and what tied it to the mail…"
        />
        {chRev?.narrativeBy === 'ai' && chRev.narrative && <div className="small muted">written by the model during triage; edit it to make it yours (the next triage then leaves it alone)</div>}
        <div className="row" style={{ gap: 6 }}>
          <button className="btn sm" disabled={drafting} onClick={onDraft}>
            {drafting ? <Spinner /> : <IconAi />} draft with the analyst
          </button>
          <span className="small muted">the model only sees the chain's steps; edit before you keep it</span>
        </div>
      </div>
      <div className="row wrap" style={{ gap: 6 }}>
        <button className="btn sm ghost" onClick={onPrevious}>
          <IconArrowLeft /> previous
        </button>
        <button
          className="btn sm"
          onClick={() => {
            setFocusChain(ch.id)
            setView('stories')
          }}
        >
          open its story
        </button>
        <AddToTimeline
          ts={ch.start}
          text={`Attack chain ${ch.identityLabel}: ${chRev?.narrative?.slice(0, 200) || ch.summary}`}
          link={{ source: 'chains', id: ch.id, label: ch.identityLabel }}
          severity={chainSeverity(ch, chRev)}
        />
        <button className="btn sm" disabled={suggesting} onClick={onSuggest}>
          {suggesting ? <Spinner /> : <IconAi />} ask the model to decide
        </button>
        <span className="spacer" />
        <button className="btn sm primary" onClick={onNext}>
          <IconCheck /> {chRev?.verdict ? 'next' : 'mark unsure and next'}
        </button>
      </div>
    </div>
  )
}
