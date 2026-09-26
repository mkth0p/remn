import type { Severity } from '../db/schema'
import { PHASE_LABEL, type Confidence, type Story, type StoryFinding, type StoryStep } from '../data/stories'
import { spineBasis, spineSteps } from '../data/storyExport'
import { fmtNum, fmtTs } from '../util/format'
import { Badge, Dot } from './ui'

/**
 * A story's spine (docs/stories.md, "Spine"): the few steps that carry it from the way in to the
 * worst of it, the first thing a reader of a story sees. Each step keeps the tie that put it in the
 * story, and how long after the step before it came; the way in and the finding the spine was
 * walked back from are marked. The toggle opens the full timeline. A story built before spines has
 * none: nothing shows and the page shows the timeline.
 */

/** why a step is in the story, in the timeline's words */
const TIE_WORDS: Record<StoryStep['tie']['kind'], string> = {
  flag: 'flagged',
  chain: 'phishing chain',
  session: 'same session',
  hop: 'same way in',
  process: 'process tree',
  address: 'same source',
  identity: 'same person',
}
const CONFIDENCE_SEV: Record<Confidence, string> = { strong: 'ok', medium: 'medium', weak: 'info' }
const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

const worst = (s: StoryStep): StoryFinding | null => s.findings.reduce<StoryFinding | null>((w, f) => (!w || SEV_RANK[f.severity] > SEV_RANK[w.severity] ? f : w), null)
const day = (ts: number) => fmtTs(ts, { date: true }).slice(0, 10)

/** how long after the step before: nothing under a minute */
function after(ms: number): string {
  const m = ms / 60_000
  return m < 1 ? '' : m < 90 ? `+${Math.round(m)} min` : m < 48 * 60 ? `+${(m / 60).toFixed(1)} h` : `+${(m / 1440).toFixed(1)} d`
}

export function StorySpine({
  story,
  full,
  onFull,
  selected,
  onSelect,
  labels,
}: {
  story: Story
  /** the full timeline shows instead of the spine */
  full: boolean
  onFull: (full: boolean) => void
  selected: string | null
  onSelect: (id: string) => void
  labels: Map<string, string>
}) {
  const steps = spineSteps(story)
  if (!steps?.length) return null
  const basis = spineBasis(story)
  const ways = new Set(basis?.wayIn ?? [])
  return (
    <div className="spine-block">
      <div className="spine-head">
        <strong>Spine</strong>
        <span className="muted small">
          {steps.length} of {fmtNum(story.steps.length)} steps
        </span>
        <div className="segmented" role="group" aria-label="what the story shows">
          <button className={full ? '' : 'active'} aria-pressed={!full} onClick={() => onFull(false)}>
            Spine
          </button>
          <button className={full ? 'active' : ''} aria-pressed={full} onClick={() => onFull(true)}>
            Full timeline
          </button>
        </div>
      </div>
      {!full && (
        <>
          {basis && <p className="spine-basis">{basis.text}</p>}
          <ol className="spine" aria-label="the spine of the story">
            {steps.map((s, i) => {
              const f = worst(s)
              const prev = steps[i - 1]
              const who = s.accounts.map((a) => labels.get(a) ?? a).slice(0, 2)
              const marks = [ways.has(s.id) && 'way in', s.id === basis?.anchor && 'anchor'].filter(Boolean) as string[]
              return (
                <li
                  key={s.id}
                  className={['spine-step', f?.severity ?? 'info', selected === s.id && 'active', ways.has(s.id) && 'way-in', s.id === basis?.anchor && 'anchor'].filter(Boolean).join(' ')}
                  onClick={() => onSelect(s.id)}
                  role="button"
                  aria-current={selected === s.id || undefined}
                >
                  <span className="when">
                    {(!prev || day(prev.ts) !== day(s.ts)) && <span className="d">{day(s.ts)}</span>}
                    {fmtTs(s.ts).slice(11, 19) || fmtTs(s.ts)}
                    {prev && <span className="gap">{after(s.ts - prev.ts)}</span>}
                  </span>
                  <span className="knot" aria-hidden="true" />
                  <span className="what">
                    <span className="title">
                      {s.title}
                      {s.count > 1 && <span className="muted"> ×{fmtNum(s.count)}</span>}
                      {marks.map((m) => (
                        <span key={m} className="mark" title={m === 'anchor' ? 'the worst finding the spine was walked back from' : 'how the intruder got in, as far as the evidence shows'}>
                          {m}
                        </span>
                      ))}
                    </span>
                    <span className="sub">{[s.host, s.ip, who.join(', ') + (s.accounts.length > 2 ? ` +${s.accounts.length - 2}` : '')].filter(Boolean).join(' · ')}</span>
                    <span className="row wrap" style={{ gap: 4 }}>
                      {s.phase && <span className="phase-chip">{PHASE_LABEL[s.phase]}</span>}
                      {f && (
                        <Badge sev={f.severity} title={f.title}>
                          {f.title}
                          {s.findings.length > 1 ? ` +${s.findings.length - 1}` : ''}
                        </Badge>
                      )}
                      <span className="tie" title={s.tie.basis}>
                        <Dot sev={CONFIDENCE_SEV[s.tie.confidence]} /> {TIE_WORDS[s.tie.kind]}: {s.tie.basis}
                      </span>
                    </span>
                  </span>
                </li>
              )
            })}
          </ol>
        </>
      )}
    </div>
  )
}
