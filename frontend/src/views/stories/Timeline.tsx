import { Badge, Dot } from '../../components/ui'
import { type MeasureReading } from '../../data/ruleMeasures'
import { PHASE_LABEL, PHASES, type Story, type StoryStep } from '../../data/stories'
import { type StepCall } from '../../data/storyDecisions'
import { fmtNum, fmtTs } from '../../util/format'
import { StepCallTag } from '../StoryDecisions'
import { CONFIDENCE_SEV, day, ORIGIN_CLASS, ORIGIN_ICON, ORIGIN_LABEL, spanText, TIE_LABEL } from './model'
import { pressable } from '../../components/pressable'

/** A finding on a step, with what its rule's measure says it is worth. */
function FindingBadge({ f, reading }: { f: StoryStep['findings'][number]; reading?: MeasureReading }) {
  const mark = reading && reading.verdict !== 'unmeasured' ? reading.label : ''
  return (
    <Badge sev={f.severity} title={`${f.title}${reading ? `\n${reading.attacks}${reading.clean ? `\n${reading.clean}` : ''}` : ''}`}>
      {f.title}
      {mark && <span className={'measure ' + reading!.verdict}> · {mark}</span>}
    </Badge>
  )
}

export function Timeline({
  story,
  phase,
  selected,
  onSelect,
  readings,
  labels,
  calls,
}: {
  story: Story
  phase: string | null
  selected: string | null
  onSelect: (id: string) => void
  readings: Map<string, MeasureReading>
  labels: Map<string, string>
  /** the analyst's call on each step: a disputed step is struck out */
  calls?: Map<string, StepCall>
}) {
  const steps = phase ? story.steps.filter((s) => s.phase === phase) : story.steps
  return (
    <div className="story">
      {!steps.length && (
        <div className="muted small" style={{ padding: 14 }}>
          No step in this phase.
        </div>
      )}
      {steps.map((s, i) => {
        const d = day(s.ts)
        const header = i === 0 || d !== day(steps[i - 1].ts)
        const Icon = ORIGIN_ICON[s.origin]
        const who = s.accounts.map((a) => labels.get(a) ?? a).slice(0, 3)
        return (
          <div key={s.id}>
            {header && <div className="story-day">{d}</div>}
            <div
              {...pressable}
              className={'step' + (selected === s.id ? ' active' : '') + (s.routine ? ' routine' : '') + (calls?.get(s.id)?.verdict === 'disputed' ? ' disputed' : '')}
              onClick={() => onSelect(s.id)}
            >
              <span className="t">
                {fmtTs(s.ts).slice(11, 19) || fmtTs(s.ts)}
                <br />
                <span className="phase-tag" title={s.phase ? `${PHASE_LABEL[s.phase]}: ${s.phaseBasis}` : 'context: no phase'}>
                  {s.phase ? (PHASES.find((p) => p.id === s.phase)?.short ?? '') : '·'}
                </span>
              </span>
              <span className={'n ' + ORIGIN_CLASS[s.origin]} title={ORIGIN_LABEL[s.origin]}>
                <Icon />
              </span>
              <span style={{ minWidth: 0 }}>
                <div className="title">
                  {s.title}
                  {s.count > 1 && (
                    <span className="muted" style={{ fontWeight: 400 }}>
                      {' '}
                      ×{fmtNum(s.count)}
                      {s.tsEnd > s.ts ? ` over ${spanText(s.tsEnd - s.ts)}` : ''}
                    </span>
                  )}
                </div>
                <div className="sub">{[s.host, s.ip, who.join(', ') + (s.accounts.length > 3 ? ` +${s.accounts.length - 3}` : '')].filter(Boolean).join(' · ')}</div>
                <div className="row wrap" style={{ gap: 4, marginTop: 3 }}>
                  {s.phase && <span className="phase-chip">{PHASE_LABEL[s.phase]}</span>}
                  {s.findings.map((f) => (
                    <FindingBadge key={f.key ?? f.ruleId} f={f} reading={readings.get(f.ruleId)} />
                  ))}
                  <span className="tie" title={s.tie.basis}>
                    <Dot sev={CONFIDENCE_SEV[s.tie.confidence]} /> {TIE_LABEL[s.tie.kind]}
                  </span>
                  <StepCallTag call={calls?.get(s.id)} />
                </div>
              </span>
            </div>
          </div>
        )
      })}
    </div>
  )
}
