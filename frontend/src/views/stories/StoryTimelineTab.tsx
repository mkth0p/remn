import { StorySpine } from '../../components/StorySpine'
import type { RelationshipGraph } from '../../components/useRelationshipGraph'
import type { MeasureReading } from '../../data/ruleMeasures'
import type { StepCall, StoryView } from '../../data/storyDecisions'
import type { Story, StoryStep } from '../../data/stories'
import { StepDecisionPanel } from '../StoryDecisions'
import { StepPane } from './StepPane'
import { Timeline } from './Timeline'

/**
 * The open story read in time: its spine, or the full timeline (asked for, filtered by a phase, or
 * with a step open off the spine), and the step open beside it with the analyst's decision on it.
 */
export function StoryTimelineTab({
  story,
  view,
  step,
  stepId,
  setStepId,
  showAll,
  spine,
  phase,
  setPhase,
  setFull,
  labels,
  readings,
  g,
  onOpen,
  onOpenRefs,
  onExplore,
  onCall,
  onOut,
  onSplit,
}: {
  story: Story
  view: StoryView
  step: StoryStep | null
  stepId: string | null
  setStepId: (id: string | null) => void
  /** the full timeline shows */
  showAll: boolean
  spine: StoryStep[] | null
  phase: string | null
  setPhase: (p: string | null) => void
  setFull: (on: boolean) => void
  labels: Map<string, string>
  readings: Map<string, MeasureReading>
  g: RelationshipGraph
  onOpen: (source: 'events' | 'mails', id: number) => void
  onOpenRefs: (refs: string[]) => void
  onExplore: (nodeId: string) => void
  onCall: (step: StoryStep, verdict: StepCall['verdict'] | null, reason: string, alsoFalsePositive: boolean) => Promise<void>
  onOut: (step: StoryStep, reason: string) => Promise<void>
  onSplit: (step: StoryStep, reason: string) => Promise<void>
}) {
  return (
    <div className="pane" style={{ flex: 1, height: 'auto', borderTop: 0, gridTemplateColumns: step ? '1fr 380px' : '1fr' }}>
      <div className="pane-main" style={{ overflow: 'auto' }}>
        <StorySpine
          story={story}
          full={showAll}
          onFull={(on) => {
            setFull(on)
            if (on) return
            setPhase(null)
            if (stepId && !spine?.some((s) => s.id === stepId)) setStepId(null)
          }}
          selected={stepId}
          onSelect={setStepId}
          labels={labels}
        />
        {showAll && <Timeline story={story} phase={phase} selected={stepId} onSelect={setStepId} readings={readings} labels={labels} calls={view.steps} />}
      </div>
      {step && (
        <StepPane story={story} step={step} readings={readings} labels={labels} g={g} onOpen={onOpen} onOpenAll={(s) => onOpenRefs(s.refs)} onExplore={onExplore} onClose={() => setStepId(null)}>
          <StepDecisionPanel
            key={step.id}
            view={view}
            step={step}
            onCall={(verdict, reason, alsoFalsePositive) => onCall(step, verdict, reason, alsoFalsePositive)}
            onOut={(reason) => onOut(step, reason)}
            onSplit={(reason) => onSplit(step, reason)}
          />
        </StepPane>
      )}
    </div>
  )
}
