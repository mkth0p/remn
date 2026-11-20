import { IconHost, IconUser } from '../../components/Icons'
import { Dot } from '../../components/ui'
import { groupByIncident, LINK_LABEL, PHASES, type Story, type StoryIncident } from '../../data/stories'
import { dismissed, type StoryView } from '../../data/storyDecisions'
import { fmtNum, fmtTs } from '../../util/format'
import { StoryCallTag } from '../StoryDecisions'
import { CONFIDENCE_SEV, spanText } from './model'

/** A tiny strip of the fifteen phases, filled where the story has one: the shape of an intrusion at a glance. */
export function PhaseStrip({ story }: { story: Story }) {
  const by = new Map(story.phases.map((p) => [p.phase, p]))
  return (
    <span className="phase-strip" aria-label={`phases: ${story.phases.map((p) => p.label).join(', ') || 'none'}`}>
      {PHASES.map((p) => {
        const hit = by.get(p.id)
        return <span key={p.id} className={'cell' + (hit ? ` on ${hit.severity ?? 'info'}` : '')} title={hit ? `${p.label}: ${hit.steps} step(s)` : p.label} />
      })}
    </span>
  )
}

/** The phases of ATT&CK in their order, the story's in its own time order (1, 2, 3 ...), each a filter for the timeline. */
export function PhaseRail({ story, active, onPick }: { story: Story; active: string | null; onPick: (p: string | null) => void }) {
  const order = new Map(story.phases.map((p, i) => [p.phase, i + 1]))
  const by = new Map(story.phases.map((p) => [p.phase, p]))
  return (
    <div className="phase-rail" role="list" aria-label="ATT&CK phases of the story">
      {PHASES.map((p) => {
        const hit = by.get(p.id)
        return (
          <button
            key={p.id}
            role="listitem"
            className={'phase' + (hit ? ` on ${hit.severity ?? 'info'}` : '') + (active === p.id ? ' active' : '')}
            disabled={!hit}
            onClick={() => onPick(active === p.id ? null : p.id)}
            title={hit ? `${p.label}: ${hit.steps} step(s), ${hit.records} record(s), ${hit.findings} finding(s), ${fmtTs(hit.first)} → ${fmtTs(hit.last)}` : `${p.label}: nothing in this story`}
          >
            <span className="code">{p.short}</span>
            <span className="lbl">{p.label}</span>
            {hit && <span className="ord">{order.get(p.id)}</span>}
          </button>
        )
      })}
    </div>
  )
}

/** The stories, the highest-scoring first; those of one incident together, under a line that says so. */
export function StoryList({
  stories,
  incidents,
  active,
  onSelect,
  views,
}: {
  stories: Story[]
  incidents?: StoryIncident[]
  active: string | null
  onSelect: (id: string) => void
  views?: Map<string, StoryView>
}) {
  return (
    <>
      {groupByIncident(stories, (s) => s, incidents).map(({ incident, items }) =>
        incident ? (
          <div key={incident.id} role="group" aria-label={`Incident ${incident.label}`} style={{ borderLeft: '2px solid var(--line-2)', margin: '6px 0 6px 8px' }}>
            <div
              className="small"
              style={{ padding: '4px 10px', color: 'var(--fg-2)' }}
              title="stories that read as one intrusion: a strong or medium link joins each to another (open one to see why)"
            >
              <Dot sev={incident.severity} /> one intrusion · {items.length} stories{incident.stories.length > items.length ? ` of ${incident.stories.length} shown` : ''} ·{' '}
              {spanText(incident.end - incident.start)}
              {incident.cut > 0 && <span style={{ color: 'var(--sev-medium)' }}> · {incident.cut} linked left out (twenty at most)</span>}
            </div>
            <StoryRows stories={items} active={active} onSelect={onSelect} views={views} />
          </div>
        ) : (
          <StoryRows key={items[0].id} stories={items} active={active} onSelect={onSelect} views={views} />
        ),
      )}
    </>
  )
}

function StoryRows({ stories, active, onSelect, views }: { stories: Story[]; active: string | null; onSelect: (id: string) => void; views?: Map<string, StoryView> }) {
  return (
    <>
      {stories.map((s) => (
        <div
          key={s.id}
          className={'story-row' + (active === s.id ? ' active' : '') + (dismissed(views?.get(s.id)?.call?.verdict) ? ' dismissed' : '')}
          onClick={() => onSelect(s.id)}
          role="button"
          aria-label={`Story ${s.title}${views?.get(s.id)?.part === 'split' ? ' (second part)' : ''}`}
        >
          <Dot sev={s.severity} />
          <div style={{ minWidth: 0 }}>
            <div className="ellipsis name">
              {s.kind === 'host' ? <IconHost /> : <IconUser />} {s.title}
            </div>
            <div className="ellipsis small" style={{ color: 'var(--fg-2)' }} title={s.headline}>
              {s.headline}
            </div>
            <PhaseStrip story={s} />
            <div className="small mono" style={{ color: 'var(--fg-3)' }}>
              {fmtTs(s.start)} · {spanText(s.end - s.start)}
            </div>
          </div>
          <div className="meta">
            <span className="score">{s.score}</span>
            <span>{s.steps.length} steps</span>
            <span>{fmtNum(s.records)} records</span>
            <span className={s.confidence === 'high' ? 'bridged' : ''} title={s.confidenceBasis ?? 'how many of its flagged steps a record ties to it'}>
              {s.confidence} confidence
            </span>
            <StoryCallTag view={views?.get(s.id)} />
          </div>
        </div>
      ))}
    </>
  )
}

/** What a host story stands on, and the stories this one reads as one intrusion with: each link's kind, how surely and why. */
export function StoryLinks({ story, stories, onStory }: { story: Story; stories: Map<string, Story>; onStory: (id: string) => void }) {
  const links = story.links ?? []
  if (!links.length && !story.standing) return null
  return (
    <div className="small" style={{ marginTop: 8, color: 'var(--fg-2)' }}>
      {story.standing && <div title="what makes this host's flags a story of their own">Stands on {story.standing}.</div>}
      {links.length > 0 && (
        <div role="list" aria-label="Linked stories" style={{ marginTop: story.standing ? 4 : 0 }}>
          <strong style={{ color: 'var(--fg-1)' }}>Linked stories</strong>
          {links.map((l) => {
            const other = stories.get(l.story)
            return (
              <div key={l.story} role="listitem" style={{ marginTop: 2 }}>
                <Dot sev={CONFIDENCE_SEV[l.confidence]} title={`${l.confidence} link`} />{' '}
                {other ? (
                  <span className="click" style={{ cursor: 'pointer', color: 'var(--fg-1)' }} onClick={() => onStory(other.id)}>
                    {other.title}
                  </span>
                ) : (
                  <span className="muted">a story this build does not list</span>
                )}{' '}
                · {LINK_LABEL[l.kind] ?? l.kind}, {l.confidence}: {l.basis}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
