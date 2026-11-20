import { IconPlay } from '../../components/Icons'
import { Spinner } from '../../components/ui'
import type { StoryView } from '../../data/storyDecisions'
import type { StoryResult } from '../../data/stories'
import { fmtTs } from '../../util/format'
import { SEV_ORDER } from './model'

/** The page's title: how many stories by severity, the campaigns, when they were built, and the build. */
export function StoriesHeader({ res, views, loaded, busy, onRebuild }: { res: StoryResult | null; views: StoryView[]; loaded: boolean; busy: boolean; onRebuild: () => void }) {
  const sevCounts = views.reduce<Record<string, number>>((m, v) => ((m[v.story.severity] = (m[v.story.severity] ?? 0) + 1), m), {})
  return (
    <div className="view-header">
      <div className="desc">
        <h1>Stories</h1>
        <span className="sub">
          {res
            ? `${views.length} ${views.length === 1 ? 'story' : 'stories'} · ${
                SEV_ORDER.slice()
                  .reverse()
                  .filter((k) => sevCounts[k])
                  .map((k) => `${sevCounts[k]} ${k}`)
                  .join(', ') || 'none'
              } · ${res.campaigns.length} campaign(s) · built ${res.builtAt ? fmtTs(res.builtAt) : ''}`
            : loaded
              ? busy
                ? 'reading the case into stories…'
                : 'not built yet: run the rules first, the stories start from their findings'
              : ''}
        </span>
      </div>
      <span className="spacer" />
      <button className="btn sm primary" onClick={onRebuild} disabled={busy}>
        {busy ? <Spinner /> : <IconPlay />} {res ? 'Rebuild stories' : 'Build stories'}
      </button>
    </div>
  )
}
