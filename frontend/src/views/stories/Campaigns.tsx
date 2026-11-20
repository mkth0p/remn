import { IconDownload } from '../../components/Icons'
import { Dot, Sev } from '../../components/ui'
import { type Campaign, type Story } from '../../data/stories'
import { useStore } from '../../state/store'
import { fmtNum, fmtTs } from '../../util/format'
import { PhaseStrip } from './StoryList'
import { spanText } from './model'
import { pressable, pressableRow } from '../../components/pressable'

export function CampaignList({ campaigns, stories, active, onSelect }: { campaigns: Campaign[]; stories: Map<string, Story>; active: string | null; onSelect: (id: string) => void }) {
  if (!campaigns.length)
    return (
      <div className="muted small" style={{ padding: 14, lineHeight: 1.5 }}>
        No campaign: no two stories share an address, a sender, a link, an attachment, a forwarding address or an application, and no flagged mail or failed logon stands outside a story.
      </div>
    )
  return (
    <>
      {campaigns.map((c) => (
        <div {...pressable} key={c.id} className={'story-row' + (active === c.id ? ' active' : '')} onClick={() => onSelect(c.id)} aria-label={`Campaign ${c.label}`}>
          <Dot sev={c.severity} />
          <div style={{ minWidth: 0 }}>
            <div className="ellipsis name mono">{c.label}</div>
            <div className="ellipsis small" style={{ color: 'var(--fg-2)' }}>
              {c.stories.length ? c.stories.map((s) => stories.get(s)?.title ?? s).join(', ') : 'no story'}
            </div>
            <div className="small mono" style={{ color: 'var(--fg-3)' }}>
              {fmtTs(c.start)} · {spanText(c.end - c.start)}
            </div>
          </div>
          <div className="meta">
            <span className="score">{c.stories.length}</span>
            <span>{c.stories.length === 1 ? 'story' : 'stories'}</span>
            <span>{fmtNum(c.targets.length)} other accounts</span>
          </div>
        </div>
      ))}
    </>
  )
}

export function CampaignDetail({
  campaign,
  stories,
  onStory,
  onOpenRefs,
  onExport,
}: {
  campaign: Campaign
  stories: Map<string, Story>
  onStory: (id: string) => void
  onOpenRefs: (refs: string[]) => void
  onExport: () => void
}) {
  const setEntity = useStore((s) => s.setEntity)
  // a story merged into another reads as that one: listed once
  const members = [...new Set(campaign.stories.map((s) => stories.get(s)).filter((s): s is Story => !!s))]
  return (
    <div className="view-body col" style={{ gap: 14 }}>
      <div className="section">
        <h3>
          <Sev sev={campaign.severity} /> {campaign.label}
        </h3>
        <div className="small muted">
          {campaign.labelKind.replace('-', ' ')} · {fmtTs(campaign.start)} → {fmtTs(campaign.end)} · {members.length} {members.length === 1 ? 'story' : 'stories'} · {fmtNum(campaign.targets.length)}{' '}
          other account(s) reached
        </div>
        <div className="row" style={{ marginTop: 8 }}>
          <button
            className="btn sm"
            onClick={onExport}
            title="the campaign as a STIX 2.1 grouping (suspicious activity): the Attack Flow of each story, the infrastructure they share, the accounts reached"
          >
            <IconDownload /> Download STIX grouping
          </button>
        </div>
      </div>
      {members.length > 0 && (
        <div className="section">
          <h3>Stories</h3>
          {members.map((s) => (
            <div {...pressable} key={s.id} className="story-row" onClick={() => onStory(s.id)}>
              <Dot sev={s.severity} />
              <div style={{ minWidth: 0 }}>
                <div className="name ellipsis">{s.title}</div>
                <div className="small ellipsis" style={{ color: 'var(--fg-2)' }}>
                  {s.headline}
                </div>
                <PhaseStrip story={s} />
              </div>
              <div className="meta">
                <span>{fmtTs(s.start)}</span>
              </div>
            </div>
          ))}
        </div>
      )}
      <div className="section">
        <h3>The infrastructure</h3>
        <table className="table compact">
          <thead>
            <tr>
              <th>kind</th>
              <th>value</th>
              <th>stories</th>
            </tr>
          </thead>
          <tbody>
            {campaign.artifacts.map((a) => (
              <tr key={a.kind + a.value}>
                <td>{a.kind.replace('-', ' ')}</td>
                <td
                  {...pressableRow}
                  className="mono click"
                  style={{ overflowWrap: 'anywhere' }}
                  onClick={() => (a.kind === 'ip' ? setEntity({ kind: 'ip', value: a.value }) : a.kind.endsWith('domain') ? setEntity({ kind: 'domain', value: a.value }) : undefined)}
                >
                  {a.value}
                </td>
                <td>{a.stories.map((s) => stories.get(s)?.title ?? s).join(', ')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {campaign.targets.length > 0 && (
        <div className="section">
          <h3>Other accounts it reached</h3>
          <p className="small muted" style={{ margin: 0 }}>
            Accounts in no story that the same sources reached: the recipients of its flagged mails, the accounts its addresses tried. Nothing here says they were compromised.
          </p>
          <table className="table compact" style={{ marginTop: 8 }}>
            <thead>
              <tr>
                <th>account</th>
                <th>what</th>
                <th>through</th>
                <th>records</th>
              </tr>
            </thead>
            <tbody>
              {campaign.targets.map((t) => (
                <tr {...pressableRow} key={t.id} style={{ cursor: 'pointer' }} onClick={() => onOpenRefs(t.refs)} title="open the records">
                  <td className="mono">{t.account}</td>
                  <td>{t.how.join(', ')}</td>
                  <td className="mono">{t.via.join(', ')}</td>
                  <td>{fmtNum(t.refs.length)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
