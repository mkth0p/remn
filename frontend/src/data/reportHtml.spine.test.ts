import { describe, expect, it } from 'vitest'
import { defaultSettings, type Case } from '../db/schema'
import { buildReportHtml, type ReportData } from './reportHtml'
import { DEFAULT_REPORT } from './review'
import { oldStory, spinedStory } from '../test/spineStory'
import type { Story } from './stories'

const kase = { id: 1, name: 'Lab', analyst: 'A. Nalyst', createdAt: 0, updatedAt: 0, storage: 'browser', settings: defaultSettings() } as Case

function report(story: Story): string {
  const data: ReportData = {
    kase,
    generatedAt: 1_700_000_000_000,
    settings: DEFAULT_REPORT,
    summary: '',
    evidence: [],
    chains: [],
    reviews: {},
    membersOf: new Map(),
    graphs: {},
    campaignInsights: [],
    incidents: [],
    findings: [],
    iocs: [],
    timeline: [],
    tasks: [],
    notes: [],
    undecided: 0,
    stories: [{ story, key: 'person|x|2026-09-04' }],
  }
  const html = buildReportHtml(data)
  const at = html.indexOf('<h2>Stories</h2>')
  return html.slice(at, html.indexOf('<h2>', at + 1))
}

describe('the spine in the report', () => {
  it('prints each story’s spine before its phases, a row per step with why it is in the story, escaped', () => {
    const card = report(spinedStory())
    expect(card).toContain('Spine: 6 of 8 steps')
    expect(card.indexOf('Spine: 6 of 8 steps')).toBeLessThan(card.indexOf('>Phases<'))
    const spine = card.slice(card.indexOf('Spine: 6 of 8 steps'), card.indexOf('>Phases<'))
    const rows = spine.split('<tr>').slice(2)
    expect(rows).toHaveLength(6)
    // in time order, from the phishing mail to the service on fs-001; the steps off the spine are not in it
    expect(rows[0]).toContain('Mail from it-desk@northstar-sso.example')
    expect(rows[0]).toContain('<span class="chip">way in</span>')
    expect(rows[2]).toContain('<span class="chip">anchor</span>')
    // the worst finding under the step, and how many more it has
    expect(rows[2]).toContain('<span class="sub">LSASS dumped with comsvcs +1</span>')
    expect(rows[5]).toContain('Service installed: PSEXESVC <span class="dim">on</span> <code>fs-001</code>')
    expect(spine).not.toContain('AnyDesk')
    expect(spine).not.toContain('whoami')
    // the phase with the worst finding's severity, and the tie
    expect(rows[2]).toContain('<span class="pill critical">critical</span> Credential access')
    expect(rows[4]).toContain('strong: a network logon from ws-004 (4648 then 4624 type 3)')
    // what the case holds is escaped, the basis too
    expect(spine).toContain('Scheduled task created \\Updater &lt;script&gt;alert(1)&lt;/script&gt;')
    expect(spine).toContain('medium: the record names them (subject) &amp; the time')
    expect(spine).not.toContain('<script>')
    expect(spine).toContain('Mail from it-desk@northstar-sso.example &lt;reset&gt; &amp; more.</div>')
    // times are UTC
    expect(rows[0]).toContain('2026-09-04 08:00:00Z')
  })

  it('prints the phases alone for a story built before spines', () => {
    const card = report(oldStory())
    expect(card).not.toContain('Spine:')
    expect(card).not.toContain('>Phases<')
    expect(card).toContain('Credential access')
  })
})
