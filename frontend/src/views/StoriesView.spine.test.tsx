// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { storyInputs, type StoryResult } from '../data/stories'
import { defaultSettings, RemnDB, setDb, type Case, type Finding } from '../db/schema'
import { useStore } from '../state/store'
import { CAMPAIGN, IDENTITIES, spinedStory } from '../test/spineStory'

vi.mock('../api/client', () => ({ apiPost: vi.fn(), apiGet: vi.fn(), API_HEADERS: {} }))
vi.mock('../data/source', () => ({
  getSource: () => ({
    kind: 'browser',
    getEvent: async (id: number) => ({ id, caseId: 1, ts: 1, eventId: 4624, computer: 'ws-004', summary: `event ${id}` }),
    getMail: async () => null,
    searchEvents: async () => ({ rows: [] }),
    searchMails: async () => ({ rows: [] }),
    listIocs: async () => ({ rows: [] }),
  }),
}))
vi.mock('../data/rules', () => ({ loadRules: async () => [], settingsForRules: () => ({}) }))
vi.mock('../data/evidenceGaps', () => ({ loadEvidenceGaps: async () => [] }))
vi.mock('../util/export', async (orig) => ({ ...(await orig<typeof import('../util/export')>()), exportJson: vi.fn() }))

import { StoriesView } from './StoriesView'
import { exportJson } from '../util/export'

const WAIT = { timeout: 8000 }
const TEST_TIMEOUT = 30_000
const kase: Case = { id: 1, name: 'Lab', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }

async function snapshot(): Promise<StoryResult> {
  return {
    version: 1,
    stories: [spinedStory()],
    campaigns: [CAMPAIGN],
    chains: { chains: [], stats: {} },
    identities: IDENTITIES,
    hosts: [],
    unstoried: [],
    stats: { events: 8, mails: 1, truncated: [] },
    builtAt: 1,
    inputs: await storyInputs(kase),
  } as StoryResult
}

let db: RemnDB
beforeEach(async () => {
  db = new RemnDB(`storiesview-spine-${Math.random()}`)
  setDb(db)
  useStore.setState({ currentCase: kase, view: 'stories', focusChain: null })
  vi.mocked(exportJson).mockReset()
})
afterEach(async () => {
  cleanup()
  await db.delete()
})

const spineList = () => screen.queryByRole('list', { name: 'the spine of the story' })

describe('the spine on the Stories page', () => {
  it(
    'opens a story on its spine, first under the phase rail, and toggles to the full timeline',
    async () => {
      await db.kv.put({ key: 'stories-1', value: await snapshot() })
      render(<StoriesView />)
      await screen.findByRole('button', { name: 'Story daniel.roy@northstar.example' }, WAIT)
      // the spine is the first thing of the story's reading, with how it was drawn
      const main = document.querySelector('.pane-main')!
      expect(main.firstElementChild?.className).toBe('spine-block')
      expect(screen.getByText('6 of 8 steps')).toBeTruthy()
      expect(screen.getByText(/Anchored on LSASS dumped with comsvcs on ws-004/)).toBeTruthy()
      const steps = within(spineList()!).getAllByRole('button')
      expect(steps.map((s) => s.querySelector('.title')?.firstChild?.textContent)).toEqual([
        'Mail from it-desk@northstar-sso.example: Password reset required',
        'Logon RemoteInteractive as NORTHSTAR\\daniel.roy from 203.0.113.69',
        'rundll32.exe comsvcs.dll MiniDump of lsass.exe',
        'Scheduled task created \\Updater <script>alert(1)</script>',
        'Logon Network as NORTHSTAR\\daniel.roy from 10.0.0.14',
        'Service installed: PSEXESVC',
      ])
      expect(steps[0].className).toContain('way-in')
      expect(steps[2].className).toContain('anchor')
      expect(steps[2].className).toContain('critical')
      expect(within(steps[4]).getByText(/same way in: a network logon from ws-004/)).toBeTruthy()
      // the steps off the spine wait in the full timeline
      expect(screen.queryByText('whoami.exe /all')).toBeNull()
      fireEvent.click(screen.getByRole('button', { name: 'Full timeline' }))
      expect(await screen.findByText('whoami.exe /all')).toBeTruthy()
      expect(screen.getByText('AnyDesk.exe started')).toBeTruthy()
      expect(spineList()).toBeNull()
      fireEvent.click(screen.getByRole('button', { name: 'Spine' }))
      expect(spineList()).toBeTruthy()
      expect(screen.queryByText('whoami.exe /all')).toBeNull()
      // a phase of the rail filters the full timeline; back to the spine clears it
      const rail = screen.getByRole('list', { name: 'ATT&CK phases of the story' })
      fireEvent.click(within(rail).getByText('Discovery'))
      expect(await screen.findByText('whoami.exe /all')).toBeTruthy()
      expect(screen.queryByText('AnyDesk.exe started')).toBeNull()
      expect(screen.getByRole('button', { name: 'Full timeline' }).getAttribute('aria-pressed')).toBe('true')
      fireEvent.click(screen.getByRole('button', { name: 'Spine' }))
      expect(spineList()).toBeTruthy()
      expect(within(rail).getByText('Discovery').closest('button')!.className).not.toContain('active')
      // a step of the spine opens as a step of the timeline does
      fireEvent.click(within(spineList()!).getAllByRole('button')[2])
      expect(await screen.findByText('Why it is in the story')).toBeTruthy()
    },
    TEST_TIMEOUT,
  )

  it(
    'downloads a story as an Attack Flow and a campaign as a STIX grouping',
    async () => {
      await db.kv.put({ key: 'stories-1', value: await snapshot() })
      // the ATT&CK tags come from the case's findings
      await db.findings.add({
        caseId: 1,
        key: 'win-lsass-dump-comsvcs|1',
        ruleId: 'win-lsass-dump-comsvcs',
        title: 'LSASS dumped with comsvcs',
        severity: 'critical',
        source: 'events',
        ts: 1,
        entities: {},
        count: 1,
        refs: [11],
        attack: ['attack.credential_access', 'attack.t1003.001'],
        status: 'new',
        createdAt: 1,
      } as Finding)
      render(<StoriesView />)
      await screen.findByRole('button', { name: 'Story daniel.roy@northstar.example' }, WAIT)
      fireEvent.click(screen.getByRole('button', { name: /Download Attack Flow/ }))
      await waitFor(() => expect(exportJson).toHaveBeenCalledTimes(1), WAIT)
      const [name, flow] = vi.mocked(exportJson).mock.calls[0] as [string, { objects: Record<string, unknown>[] }]
      expect(name).toBe('attack-flow-daniel.roy_northstar.example.json')
      expect(flow.objects.filter((o) => o.type === 'attack-flow')).toHaveLength(1)
      expect(flow.objects.filter((o) => o.type === 'attack-action')).toHaveLength(6)
      expect(flow.objects.find((o) => o.type === 'attack-action' && o.name === 'LSASS dumped with comsvcs')?.technique_id).toBe('T1003.001')

      fireEvent.click(screen.getByText('Campaigns'))
      fireEvent.click(await screen.findByRole('button', { name: 'Campaign 203.0.113.69' }))
      fireEvent.click(await screen.findByRole('button', { name: /Download STIX grouping/ }))
      await waitFor(() => expect(exportJson).toHaveBeenCalledTimes(2), WAIT)
      const [gname, grouping] = vi.mocked(exportJson).mock.calls[1] as [string, { objects: Record<string, unknown>[] }]
      expect(gname).toBe('stix-grouping-203.0.113.69.json')
      expect(grouping.objects.find((o) => o.type === 'grouping')).toMatchObject({ context: 'suspicious-activity' })
    },
    TEST_TIMEOUT,
  )
})
