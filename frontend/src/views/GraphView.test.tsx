// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Chain, ChainResult } from '../data/chains'
import { defaultSettings, RemnDB, setDb, type Case } from '../db/schema'
import { useStore } from '../state/store'

// the ECharts canvas does not run in jsdom: stand the graph in with its props
vi.mock('../components/ChainGraph', () => ({
  ChainGraph: ({ mode, chain, chains, onStep, onChain }: { mode: string; chain: Chain | null; chains: Chain[]; onStep: (i: number) => void; onChain: (id: string) => void }) => (
    <div data-testid="chain-graph" data-mode={mode} data-chain={chain?.id ?? ''} data-count={chains.length}>
      <button onClick={() => onStep(0)}>graph step 0</button>
      <button onClick={() => onChain(chains[1]?.id ?? '')}>graph chain 1</button>
    </div>
  ),
}))

import { GraphView } from './GraphView'

const WAIT = { timeout: 8000 }
const TEST_TIMEOUT = 30_000
const T0 = Date.UTC(2026, 8, 4, 8, 26)
const kase: Case = { id: 1, name: 'Lab', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }

const chain = (id: string, who: string, score: number): Chain => ({
  id,
  identity: who,
  identityLabel: who,
  seed: { source: 'mails', id: 1, ts: T0, subject: `Invoice for ${who}`, fromAddr: 'billing@evil.example', risk: 85, flags: [], findings: [], urlDomains: ['evil.example'], attachments: [] },
  steps: [
    {
      kind: 'event',
      source: 'events',
      id: 7,
      refs: [7, 8],
      ts: T0 + 60_000,
      tsEnd: T0 + 120_000,
      count: 2,
      title: `Sign-in by ${who} from 203.0.113.69`,
      weight: 10,
      artifacts: ['ip 203.0.113.69'],
      findings: [{ ruleId: 'm365-risky-signin', title: 'Risky sign-in', severity: 'high' }],
      offsetMin: 1,
      ipAddress: '203.0.113.69',
      origin: 'm365',
    },
  ],
  start: T0,
  end: T0 + 2 * 3_600_000,
  score,
  severity: score >= 80 ? 'critical' : 'high',
  artifactLinks: 1,
  entities: { user: who, ips: ['203.0.113.69'], hosts: [], attackerAddresses: ['billing@evil.example'], domains: ['evil.example'] },
  summary: `${who} opened the invoice and signed in from 203.0.113.69`,
})

let db: RemnDB
beforeEach(async () => {
  db = new RemnDB(`graphview-${Math.random()}`)
  setDb(db)
  useStore.setState({ currentCase: kase, view: 'graph', focusChain: null })
})
afterEach(async () => {
  cleanup()
  await db.delete()
})

describe('the Graph page', () => {
  it(
    'sends the analyst to Stories when no chains were built',
    async () => {
      render(<GraphView />)
      expect(await screen.findByText('No chains to draw', {}, WAIT)).toBeTruthy()
      fireEvent.click(screen.getByText('Go to Stories'))
      expect(useStore.getState().view).toBe('stories')
    },
    TEST_TIMEOUT,
  )

  it(
    'lists the chains, opens the focused one, details a step and switches to all chains',
    async () => {
      const res: ChainResult = { chains: [chain('c-alice', 'alice@corp.example', 90), chain('c-bob', 'bob@corp.example', 60)], stats: {}, builtAt: T0 }
      await db.kv.put({ key: 'chains-1', value: res })
      useStore.setState({ focusChain: 'c-bob' })
      render(<GraphView />)
      expect(await screen.findByRole('button', { name: 'Chain alice@corp.example' }, WAIT)).toBeTruthy()
      expect(screen.getByRole('button', { name: 'Chain bob@corp.example' }).className).toContain('active')
      expect(useStore.getState().focusChain).toBeNull()
      const graph = screen.getByTestId('chain-graph')
      expect(graph.dataset.mode).toBe('chain')
      expect(graph.dataset.chain).toBe('c-bob')
      // a step clicked in the graph opens its pane
      fireEvent.click(screen.getByText('graph step 0'))
      expect(await screen.findByText('Step 1 of 1')).toBeTruthy()
      expect(screen.getByText('Microsoft 365 / Entra')).toBeTruthy()
      expect(screen.getByText('m365-risky-signin')).toBeTruthy()
      fireEvent.click(screen.getByText('Open 2 row(s)'))
      expect(useStore.getState().view).toBe('events')
      expect(useStore.getState().eventsFilter.conditions).toEqual([{ field: 'id', op: 'in', value: [7, 8] }])
    },
    TEST_TIMEOUT,
  )

  it(
    'opens a chain clicked in the all-chains graph as its own graph',
    async () => {
      const res: ChainResult = { chains: [chain('c-alice', 'alice@corp.example', 90), chain('c-bob', 'bob@corp.example', 60)], stats: {}, builtAt: T0 }
      await db.kv.put({ key: 'chains-1', value: res })
      render(<GraphView />)
      await screen.findByRole('button', { name: 'Chain alice@corp.example' }, WAIT)
      fireEvent.click(screen.getByText('all chains'))
      expect(screen.getByTestId('chain-graph').dataset.mode).toBe('campaign')
      expect(screen.getByText('2 chains against the sender addresses, link domains, IPs and hosts they share')).toBeTruthy()
      fireEvent.click(screen.getByText('graph chain 1'))
      expect(screen.getByTestId('chain-graph').dataset.mode).toBe('chain')
      expect(screen.getByTestId('chain-graph').dataset.chain).toBe('c-bob')
    },
    TEST_TIMEOUT,
  )
})
