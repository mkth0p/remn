import { describe, expect, it } from 'vitest'
import type { Chain, ChainStep } from './chains'
import { buildCampaignGraph, buildChainGraph, MAX_COLUMNS } from './chainGraph'

const M = 60_000
const step = (p: Partial<ChainStep> & { title: string; ts: number }): ChainStep => ({
  kind: 'event',
  source: 'events',
  id: null,
  count: 1,
  weight: 1,
  artifacts: [],
  findings: [],
  offsetMin: (p.ts - 1000) / M,
  tsEnd: p.ts,
  origin: 'm365',
  ...p,
})
const chain = (p: Partial<Chain> = {}): Chain => ({
  id: 'c1',
  identity: 'alice',
  identityLabel: 'alice@corp.test',
  start: 1000,
  end: 1000 + 60 * M,
  score: 90,
  severity: 'critical',
  artifactLinks: 2,
  summary: 's',
  seed: {
    id: 7,
    ts: 1000,
    subject: 'Urgent invoice',
    fromAddr: 'ceo@evil.test',
    risk: 90,
    flags: [],
    findings: [{ ruleId: 'mail-credential-phishing', title: 'Credential phishing', severity: 'critical' }],
    urlDomains: ['evil-login.net'],
    attachments: ['invoice.html'],
  },
  entities: { user: 'alice@corp.test', ips: ['203.0.113.9'], hosts: ['WS-1.corp.test'], attackerAddresses: ['ceo@evil.test'], domains: ['evil-login.net'] },
  steps: [
    step({ title: 'sign-in from NL', ts: 1000 + 1 * M, ipAddress: '203.0.113.9' }),
    step({ title: 'sign-in from NL', ts: 1000 + 2 * M, ipAddress: '203.0.113.9' }),
    step({ title: 'mailbox items accessed', ts: 1000 + 3 * M, ipAddress: '203.0.113.9' }),
    step({
      title: 'reply to the sender: RE: Urgent invoice',
      ts: 1000 + 5 * M,
      kind: 'mail',
      source: 'mails',
      id: 8,
      weight: 4,
      artifacts: ['victim engaged with the sender', 'same thread'],
      origin: undefined,
    }),
    step({ title: 'DNS query evil-login.net', ts: 1000 + 9 * M, origin: 'host', computer: 'WS-1.corp.test', weight: 4, artifacts: ['mail URL domain evil-login.net'] }),
    step({
      title: 'inbox rule created: forward to drop@evil.test',
      ts: 1000 + 20 * M,
      ipAddress: '203.0.113.9',
      weight: 5,
      artifacts: ['forwarding rule'],
      findings: [{ ruleId: 'm365-inbox-rule-forwarding', title: 'Inbox rule forwards mail', severity: 'high' }],
    }),
  ],
  ...p,
})

describe('buildChainGraph', () => {
  it('collapses routine runs, keeps linked steps, and ties artifacts back to the seed infrastructure', () => {
    const g = buildChainGraph(chain())
    const ids = g.nodes.map((n) => n.id)
    expect(ids).toContain('seed')
    expect(ids).toContain('victim')
    expect(ids.filter((i) => i.startsWith('routine:'))).toHaveLength(1)
    const routine = g.nodes.find((n) => n.kind === 'routine')!
    expect(routine.stepIdxs).toEqual([0, 1, 2])
    expect(routine.label).toBe('3 routine steps')
    expect(routine.lane).toBe('cloud')
    expect(g.nodes.filter((n) => n.kind === 'step').map((n) => n.stepIdx)).toEqual([3, 4, 5])
    // artifact edges: reply -> sender address, DNS step <- link domain, rule -> forward address
    const artifacts = g.edges.filter((e) => e.kind === 'artifact')
    expect(artifacts).toContainEqual({ source: 'step:3', target: 'address:ceo@evil.test', kind: 'artifact', label: 'replied' })
    expect(artifacts).toContainEqual({ source: 'domain:evil-login.net', target: 'step:4', kind: 'artifact', label: 'link' })
    expect(artifacts).toContainEqual({ source: 'step:5', target: 'address:drop@evil.test', kind: 'artifact', label: 'forwards to' })
    // machines and ips hang under the steps; the sequence runs seed -> victim -> routine -> steps
    expect(g.nodes.find((n) => n.id === 'host:WS-1.corp.test')?.lane).toBe('infra')
    expect(g.edges.filter((e) => e.kind === 'sequence').map((e) => `${e.source}>${e.target}`)).toEqual(['victim>routine:0', 'routine:0>step:3', 'step:3>step:4', 'step:4>step:5'])
    expect(g.nodes.find((n) => n.id === 'step:5')?.severity).toBe('high')
    expect(g.columns).toBe(5)
    // columns increase with time; entity nodes sit at the mean column of their neighbours
    expect(g.nodes.find((n) => n.id === 'step:4')!.x).toBeGreaterThan(g.nodes.find((n) => n.id === 'step:3')!.x)
    expect(g.nodes.find((n) => n.id === 'ip:203.0.113.9')!.x).toBeGreaterThan(0)
  })

  it('does not collapse a routine step that carries a finding', () => {
    const c = chain({ steps: [step({ title: 'sign-in', ts: 2000, findings: [{ ruleId: 'r', title: 't', severity: 'low' }] }), step({ title: 'sign-in', ts: 3000 })] })
    const g = buildChainGraph(c)
    expect(g.nodes.filter((n) => n.kind === 'step')).toHaveLength(1)
    expect(g.nodes.filter((n) => n.kind === 'routine')).toHaveLength(1)
  })
})

describe('buildCampaignGraph', () => {
  it('marks infrastructure shared by several chains and lists it as an insight', () => {
    const a = chain({ id: 'a' })
    const b = chain({
      id: 'b',
      identityLabel: 'bob@corp.test',
      entities: { user: 'bob@corp.test', ips: ['203.0.113.9', '198.51.100.7'], hosts: [], attackerAddresses: ['ceo@evil.test'], domains: ['other.test'] },
    })
    const g = buildCampaignGraph([a, b])
    expect(g.nodes.filter((n) => n.kind === 'chain')).toHaveLength(2)
    expect(g.nodes.find((n) => n.id === 'ip:203.0.113.9')?.degree).toBe(2)
    expect(g.nodes.find((n) => n.id === 'ip:198.51.100.7')?.degree).toBe(1)
    expect(g.nodes.find((n) => n.id === 'address:ceo@evil.test')?.degree).toBe(2)
    expect(g.insights.map((i) => i.text)).toContain('source ip 203.0.113.9 appears in 2 chains'.replace('source ip', 'ip'))
    expect(g.insights.some((i) => i.text.includes('ceo@evil.test appears in 2 chains'))).toBe(true)
    expect(g.edges.every((e) => e.source.startsWith('chain:'))).toBe(true)
  })
})

describe('folding', () => {
  it('folds consecutive repeats of the same action even when they carry findings, and never folds a step tied to the mail', () => {
    const steps: ChainStep[] = []
    for (let i = 0; i < 30; i++)
      steps.push(
        step({
          title: `sign-in from NL via Other clients to Office 365 (${i})`,
          ts: 1000 + i * M,
          ipAddress: '203.0.113.9',
          weight: 2,
          findings: [{ ruleId: 'm365-signin-risky', title: 'Risky sign-in', severity: 'high' }],
        }),
      )
    steps.push(step({ title: 'DNS query evil-login.net', ts: 1000 + 40 * M, origin: 'host', computer: 'WS-1', weight: 4, artifacts: ['mail URL domain evil-login.net'] }))
    for (let i = 0; i < 30; i++)
      steps.push(
        step({
          title: 'mailbox items accessed (Sync)',
          ts: 1000 + (50 + i) * M,
          ipAddress: '203.0.113.9',
          weight: 2,
          findings: [{ ruleId: 'm365-mailitemsaccessed-burst', title: 'Burst', severity: 'medium' }],
        }),
      )
    const g = buildChainGraph(chain({ steps }))
    const stepNodes = g.nodes.filter((n) => n.kind === 'step' || n.kind === 'routine')
    expect(stepNodes).toHaveLength(3)
    expect(stepNodes[0].label).toMatch(/×30$/)
    expect(stepNodes[0].severity).toBe('high')
    expect(stepNodes[0].stepIdxs).toHaveLength(30)
    expect(stepNodes[1].stepIdx).toBe(30)
    expect(g.edges.filter((e) => e.kind === 'artifact')).toHaveLength(1)
    expect(g.columns).toBeLessThanOrEqual(MAX_COLUMNS + 1)
  })
})
