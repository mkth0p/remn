import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { RemnDB, setDb } from '../db/schema'
import { persistChainResult, type Chain, type ChainStep } from './chains'

let db: RemnDB

beforeEach(() => {
  db = new RemnDB(`chains-${Math.random()}`)
  setDb(db)
})
afterEach(async () => {
  await db.delete()
})

// an invented mail-led chain: the seed mail, then the steps given
function chain(steps: Partial<ChainStep>[], kind?: 'authentication', severity: Chain['severity'] = 'high'): Chain {
  return {
    kind,
    id: `chain-alice-${steps.length}`,
    identity: 'alice@example.test',
    identityLabel: 'alice@example.test',
    seed: { id: 1, ts: 1, subject: 'Invoice', fromAddr: 'billing@lure.example', risk: 80, flags: [], findings: [], urlDomains: [], attachments: [] },
    steps: steps.map((s, i) => ({ kind: 'event', source: 'events', id: i + 2, ts: i + 2, tsEnd: i + 2, count: 1, title: 'step', weight: 1, artifacts: [], findings: [], offsetMin: 0, ...s })),
    start: 1,
    end: 9,
    score: 60,
    severity,
    artifactLinks: 1,
    entities: { user: 'alice@example.test', ips: [], hosts: [], attackerAddresses: [], domains: [] },
    summary: '',
  }
}

async function attackOf(c: Chain): Promise<string[]> {
  await persistChainResult(1, { chains: [c], stats: {} })
  const [f] = await db.findings.where('[caseId+ruleId]').equals([1, 'chain']).toArray()
  return f.attack
}

describe('the ATT&CK techniques of a chain finding', () => {
  it('tags a mail-led chain whose steps only show the link resolved as phishing alone', async () => {
    expect(await attackOf(chain([{ title: 'DNS query lure.example', artifacts: ['mail URL domain lure.example'], operation: 22 }]))).toEqual(['T1566'])
  })

  it('adds email collection only for a step that forwards the mailbox, sets an inbox rule or reads it with a finding', async () => {
    const read = { title: 'mailbox items accessed (bind)', operation: 'MailItemsAccessed', origin: 'm365' as const }
    expect(await attackOf(chain([read]))).toEqual(['T1566'])
    expect(await attackOf(chain([{ ...read, findings: [{ ruleId: 'm365-burst', title: 'burst', severity: 'medium' }] }]))).toEqual(['T1566', 'T1114'])
    expect(await attackOf(chain([{ title: 'inbox rule created', operation: 'New-InboxRule', origin: 'm365' }]))).toEqual(['T1566', 'T1114'])
    expect(await attackOf(chain([{ title: 'mailbox forwarding to x@lure.example', operation: 'Set-Mailbox', artifacts: ['mailbox forwarding'] }]))).toEqual(['T1566', 'T1114'])
  })

  it('adds valid accounts only for a sign-in that worked and does not look like the person', async () => {
    const signIn = { title: 'sign-in from FR', operation: 'SignIn', origin: 'm365' as const }
    expect(await attackOf(chain([signIn]))).toEqual(['T1566'])
    expect(await attackOf(chain([{ ...signIn, title: 'sign-in from RU', artifacts: ['unexpected country'] }]))).toEqual(['T1566', 'T1078'])
    expect(await attackOf(chain([{ ...signIn, title: 'failed sign-in (50126)', artifacts: ['unexpected country'] }]))).toEqual(['T1566'])
  })

  it('keeps an authentication chain brute force, and valid accounts once a guessed password worked', async () => {
    expect(await attackOf(chain([], 'authentication', 'medium'))).toEqual(['T1110'])
    expect(await attackOf(chain([], 'authentication', 'high'))).toEqual(['T1110', 'T1078'])
  })
})
