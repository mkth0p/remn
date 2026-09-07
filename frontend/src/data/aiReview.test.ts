import { describe, expect, it } from 'vitest'
import type { Chain } from './chains'
import type { Finding } from '../db/schema'
import { buildIncidents } from '../rules/incidents'
import { reviewQueue } from './review'
import { describeItem, normaliseDecision, parseDecisions, suggestionsFor } from './aiReview'

let seq = 1
const f = (p: Partial<Finding> & { ruleId: string; severity: Finding['severity'] }): Finding => ({ id: seq++, caseId: 1, key: `${p.ruleId}|${seq}`, title: p.ruleId, source: 'mails', ts: 10, entities: {}, count: 1, refs: [seq], attack: [], status: 'new', createdAt: 0, ...p })
const chain: Chain = {
  id: 'alice', identity: 'alice', identityLabel: 'alice@corp.test', start: 0, end: 3_600_000, score: 80, severity: 'high', artifactLinks: 1, summary: 'summary',
  seed: { id: 7, ts: 0, subject: 'Urgent invoice', fromAddr: 'x@evil.test', risk: 90, flags: ['spf_fail'], findings: [], urlDomains: [], attachments: [] },
  steps: [{ kind: 'event', source: 'events', id: 11, ts: 60_000, tsEnd: 60_000, count: 1, title: 'logon from 203.0.113.9', weight: 3, artifacts: ['mail URL domain'], findings: [], offsetMin: 1, origin: 'm365' }],
  entities: { user: 'alice', ips: ['203.0.113.9'], hosts: [], attackerAddresses: ['x@evil.test'], domains: [] },
}

function queue() {
  const rows = [
    f({ ruleId: 'chain', key: 'chain|alice|7', severity: 'high', refs: [7] }),
    f({ ruleId: 'mail-credential-phishing', severity: 'critical', refs: [7] }),
    f({ ruleId: 'win-logon-external', severity: 'medium', source: 'events', refs: [11], entities: { targetUser: 'alice' } }),
    f({ ruleId: 'other', severity: 'high', refs: [8], entities: { subject: 'Other mail' } }),
  ]
  return reviewQueue(buildIncidents(rows, { chains: [chain] }), [chain], {})
}

describe('AI review', () => {
  it('describes a chain with its seed, tied steps and linked finding ids, and an incident with its findings', () => {
    const [c, i] = queue()
    const dc = describeItem(c, {}) as { id: string; kind: string; steps: string[]; linkedFindings: { id: number; rule: string }[] }
    expect(dc.id).toBe('chain:alice')
    expect(dc.kind).toBe('chain')
    expect(dc.steps[0]).toContain('logon from 203.0.113.9')
    expect(dc.linkedFindings.map((x) => x.rule).sort()).toEqual(['mail-credential-phishing', 'win-logon-external'])
    const di = describeItem(i, {}) as { id: string; kind: string; findings: { rule: string }[] }
    expect(di.id).toBe(`incident:${i.incident!.id}`)
    expect(di.findings[0].rule).toBe('other')
  })

  it('parses a JSON array, fenced or wrapped in prose, validates decisions per kind and unlink ids against the chain', () => {
    const items = queue()
    const chainItem = items[0]
    const memberIds = chainItem.incident!.findings.filter((x) => x.ruleId !== 'chain').map((x) => x.id!)
    const text = `Here you go:\n\`\`\`json\n[{"id":"chain:alice","decision":"confirmed","severity":"critical","include":true,"reason":"External logon tied to the phishing URL.","unlink":[${memberIds[1]}, 9999]},{"id":"${items[1].id}","decision":"False Positive","severity":"nope","include":false,"reason":"Known sender."},{"id":"incident:ghost","decision":"reviewed","reason":"x"}]\n\`\`\``
    const { decisions, rejected } = parseDecisions(text, items)
    expect(decisions).toHaveLength(2)
    expect(decisions[0]).toMatchObject({ id: 'chain:alice', decision: 'confirmed', severity: 'critical', include: true, unlink: [memberIds[1]] })
    expect(decisions[1]).toMatchObject({ id: items[1].id, decision: 'false_positive', include: false })
    expect(decisions[1].severity).toBeUndefined()
    expect(rejected).toHaveLength(1)
    expect(rejected[0]).toContain('ghost')
  })

  it('reads the words models use for a decision and says them in the item kind\'s words', () => {
    const items = queue()
    const { decisions, rejected } = parseDecisions(JSON.stringify([{ id: 'chain:alice', decision: 'escalate', reason: 'r' }, { id: items[1].id, decision: 'dismiss', reason: 'r' }]), items)
    expect(decisions.map((d) => d.decision)).toEqual(['confirmed', 'reviewed'])
    expect(rejected).toHaveLength(0)
    expect(normaliseDecision('False Positive', 'chain')).toBe('benign')
    expect(normaliseDecision('true-positive', 'incident')).toBe('escalated')
    expect(normaliseDecision('inconclusive', 'incident')).toBe('reviewed')
    expect(normaliseDecision('whatever', 'incident')).toBeNull()
  })

  it('falls back to one object per line when the array is broken', () => {
    const items = queue()
    const { decisions } = parseDecisions('{"id":"chain:alice","decision":"unsure","reason":"not enough"}\n{"id":"nope","decision":"unsure","reason":"x"', items)
    expect(decisions.map((d) => d.id)).toEqual(['chain:alice'])
  })

  it('collects the suggestions that concern an item: its own target and its findings', () => {
    const [c, i] = queue()
    const memberId = c.incident!.findings[1].id!
    const all = {
      'chain:alice': { target: 'chain:alice', reason: 'a', at: 1, by: 'chat' as const },
      [`finding:${memberId}`]: { target: `finding:${memberId}`, reason: 'b', at: 1, by: 'chat' as const },
      [`incident:${i.incident!.id}`]: { target: `incident:${i.incident!.id}`, reason: 'c', at: 1, by: 'triage' as const },
    }
    expect(suggestionsFor(c, all).map((s) => s.reason)).toEqual(['a', 'b'])
    expect(suggestionsFor(i, all).map((s) => s.reason)).toEqual(['c'])
  })
})
