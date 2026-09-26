import { describe, expect, it } from 'vitest'
import type { Finding } from '../db/schema'
import { byPriority, decisionSignature, pastDecisions, PRIORITY, scoreFindings, shortReasons, userKey } from './findingPriority'
import { ruleTrust } from './ruleMeasures'
import { findingPhase } from './stories'

const H = 3_600_000
const T0 = Date.UTC(2026, 8, 1, 10)
let n = 0
function finding(p: Partial<Finding> & { ruleId: string }): Finding {
  n++
  return { id: n, caseId: 1, key: `${p.ruleId}|${n}`, title: p.ruleId, severity: 'high', source: 'events', ts: T0, entities: {}, count: 1, refs: [n], attack: [], status: 'new', createdAt: 0, ...p }
}
const on = (host: string, extra: Record<string, string> = {}) => ({ computer: host, ...extra })
const detects = ruleTrust({ hits: 3, of: 4, clean: { findings: 0, events: 0, machines: 0, scope: 1000, of: 7 } })
const trustAll = () => detects

describe('the priority of a finding', () => {
  it('starts from the effective severity and the rule confidence', () => {
    const plain = finding({ ruleId: 'r1', entities: on('ws-1') })
    const rescored = finding({ ruleId: 'r2', severity: 'low', severityOverride: 'critical', entities: on('ws-1'), ts: T0 + 100 * H })
    const unsure = finding({ ruleId: 'r3', confidence: 'low', entities: on('ws-1'), ts: T0 + 200 * H })
    const s = scoreFindings([plain, rescored, unsure], { trust: trustAll })
    expect(s.get(plain.key)!.score).toBe(PRIORITY.severity.high)
    expect(s.get(rescored.key)!.score).toBe(PRIORITY.severity.critical)
    expect(s.get(rescored.key)!.reasons[0].text).toBe("Critical severity (the review's override; the rule says low): 10 points.")
    expect(s.get(unsure.key)!.score).toBe(Math.round(6 * PRIORITY.confidence.low * 10) / 10)
    expect(s.get(unsure.key)!.reasons.map((r) => r.text)).toContain("Its rule's confidence is low: x0.7.")
  })

  it('weighs the rule by its measure as the stories do: a lead or a rule noisy on clean machines weighs less', () => {
    const f = finding({ ruleId: 'lead', entities: on('ws-1') })
    const g = finding({ ruleId: 'noisy', entities: on('ws-1'), ts: T0 + 100 * H })
    const trust = new Map([
      ['lead', ruleTrust({ of: 4 })],
      ['noisy', ruleTrust({ hits: 1, of: 1, clean: { findings: 12, events: 40, machines: 7, scope: 1000, of: 7 } })],
    ])
    const s = scoreFindings([f, g], { trust: (id) => trust.get(id) })
    expect(s.get(f.key)!.score).toBe(3.6)
    expect(s.get(f.key)!.reasons[1]).toMatchObject({ kind: 'trust', tone: 'down', short: 'lead', text: 'Its rule is a lead, never seen to detect what it looks for: x0.6.' })
    // fired on every clean machine: half its weight
    expect(s.get(g.key)!.score).toBe(3)
    expect(s.get(g.key)!.reasons[1].text).toBe('Its rule detects what it looks for on recorded attacks, and it fired on 7 of 7 clean machines: x0.5.')
    // a rule the page does not know (another tool's) is unmeasured
    expect(scoreFindings([f]).get(f.key)!.reasons[1].short).toBe('unmeasured')
  })

  it('ranks a rule that fires on one host of many above the same kind of rule firing everywhere', () => {
    const far = (i: number) => T0 + i * 100 * H
    const hosts = ['ws-1', 'ws-2', 'ws-3', 'ws-4']
    const everywhere = hosts.map((h, i) => finding({ ruleId: 'common', entities: on(h), ts: far(i) }))
    const once = finding({ ruleId: 'rare', entities: on('WS-2.corp.example'), ts: far(10) })
    const s = scoreFindings([...everywhere, once], { trust: trustAll })
    expect(s.get(once.key)!.score).toBe(6 * PRIORITY.rare)
    expect(s.get(once.key)!.reasons.find((r) => r.kind === 'rarity')!.text).toBe("Its rule fired on 1 of the 4 hosts of the case's findings (ws-2): x1.5.")
    expect(s.get(everywhere[0].key)!.score).toBe(6 * PRIORITY.common)
    expect(shortReasons(s.get(everywhere[0].key))).toBe('4 of 4 hosts')
    // a finding with no host is compared by its user
    const users = ['alice', 'bob', 'carol'].map((u, i) => finding({ ruleId: 'logon', entities: { targetUser: `CORP\\${u}` }, ts: far(20 + i) }))
    const lone = finding({ ruleId: 'spray', entities: { targetUser: 'alice@corp.example' }, ts: far(30) })
    const su = scoreFindings([...users, lone], { trust: trustAll })
    expect(su.get(lone.key)!.reasons.find((r) => r.kind === 'rarity')!.short).toBe('1 of 3 users')
  })

  it('does not call a rule rare in a case of fewer hosts than the floor', () => {
    const a = finding({ ruleId: 'x', entities: on('ws-1') })
    const b = finding({ ruleId: 'y', entities: on('ws-2'), ts: T0 + 100 * H })
    expect(
      scoreFindings([a, b], { trust: trustAll })
        .get(a.key)!
        .reasons.some((r) => r.kind === 'rarity'),
    ).toBe(false)
  })

  it('raises a finding that other rules corroborate on its host within a day, more for other tactics, and names them', () => {
    const f = finding({ ruleId: 'dump', title: 'LSASS dumped', attack: ['T1003.001'], entities: on('ws-1') })
    const same = finding({ ruleId: 'dump2', title: 'Credential file read', attack: ['T1555'], entities: on('WS-1'), ts: T0 + 3 * H })
    const other = finding({ ruleId: 'svc', title: 'Service installed', attack: ['T1543.003'], entities: on('ws-1'), ts: T0 - 20 * H })
    const late = finding({ ruleId: 'late', title: 'Too late', attack: ['T1021'], entities: on('ws-1'), ts: T0 + 30 * H })
    const fp = finding({ ruleId: 'fp', title: 'Dismissed', attack: ['T1021'], entities: on('ws-1'), ts: T0 + H, status: 'false_positive' })
    const elsewhere = finding({ ruleId: 'else', title: 'Elsewhere', attack: ['T1021'], entities: on('ws-9'), ts: T0 + H })
    const s = scoreFindings([f, same, other, late, fp, elsewhere], { trust: trustAll })
    const r = s.get(f.key)!.reasons.find((x) => x.kind === 'corroboration')!
    // two other rules, one of another tactic (persistence): +3
    expect(s.get(f.key)!.score).toBe(6 + 3)
    expect(r.short).toBe('+2 rules, 1 tactic')
    expect(r.text).toBe('2 other rules on ws-1 within 24 hours, 1 of another tactic: Service installed (persistence), Credential file read (credential access): +3.')
  })

  it('caps what corroboration adds and reads the same user on other hosts', () => {
    const f = finding({ ruleId: 'base', entities: { targetUser: 'alice' } })
    const many = Array.from({ length: 6 }, (_, i) =>
      finding({ ruleId: `r${i}`, attack: [['T1059', 'T1543', 'T1003', 'T1021', 'T1087', 'T1486'][i]], entities: { computer: `ws-${i}`, subjectUser: 'CORP\\Alice' }, ts: T0 + i * H }),
    )
    const s = scoreFindings([f, ...many], { trust: trustAll })
    expect(s.get(f.key)!.score).toBe(6 + PRIORITY.corroborationCap)
    expect(s.get(f.key)!.reasons.find((x) => x.kind === 'corroboration')!.text).toMatch(/^6 other rules for alice within 24 hours, 6 of another tactic: .* and 3 more: \+6\.$/)
  })

  it('demotes a finding an analyst marked false positive before on the same rule and entities, in another case, and says where and when', () => {
    const decidedAt = Date.UTC(2026, 7, 14, 9)
    const old = finding({
      caseId: 7,
      ruleId: 'psexec',
      entities: on('srv-1', { image: 'C:\\Tools\\PsExec.exe', commandLine: 'psexec \\\\srv' }),
      status: 'false_positive',
      decidedBy: 'analyst',
      decidedAt,
    })
    const now = finding({ ruleId: 'psexec', entities: on('ws-4', { image: 'c:\\tools\\psexec.exe', commandLine: 'PSEXEC \\\\srv' }) })
    const memory = pastDecisions([old], new Map([[7, 'Acme 2026-08']]))
    const p = scoreFindings([now], { trust: trustAll, memory }).get(now.key)!
    expect(p.score).toBe(6 * PRIORITY.falsePositiveBefore)
    expect(p.reasons.find((r) => r.kind === 'memory')!.text).toBe('The same rule on the same entities was marked false positive in case Acme 2026-08 on 2026-08-14: x0.25.')
    // another command line is another decision
    const other = finding({ ruleId: 'psexec', entities: on('ws-4', { image: 'c:\\tools\\psexec.exe', commandLine: 'psexec \\\\dc' }) })
    expect(
      scoreFindings([other], { trust: trustAll, memory })
        .get(other.key)!
        .reasons.some((r) => r.kind === 'memory'),
    ).toBe(false)
  })

  it('promotes a finding escalated before in this case, and ignores the model’s own decisions', () => {
    const first = finding({ ruleId: 'svc', entities: on('ws-1', { serviceName: 'evil' }), status: 'escalated' })
    const second = finding({ ruleId: 'svc', entities: on('ws-2', { serviceName: 'EVIL' }), ts: T0 + 100 * H })
    const memory = pastDecisions([first, second], new Map([[1, 'This']]))
    const s = scoreFindings([first, second], { trust: trustAll, memory })
    expect(s.get(second.key)!.score).toBe(6 + PRIORITY.escalatedBefore)
    expect(s.get(second.key)!.reasons.find((r) => r.kind === 'memory')!.text).toBe('The same rule on the same entities was escalated in this case: +5.')
    // its own decision is not a past one
    expect(s.get(first.key)!.reasons.some((r) => r.kind === 'memory')).toBe(false)
    const byModel = { ...first, id: 999, decidedBy: 'ai' as const }
    expect(pastDecisions([byModel], new Map())).toEqual([])
  })

  it('keys a decision on what the rule found, not where, unless the rule names only where', () => {
    expect(decisionSignature({ ruleId: 'r', entities: { computer: 'WS-1', user: 'bob', serviceName: 'Svc' } })).toBe('r\u0000serviceName=svc')
    expect(decisionSignature({ ruleId: 'r', entities: { subjectUser: 'Bob', ipAddress: '10.0.0.1' } })).toBe('r\u0000ipAddress=10.0.0.1\u0000subjectUser=bob')
    expect(decisionSignature({ ruleId: 'r', entities: {} })).toBeNull()
    expect(userKey('CORP\\Alice')).toBe('alice')
    expect(userKey('WS-1$')).toBe('')
    expect(userKey('NT AUTHORITY\\SYSTEM')).toBe('')
  })

  it('sorts decided findings below the new ones, then by score, then the latest first', () => {
    const low = finding({ ruleId: 'a', severity: 'low', entities: on('ws-1') })
    const crit = finding({ ruleId: 'b', severity: 'critical', entities: on('ws-1'), ts: T0 + 100 * H, status: 'reviewed' })
    const high = finding({ ruleId: 'c', severity: 'high', entities: on('ws-1'), ts: T0 + 200 * H })
    const esc = finding({ ruleId: 'd', severity: 'medium', entities: on('ws-1'), ts: T0 + 300 * H, status: 'escalated' })
    const s = scoreFindings([low, crit, high, esc], { trust: trustAll })
    expect([low, crit, high, esc].sort(byPriority(s)).map((f) => f.ruleId)).toEqual(['c', 'd', 'a', 'b'])
    expect(s.get(crit.key)!.decided).toBe(true)
    expect(s.get(crit.key)!.reasons.at(-1)!.text).toBe('Already reviewed: it sorts below the findings still to look at.')
    expect(s.get(esc.key)!.decided).toBe(false)
  })
})

describe('a finding’s tactic (mirror of stories.finding_phase)', () => {
  it('takes the rule’s tactic tag, else its technique’s, and splits defense evasion by the technique', () => {
    expect(findingPhase({ attack: ['T1003.001'], tags: [] })).toBe('credential-access')
    expect(findingPhase({ attack: ['attack.t1021.002'], tags: ['phishing'] })).toBe('initial-access')
    expect(findingPhase({ attack: ['T1562.001'], tags: ['defense-evasion'] })).toBe('defense-impairment')
    expect(findingPhase({ attack: [], tags: ['m365'] })).toBeNull()
  })
})
