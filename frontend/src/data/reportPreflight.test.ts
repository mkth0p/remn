import { describe, expect, it } from 'vitest'
import { issueStatus, preflightChecks } from './reportPreflight'
import type { Evidence } from '../db/schema'

const good = { id: 1, caseId: 1, name: 'dc.evtx', kind: 'evtx', status: 'done', integrity: 'verified', stats: { errors: 0 } } as unknown as Evidence
const input = { evidence: [good], rules: { lastRun: 1, evidenceAfter: 0, errors: 0 }, undecided: 0, aiDecided: 0, unprintedConfirmed: 0 }

describe('report preflight', () => {
  it('passes when the analysis is complete and decided', () => {
    const checks = preflightChecks(input)
    expect(checks.every((c) => c.ok)).toBe(true)
    expect(issueStatus(checks, { waivers: {}, finalAt: 5 })).toMatchObject({ status: 'final', finalAt: 5 })
  })

  it('stays a draft while a check is open, and becomes final once it is waived with a reason', () => {
    const checks = preflightChecks({ ...input, undecided: 3, rules: { lastRun: null, evidenceAfter: 0, errors: 0 } })
    expect(checks.filter((c) => !c.ok).map((c) => c.id)).toEqual(['rules', 'decided'])
    expect(issueStatus(checks, { waivers: {}, finalAt: 5 }).status).toBe('draft')
    expect(issueStatus(checks, { waivers: { rules: 'rules run by the SOC', decided: '  ' }, finalAt: 5 }).status).toBe('draft')
    const s = issueStatus(checks, { waivers: { rules: 'rules run by the SOC', decided: 'low-severity noise left for later' }, finalAt: 5 })
    expect(s.status).toBe('final')
    expect(s.waived.map((w) => w.reason)).toEqual(['rules run by the SOC', 'low-severity noise left for later'])
  })

  it('goes back to draft when a new check opens after issuing', () => {
    const later = preflightChecks({ ...input, rules: { lastRun: 1, evidenceAfter: 1, errors: 0 } })
    expect(issueStatus(later, { waivers: {}, finalAt: 5 }).status).toBe('draft')
  })

  it('counts a parse that stopped, and a file without a verified digest', () => {
    const stopped = { ...good, name: 'mail.pst', status: 'error', error: 'limit', integrity: 'pending' } as unknown as Evidence
    const checks = preflightChecks({ ...input, evidence: [good, stopped] })
    expect(checks.find((c) => c.id === 'read')).toMatchObject({ ok: false, detail: 'mail.pst' })
    expect(checks.find((c) => c.id === 'integrity')?.ok).toBe(false)
  })
})
