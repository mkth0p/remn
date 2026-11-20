import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case, type Finding } from '../db/schema'
import { decisionCases, loadDecisionSources, loadPastDecisions, saveDecisionSources } from './findingPriority'

/**
 * Decisions an analyst took in one case, read for another. The cases are invented: two
 * engagements in one browser, the second for another client whose IT runs the same tool.
 */

let db: RemnDB
const kase = (id: number, name: string): Case => ({ id, name, storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() })
const decided = (caseId: number, key: string, status: Finding['status'], patch: Partial<Finding> = {}): Finding => ({
  caseId,
  key,
  ruleId: 'win-psexec-service',
  title: 'PsExec service installed',
  source: 'events',
  severity: 'high',
  refs: [1],
  entities: { computer: 'srv-1', image: 'C:\\Tools\\PsExec.exe' },
  count: 1,
  attack: [],
  ts: 1,
  status,
  decidedBy: 'analyst',
  decidedAt: Date.UTC(2026, 7, 14),
  createdAt: 5,
  ...patch,
})

beforeEach(async () => {
  db = new RemnDB(`priority-${Math.random()}`)
  setDb(db)
  await db.cases.bulkAdd([kase(1, 'Client A, November'), kase(7, 'Client B, August'), kase(9, 'Client C, June')])
  await db.findings.bulkAdd([
    decided(7, 'win-psexec-service|7', 'false_positive'),
    decided(9, 'win-psexec-service|9', 'escalated'),
    decided(9, 'win-psexec-service|10', 'false_positive', { decidedBy: 'ai' }),
    decided(1, 'win-psexec-service|1', 'false_positive', { entities: { computer: 'ws-2', image: 'C:\\Tools\\other.exe' } }),
  ])
})
afterEach(async () => {
  await db.delete()
})

describe('the decisions a case remembers', () => {
  it('reads only the decisions of its own case when the analyst chose no other', async () => {
    const memory = await loadPastDecisions(1)
    expect(memory.map((d) => d.caseId)).toEqual([1])
    expect(await loadDecisionSources(1)).toEqual([])
  })

  it('reads the decisions of the other cases the analyst chose for this one, and of no case besides', async () => {
    await saveDecisionSources(1, [7])
    const memory = await loadPastDecisions(1, await loadDecisionSources(1))
    expect(memory.map((d) => d.caseId).sort()).toEqual([1, 7])
    // the choice is this case's: the other cases keep reading only their own decisions
    expect(await loadDecisionSources(7)).toEqual([])
    expect((await loadPastDecisions(7, await loadDecisionSources(7))).map((d) => d.caseId)).toEqual([7])
  })

  it('offers the other cases where an analyst decided findings, with how many of each kind, and forgets a case that is gone', async () => {
    expect(await decisionCases(1)).toEqual([
      { caseId: 7, caseName: 'Client B, August', falsePositives: 1, escalated: 0 },
      { caseId: 9, caseName: 'Client C, June', falsePositives: 0, escalated: 1 },
    ])
    await saveDecisionSources(1, [7, 9])
    await db.cases.delete(9)
    await db.findings.where('caseId').equals(9).delete()
    expect(await loadDecisionSources(1)).toEqual([7])
  })
})
