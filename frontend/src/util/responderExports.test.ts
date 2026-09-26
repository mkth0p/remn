import { describe, expect, it } from 'vitest'
import type { Case, CaseNote, EventRow, Finding } from '../db/schema'
import { navigatorLayer, techniqueId, timelineRecords, toTimelineCsv, toTimesketchJsonl } from './responderExports'

let seq = 1
const f = (p: Partial<Finding> & { ruleId: string; severity: Finding['severity'] }): Finding => ({
  id: seq++,
  caseId: 1,
  key: `${p.ruleId}|${seq}`,
  title: p.ruleId,
  source: 'events',
  ts: Date.UTC(2026, 0, 2, 3, 4, 5),
  entities: {},
  count: 1,
  refs: [],
  attack: [],
  status: 'new',
  createdAt: 0,
  ...p,
})
const kase = { id: 1, name: 'Case', analyst: 'A. Nalyst' } as Case

describe('timeline export', () => {
  it('gives every line the three fields Timesketch requires, in time order, and counts what has no time', () => {
    const note: CaseNote = { caseId: 1, kind: 'timeline', text: 'user reported the mail', ts: Date.UTC(2026, 0, 1), createdAt: 0, updatedAt: 0 }
    const untimedNote: CaseNote = { ...note, text: 'artefact', untimed: true }
    const ev = { caseId: 1, evidenceId: 1, id: 9, ts: Date.UTC(2026, 0, 3), eventId: 4624, provider: 'Security', computer: 'WS1', targetUser: 'bob', summary: 'logon type 10' } as EventRow
    const obs = { caseId: 1, evidenceId: 1, id: 10, recordKind: 'observation', artifactType: 'prefetch', ts: null, observedAt: Date.UTC(2026, 0, 4), eventId: null } as EventRow
    const { records, untimed } = timelineRecords({
      findings: [
        f({ ruleId: 'rdp-logon', severity: 'high', severityOverride: 'critical', entities: { computer: 'WS1', ipAddress: '203.0.113.9' }, attack: ['T1021.001'] }),
        f({ ruleId: 'untimed', severity: 'low', ts: null }),
      ],
      notes: [note, untimedNote],
      events: [ev, obs],
    })
    expect(untimed).toBe(2)
    expect(records.map((r) => r.datetime)).toEqual(['2026-01-01T00:00:00.000Z', '2026-01-02T03:04:05.000Z', '2026-01-03T00:00:00.000Z', '2026-01-04T00:00:00.000Z'])
    for (const r of records) expect(r.message && r.datetime && r.timestamp_desc).toBeTruthy()
    const finding = records[1]
    expect(finding).toMatchObject({ message: '[critical] rdp-logon', severity: 'critical', host: 'WS1', ip: '203.0.113.9', attack: 'T1021.001', data_type: 'remn:finding' })
    expect(records[2]).toMatchObject({ message: 'logon type 10', timestamp_desc: 'Event Recorded', host: 'WS1', user: 'bob', remn_ref: 'events:9' })
    expect(records[3]).toMatchObject({ timestamp_desc: 'Collected', data_type: 'remn:prefetch' })
    const lines = toTimesketchJsonl(records).trim().split('\n')
    expect(lines).toHaveLength(4)
    expect(JSON.parse(lines[1]).tag).toEqual(['remn', 'critical', 'T1021.001'])
  })

  it('writes CSV with a header Timeline Explorer reads and neutralises formulas', () => {
    const { records } = timelineRecords({ findings: [f({ ruleId: 'x', severity: 'low', title: '=HYPERLINK("http://evil")' })] })
    const csv = toTimelineCsv(records)
    const [head, row] = csv.split('\r\n')
    expect(head.startsWith('datetime,timestamp_desc,message,')).toBe(true)
    expect(row).toContain('"[low] =HYPERLINK(""http://evil"")"')
  })
})

describe('ATT&CK Navigator layer', () => {
  it('reads the technique forms rules use', () => {
    expect(techniqueId('T1059.001')).toBe('T1059.001')
    expect(techniqueId('attack.t1566')).toBe('T1566')
    expect(techniqueId('attack.initial_access')).toBeNull()
  })

  it('colours each technique by its worst severity, leaves false positives out, and shows sub-techniques under their parent', () => {
    const layer = navigatorLayer(kase, [
      f({ ruleId: 'ps-enc', severity: 'medium', attack: ['T1059.001'], status: 'escalated' }),
      f({ ruleId: 'ps-dl', severity: 'high', attack: ['attack.t1059.001', 'T1105'] }),
      f({ ruleId: 'fp', severity: 'critical', attack: ['T1105', 'T1003'], status: 'false_positive' }),
    ]) as { versions: Record<string, string>; domain: string; techniques: Record<string, unknown>[] }
    expect(layer.versions.layer).toBe('4.5')
    expect(layer.domain).toBe('enterprise-attack')
    const byId = Object.fromEntries(layer.techniques.map((t) => [t.techniqueID, t]))
    expect(Object.keys(byId)).toEqual(['T1059', 'T1059.001', 'T1105'])
    expect(byId['T1059.001']).toMatchObject({ score: 4, color: '#d1403f' })
    expect(String(byId['T1059.001'].comment)).toContain('2 findings, 1 confirmed; worst high')
    expect(byId['T1059']).toMatchObject({ showSubtechniques: true })
    expect(byId['T1059'].score).toBeUndefined()
    expect(byId['T1105']).toMatchObject({ score: 4 })
  })
})
