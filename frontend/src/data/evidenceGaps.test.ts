import { describe, expect, it } from 'vitest'
import type { Evidence, Finding } from '../db/schema'
import { evidenceGaps, fileSequences, incidentStart, type FileSequenceStats } from './evidenceGaps'

const T0 = Date.UTC(2026, 8, 8, 10, 0, 0)
const H = 3_600_000

const ev = (id: number, name: string, stats: Record<string, unknown>, format = 'evtx'): Evidence =>
  ({ id, caseId: 1, name, size: 1, kind: 'evtx', format, status: 'done', integrity: 'verified', addedAt: 0, count: 1, stats }) as Evidence

const seq = (over: Partial<FileSequenceStats>): FileSequenceStats => ({
  file: 'Security.evtx',
  count: 100,
  channel: 'Security',
  channels: 1,
  computer: 'DC01',
  computers: 1,
  first: 1,
  last: 100,
  missing: 0,
  firstTs: T0,
  lastTs: T0 + H,
  checksums: { chunks: 3, fileHeader: true, dirty: false },
  ...over,
})

const finding = (over: Partial<Finding>): Finding =>
  ({ caseId: 1, ruleId: 'r', key: 'k', title: 't', severity: 'high', source: 'events', ts: T0, entities: {}, count: 1, refs: [1], attack: [], status: 'new', createdAt: 0, ...over }) as Finding

describe('what the evidence cannot show', () => {
  it('names the holes in a log’s own numbering and the times that run backwards', () => {
    const gaps = evidenceGaps({
      evidence: [
        ev(1, 'Security.evtx', {
          sequences: [
            seq({
              first: 1,
              last: 5000,
              missing: 1210,
              holeCount: 3,
              holes: [
                [20, 29],
                [3000, 4199],
                [4500, 4500],
              ],
              backwards: 2,
              backwardsMaxMs: 2 * H + 14 * 60_000,
              backwardsAt: [4200, 4700],
            }),
          ],
        }),
      ],
    })
    expect(gaps.map((g) => g.kind)).toEqual(['record-holes', 'time-backwards'])
    expect(gaps[0]).toMatchObject({ severity: 'high', evidenceId: 1 })
    expect(gaps[0].text).toBe(
      'Security on DC01 (Security.evtx): 1,210 records missing from its numbering, in 3 gaps between record 1 and 5,000 (the largest: 3,000–4,199). Records deleted from the log, or in a part that could not be read.',
    )
    expect(gaps[1].text).toContain('write times run backwards 2 times between consecutive records (the largest step 2h 14m, first at record 4,200)')
  })

  it('names a file forwarded from several machines by the file, and says when the holes are a floor', () => {
    const [gap] = evidenceGaps({
      evidence: [ev(1, 'wef.zip', { sequences: [seq({ file: 'ForwardedEvents.evtx', channels: 3, computers: 12, missing: 5, holeCount: 1, holes: [[9, 13]], overflow: true })] })],
    })
    expect(gap.text).toMatch(/^ForwardedEvents\.evtx \(3 channels from 12 computers\): at least 5 records missing from its numbering, in at least 1 gap/)
  })

  it('says which chunks fail their checksum, and what a failing header means', () => {
    const gaps = evidenceGaps({
      evidence: [ev(1, 'Security.evtx', { sequences: [seq({ checksums: { chunks: 40, fileHeader: false, dirty: true, badData: [3, 9], badDataCount: 2, badHeader: [9], badHeaderCount: 1 } })] })],
    })
    expect(gaps.map((g) => [g.kind, g.severity])).toEqual([
      ['checksum', 'high'],
      ['checksum', 'medium'],
    ])
    expect(gaps[0].text).toBe('Security.evtx: 2 of 40 chunks fail their checksum. Their records were changed after Windows wrote them, or damaged; they were read all the same.')
    expect(gaps[1].text).toBe("Security.evtx: 1 chunk header and the file header fail its checksum: the file's structure was changed after it was written.")
  })

  it('finds records that are in none of the files of one log, and ignores overlaps', () => {
    const archive = ev(1, 'logs.zip', {
      sequences: [
        seq({ file: 'Archive-Security-1.evtx', first: 1, last: 1000 }),
        seq({ file: 'Archive-Security-2.evtx', first: 900, last: 2000 }),
        seq({ file: 'Security.evtx', first: 2600, last: 3000 }),
        seq({ file: 'System.evtx', channel: 'System', first: 5000, last: 6000 }),
      ],
    })
    const gaps = evidenceGaps({ evidence: [archive] })
    expect(gaps.map((g) => g.text)).toEqual([
      'Security on DC01: records 2,001–2,599 are in none of the files read (Archive-Security-2.evtx ends at record 2,000, Security.evtx starts at 2,600): an archive or export is missing.',
    ])
  })

  it('reads the numbering of a package member as well as of a log uploaded alone', () => {
    const pkg = ev(
      2,
      'collection.zip',
      {
        files: [
          { name: 'EventLogs/Security.evtx', status: 'parsed', sequences: [seq({ file: 'EventLogs/Security.evtx' })] },
          { name: 'x.csv', status: 'parsed' },
        ],
      },
      'zip',
    )
    expect(fileSequences([pkg, ev(3, 'System.evtx', { sequences: [seq({ file: 'System.evtx' })] })]).map((s) => [s.file, s.evidenceId])).toEqual([
      ['EventLogs/Security.evtx', 2],
      ['System.evtx', 3],
    ])
  })

  it('names the logs of a computer that start after the first finding', () => {
    const evidence = [
      ev(1, 'logs.zip', {
        sequences: [
          seq({ file: 'Security.evtx', firstTs: T0 + 50 * H }),
          seq({ file: 'System.evtx', channel: 'System', firstTs: T0 - 24 * H }),
          seq({ file: 'Sysmon.evtx', channel: 'Microsoft-Windows-Sysmon/Operational', firstTs: T0 + 30 * 60_000 }),
        ],
      }),
    ]
    const gaps = evidenceGaps({ evidence, incidentStart: T0 })
    expect(gaps.map((g) => g.text)).toEqual([
      'On DC01, one log starts after the first finding (2026-09-08 10:00:00Z): Security at 2026-09-10 12:00:00Z. Earlier events there were overwritten or not collected.',
    ])
    // without a finding there is nothing to be late for
    expect(evidenceGaps({ evidence })).toEqual([])
  })

  it('names an audit log export cut at a service limit, in a package or alone', () => {
    const pkg = ev(
      1,
      'm365.zip',
      {
        files: [
          { name: 'UAL-2026-09-01.json', status: 'parsed', format: 'm365-ual-json', count: 4990, duplicates: 10 },
          { name: 'UAL-2026-09-02.json', status: 'parsed', format: 'm365-ual-json', count: 4999 },
          { name: 'signins.json', status: 'parsed', format: 'entra-signin-json', count: 5000 },
        ],
      },
      'zip',
    )
    const alone = ev(2, 'audit.csv', { count: 50000 }, 'm365-ual-csv')
    const gaps = evidenceGaps({ evidence: [pkg, alone] })
    expect(gaps.map((g) => [g.kind, g.evidenceId])).toEqual([
      ['export-cap', 1],
      ['export-cap', 2],
    ])
    expect(gaps[0].text).toBe(
      'UAL-2026-09-01.json: exactly 5,000 Unified Audit Log records, the most one Search-UnifiedAuditLog call returns. Records after that point in its time window are probably missing.',
    )
    expect(gaps[1].text).toContain('audit.csv: exactly 50,000 Unified Audit Log records, the most a large-set search returns')
  })

  it('says from when a mailbox’s item reads were throttled, once per mailbox', () => {
    const gaps = evidenceGaps({
      evidence: [],
      throttled: [
        { user: 'alice@example.test', ts: T0 + H },
        { user: 'alice@example.test', ts: T0 },
        { user: 'bob@example.test', ts: T0 + 2 * H },
      ],
    })
    expect(gaps.map((g) => g.text.split(' was throttled from ')[0])).toEqual(['MailItemsAccessed for alice@example.test', 'MailItemsAccessed for bob@example.test'])
    expect(gaps[0].text).toContain('from 2026-09-08 10:00:00Z: for the 24 hours after it')
  })

  it('says when sign-ins start after the first finding, with how long Entra keeps them', () => {
    const channels = [{ value: 'Entra SignIn', count: 10, first: T0 + 3 * 24 * H, last: T0 + 4 * 24 * H }]
    const [gap] = evidenceGaps({ evidence: [], channels, incidentStart: T0 })
    expect(gap).toMatchObject({ kind: 'signins-start-late', severity: 'medium' })
    expect(gap.text).toContain('Entra keeps them 7 days without a P1 or P2 licence, 30 days with one')
    expect(evidenceGaps({ evidence: [], channels, incidentStart: T0 + 3 * 24 * H })).toEqual([])
  })

  it('dates the incident from the first finding that matters', () => {
    const findings = [
      finding({ ts: T0 - 5 * H, status: 'false_positive' }),
      finding({ ts: T0 - 4 * H, severity: 'low' }),
      finding({ ts: T0 - 3 * H, severity: 'low', severityOverride: 'high' }),
      finding({ ts: T0 }),
    ]
    expect(incidentStart(findings)).toBe(T0 - 3 * H)
    expect(incidentStart([])).toBeNull()
  })

  it('lists the most serious first', () => {
    const gaps = evidenceGaps({
      evidence: [ev(1, 'Security.evtx', { sequences: [seq({ backwards: 1, backwardsMaxMs: 5000, backwardsAt: [7], missing: 3, holeCount: 1, holes: [[4, 6]] })] })],
      throttled: [{ user: 'a@example.test', ts: T0 }],
    })
    expect(gaps.map((g) => g.severity)).toEqual(['high', 'high', 'medium'])
  })
})
