import { afterEach, describe, expect, it } from 'vitest'
import { FileSequence, Lineage, Stats } from './ledger'
import { BigInteger } from './py'

const SYSMON = 'Microsoft-Windows-Sysmon'
const SECURITY = 'Microsoft-Windows-Security-Auditing'

describe('FileSequence', () => {
  const limits = { spans: FileSequence.MAX_SPANS }
  afterEach(() => {
    FileSequence.MAX_SPANS = limits.spans
  })

  it('gives an empty file its name, count and no times', () => {
    expect(new FileSequence('empty.evtx').toDict()).toEqual({ file: 'empty.evtx', count: 0, firstTs: null, lastTs: null })
  })

  it('follows record numbers out of order into spans, and names the holes between them', () => {
    const seq = new FileSequence('a.evtx')
    for (const id of [1, 2, 3, 7, 8, 5]) seq.add(id, null)
    expect(seq.spans).toEqual([
      [1, 3],
      [5, 5],
      [7, 8],
    ])
    expect(seq.toDict()).toMatchObject({
      count: 6,
      first: 1,
      last: 8,
      missing: 2,
      holes: [
        [4, 4],
        [6, 6],
      ],
      holeCount: 2,
    })
  })

  it('joins two spans when the record between them arrives, and grows a span at its start', () => {
    const seq = new FileSequence('a.evtx')
    for (const id of [1, 2, 3, 5, 7, 8]) seq.add(id, null)
    seq.add(4, null)
    expect(seq.spans).toEqual([
      [1, 5],
      [7, 8],
    ])
    seq.add(10, null)
    seq.add(12, null)
    seq.add(11, null)
    expect(seq.spans).toEqual([
      [1, 5],
      [7, 8],
      [10, 12],
    ])
    seq.add(6, null)
    expect(seq.spans).toEqual([
      [1, 8],
      [10, 12],
    ])
    const lone = new FileSequence('b.evtx')
    lone.add(1, null)
    lone.add(5, null)
    lone.add(4, null)
    expect(lone.spans).toEqual([
      [1, 1],
      [4, 5],
    ])
  })

  it('counts a repeated record number once in the spans and every time in the count', () => {
    const seq = new FileSequence('a.evtx')
    for (const id of [1, 2, 3, 2]) seq.add(id, null)
    expect(seq.spans).toEqual([[1, 3]])
    expect(seq.toDict()).toMatchObject({ count: 4, missing: 0 })
    expect(seq.toDict()).not.toHaveProperty('holes')
  })

  it('counts records without a usable number but leaves them out of the spans', () => {
    const seq = new FileSequence('a.evtx')
    for (const id of ['7', 0, -3, 1.5, null, new BigInteger('99999999999999999999')]) seq.add(id, null)
    expect(seq.spans).toEqual([])
    expect(seq.toDict()).toEqual({ file: 'a.evtx', count: 6, firstTs: null, lastTs: null })
  })

  it('stops opening spans past its limit and says the holes it lists are a floor', () => {
    FileSequence.MAX_SPANS = 3
    const seq = new FileSequence('a.evtx')
    for (const id of [1, 3, 5, 7]) seq.add(id, null)
    expect(seq.overflow).toBe(true)
    seq.add(9, null)
    seq.add(8, null)
    expect(seq.spans).toEqual([
      [1, 1],
      [3, 3],
      [5, 5],
      [7, 8],
    ])
    expect(seq.toDict()).toMatchObject({ overflow: true })
  })

  it('counts a record written more than a second before the record numbered just before it', () => {
    const seq = new FileSequence('a.evtx')
    seq.add(1, 10_000)
    seq.add(2, 8_000)
    seq.add(3, 7_500)
    seq.add(5, 1_000)
    seq.add(6, null)
    seq.add(7, 0)
    expect(seq.toDict()).toMatchObject({ backwards: 1, backwardsMaxMs: 2000, steps: [[2, 10_000, 8_000]] })
  })

  it('keeps the most common channel and computer, ties in the order first seen, and the time range', () => {
    const seq = new FileSequence('a.evtx')
    seq.add(1, null, { channel: 'Security', computer: 'WS-01', ts: 3000 })
    seq.add(2, null, { channel: 'System', computer: 'WS-02', ts: 1000 })
    seq.add(3, null, { channel: 'Security', computer: '', ts: 2000 })
    seq.add(4, null, { channel: null, ts: null })
    expect(seq.toDict()).toMatchObject({ channel: 'Security', channels: 2, computer: 'WS-01', computers: 2, computerNames: ['WS-01', 'WS-02'], firstTs: 1000, lastTs: 3000 })
  })

  it('notes clock changes of more than a second and the starts of the event log service', () => {
    const seq = new FileSequence('a.evtx')
    seq.add(1, null, { eventId: 4616, provider: SECURITY, computer: 'WS-01', previousTime: '2026-01-01T10:00:00Z', newTime: '2026-01-01T12:00:00Z' })
    seq.add(2, null, { eventId: 4616, provider: SECURITY, computer: 'WS-01', previousTime: '2026-01-01T10:00:00.000Z', newTime: '2026-01-01T10:00:00.400Z' })
    seq.add(3, null, { eventId: 1, provider: 'Microsoft-Windows-Kernel-General', computer: 'WS-02', data: { OldTime: '2026-01-02T00:00:10Z', NewTime: '2026-01-02T00:00:00Z' } })
    seq.add(4, null, { eventId: 1, provider: SYSMON, data: { OldTime: '2026-01-02T00:00:10Z', NewTime: '2026-01-01T00:00:00Z' } })
    seq.add(5, null, { eventId: 6005, provider: 'EventLog', computer: 'WS-01', ts: 5000 })
    seq.add(6, null, { eventId: 6005, provider: 'Other', ts: 6000 })
    seq.add(7, null, { eventId: 4616, provider: SECURITY, previousTime: 'unreadable', newTime: '2026-01-01T12:00:00Z' })
    const out = seq.toDict()
    expect(out.clockChanges).toEqual([
      { computer: 'WS-01', old: Date.UTC(2026, 0, 1, 10), new: Date.UTC(2026, 0, 1, 12) },
      { computer: 'WS-02', old: Date.UTC(2026, 0, 2, 0, 0, 10), new: Date.UTC(2026, 0, 2) },
    ])
    expect(out.logStarts).toEqual([{ computer: 'WS-01', ts: 5000 }])
  })

  it('carries the checksum result when the reader set one', () => {
    const seq = new FileSequence('a.evtx')
    seq.checksums = { chunks: 2, fileHeader: true, dirty: false, badData: [1], badDataCount: 1 }
    expect(seq.toDict().checksums).toEqual({ chunks: 2, fileHeader: true, dirty: false, badData: [1], badDataCount: 1 })
  })
})

describe('Stats', () => {
  it('counts the upload by event id, channel, provider, computer and level, most common first', () => {
    const stats = new Stats()
    stats.add({ ts: 2000, eventId: 4624, channel: 'Security', provider: SECURITY, computer: 'WS-01', levelName: 'Information' })
    stats.add({ ts: 1000, eventId: 4625, channel: 'Security', provider: SECURITY, computer: 'WS-01', levelName: 'Information' })
    stats.add({ ts: 3000, eventId: 4625, channel: 'System', provider: 'EventLog', computer: '', levelName: 'Warning' })
    stats.add({ ts: null, eventId: new BigInteger('99999999999999999999'), channel: null, levelName: null })
    stats.add({ eventId: null })
    stats.errors = 2
    const out = stats.toDict()
    expect(out).toEqual({
      count: 5,
      errors: 2,
      firstTs: 1000,
      lastTs: 3000,
      eventIds: { 4625: 2, 4624: 1, '99999999999999999999': 1 },
      channels: { Security: 2, System: 1 },
      providers: { [SECURITY]: 2, EventLog: 1 },
      computers: { 'WS-01': 2 },
      levels: { Information: 2, Warning: 1 },
    })
    expect(Object.keys(out.eventIds as object)).toEqual(['4624', '4625', '99999999999999999999'])
  })

  it('lists the files it began, each with its own ledger', () => {
    const stats = new Stats()
    stats.beginFile('one.evtx').add(1, null)
    stats.beginFile('two.evtx')
    expect((stats.toDict().sequences as { file: string; count: number }[]).map((s) => [s.file, s.count])).toEqual([
      ['one.evtx', 1],
      ['two.evtx', 0],
    ])
    expect(new Stats().toDict()).not.toHaveProperty('sequences')
  })
})

describe('Lineage', () => {
  const max = Lineage.MAX
  afterEach(() => {
    Lineage.MAX = max
  })

  const creation = (guid: string, parent: string, data: Record<string, unknown>) => ({ eventId: 1, provider: SYSMON, processGuid: guid, parentProcessGuid: parent, data })

  it("fills in the parent's account of a Sysmon process creation from the parent's own creation", () => {
    const lineage = new Lineage()
    lineage.apply(creation('{AAA}', '{000}', { User: 'EXAMPLE\\user1' }))
    const child = creation('{BBB}', '{aaa}', {})
    lineage.apply(child)
    expect(child.data).toEqual({ ParentUser: 'EXAMPLE\\user1' })
    expect(child).toMatchObject({ enriched: "data.ParentUser from the parent's process creation event" })
  })

  it('leaves a parent account the event already has, and an unknown parent, alone', () => {
    const lineage = new Lineage()
    lineage.apply(creation('{AAA}', '{000}', { User: 'EXAMPLE\\user1' }))
    const known = creation('{BBB}', '{AAA}', { ParentUser: 'EXAMPLE\\user9' })
    const unknown = creation('{CCC}', '{DDD}', {})
    lineage.apply(known)
    lineage.apply(unknown)
    expect(known.data.ParentUser).toBe('EXAMPLE\\user9')
    expect(unknown.data).toEqual({})
    expect(known).not.toHaveProperty('enriched')
  })

  it('forgets the oldest processes past its limit', () => {
    Lineage.MAX = 2
    const lineage = new Lineage()
    for (const g of ['{A}', '{B}', '{C}']) lineage.apply(creation(g, '{0}', { User: `user-${g}` }))
    const ofA = creation('{X}', '{a}', {})
    const ofC = creation('{Y}', '{c}', {})
    lineage.apply(ofA)
    lineage.apply(ofC)
    expect(ofA.data).toEqual({})
    expect(ofC.data).toEqual({ ParentUser: 'user-{C}' })
  })

  const security4688 = (row: Record<string, unknown>): Record<string, unknown> => ({ eventId: 4688, channel: 'Security', computer: 'WS-01', ...row })

  it('fills in the parent image of a 4688 from the 4688 that created the parent process id within a week', () => {
    const lineage = new Lineage()
    lineage.apply(security4688({ newProcessId: '0x1a4', processName: 'C:\\Windows\\System32\\cmd.exe', ts: 1000 }))
    const child = security4688({ newProcessId: '0x2b8', callerProcessId: '0x1A4', processName: 'C:\\Windows\\System32\\whoami.exe', ts: 2000, enriched: 'earlier note' })
    lineage.apply(child)
    expect(child).toMatchObject({ parentProcessName: 'C:\\Windows\\System32\\cmd.exe', enriched: 'earlier note; parentProcessName from the 4688 that created the parent process id' })
  })

  it('does not take a parent image from another computer, from later, or from more than a week before', () => {
    const lineage = new Lineage()
    lineage.apply(security4688({ newProcessId: '0x1a4', processName: 'cmd.exe', ts: 10 * 86_400_000 }))
    const elsewhere = security4688({ computer: 'WS-02', callerProcessId: '0x1a4', ts: 10 * 86_400_000 + 1 })
    const before = security4688({ callerProcessId: '0x1a4', ts: 10 * 86_400_000 - 1 })
    const late = security4688({ callerProcessId: '0x1a4', ts: 17 * 86_400_000 + 1 })
    const otherChannel = { ...security4688({ callerProcessId: '0x1a4', ts: 10 * 86_400_000 + 1 }), channel: 'System' }
    for (const row of [elsewhere, before, late, otherChannel]) {
      lineage.apply(row)
      expect(row).not.toHaveProperty('parentProcessName')
    }
  })

  it('keeps a parent image the event already has', () => {
    const lineage = new Lineage()
    lineage.apply(security4688({ newProcessId: '0x1a4', processName: 'cmd.exe', ts: 1000 }))
    const child = security4688({ callerProcessId: '0x1a4', parentProcessName: 'explorer.exe', ts: 2000 })
    lineage.apply(child)
    expect(child.parentProcessName).toBe('explorer.exe')
  })

  const imageLoad = (guid: string, signed: string, extra: Record<string, unknown> = {}) => ({
    eventId: 7,
    provider: SYSMON,
    processGuid: guid,
    image: 'C:\\Tools\\agent.exe',
    imageLoaded: 'C:\\Tools\\Agent.exe',
    signed,
    signatureStatus: 'Valid',
    signature: ' Example Software Ltd ',
    data: {},
    ...extra,
  })
  const access = (source: string) => ({ eventId: 10, provider: SYSMON, data: { SourceProcessGUID: source } }) as Record<string, unknown>

  it("names the signer of a process access's source from that process's own signed image load", () => {
    const lineage = new Lineage()
    lineage.apply(imageLoad('{CCC}', 'true'))
    const row = access('{ccc}')
    lineage.apply(row)
    expect(row).toMatchObject({ sourceSigner: 'Example Software Ltd', enriched: "sourceSigner from the source process's own image load (Sysmon 7)" })
  })

  it('names no signer for a process that loaded its image unsigned, even after a signed load', () => {
    const lineage = new Lineage()
    lineage.apply(imageLoad('{DDD}', 'false'))
    lineage.apply(imageLoad('{DDD}', 'true'))
    const row = access('{DDD}')
    lineage.apply(row)
    expect(row).not.toHaveProperty('sourceSigner')
  })

  it('names no signer from a library load, an invalid signature or a process it has not seen', () => {
    const lineage = new Lineage()
    lineage.apply(imageLoad('{EEE}', 'true', { imageLoaded: 'C:\\Windows\\System32\\ntdll.dll' }))
    lineage.apply(imageLoad('{FFF}', 'true', { signatureStatus: 'Expired' }))
    lineage.apply(imageLoad('', 'true'))
    for (const source of ['{EEE}', '{FFF}', '{999}', '']) {
      const row = access(source)
      lineage.apply(row)
      expect(row).not.toHaveProperty('sourceSigner')
    }
  })

  it('reads the image load fields from the event data when the row lacks them', () => {
    const lineage = new Lineage()
    lineage.apply({
      eventId: 7,
      provider: SYSMON,
      imageLoaded: 'c:\\tools\\agent.exe',
      data: { ProcessGuid: '{ABC}', Signed: 'true', Image: 'C:\\Tools\\agent.exe', SignatureStatus: 'Valid', Signature: 'Example Software Ltd' },
    })
    const row = { eventId: 8, provider: SYSMON, data: { SourceProcessGuid: '{abc}' } } as Record<string, unknown>
    lineage.apply(row)
    expect(row.sourceSigner).toBe('Example Software Ltd')
  })
})
