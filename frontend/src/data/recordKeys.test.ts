import { describe, expect, it } from 'vitest'
import type { Evidence } from '../db/schema'
import { eventDuplicateKey, recordLabel, recordRef } from './recordKeys'

const evidence: Evidence = {
  id: 3,
  caseId: 1,
  name: 'logs.zip',
  size: 10,
  kind: 'evtx',
  integrity: 'verified',
  addedAt: 0,
  status: 'done',
  count: 2,
  sha256Client: 'c'.repeat(64),
  sha256Server: 's'.repeat(64),
}

describe('eventDuplicateKey', () => {
  it('names an event by its computer, channel and record number, in lower case', () => {
    expect(eventDuplicateKey({ computer: 'WS-01.Example.Test', channel: 'Security', recordId: 4200 })).toBe('ws-01.example.test|security|4200')
    expect(eventDuplicateKey({ computer: 'WS-01', channel: 'Security', recordId: '17' })).toBe('ws-01|security|17')
  })

  it('takes a cloud record key as it is', () => {
    expect(eventDuplicateKey({ recordKey: ' ual:abc-1 ', computer: 'WS-01', channel: 'Security', recordId: 1 })).toBe('ual:abc-1')
  })

  it('gives nothing without all three parts', () => {
    expect(eventDuplicateKey({ channel: 'Security', recordId: 1 })).toBeUndefined()
    expect(eventDuplicateKey({ computer: 'WS-01', recordId: 1 })).toBeUndefined()
    expect(eventDuplicateKey({ computer: 'WS-01', channel: 'Security' })).toBeUndefined()
    expect(eventDuplicateKey({ computer: '  ', channel: 'Security', recordId: 1 })).toBeUndefined()
    expect(eventDuplicateKey({ computer: 'WS-01', channel: 'Security', recordId: '1.5' })).toBeUndefined()
    expect(eventDuplicateKey({ computer: 'WS-01', channel: 'Security', recordId: Infinity })).toBeUndefined()
  })
})

describe('recordRef', () => {
  it('places an event log record by its number, channel and computer in the archive member', () => {
    const ref = recordRef({ id: 9, sourceFile: 'Security.evtx', sourceSha256: 'm'.repeat(64), recordId: 4200, computer: 'DC-01', channel: 'Security' }, 'events', evidence)
    expect(ref).toEqual({
      file: 'logs.zip › Security.evtx',
      record: 'record 4,200 (Security on DC-01)',
      at: { kind: 'record', n: 4200, channel: 'Security', computer: 'DC-01' },
      sha256: 'm'.repeat(64),
      duplicateKey: 'dc-01|security|4200',
      key: `${'m'.repeat(64)}:Security.evtx#dc-01|security|4200`,
    })
    expect(recordLabel(ref)).toBe('logs.zip › Security.evtx record 4,200 (Security on DC-01)')
  })

  it('names the upload alone when the member is the upload, and prefers the server hash to the browser hash', () => {
    const ref = recordRef({ sourceFile: 'logs.zip', recordId: 7 }, 'events', evidence)
    expect(ref).toEqual({ file: 'logs.zip', record: 'record 7', at: { kind: 'record', n: 7 }, sha256: 's'.repeat(64), duplicateKey: undefined, key: `${'s'.repeat(64)}:#7` })
    expect(recordRef({ recordId: 7 }, 'events', { ...evidence, sha256Server: undefined }).sha256).toBe('c'.repeat(64))
  })

  it('names the evidence by number when it is not known, and keys by the upload name without a hash', () => {
    const ref = recordRef({ evidenceId: 5, recordId: 7 }, 'events')
    expect(ref).toEqual({ file: 'evidence #5', record: 'record 7', at: { kind: 'record', n: 7 }, sha256: undefined, duplicateKey: undefined, key: 'evidence #5:#7' })
    expect(recordRef({ recordId: 7 }, 'events').file).toBe('evidence #?')
  })

  it('names Unified Audit Log, sign-in and other cloud records by their own ids', () => {
    expect(recordRef({ recordKey: 'ual:abc-1' }, 'events', evidence)).toMatchObject({ record: 'audit record abc-1', duplicateKey: 'ual:abc-1', key: `${'s'.repeat(64)}:#ual:abc-1` })
    expect(recordRef({ recordKey: 'entra:sign-9' }, 'events', evidence).record).toBe('sign-in sign-9')
    expect(recordRef({ recordKey: 'other:x' }, 'events', evidence).record).toBe('record x')
    expect(recordRef({ recordKey: 'plain' }, 'events', evidence).record).toBe('record plain')
  })

  it('places a row without a record number by its index in the file, or else by its id', () => {
    expect(recordRef({ id: 12, sourceIndex: 41 }, 'events', evidence)).toMatchObject({ record: 'row 42', key: `${'s'.repeat(64)}:#i41` })
    expect(recordRef({ id: 12 }, 'events', evidence)).toMatchObject({ record: 'row 12', key: `${'s'.repeat(64)}:#id12` })
  })

  it('places a mail by its index in the mailbox, or else by its Message-ID, or else by its id', () => {
    expect(recordRef({ id: 2, sourceIndex: 0, messageId: '<A1@Mail.Example.Test>' }, 'mails', evidence)).toEqual({
      file: 'logs.zip',
      record: 'message 1',
      at: { kind: 'message', n: 1 },
      sha256: 's'.repeat(64),
      duplicateKey: 'mid:<a1@mail.example.test>',
      key: `${'s'.repeat(64)}:#m0`,
    })
    expect(recordRef({ id: 2, messageId: '<a1@mail.example.test>' }, 'mails', evidence)).toMatchObject({
      record: 'Message-ID <a1@mail.example.test>',
      key: `${'s'.repeat(64)}:#mid:<a1@mail.example.test>`,
    })
    expect(recordRef({ id: 2 }, 'mails', evidence)).toMatchObject({ record: 'row 2', duplicateKey: undefined, key: `${'s'.repeat(64)}:#mid:2` })
  })
})
