import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { expect, it } from 'vitest'
import { flatten } from './flatten'
import type { Json } from './py'

// the cases tests/backend/test_evtx.py runs through the server's parser
const CASES = JSON.parse(readFileSync(join(__dirname, '../../../../tests/fixtures/evtx/product-fields.json'), 'utf-8')) as { name: string; event: Json; expect: Record<string, unknown> }[]

it.each(CASES.map((c) => [c.name, c] as const))('%s: SQL audit and sshd lines give who and from where', (_name, c) => {
  const row = flatten(c.event, null, false)
  expect(Object.fromEntries(Object.keys(c.expect).map((k) => [k, row[k] ?? null]))).toEqual(c.expect)
})

// the same event as test_the_unnamed_data_of_a_classic_event_reaches_the_rules_whole in tests/backend/test_evtx.py
it('keeps the unnamed Data of a classic event whole in message past 4,000 characters', () => {
  const host = 'HostApplication=powershell.exe ' + '-NoP '.repeat(900) + '-enc SQBFAFgA'
  const event: Json = {
    Event: {
      System: {
        Provider: { '#attributes': { Name: 'PowerShell' } },
        EventID: 400,
        TimeCreated: { '#attributes': { SystemTime: '2026-09-01T22:13:40.123456Z' } },
        EventRecordID: 4242,
        Channel: 'Windows PowerShell',
        Computer: 'WS01.corp.local',
      },
      EventData: { Data: ['Available', 'None', `\tNewEngineState=Available\n\t${host}\n\tEngineVersion=5.1`] },
    },
  }
  const row = flatten(event, null, false)
  expect(row.message).toBe(`Available\nNone\n\tNewEngineState=Available\n\t${host}\n\tEngineVersion=5.1`)
})
