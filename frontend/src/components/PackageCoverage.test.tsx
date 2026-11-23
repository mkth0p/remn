// @vitest-environment jsdom
import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { PackageCoverage } from './PackageCoverage'

afterEach(cleanup)

// invented members of a collection, with the notes the server writes on them
const MEMBERS = [
  {
    name: 'audit/ual.csv',
    status: 'parsed',
    count: 9000,
    note: '1,204 record(s) have no time: their date is missing or could not be read; 3 record(s) hold a value cut at its length limit, marked by a closing …',
  },
  { name: 'logs/big.txt', status: 'parsed', count: 2_000_000, note: 'kept the first 2,000,000 lines; the file is longer than that' },
  { name: 'triage!/amcache', status: 'parsed', count: 500_000, note: 'stopped at 500,000 records, the cap for this artifact' },
  { name: 'audit/mixed.json', status: 'parsed', count: 40, note: '2 record(s) are not of the kind the file holds and were not read' },
  {
    name: 'mde/MPLog.log',
    status: 'parsed',
    count: 12,
    note: 'Defender engine log: 40,000 lines read, 12 kept: those naming a detection, threat, quarantine, remediation, exclusion or protection change, with the lines either side that qualify them',
  },
  { name: 'Security.evtx', status: 'parsed', count: 10 },
]
const badgeOf = (name: string) => screen.getByText(name).closest('tr')!.querySelector('.badge')!

describe('the package coverage table', () => {
  it('calls a member partial only when its note says part of the file was not read', () => {
    render(<PackageCoverage stats={{ files: MEMBERS, membersTotal: MEMBERS.length }} />)
    // undated records and values cut at their limit are about a file read whole
    expect(badgeOf('audit/ual.csv').textContent).toBe('parsed (with notes)')
    expect(badgeOf('audit/ual.csv').getAttribute('title')).toBe('the file was read whole: the note says how')
    for (const name of ['logs/big.txt', 'triage!/amcache', 'audit/mixed.json', 'mde/MPLog.log']) {
      expect(badgeOf(name).textContent).toBe('parsed (partial)')
      expect(badgeOf(name).getAttribute('title')).toBe('part of the file was not read: see the note')
    }
    expect(badgeOf('Security.evtx').textContent).toBe('parsed')
  })
})
