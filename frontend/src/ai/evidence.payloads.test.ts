import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { scanEvidence } from './evidence'

/**
 * How much of an invented set of text addressed to a model the evidence check finds. The numbers
 * are a measurement of the patterns, not a promise: docs/ai.md quotes them, so a change to the
 * patterns that moves them fails here until the page says the new numbers.
 */
interface Payload {
  id: string
  category: 'english' | 'other_language' | 'encoded' | 'split' | 'benign'
  note: string
  row: Record<string, unknown>
}
const SET = JSON.parse(readFileSync(join(__dirname, '../../../tests/fixtures/injection_payloads.json'), 'utf-8')) as { payloads: Payload[] }

const found = (category: Payload['category']): string[] => SET.payloads.filter((p) => p.category === category && scanEvidence(p.row, 'mail:1').suspects.length > 0).map((p) => p.id)
const total = (category: Payload['category']): number => SET.payloads.filter((p) => p.category === category).length

describe('the evidence check on the invented payload set', () => {
  it('finds 9 of 12 written in english', () => {
    expect(total('english')).toBe(12)
    expect(found('english')).toEqual(['en-01', 'en-02', 'en-03', 'en-04', 'en-06', 'en-08', 'en-09', 'en-10', 'en-11'])
  })

  it('finds 1 of 16 written in another language, the one whose second half is english', () => {
    expect(total('other_language')).toBe(16)
    expect(found('other_language')).toEqual(['lang-16-fr+en'])
  })

  it('finds none of 12 encoded, spaced out or written with look-alike letters', () => {
    expect(total('encoded')).toBe(12)
    expect(found('encoded')).toEqual([])
  })

  it('finds 1 of 8 split across fields, the one whose second half reads as an instruction on its own', () => {
    expect(total('split')).toBe(8)
    expect(found('split')).toEqual(['split-02'])
  })

  it('flags 3 of 18 lines of ordinary evidence text', () => {
    expect(total('benign')).toBe(18)
    expect(found('benign')).toEqual(['benign-09', 'benign-12', 'benign-13'])
  })

  it('does not find a payload it would find when it sits past what the check reads, and counts that place as unread', () => {
    const payload = SET.payloads.find((p) => p.id === 'en-01')?.row.textPreview as string
    expect(scanEvidence({ textPreview: payload }).suspects).toHaveLength(1)
    let deep: unknown = { textPreview: payload }
    for (let i = 0; i < 9; i++) deep = { inner: deep }
    const pastTheCap = [{ textPreview: `${'x'.repeat(20_000)} ${payload}` }, { rows: [...Array.from({ length: 200 }, (_, i) => ({ subject: `Weekly report ${i}` })), { textPreview: payload }] }, deep]
    for (const row of pastTheCap) expect(scanEvidence(row, 'mail:1')).toEqual({ suspects: [], unread: 1 })
  })
})
