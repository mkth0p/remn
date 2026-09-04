import { describe, expect, it } from 'vitest'
import { compileCond } from './engine'
import { levenshtein } from './filter'

describe('levenshtein operator', () => {
  it('computes edit distance', () => {
    expect(levenshtein('kitten', 'sitting')).toBe(3)
    expect(levenshtein('', 'abc')).toBe(3)
    expect(levenshtein('apple developer', 'apple developer')).toBe(0)
  })
  it('matches display names within the given distance, case-insensitively', () => {
    const pred = compileCond({ 'fromName|levenshtein': ['apple developer', 2] })
    expect(pred({ fromName: 'Apple Developer' })).toBe(true)
    expect(pred({ fromName: 'Appel Developer' })).toBe(true)
    expect(pred({ fromName: 'Apple Support' })).toBe(false)
    expect(pred({})).toBe(false)
  })
})
