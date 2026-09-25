import { describe, expect, it } from 'vitest'
import { toggleFacetValue } from './facetToggle'
import { compileCond } from '../rules/engine'

describe('facet values', () => {
  it('are alternatives within a field, however many are picked', () => {
    let c = toggleFacetValue([], 'targetUser', 'u0')
    c = toggleFacetValue(c, 'targetUser', 'u1')
    c = toggleFacetValue(c, 'targetUser', 'u2')
    expect(c).toEqual([{ field: 'targetUser', op: 'in', value: ['u0', 'u1', 'u2'] }])
  })
  it('come out again when picked again, down to no condition', () => {
    let c = toggleFacetValue([], 'fromDomain', 'a.com')
    c = toggleFacetValue(c, 'fromDomain', 'b.com')
    c = toggleFacetValue(c, 'fromDomain', 'A.com')
    expect(c).toEqual([{ field: 'fromDomain', op: 'eq', value: 'b.com' }])
    expect(toggleFacetValue(c, 'fromDomain', 'b.com')).toEqual([])
  })
  it('exclude the same way, and leave other fields alone', () => {
    let c = toggleFacetValue([{ field: 'eventId', op: 'eq', value: 4624 }], 'computer', 'WS1', true)
    c = toggleFacetValue(c, 'computer', 'WS2', true)
    expect(c).toEqual([
      { field: 'eventId', op: 'eq', value: 4624 },
      { field: 'computer', op: 'nin', value: ['WS1', 'WS2'] },
    ])
  })
  it('select rows, which a pair of eq conditions never did', () => {
    const conds = toggleFacetValue(toggleFacetValue([], 'targetUser', 'u0'), 'targetUser', 'u2')
    const pred = compileCond(Object.fromEntries(conds.map((c) => [`${c.field}|${c.op}`, c.value])))
    expect(pred({ targetUser: 'u2' })).toBe(true)
  })
})
