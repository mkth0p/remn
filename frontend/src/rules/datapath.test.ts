import { describe, expect, it } from 'vitest'
import { compileCond } from './engine'

describe('data.* paths on event rows', () => {
  it('reads flat dotted keys (M365 ModifiedProperties) and nested EventData alike', () => {
    const row = { operation: 'Add member to role.', data: { 'Role.DisplayName': 'Global Administrator', CommandLine: 'x', nested: { deep: 'v' } } }
    expect(compileCond({ 'data.Role.DisplayName|re': '(?i)global admin' })(row)).toBe(true)
    expect(compileCond({ 'data.CommandLine': 'x' })(row)).toBe(true)
    expect(compileCond({ 'data.nested.deep': 'v' })(row)).toBe(true)
    expect(compileCond({ 'data.ForwardTo|exists': true })(row)).toBe(false)
    expect(compileCond({ 'data.ForwardTo|exists': false })(row)).toBe(true)
  })
})
