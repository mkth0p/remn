import { describe, expect, it } from 'vitest'
import { validateRule, type Rule } from './engine'
import { HAYABUSA_NO_AUTHOR, ruleAuthorOf, ruleAuthors } from './authors'

// invented rules: one with a Sigma header naming its author, one of REMN's own without
const asRule = (r: unknown): Rule => {
  const v = validateRule(r)
  if (!v.ok) throw new Error(v.error)
  return v.rule
}
const where = { eventId: 4104 }
const sigma = asRule({ id: 'sigma-0001', title: 'Encoded PowerShell', severity: 'high', source: 'events', where, sigma: { id: 'x', author: 'A. Rule-Writer' } })
const own = asRule({ id: 'win-rdp-logon', title: 'RDP logon', severity: 'medium', source: 'events', where })

describe('the author of a finding', () => {
  it('is the one its rule names, says Hayabusa records none for its detections, and is empty for a rule that names none', () => {
    const authors = ruleAuthors([sigma, own])
    expect(ruleAuthorOf('sigma-0001', authors)).toBe('A. Rule-Writer')
    expect(ruleAuthorOf('engine:hayabusa:Mimikatz Use', authors)).toBe(HAYABUSA_NO_AUTHOR)
    expect(HAYABUSA_NO_AUTHOR).toContain('Hayabusa')
    expect(ruleAuthorOf('win-rdp-logon', authors)).toBe('')
    // the report says it in its own words
    expect(ruleAuthorOf('engine:hayabusa:x', authors, 'auteur non transmis par Hayabusa')).toBe('auteur non transmis par Hayabusa')
  })
})
