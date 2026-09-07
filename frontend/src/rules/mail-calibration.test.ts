import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'
import { runRule, validateRule, type Rule, MAX_REFS } from './engine'

const root = join(__dirname, '../../..')
const fixture = JSON.parse(readFileSync(join(root, 'samples/synthetic/mail-calibration.json'), 'utf8'))

describe('mail calibration across rule engines', () => {
  it('keeps benign capabilities below high while retaining malicious controls in core rules', () => {
    const rows = fixture.examples.map((e: { row: Record<string, unknown> }) => e.row)
    const malicious = fixture.examples.filter((e: { label: string }) => e.label === 'malicious').map((e: { row: { id: number } }) => e.row.id)
    const high = new Set<number>()
    for (const file of readdirSync(join(root, 'rules/mail')).filter((f) => f.endsWith('.yaml'))) {
      for (const doc of yaml.loadAll(readFileSync(join(root, 'rules/mail', file), 'utf8'))) {
        if (!doc) continue
        const r = validateRule(doc)
        if (!r.ok) throw new Error(r.error)
        for (const f of runRule(r.rule, { rows, settings: fixture.settings })) {
          if (['high', 'critical'].includes(f.severity)) f.refs.forEach((id) => high.add(id))
        }
      }
    }
    expect([...high].sort()).toEqual(malicious.sort())
  })

  for (const window of [undefined, '10m'])
    it(`preserves the strongest escalation beyond the reference cap, window=${window}`, () => {
      const rows = Array.from({ length: MAX_REFS + 2 }, (_, i) => ({
        id: i + 1,
        date: i * 1000,
        fromAddr: 'sender@example.org',
        subject: 'file',
        flags: [i === MAX_REFS + 1 ? 'att_macro_vba_stomping' : 'att_office_macro'],
      }))
      const rule: Rule = {
        id: 'macro-review',
        title: 'Macro review',
        source: 'mails',
        severity: 'medium',
        confidence: 'low',
        where: {},
        then_flags: [{ att_macro_vba_stomping: 'critical' }],
        ...(window ? { group_by: ['fromAddr'], threshold: '>= 2', window } : {}),
      }
      const found = runRule(rule, { rows })
      expect(found).toHaveLength(1)
      expect(found[0]).toMatchObject({ severity: 'critical', confidence: 'low', escalation: 'att_macro_vba_stomping' })
      expect(found[0].refs).toHaveLength(MAX_REFS)
      expect(found[0].refs).toContain(MAX_REFS + 2)
    })
})
