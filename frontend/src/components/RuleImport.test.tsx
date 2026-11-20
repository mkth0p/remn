// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { RemnDB, setDb } from '../db/schema'

// the converter's answer for the file picked, as the server would give it
const answer = vi.hoisted(() => ({ body: null as unknown }))
vi.mock('../api/client', () => ({ apiPostForm: async () => answer.body }))

const { RuleImport } = await import('./RuleImport')

let db: RemnDB
beforeEach(() => {
  db = new RemnDB(`rule-import-${Math.random()}`)
  setDb(db)
})
afterEach(async () => {
  cleanup()
  db.close()
  await db.delete()
})

// invented conversions: one rule translated, the rest skipped for an aggregation
const converted = (n: number) => Array.from({ length: n }, (_, i) => ({ ok: true, id: `sigma-${i}`, title: `Rule ${i}`, yaml: `id: sigma-${i}`, warnings: [] }))
const skipped = (n: number) => Array.from({ length: n }, (_, i) => ({ ok: false, id: `skip-${i}`, title: `Skipped ${i}`, error: 'aggregation / correlation expression (| count() ...)', warnings: [] }))

async function pick(kind: 'sigma' | 'sublime') {
  const { container } = render(<RuleImport kind={kind} />)
  const input = container.querySelector('input[type=file]') as HTMLInputElement
  fireEvent.change(input, { target: { files: [new File(['title: t'], 'rules.zip')] } })
  return screen.findByRole('dialog')
}

describe('the rule import dialog', () => {
  it('does not name as skipped the encodings the Sigma converter expands', async () => {
    answer.body = { rules: [...converted(1), ...skipped(1)], summary: { total: 2, converted: 1, skipped: 1, reasons: [['aggregation / correlation expression (| count() ...)', 1]] } }
    const dialog = await pick('sigma')
    expect(dialog.textContent).toContain('1 of 2 rule(s) translate to the REMN DSL; 1 skipped.')
    expect(dialog.textContent).not.toMatch(/base64 \/ utf16 modifiers/)
    expect(dialog.textContent).toContain('base64 and utf16 values are expanded into the strings they can appear as')
  })

  it('says how many rules a long list leaves out', async () => {
    answer.body = { rules: converted(320), summary: { total: 320, converted: 320, skipped: 0, reasons: [] } }
    const dialog = await pick('sigma')
    expect(dialog.querySelectorAll('tbody tr')).toHaveLength(300)
    expect(dialog.textContent).toContain('showing the first 300 of 320; all 320 are added')
  })
})
