// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case } from '../db/schema'
import { useStore } from '../state/store'

const rule = (id: string, measured?: object, origin = 'bundled') => ({
  rule: { id, title: `title of ${id}`, severity: 'high', source: 'events' },
  yaml: '',
  file: `${id}.yaml`,
  origin,
  enabled: true,
  measured,
})

vi.mock('../data/rules', () => ({
  loadRules: vi.fn(async () => [
    rule('sigma-detects', { own: true, of: 3, hits: 2, fires: 2, clean: { findings: 0, events: 0, machines: 0, scope: 9000, of: 7 } }),
    rule('win-lead', { of: 5, fires: 1 }),
    rule('win-noisy', { of: 2, hits: 1, fires: 1, clean: { findings: 41, events: 43, machines: 3, scope: 1_250_000, of: 7 } }),
    rule('sigma-misses', { own: false, of: 1 }),
    rule('mail-unmeasured'),
  ]),
  parseRuleYaml: vi.fn(() => ({ rules: [], errors: [] })),
}))
vi.mock('../components/RuleImport', () => ({ RuleImport: () => null }))

import { RulesView } from './RulesView'

const kase: Case = { id: 1, name: 'Lab', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
let db: RemnDB
beforeEach(() => {
  db = new RemnDB(`rules-${Math.random()}`)
  setDb(db)
  useStore.setState({ currentCase: kase, view: 'rules', rulesVersion: 0 })
})
afterEach(async () => {
  cleanup()
  await db.delete()
})

const measureOf = (id: string) => screen.getByText(id).closest('tr')?.querySelector('[data-measure]')

it('shows each rule’s measure, the reasons on hover, and lists the leads alone', async () => {
  await act(async () => {
    render(<RulesView />)
  })
  await waitFor(() => expect(screen.getByText('sigma-detects')).toBeTruthy(), { timeout: 8000 })
  expect(measureOf('sigma-detects')?.textContent).toBe('detects')
  expect(measureOf('win-lead')?.textContent).toBe('lead')
  expect(measureOf('win-noisy')?.textContent).toBe('detectsfires on clean machines')
  expect(measureOf('sigma-misses')?.textContent).toBe('misses its sample')
  expect(measureOf('mail-unmeasured')).toBeFalsy()
  expect(measureOf('win-lead')?.querySelector('.badge')?.getAttribute('title')).toContain('Fires on none of the 5 recorded attacks of what it looks for')
  const filter = Array.from(document.querySelectorAll('select')).find((s) => Array.from(s.options).some((o) => o.value === 'lead'))!
  fireEvent.change(filter, { target: { value: 'lead' } })
  await waitFor(() => expect(screen.queryByText('sigma-detects')).toBeNull())
  expect(screen.getByText('win-lead')).toBeTruthy()
  expect(screen.getByText('sigma-misses')).toBeTruthy()
  fireEvent.change(filter, { target: { value: 'noisy' } })
  await waitFor(() => expect(screen.queryByText('win-lead')).toBeNull())
  expect(screen.getByText('win-noisy')).toBeTruthy()
}, 30_000)
