import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'
import { compileCond, ruleEventIds, validateRule } from './engine'

// The community packs (rules/community/<id>, written by tools/import_community_rules.py) must be
// accepted by the browser engine exactly like the SQL engine (tests/backend/test_packs.py).
const RULES = join(__dirname, '../../../rules')
const COMMUNITY = join(RULES, 'community')
const packIds = readdirSync(COMMUNITY).filter((d) => existsSync(join(COMMUNITY, d, 'pack.json')))

function docsIn(dir: string, skipCommunity = false): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = []
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (name === 'community' && skipCommunity) continue
    if (statSync(p).isDirectory()) out.push(...docsIn(p, skipCommunity))
    else if (name.endsWith('.yaml')) for (const d of yaml.loadAll(readFileSync(p, 'utf-8'))) if (d && typeof d === 'object') out.push(d as Record<string, unknown>)
  }
  return out
}

describe('community rule packs', () => {
  it('ships the SigmaHQ and Sublime packs', () => {
    expect(packIds).toEqual(expect.arrayContaining(['sigma-windows', 'sigma-emerging-threats', 'sigma-threat-hunting', 'sublime']))
  })

  for (const id of packIds) {
    it(`${id}: every rule validates and compiles on the browser engine`, () => {
      const manifest = JSON.parse(readFileSync(join(COMMUNITY, id, 'pack.json'), 'utf-8'))
      const docs = docsIn(join(COMMUNITY, id))
      expect(docs.length).toBe(manifest.counts.converted)
      let noPrefilter = 0
      for (const d of docs) {
        const v = validateRule(d)
        if (!v.ok) throw new Error(`${id}: ${v.error}`)
        expect(v.rule.source).toBe(manifest.source)
        try {
          compileCond(v.rule.where, {})
          if (v.rule.exclude) compileCond(v.rule.exclude, {})
        } catch (e) {
          throw new Error(`${v.rule.id}: ${(e as Error).message}`)
        }
        if (manifest.source === 'events' && !ruleEventIds(v.rule.where)) noPrefilter++
      }
      // events are read through the [caseId+eventId] index; a full scan per rule would not scale to 3,000 rules
      if (manifest.source === 'events') expect(noPrefilter).toBeLessThanOrEqual(Math.max(3, Math.floor(docs.length / 100)))
    })
  }

  it('rule ids are unique across the core catalogue and every pack', () => {
    const ids = [...docsIn(RULES, true), ...packIds.flatMap((id) => docsIn(join(COMMUNITY, id)))].map((d) => String(d.id))
    const dup = ids.filter((x, i) => ids.indexOf(x) !== i)
    expect(dup).toEqual([])
    expect(ids.length).toBeGreaterThan(2500)
  })
})
