import { describe, expect, it } from 'vitest'
import { ATTACK_FLOW_EXT, campaignGrouping, spineSteps, storyAttackFlow, techniqueId, type ExportContext } from './storyExport'
import { ATTACK_TAGS, CAMPAIGN, IDENTITIES, oldStory, SPINE, spinedStory, STEPS } from '../test/spineStory'

type Obj = Record<string, unknown> & { type: string; id: string }
type Bundle = { type: string; id: string; objects: Obj[] }

const ctx: ExportContext = { caseName: 'Lab', attackOf: (f) => ATTACK_TAGS[f.ruleId] ?? [], identities: IDENTITIES, now: Date.UTC(2026, 8, 20) }

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}'
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/
// the cyber-observables here: no created, modified or author
const SCO = new Set(['ipv4-addr', 'ipv6-addr', 'domain-name', 'file', 'email-addr', 'software'])
// what each type must have, by STIX 2.1 and the Attack Flow schema (2.0.0)
const REQUIRED: Record<string, string[]> = {
  identity: ['name'],
  infrastructure: ['name'],
  relationship: ['relationship_type', 'source_ref', 'target_ref'],
  grouping: ['context', 'object_refs'],
  'marking-definition': ['created', 'definition_type', 'definition'],
  'extension-definition': ['name', 'schema', 'version', 'extension_types', 'created_by_ref'],
  'attack-flow': ['name', 'scope', 'start_refs'],
  'attack-action': ['name'],
  'attack-asset': ['name'],
  'ipv4-addr': ['value'],
  'domain-name': ['value'],
  file: ['hashes'],
}
const FLOW_TYPES = new Set(['attack-flow', 'attack-action', 'attack-asset', 'attack-condition', 'attack-operator'])

/** Every rule of the bundle's shape this export promises; the problems found, none when it holds. */
function problems(b: Bundle): string[] {
  const out: string[] = []
  if (b.type !== 'bundle') out.push('not a bundle')
  if (!new RegExp(`^bundle--${UUID}$`).test(b.id)) out.push(`bundle id ${b.id}`)
  const ids = new Set<string>()
  for (const o of b.objects) {
    if (!new RegExp(`^${o.type}--${UUID}$`).test(o.id)) out.push(`id ${o.id} of a ${o.type}`)
    if (ids.has(o.id)) out.push(`${o.id} twice`)
    ids.add(o.id)
    if (o.spec_version !== '2.1') out.push(`${o.id}: spec_version ${String(o.spec_version)}`)
    for (const p of REQUIRED[o.type] ?? []) if (o[p] === undefined || o[p] === '' || (Array.isArray(o[p]) && !(o[p] as unknown[]).length)) out.push(`${o.id}: no ${p}`)
    if (!SCO.has(o.type)) {
      for (const p of o.type === 'marking-definition' ? ['created'] : ['created', 'modified'])
        if (typeof o[p] !== 'string' || !TIMESTAMP.test(o[p] as string)) out.push(`${o.id}: ${p} ${String(o[p])}`)
    }
    for (const p of ['execution_start', 'execution_end']) if (o[p] !== undefined && !TIMESTAMP.test(String(o[p]))) out.push(`${o.id}: ${p}`)
    if (o.confidence !== undefined && !(Number.isInteger(o.confidence) && (o.confidence as number) >= 0 && (o.confidence as number) <= 100)) out.push(`${o.id}: confidence ${String(o.confidence)}`)
    if (FLOW_TYPES.has(o.type)) {
      const ext = (o.extensions as Record<string, { extension_type?: string }> | undefined)?.[ATTACK_FLOW_EXT]
      if (ext?.extension_type !== 'new-sdo') out.push(`${o.id}: no Attack Flow extension`)
    }
    if (o.type === 'attack-flow' && !['incident', 'campaign', 'threat-actor', 'malware', 'attack-tree', 'other'].includes(String(o.scope))) out.push(`${o.id}: scope ${String(o.scope)}`)
    if (o.type === 'attack-action' && o.technique_id !== undefined && !/^T\d{4}(\.\d{3})?$/.test(String(o.technique_id))) out.push(`${o.id}: technique ${String(o.technique_id)}`)
  }
  // every reference resolves inside the bundle
  for (const o of b.objects) {
    for (const [k, v] of Object.entries(o)) {
      const refs = k.endsWith('_ref') ? [v] : k.endsWith('_refs') ? (v as unknown[]) : []
      for (const r of refs) if (typeof r !== 'string' || !ids.has(r)) out.push(`${o.id}: ${k} ${String(r)} is not in the bundle`)
    }
  }
  return out
}

const byType = (b: Bundle, t: string) => b.objects.filter((o) => o.type === t)
const byId = (b: Bundle) => new Map(b.objects.map((o) => [o.id, o]))

/** The actions from the flow's start along effect_refs. */
function walk(b: Bundle): Obj[] {
  const all = byId(b)
  const flow = byType(b, 'attack-flow')[0]
  const out: Obj[] = []
  let at = all.get((flow.start_refs as string[])[0])
  while (at && out.length < 100) {
    out.push(at)
    at = all.get(((at.effect_refs as string[] | undefined) ?? [])[0])
  }
  return out
}

describe('a story as an Attack Flow', () => {
  it('is a STIX 2.1 bundle of the Attack Flow extension whose every reference resolves', async () => {
    const b = (await storyAttackFlow(spinedStory(), ctx)) as Bundle
    expect(problems(b)).toEqual([])
    const flows = byType(b, 'attack-flow')
    expect(flows).toHaveLength(1)
    expect(flows[0]).toMatchObject({ scope: 'incident', name: 'daniel.roy@northstar.example: Credential phishing link → LSASS dumped with comsvcs', confidence: 70 })
    expect(String(flows[0].description)).toContain('Anchored on LSASS dumped with comsvcs')
    // the extension it uses is defined in the bundle, and everything is TLP:AMBER from the case
    expect(byType(b, 'extension-definition').map((o) => o.id)).toEqual([ATTACK_FLOW_EXT])
    expect(byType(b, 'marking-definition')[0]).toMatchObject({ name: 'TLP:AMBER' })
    expect(flows[0].created_by_ref).toBe(byType(b, 'identity').find((i) => i.name === 'REMN case: Lab')?.id)
  })

  it('runs one action per spine step in the spine’s order, with its technique, tactic and the confidence of its tie', async () => {
    const b = (await storyAttackFlow(spinedStory(), ctx)) as Bundle
    const actions = byType(b, 'attack-action')
    expect(actions).toHaveLength(SPINE.length)
    const path = walk(b)
    expect(path).toHaveLength(SPINE.length)
    expect(path.map((a) => a.execution_start)).toEqual(SPINE.map((id) => new Date(STEPS.find((s) => s.id === id)!.ts).toISOString()))
    expect(path.map((a) => a.name)).toEqual([
      'Credential phishing link',
      'RDP logon from a non-internal address',
      'LSASS dumped with comsvcs',
      'Scheduled task created',
      'Network logon from a workstation',
      'Service installed',
    ])
    expect(path.map((a) => a.technique_id)).toEqual(['T1566.002', 'T1133', 'T1003.001', 'T1053.005', 'T1021.002', undefined])
    expect(path.map((a) => a.tactic_id)).toEqual(['initial-access', 'initial-access', 'credential-access', 'persistence', 'lateral-movement', 'persistence'])
    // strong ties 90, the medium one (the task, tied by the name on its record) 70
    expect(path.map((a) => a.confidence)).toEqual([90, 90, 90, 70, 90, 90])
    expect(path[2].external_references).toEqual([{ source_name: 'mitre-attack', external_id: 'T1003.001', url: 'https://attack.mitre.org/techniques/T1003/001/' }])
    expect(path[5].effect_refs).toBeUndefined()
    // the steps off the spine are not in the flow
    expect(actions.some((a) => String(a.description).includes('AnyDesk') || String(a.description).includes('whoami'))).toBe(false)
  })

  it('names the hosts, accounts and addresses the steps touch as assets', async () => {
    const b = (await storyAttackFlow(spinedStory(), ctx)) as Bundle
    const all = byId(b)
    const assets = byType(b, 'attack-asset')
    expect(assets.map((a) => a.name).sort()).toEqual(['10.0.0.14', '203.0.113.69', 'daniel.roy@northstar.example', 'fs-001', 'ws-004'])
    const person = assets.find((a) => a.name === 'daniel.roy@northstar.example')!
    expect(all.get(person.object_ref as string)).toMatchObject({ type: 'identity', identity_class: 'individual' })
    // an address is infrastructure that consists of the address, whose id is STIX's own for it
    const infra = all.get(assets.find((a) => a.name === '203.0.113.69')!.object_ref as string)!
    expect(infra.type).toBe('infrastructure')
    const rel = byType(b, 'relationship').find((r) => r.source_ref === infra.id)!
    expect(rel).toMatchObject({ relationship_type: 'consists-of', target_ref: 'ipv4-addr--990a3ca5-0b8e-5834-8560-038920610bd1' })
    const logon = walk(b)[1]
    expect((logon.asset_refs as string[]).map((r) => all.get(r)?.name).sort()).toEqual(['203.0.113.69', 'daniel.roy@northstar.example', 'ws-004'])
  })

  it('gives the same objects the same ids each time', async () => {
    const a = (await storyAttackFlow(spinedStory(), ctx)) as Bundle
    const b = (await storyAttackFlow(spinedStory(), ctx)) as Bundle
    expect(a.objects).toEqual(b.objects)
    expect(a.id).not.toBe(b.id)
  })

  it('reads a story built before spines by its flagged steps', async () => {
    const old = oldStory()
    expect(spineSteps(old)).toBeNull()
    const b = (await storyAttackFlow(old, ctx)) as Bundle
    expect(problems(b)).toEqual([])
    expect(walk(b).map((a) => a.name)).toContain('Remote access tool started')
    expect(walk(b)).toHaveLength(STEPS.filter((s) => s.findings.some((f) => f.severity !== 'low' && f.severity !== 'info')).length)
  })

  it('reads a technique from an ATT&CK tag', () => {
    expect(techniqueId('attack.t1003.001')).toBe('T1003.001')
    expect(techniqueId('T1059')).toBe('T1059')
    expect(techniqueId('attack.credential_access')).toBeNull()
    expect(techniqueId('attack.g0016')).toBeNull()
  })
})

describe('a campaign as a STIX grouping', () => {
  it('groups the flows of its stories, the infrastructure they share and the accounts its sources reached', async () => {
    const b = (await campaignGrouping(CAMPAIGN, [spinedStory()], ctx)) as Bundle
    expect(problems(b)).toEqual([])
    const all = byId(b)
    const groupings = byType(b, 'grouping')
    expect(groupings).toHaveLength(1)
    const g = groupings[0]
    expect(g).toMatchObject({ context: 'suspicious-activity', name: 'Campaign 203.0.113.69' })
    const members = (g.object_refs as string[]).map((r) => all.get(r)!)
    expect(members.map((m) => m.type)).toEqual(['attack-flow', 'infrastructure', 'domain-name', 'file', 'identity'])
    expect(members[2]).toMatchObject({ value: 'northstar-sso.example', id: 'domain-name--4a20bd6a-e4b9-5d43-a1f2-c25d6115a444' })
    expect(members[4]).toMatchObject({ name: 'northstar\\employee019' })
    expect(String(members[4].description)).toContain('nothing says the account was compromised')
    // the address the flow and the campaign both name is one object
    expect(byType(b, 'infrastructure').filter((i) => i.name === '203.0.113.69')).toHaveLength(1)
  })

  it('is still a valid grouping when none of its stories is at hand', async () => {
    const b = (await campaignGrouping({ ...CAMPAIGN, artifacts: [], targets: [] }, [], ctx)) as Bundle
    expect(problems(b)).toEqual([])
    expect(byType(b, 'extension-definition')).toHaveLength(0)
    expect(byType(b, 'grouping')[0].object_refs).toHaveLength(1)
  })
})
