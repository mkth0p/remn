/**
 * A story's spine, and a story or a campaign exported for another tool
 * (docs/stories.md, "Spine" and "Export").
 *
 * The spine is built with the story (stories._spine): the few steps that carry it from the way in
 * to the worst of it, each keeping its tie. A story exports as a MITRE CTID Attack Flow: a STIX 2.1
 * bundle with the Attack Flow extension, an attack-action per spine step in the spine's order, the
 * hosts, accounts and addresses those steps touch as attack-assets (an account also as an identity,
 * an address also as infrastructure). A campaign exports as a STIX 2.1 grouping of the flows of its
 * stories, the infrastructure they share and the accounts its sources reached. Identifiers come
 * from the content (the STIX export helpers of util/export), so the same export twice is the same
 * objects.
 */
import { getDb } from '../db/schema'
import type { Case, Finding } from '../db/schema'
import { canonical, exportJson, REMN_NS, STIX_SCO_NS, stixObservable, TLP_AMBER, uuid5 } from '../util/export'
import { uuid4 } from '../util/uuid'
import type { Campaign, Confidence, Identity, Story, StoryFinding, StoryStep } from './stories'

/** What a spine was anchored on and where it starts (stories._spine_basis). */
export interface SpineBasis {
  /** the step of the worst finding the ties were walked back from */
  anchor: string
  /** the ways in the ties lead back to, first first; empty when none is in the evidence */
  wayIn: string[]
  tied: boolean
  /** steps on the spine's paths left to the full timeline (past its cap, or a flag repeated on its host) */
  cut: number
  text: string
}
/** A story as a build that knows spines returns it; a snapshot built before has neither field. */
export type SpinedStory = Story & { spine?: string[]; spineBasis?: SpineBasis | null }

/** The steps of a story's spine in time order, or null when its build had no spine (build it again). */
export function spineSteps(story: Story): StoryStep[] | null {
  const ids = (story as SpinedStory).spine
  if (!ids) return null
  const by = new Map(story.steps.map((s) => [s.id, s]))
  return ids.map((id) => by.get(id)).filter((s): s is StoryStep => !!s)
}
export const spineBasis = (story: Story): SpineBasis | null => (story as SpinedStory).spineBasis ?? null

// ---------------------------------------------------------------------------------------------------
// Attack Flow
// ---------------------------------------------------------------------------------------------------

/** The Attack Flow language's STIX extension (https://center-for-threat-informed-defense.github.io/attack-flow/language/). */
export const ATTACK_FLOW_EXT = 'extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4'
const AF_AUTHOR = 'identity--fb9c968a-745b-4ade-9b25-c324172197f4'
const AF_CREATED = '2022-08-02T19:34:35.143Z'
/** the extension's definition and its author, as the Attack Flow corpus ships them, so a bundle names what it extends STIX with */
const ATTACK_FLOW_DEFINITION = [
  {
    type: 'extension-definition',
    spec_version: '2.1',
    id: ATTACK_FLOW_EXT,
    created: AF_CREATED,
    modified: AF_CREATED,
    created_by_ref: AF_AUTHOR,
    name: 'Attack Flow',
    description: 'Extends STIX 2.1 with features to create Attack Flows.',
    schema: 'https://center-for-threat-informed-defense.github.io/attack-flow/stix/attack-flow-schema-2.0.0.json',
    version: '2.0.0',
    extension_types: ['new-sdo'],
    external_references: [
      { source_name: 'Documentation', description: 'Documentation for Attack Flow', url: 'https://center-for-threat-informed-defense.github.io/attack-flow' },
      { source_name: 'GitHub', description: 'Source code repository for Attack Flow', url: 'https://github.com/center-for-threat-informed-defense/attack-flow' },
    ],
  },
  {
    type: 'identity',
    spec_version: '2.1',
    id: AF_AUTHOR,
    created: AF_CREATED,
    modified: AF_CREATED,
    created_by_ref: AF_AUTHOR,
    name: 'MITRE Engenuity Center for Threat-Informed Defense',
    identity_class: 'organization',
  },
]
/** TLP:AMBER, as STIX 2.1 predefines it: a story is for the recipient's organisation */
const TLP_AMBER_DEFINITION = {
  type: 'marking-definition',
  spec_version: '2.1',
  id: TLP_AMBER,
  created: '2017-01-20T00:00:00.000Z',
  definition_type: 'tlp',
  name: 'TLP:AMBER',
  definition: { tlp: 'amber' },
}
const NEW_SDO = { [ATTACK_FLOW_EXT]: { extension_type: 'new-sdo' } }
/** how surely a tie holds, on Attack Flow's confidence scale (probable, very probable) */
export const TIE_CONFIDENCE: Record<Confidence, number> = { strong: 90, medium: 70, weak: 50 }
/** a spine an older snapshot does not have is read as the story's flags, as many as a spine holds */
const SPINE_MAX = 15

type Obj = Record<string, unknown> & { type: string; id: string }

/** What an export reads beside the story: the case, its findings' ATT&CK tags, the identities' names. */
export interface ExportContext {
  caseName: string
  /** the ATT&CK tags of a step's finding (Finding.attack), by its key or rule */
  attackOf: (f: StoryFinding) => string[]
  identities: Identity[]
  /** the objects' created and modified time; now when not given */
  now?: number
}

/** A technique id from an ATT&CK tag: T1003.001 from 'attack.t1003.001'. */
export function techniqueId(tag: string): string | null {
  const m = /^(?:attack\.)?(t\d{4}(?:\.\d{3})?)$/i.exec(tag.trim())
  return m ? m[1].toUpperCase() : null
}
const techniqueUrl = (t: string) => `https://attack.mitre.org/techniques/${t.replace('.', '/')}/`
const iso = (ts: number) => new Date(ts).toISOString()
const SEV: Record<string, number> = { critical: 5, high: 4, medium: 2, low: 1, info: 0 }

/** Builds a bundle's objects once each, with ids from their content. */
class Objects {
  readonly list: Obj[] = []
  private readonly byId = new Map<string, Obj>()
  constructor(
    readonly ctx: ExportContext,
    readonly created: string,
    readonly author: string,
  ) {}
  /** a REMN object's id: from the case and a key */
  async idOf(type: string, key: string): Promise<string> {
    return `${type}--${await uuid5(REMN_NS, `${type}:${this.ctx.caseName}:${key}`)}`
  }
  add(o: Obj): string {
    if (!this.byId.has(o.id)) {
      this.byId.set(o.id, o)
      this.list.push(o)
    }
    return o.id
  }
  /** a REMN object: its id from the case and a key, with its author, times and marking */
  async sdo(type: string, key: string, props: Record<string, unknown>): Promise<string> {
    const id = await this.idOf(type, key)
    return this.add({ type, spec_version: '2.1', id, created: this.created, modified: this.created, created_by_ref: this.author, ...props, object_marking_refs: [TLP_AMBER] })
  }
  /** a cyber-observable: its id from its identifying properties, as STIX 2.1 derives them */
  async sco(type: string, key: Record<string, unknown>, props: Record<string, unknown> = {}): Promise<string> {
    const id = `${type}--${await uuid5(STIX_SCO_NS, canonical(key))}`
    return this.add({ type, spec_version: '2.1', id, ...key, ...props, object_marking_refs: [TLP_AMBER] })
  }
  /** an Attack Flow object */
  async flow(type: string, key: string, props: Record<string, unknown>): Promise<string> {
    return this.sdo(type, key, { ...props, extensions: NEW_SDO })
  }
  /** an address as the story or the campaign saw it: infrastructure of the address it consists of */
  async address(ip: string, description: string): Promise<string> {
    const obs = stixObservable('ip', ip)!
    const sco = await this.sco(String(obs.sco.type), { value: ip })
    const infra = await this.sdo('infrastructure', `ip:${ip}`, { name: ip, description })
    await this.sdo('relationship', `consists-of:${ip}`, { relationship_type: 'consists-of', source_ref: infra, target_ref: sco })
    return infra
  }
  /** an account by the identity the resolver gives it */
  async account(iid: string, description: string): Promise<string> {
    const ident = this.ctx.identities.find((i) => i.id === iid)
    return this.sdo('identity', `account:${iid}`, { name: ident?.label ?? iid, identity_class: ident?.kind === 'service' ? 'system' : 'individual', description })
  }
}

/** The finding a step is read by: its worst, one with an ATT&CK technique first. */
function stepFinding(step: StoryStep, ctx: ExportContext): { f: StoryFinding | null; techniques: string[] } {
  const ranked = [...step.findings].sort((a, b) => (SEV[b.severity] ?? 0) - (SEV[a.severity] ?? 0))
  const withTech = ranked.map((f) => ({
    f,
    techniques: [
      ...new Set(
        ctx
          .attackOf(f)
          .map(techniqueId)
          .filter((t): t is string => !!t),
      ),
    ],
  }))
  return withTech.find((x) => x.techniques.length) ?? { f: ranked[0] ?? null, techniques: [] }
}

/** The objects of one story's flow in a bundle being built; the flow's id. */
async function addFlow(o: Objects, story: Story): Promise<string> {
  const ctx = o.ctx
  const flagged = story.steps.filter((s) => s.findings.some((f) => (SEV[f.severity] ?? 0) >= 2))
  const spine = spineSteps(story)
  const steps = spine?.length ? spine : (flagged.length ? flagged : story.steps).slice(0, SPINE_MAX)
  const basis = spineBasis(story)
  const attacker = new Set(story.attackerAddresses)
  const actions: { id: string; props: Record<string, unknown>; key: string }[] = []
  for (const step of steps) {
    const assets: string[] = []
    if (step.host) assets.push(await o.flow('attack-asset', `host:${step.host}`, { name: step.host, description: `the host ${step.host} of the case` }))
    for (const iid of step.accounts.slice(0, 5)) {
      const ident = await o.account(iid, `an account the story's records name`)
      assets.push(await o.flow('attack-asset', `account:${iid}`, { name: ctx.identities.find((i) => i.id === iid)?.label ?? iid, object_ref: ident }))
    }
    if (step.ip) {
      const infra = await o.address(step.ip, attacker.has(step.ip) ? "a source the story's findings name" : 'an address a step of the story came from')
      assets.push(await o.flow('attack-asset', `ip:${step.ip}`, { name: step.ip, object_ref: infra }))
    }
    const { f, techniques } = stepFinding(step, ctx)
    const where = [step.host, step.ip].filter(Boolean).join(', ')
    actions.push({
      key: `${story.id}:${step.id}`,
      id: await o.idOf('attack-action', `${story.id}:${step.id}`),
      props: {
        name: (f?.title || step.title).slice(0, 250),
        ...(techniques.length ? { technique_id: techniques[0] } : {}),
        ...(step.phase ? { tactic_id: step.phase } : {}),
        description: `${step.title}${where ? ` (${where})` : ''}. ${step.phase ? `${step.phaseBasis}. ` : ''}Why it is in the story (${step.tie.confidence}): ${step.tie.basis}.`,
        confidence: TIE_CONFIDENCE[step.tie.confidence] ?? 50,
        execution_start: iso(step.ts),
        ...(step.tsEnd > step.ts ? { execution_end: iso(step.tsEnd) } : {}),
        ...(assets.length ? { asset_refs: [...new Set(assets)] } : {}),
        ...(techniques.length ? { external_references: techniques.map((t) => ({ source_name: 'mitre-attack', external_id: t, url: techniqueUrl(t) })) } : {}),
      },
    })
  }
  // each action leads to the next, in the spine's order
  for (const [i, a] of actions.entries()) {
    await o.flow('attack-action', a.key, { ...a.props, ...(actions[i + 1] ? { effect_refs: [actions[i + 1].id] } : {}) })
  }
  return o.flow('attack-flow', story.id, {
    name: `${story.title}: ${story.headline}`.slice(0, 250),
    description: [basis?.text, story.summary].filter(Boolean).join(' '),
    scope: 'incident',
    start_refs: actions.length ? [actions[0].id] : [],
    confidence: TIE_CONFIDENCE[story.confidence] ?? 50,
  })
}

/** A bundle's first objects: the marking and the case's own identity (as the indicator export names it), the author of the rest. */
async function newBundle(ctx: ExportContext): Promise<Objects> {
  const created = iso(ctx.now ?? Date.now())
  const author = `identity--${await uuid5(REMN_NS, `case:${ctx.caseName}`)}`
  const o = new Objects(ctx, created, author)
  o.add(TLP_AMBER_DEFINITION)
  o.add({ type: 'identity', spec_version: '2.1', id: author, created, modified: created, name: `REMN case: ${ctx.caseName}`, identity_class: 'system' })
  return o
}

/** A story as a MITRE CTID Attack Flow: a STIX 2.1 bundle whose flow (scope incident) runs along its spine. */
export async function storyAttackFlow(story: Story, ctx: ExportContext): Promise<Record<string, unknown>> {
  const o = await newBundle(ctx)
  for (const d of ATTACK_FLOW_DEFINITION) o.add(d)
  await addFlow(o, story)
  return { type: 'bundle', id: `bundle--${uuid4()}`, objects: o.list }
}

/**
 * A campaign as a STIX 2.1 grouping (context suspicious-activity): the Attack Flow of each of its
 * stories, the infrastructure they share and the accounts outside them its sources reached, which
 * the grouping says nothing more of (nothing says they were compromised).
 */
export async function campaignGrouping(campaign: Campaign, stories: Story[], ctx: ExportContext): Promise<Record<string, unknown>> {
  const o = await newBundle(ctx)
  const refs: string[] = []
  const members = campaign.stories.map((id) => stories.find((s) => s.id === id)).filter((s): s is Story => !!s)
  if (members.length) for (const d of ATTACK_FLOW_DEFINITION) o.add(d)
  for (const s of members) refs.push(await addFlow(o, s))
  for (const a of campaign.artifacts) {
    if (a.kind === 'ip') refs.push(await o.address(a.value, "a source the campaign's stories name"))
    else if (a.kind === 'sender-domain' || a.kind === 'link-domain') refs.push(await o.sco('domain-name', { value: a.value }))
    else if (a.kind === 'attachment' && /^[0-9a-f]{64}$/i.test(a.value)) refs.push(await o.sco('file', { hashes: { 'SHA-256': a.value.toLowerCase() } }))
    else if (a.kind === 'forwarding') refs.push(await o.sco('email-addr', { value: a.value }))
    else if (a.kind === 'application') refs.push(await o.sco('software', { name: a.value }))
  }
  for (const t of campaign.targets) refs.push(await o.account(t.id, `Reached by the campaign's sources (${t.how.join(', ')}, through ${t.via.join(', ')}); nothing says the account was compromised.`))
  const label = campaign.labelKind.replace('-', ' ')
  await o.sdo('grouping', `campaign:${campaign.id}`, {
    name: `Campaign ${campaign.label}`.slice(0, 250),
    description: `Stories that share the attacker's infrastructure (named by its ${label}), from ${iso(campaign.start)} to ${iso(campaign.end)}: ${members.length} ${members.length === 1 ? 'story' : 'stories'}, ${campaign.targets.length} other account(s) its sources reached.`,
    context: 'suspicious-activity',
    object_refs: refs.length ? [...new Set(refs)] : [o.author],
  })
  return { type: 'bundle', id: `bundle--${uuid4()}`, objects: o.list }
}

// ---------------------------------------------------------------------------------------------------
// downloads
// ---------------------------------------------------------------------------------------------------

/** The ATT&CK tags of the case's findings, by key and by rule: a story's steps name their findings by these. */
async function attackTags(kase: Case): Promise<ExportContext['attackOf']> {
  const findings: Finding[] = await getDb().findings.where('caseId').equals(kase.id!).toArray()
  const byKey = new Map(findings.map((f) => [f.key, f.attack ?? []]))
  const byRule = new Map<string, string[]>()
  for (const f of findings) if (!byRule.has(f.ruleId)) byRule.set(f.ruleId, f.attack ?? [])
  return (f) => (f.key && byKey.get(f.key)) || byRule.get(f.ruleId) || []
}
const slug = (s: string) =>
  s
    .replace(/[^a-z0-9_.-]+/gi, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 60) || 'story'

export async function downloadAttackFlow(kase: Case, story: Story, identities: Identity[]): Promise<void> {
  const bundle = await storyAttackFlow(story, { caseName: kase.name, attackOf: await attackTags(kase), identities })
  exportJson(`attack-flow-${slug(story.title)}.json`, bundle)
}

export async function downloadCampaignGrouping(kase: Case, campaign: Campaign, stories: Story[], identities: Identity[]): Promise<void> {
  const bundle = await campaignGrouping(campaign, stories, { caseName: kase.name, attackOf: await attackTags(kase), identities })
  exportJson(`stix-grouping-${slug(campaign.label)}.json`, bundle)
}
