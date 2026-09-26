import type { Campaign, Identity, Story, StoryFinding, StoryStep } from '../data/stories'
import type { SpinedStory } from '../data/storyFlow'

/**
 * A synthetic story with a spine, for the tests of the spine's page section, its report table and
 * the Attack Flow export: a phishing mail, an RDP logon from outside in the same person's name, a
 * dump of LSASS and a scheduled task in that session, a network logon to FS-001 and a service
 * installed there. A remote access tool started before the RDP logon and a whoami after the service
 * are in the story but not on the spine. No real person, host or address: the names are made up and
 * the addresses are documentation ranges.
 */

export const T0 = Date.UTC(2026, 8, 4, 8, 0)
const MIN = 60_000

const finding = (ruleId: string, title: string, severity: StoryFinding['severity']): StoryFinding => ({ ruleId, title, severity, key: `${ruleId}|1` })

function step(id: string, minutes: number, extra: Partial<StoryStep>): StoryStep {
  return {
    id,
    refs: [id],
    source: id.startsWith('mail:') ? 'mails' : 'events',
    ts: T0 + minutes * MIN,
    tsEnd: T0 + minutes * MIN,
    count: 1,
    title: `record ${id}`,
    host: 'ws-004',
    ip: null,
    origin: 'host',
    phase: null,
    phaseBasis: '',
    findings: [],
    severity: null,
    tie: { kind: 'session', basis: 'in the RDP session 0x9a01 on ws-004', confidence: 'strong' },
    notes: [],
    accounts: ['id:daniel'],
    session: 'ses:rdp',
    process: null,
    hops: [],
    routine: false,
    ...extra,
  }
}

export const STEPS: StoryStep[] = [
  step('mail:1', 0, {
    title: 'Mail from it-desk@northstar-sso.example: Password reset required',
    origin: 'mail',
    host: null,
    session: null,
    phase: 'initial-access',
    phaseBasis: 'a phishing mail with a link',
    findings: [finding('mail-credential-phishing', 'Credential phishing link', 'high')],
    severity: 'high',
    tie: { kind: 'chain', basis: 'the phishing chain of this mail', confidence: 'strong' },
  }),
  step('event:2', 3, {
    title: 'AnyDesk.exe started',
    phase: 'command-and-control',
    phaseBasis: 'rule tag command-and-control',
    findings: [finding('win-remote-access-tool', 'Remote access tool started', 'medium')],
    severity: 'medium',
    session: 'ses:local',
  }),
  step('event:10', 20, {
    title: 'Logon RemoteInteractive as NORTHSTAR\\daniel.roy from 203.0.113.69',
    ip: '203.0.113.69',
    phase: 'initial-access',
    phaseBasis: 'an RDP logon from outside',
    findings: [finding('win-rdp-logon-external', 'RDP logon from a non-internal address', 'high')],
    severity: 'high',
    tie: { kind: 'address', basis: 'from 203.0.113.69, the address the phishing link led to', confidence: 'strong' },
  }),
  step('event:11', 24, {
    title: 'rundll32.exe comsvcs.dll MiniDump of lsass.exe',
    phase: 'credential-access',
    phaseBasis: 'rule tag credential-access, technique T1003.001',
    findings: [finding('win-lsass-dump-comsvcs', 'LSASS dumped with comsvcs', 'critical'), finding('win-rundll32-odd', 'rundll32 with an odd entry point', 'medium')],
    severity: 'critical',
  }),
  step('event:12', 30, {
    title: 'Scheduled task created \\Updater <script>alert(1)</script>',
    phase: 'persistence',
    phaseBasis: 'rule tag persistence',
    findings: [finding('win-task-created', 'Scheduled task created', 'high')],
    severity: 'high',
    tie: { kind: 'identity', basis: 'the record names them (subject) & the time', confidence: 'medium' },
  }),
  step('event:14', 41, {
    title: 'Logon Network as NORTHSTAR\\daniel.roy from 10.0.0.14',
    host: 'fs-001',
    ip: '10.0.0.14',
    session: 'ses:fs',
    phase: 'lateral-movement',
    phaseBasis: 'a network logon from another host of the case',
    findings: [finding('win-lateral-logon', 'Network logon from a workstation', 'medium')],
    severity: 'medium',
    tie: { kind: 'hop', basis: 'a network logon from ws-004 (4648 then 4624 type 3)', confidence: 'strong' },
    hops: ['hop:fs'],
  }),
  step('event:16', 43, {
    title: 'Service installed: PSEXESVC',
    host: 'fs-001',
    session: 'ses:fs',
    phase: 'persistence',
    phaseBasis: 'rule tag persistence',
    findings: [finding('win-service-installed', 'Service installed', 'high')],
    severity: 'high',
    tie: { kind: 'session', basis: 'in the network session 0x5501 on fs-001', confidence: 'strong' },
  }),
  step('event:20', 50, { title: 'whoami.exe /all', phase: 'discovery', phaseBasis: 'a discovery program' }),
]

export const SPINE = ['mail:1', 'event:10', 'event:11', 'event:12', 'event:14', 'event:16']

export function spinedStory(over: Partial<SpinedStory> = {}): SpinedStory {
  return {
    id: 'story-1',
    kind: 'person',
    subject: { kind: 'person', id: 'id:daniel', label: 'daniel.roy@northstar.example', org: 'northstar.example' },
    title: 'daniel.roy@northstar.example',
    headline: 'Credential phishing link → LSASS dumped with comsvcs',
    summary: 'It starts with a phishing mail and ends with a service on fs-001.',
    start: STEPS[0].ts,
    end: STEPS[STEPS.length - 1].ts,
    severity: 'critical',
    score: 92,
    confidence: 'medium',
    phases: [
      { phase: 'initial-access', label: 'Initial access', first: T0, last: T0 + 20 * MIN, steps: 2, records: 2, findings: 2, severity: 'high' },
      { phase: 'command-and-control', label: 'Command and control', first: T0 + 3 * MIN, last: T0 + 3 * MIN, steps: 1, records: 1, findings: 1, severity: 'medium' },
      { phase: 'credential-access', label: 'Credential access', first: T0 + 24 * MIN, last: T0 + 24 * MIN, steps: 1, records: 1, findings: 2, severity: 'critical' },
      { phase: 'persistence', label: 'Persistence', first: T0 + 30 * MIN, last: T0 + 43 * MIN, steps: 2, records: 2, findings: 2, severity: 'high' },
      { phase: 'lateral-movement', label: 'Lateral movement', first: T0 + 41 * MIN, last: T0 + 41 * MIN, steps: 1, records: 1, findings: 1, severity: 'medium' },
      { phase: 'discovery', label: 'Discovery', first: T0 + 50 * MIN, last: T0 + 50 * MIN, steps: 1, records: 1, findings: 0, severity: null },
    ],
    steps: STEPS,
    records: STEPS.length,
    hosts: ['ws-004', 'fs-001'],
    accounts: ['id:daniel'],
    ips: ['203.0.113.69', '10.0.0.14'],
    attackerAddresses: ['203.0.113.69'],
    chains: ['chain-1'],
    findings: [],
    campaigns: ['campaign-1'],
    gaps: [],
    lineage: { sessions: [], hops: [], processes: [] },
    spine: SPINE,
    spineBasis: {
      anchor: 'event:11',
      wayIn: ['mail:1'],
      tied: true,
      cut: 0,
      text: "Anchored on LSASS dumped with comsvcs on ws-004. The story's ties lead back from it to the way in: Mail from it-desk@northstar-sso.example <reset> & more.",
    },
    ...over,
  }
}

/** The same story as a build before spines left it: no spine, no basis. */
export function oldStory(): Story {
  const { spine: _spine, spineBasis: _basis, ...rest } = spinedStory()
  return rest
}

/** The ATT&CK tags of the findings above, by rule, as the case's findings carry them. */
export const ATTACK_TAGS: Record<string, string[]> = {
  'mail-credential-phishing': ['attack.initial_access', 'attack.t1566.002'],
  'win-remote-access-tool': ['attack.command_and_control', 'attack.t1219'],
  'win-rdp-logon-external': ['attack.initial_access', 'attack.t1133'],
  'win-lsass-dump-comsvcs': ['attack.credential_access', 'attack.t1003.001'],
  'win-rundll32-odd': ['attack.defense_evasion', 'attack.t1218.011'],
  'win-task-created': ['attack.persistence', 'attack.t1053.005'],
  'win-lateral-logon': ['attack.lateral_movement', 'attack.t1021.002'],
  // a rule with no technique: its step's action names none
  'win-service-installed': ['attack.persistence'],
}

export const IDENTITIES: Identity[] = [
  { id: 'id:daniel', label: 'daniel.roy@northstar.example', kind: 'person', org: 'northstar.example', forms: [], joins: [], possibly: [], namesakes: [], conflicts: [], notes: [] },
  { id: 'id:e19', label: 'northstar\\employee019', kind: 'person', org: 'northstar.example', forms: [], joins: [], possibly: [], namesakes: [], conflicts: [], notes: [] },
]

export const CAMPAIGN: Campaign = {
  id: 'campaign-1',
  label: '203.0.113.69',
  labelKind: 'ip',
  artifacts: [
    { kind: 'ip', value: '203.0.113.69', stories: ['story-1'] },
    { kind: 'link-domain', value: 'northstar-sso.example', stories: ['story-1'] },
    { kind: 'attachment', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', stories: ['story-1'] },
  ],
  stories: ['story-1'],
  people: ['id:daniel'],
  targets: [{ id: 'id:e19', account: 'northstar\\employee019', how: ['failed logon'], via: ['203.0.113.69'], refs: ['event:3'] }],
  start: T0,
  end: T0 + 50 * MIN,
  severity: 'critical',
}
