/**
 * Playbooks: investigations the agent runs on its own from one click, each a goal, the checks an
 * experienced analyst would make in order, and what to hand back. The checks seed the plan; the
 * agent adapts it to what the case holds, records hypotheses as it goes, and queues what it finds
 * (timeline entries, decisions, row marks) in the approval inbox.
 */
import type { CaseShape, PlanStep } from './tools'

export interface Playbook {
  id: string
  title: string
  /** one line on the card */
  summary: string
  needs: 'events' | 'mails' | 'any'
  attack: string[]
  steps: string[]
  goal: string
}

export const PLAYBOOKS: Playbook[] = [
  {
    id: 'phish-to-compromise',
    title: 'Phishing to compromise',
    summary: 'From the riskiest mails to what their recipients’ accounts and machines did next.',
    needs: 'mails',
    attack: ['T1566', 'T1078', 'T1114.003'],
    goal: 'Decide whether a phishing mail led to an account or host compromise, and who was affected.',
    steps: [
      'Rank the riskiest mails (credential phishing, macros, HTML smuggling, lookalike senders)',
      'Find who received each and whether a chain ties later activity to it',
      'Follow each recipient: logons or sign-ins after the mail, from new places',
      'Look for mailbox rules, forwarding and mass mail access after the mail',
      'Look for execution on the recipient’s machine after the mail (Office or browser spawning scripts)',
      'Settle compromise per recipient: confirmed, suspected or not supported',
    ],
  },
  {
    id: 'brute-force',
    title: 'Password guessing',
    summary: 'Brute force and spraying: the sources, the targeted accounts, and whether any got in.',
    needs: 'events',
    attack: ['T1110.001', 'T1110.003', 'T1078'],
    goal: 'Find password guessing, tell brute force from spraying, and establish whether any attempt succeeded and what the session did.',
    steps: [
      'Shape of failed logons over time (4625, 4771, 4776) and their status codes',
      'Top sources and targeted accounts: one account many passwords, or many accounts few passwords',
      'Successful logons (4624) from the same sources after the failures',
      'Lockouts (4740) and what else the sources touched',
      'What each successful session did (logon_session)',
    ],
  },
  {
    id: 'lateral-movement',
    title: 'Lateral movement',
    summary: 'RDP, PsExec, admin shares, WinRM, WMI and remote tasks: the path from host to host.',
    needs: 'events',
    attack: ['T1021.001', 'T1021.002', 'T1021.006', 'T1047', 'T1569.002'],
    goal: 'Reconstruct movement between hosts: which account went from where to where, how, and when.',
    steps: [
      'Network and RDP logons (4624 types 3 and 10, 1149, 21, 25) by source and account',
      'Admin share access (5140, 5145 on ADMIN$, C$, IPC$) and remote service installs (7045, 4697, PSEXESVC)',
      'WinRM (wsmprovhost) and WMI (wmiprvse children) execution',
      'Remote scheduled tasks (4698) and explicit credential use (4648)',
      'Build the host-to-host path in time order',
    ],
  },
  {
    id: 'persistence',
    title: 'Persistence sweep',
    summary: 'Services, tasks, Run keys, WMI subscriptions, new accounts and startup files.',
    needs: 'events',
    attack: ['T1543.003', 'T1053.005', 'T1547.001', 'T1546.003', 'T1136'],
    goal: 'List every persistence mechanism created in the period, tie each to the process and account that made it, and separate the malicious from the routine.',
    steps: [
      'New services (7045, 4697) and their binaries',
      'Scheduled tasks created or changed (4698, 4702, 106)',
      'Run and RunOnce keys, Winlogon and IFEO values (Sysmon 12 and 13)',
      'WMI event subscriptions (Sysmon 19, 20, 21; WMI-Activity 5861)',
      'New accounts and group additions (4720, 4728, 4732, 4756)',
      'Files dropped in startup folders (Sysmon 11)',
    ],
  },
  {
    id: 'm365-bec',
    title: 'Microsoft 365 account takeover',
    summary: 'Sign-ins, MFA changes, inbox rules, forwarding, consent grants and mail access.',
    needs: 'events',
    attack: ['T1078.004', 'T1114.003', 'T1098', 'T1528'],
    goal: 'Decide whether a Microsoft 365 account was taken over, from where, and what the attacker did with the mailbox.',
    steps: [
      'Sign-ins by account, country, IP and client; failures before successes',
      'MFA and security-info changes, new devices and app passwords',
      'Inbox rules (New-InboxRule, Set-InboxRule, UpdateInboxRules) and forwarding (Set-Mailbox)',
      'OAuth consent grants and new app permissions',
      'Mail access and sending after the suspicious sign-in (MailItemsAccessed, Send, deletions)',
    ],
  },
  {
    id: 'ransomware-precursors',
    title: 'Ransomware precursors',
    summary: 'Shadow copy deletion, backup and Defender tampering, log clearing, discovery and staging.',
    needs: 'events',
    attack: ['T1490', 'T1562.001', 'T1070.001', 'T1087', 'T1567'],
    goal: 'Find the preparations that come before ransomware or extortion, and how far they got.',
    steps: [
      'Recovery inhibition: vssadmin, wmic shadowcopy, wbadmin, bcdedit',
      'Security tooling tampered with: Defender settings and exclusions (5001, 5007, Set-MpPreference), services stopped',
      'Logs cleared (1102, 104) and audit policy changes (4719)',
      'Discovery: net group, nltest, AdFind, share and host enumeration',
      'Staging and exfiltration tools (rclone, MEGA, archives) and remote execution spread',
    ],
  },
  {
    id: 'credential-access',
    title: 'Credential theft',
    summary: 'LSASS access and dumps, DCSync, Kerberoasting, AS-REP roasting, NTDS and SAM copies.',
    needs: 'events',
    attack: ['T1003.001', 'T1003.006', 'T1558.003', 'T1558.004', 'T1003.003'],
    goal: 'Find attempts to steal credentials, which accounts are exposed as a result, and whether the credentials were used afterwards.',
    steps: [
      'LSASS access (Sysmon 10 on lsass.exe) and dump tools (procdump, comsvcs MiniDump)',
      'Credential tooling in script blocks (4104) and command lines',
      'DCSync: directory replication rights used by a non-DC account (4662)',
      'Kerberoasting (4769 with RC4 across many services) and AS-REP roasting (4768 without pre-authentication)',
      'NTDS.dit and SAM/SYSTEM hive copies',
      'Use of the exposed accounts afterwards',
    ],
  },
]

export function playbookFits(p: Playbook, shape: CaseShape): boolean {
  if (p.needs === 'events') return shape.events > 0
  if (p.needs === 'mails') return shape.mails > 0
  return shape.events > 0 || shape.mails > 0
}

/** The message that starts a playbook, and the plan it starts from. */
export function playbookStart(p: Playbook): { question: string; plan: PlanStep[] } {
  const question =
    `Run the "${p.title}" playbook on this case. Goal: ${p.goal}\n` +
    `Checks, in order (adapt them to what the case holds; skip what does not apply and say why):\n` +
    p.steps.map((s, i) => `${i + 1}. ${s}`).join('\n') +
    `\nRelevant ATT&CK: ${p.attack.join(', ')}.\n` +
    'As you go: keep the plan up to date, record each hypothesis with the rows for and against it, and propose timeline entries for the key moments and decisions on the findings the evidence settles. ' +
    'Finish with what happened, your confidence, and the gaps in the evidence.'
  return { question, plan: p.steps.map((title) => ({ title, status: 'todo' })) }
}
