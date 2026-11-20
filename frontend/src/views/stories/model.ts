import { IconCloud, IconHost, IconMail } from '../../components/Icons'
import { type Confidence, type Identity, type Story, type StoryStep } from '../../data/stories'
import { type EventRow, type MailRow, type Severity } from '../../db/schema'
import { fmtTs } from '../../util/format'

export type Mode = 'stories' | 'campaigns' | 'explore'
export type Tab = 'story' | 'lineage' | 'identity' | 'gaps' | 'decisions' | 'json'
export type Detail = { source: 'events'; row: EventRow } | { source: 'mails'; row: MailRow } | null

/** What a build keeps open: the story that was (and its step), or the story a link asked for. */
export type Follow = ({ story: Story; identities: Identity[] } | { link: string }) & { step?: string }

export const SEV_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical']
export const ORIGIN_ICON = { mail: IconMail, cloud: IconCloud, host: IconHost } as const
export const ORIGIN_CLASS = { mail: 'mail', cloud: 'm365', host: 'host' } as const
export const ORIGIN_LABEL = { mail: 'mailbox', cloud: 'Microsoft 365 / Entra', host: 'Windows host' } as const
export const TIE_LABEL: Record<StoryStep['tie']['kind'], string> = {
  flag: 'flagged',
  chain: 'phishing chain',
  session: 'same session',
  hop: 'same way in',
  process: 'process tree',
  address: 'same source',
  identity: 'same person',
}
export const CONFIDENCE_SEV: Record<Confidence, string> = { strong: 'ok', medium: 'medium', weak: 'info' }

export function spanText(ms: number): string {
  const m = ms / 60_000
  return m < 1 ? 'under a minute' : m < 90 ? `${Math.round(m)} min` : m < 48 * 60 ? `${(m / 60).toFixed(1)} h` : `${(m / 1440).toFixed(1)} d`
}
export const day = (ts: number) => fmtTs(ts, { date: true }).slice(0, 10)
/** What a story's score is made of, for its tooltip (the summary says it in a sentence). */
export const scoreTitle = ({ scoreParts: p }: Story) =>
  p ? `${p.runPoints} for its run in ATT&CK's order, ${p.otherPoints} for ${p.others} other technique(s), ${p.chainPoints} for a phishing chain` : undefined
