/**
 * How far a rule's finding can be taken as a detection. tools/measure_rules.py runs every event
 * rule on recorded attacks and on the logs of clean machines (rules/measures.json), and the
 * server attaches each measure to the rule it was taken on. A rule that fires on recordings of
 * what it looks for detects it; one that has never been seen to is a lead: its finding says
 * where to look, not what happened. How often a rule fires on clean machines says how much of
 * what it finds may be benign.
 */
import { fmtNum } from '../util/format'

export interface RuleMeasure {
  /** the rule's logic has changed since it was measured */
  changed?: boolean
  /** case settings it cannot run without: not measured */
  settings?: string[]
  /** a SigmaHQ rule with a regression sample: whether it fires on it */
  own?: boolean
  /** recordings of what it looks for: its own sample, a file reviewed as identifying it, one labelled with its technique */
  of?: number
  /** of those, the ones it fires on */
  hits?: number
  /** recordings it fires on at all */
  fires?: number
  /** on the logs of clean machines: its findings, the events they cover, the machines it fired on, the events it reads and the machines that log them */
  clean?: { findings: number; events: number; machines: number; scope: number; of: number }
}

export interface MeasureSources {
  version: number
  measured: string
  sources: {
    sigma?: { repo: string; sha: string; recordings: number }
    attackSamples?: { repo: string; sha: string; recordings: number }
    attackData?: { repo: string; sha: string; recordings: number; unreadable?: number; missing?: number }
    attackDataWindows?: { repo: string; sha: string; recordings: number; maxMb?: number; overSize?: number; missing?: number }
    evtxToMitre?: { repo: string; sha: string; recordings: number }
    baseline?: { repo: string; tag: string; machines: number; events: number }
  }
  /** the rules measured, and those seen to fire on a recording of what they look for */
  totals?: { rules: number; detect: number }
}

export type MeasureVerdict = 'detects' | 'misses' | 'lead' | 'changed' | 'settings' | 'custom' | 'unmeasured'

export interface MeasureReading {
  verdict: MeasureVerdict
  /** a word or two for a badge; '' when there is nothing to show */
  label: string
  /** what the recorded attacks show */
  attacks: string
  /** what the clean machines show; '' when the rule was not measured */
  clean: string
  /** it fired on the logs of a clean machine */
  noisy: boolean
  /** events of its findings on clean machines per 10,000 events it reads there */
  rate?: number
}

const plural = (n: number, one: string, many = `${one}s`) => (n === 1 ? one : many)

/** A rate per 10,000 events, to two significant figures. */
export function fmtRate(rate: number): string {
  if (rate === 0) return '0'
  if (rate < 0.01) return 'under 0.01'
  return rate < 10 ? String(Number(rate.toPrecision(2))) : fmtNum(Math.round(rate))
}

function cleanText(c: RuleMeasure['clean']): { text: string; noisy: boolean; rate?: number } {
  if (!c || !c.scope) return { text: 'No clean machine it was measured on logs what it reads, so how often it fires on benign activity is not known.', noisy: false }
  const rate = (c.events / c.scope) * 10_000
  if (!c.findings) return { text: `It never fired on the ${fmtNum(c.scope)} events of what it reads on ${fmtNum(c.of)} clean Windows ${plural(c.of, 'machine')}.`, noisy: false, rate }
  // a rule that matches every event it reads (a service installed, an audit policy changed) is a percentage, not a rate
  const share = rate >= 100 ? `${Math.round(rate / 100)}%` : `${fmtRate(rate)} per 10,000`
  return {
    text: `On clean Windows machines it fired ${fmtNum(c.findings)} ${plural(c.findings, 'time')}, on ${fmtNum(c.machines)} of ${fmtNum(c.of)}, matching ${fmtNum(c.events)} of the ${fmtNum(c.scope)} events of what it reads (${share}): benign activity matches it too.`,
    noisy: true,
    rate,
  }
}

/** What a rule's measure says, for a badge and in words. */
export function readMeasure(m: RuleMeasure | undefined, origin?: 'bundled' | 'pack' | 'custom'): MeasureReading {
  if (origin === 'custom') return { verdict: 'custom', label: 'your rule', attacks: 'Your own rule: it was not measured on recorded attacks.', clean: '', noisy: false }
  if (!m) return { verdict: 'unmeasured', label: '', attacks: 'This rule was not measured on recorded attacks.', clean: '', noisy: false }
  if (m.changed) return { verdict: 'changed', label: 'changed', attacks: 'The rule has changed since it was measured, and the measure was of its earlier form.', clean: '', noisy: false }
  if (m.settings?.length)
    return {
      verdict: 'settings',
      label: 'needs settings',
      attacks: `Not measured: it runs only once the case's ${m.settings.join(', ').replace(/_/g, ' ')} ${m.settings.length === 1 ? 'is' : 'are'} set, which recorded attacks do not have.`,
      clean: '',
      noisy: false,
    }
  const { text: clean, noisy, rate } = cleanText(m.clean)
  const of = m.of ?? 0
  const hits = m.hits ?? 0
  if (hits) {
    const own = m.own === true ? ', its own SigmaHQ test sample among them' : m.own === false ? ', though not on the SigmaHQ sample recorded for it' : ''
    return { verdict: 'detects', label: 'detects', attacks: `Fires on ${fmtNum(hits)} of ${fmtNum(of)} recorded ${plural(of, 'attack')} of what it looks for${own}.`, clean, noisy, rate }
  }
  if (m.own === false)
    return {
      verdict: 'misses',
      label: 'misses its sample',
      attacks: `Does not fire on the SigmaHQ sample recorded for it${of > 1 ? ` nor on the ${fmtNum(of - 1)} other ${plural(of - 1, 'recording')} of what it looks for` : ''}: as converted, it may not match what it looks for. Its findings are leads to check.`,
      clean,
      noisy,
      rate,
    }
  return {
    verdict: 'lead',
    label: 'lead',
    attacks: of
      ? `Fires on none of the ${fmtNum(of)} recorded ${plural(of, 'attack')} of what it looks for: its findings are leads to check, not detections.`
      : 'No recording of what it looks for was available to measure it on: its findings are leads to check, not detections.',
    clean,
    noisy,
    rate,
  }
}

/** A finding from a rule not shown to detect what it looks for. */
export const isLead = (r: MeasureReading) => r.verdict === 'lead' || r.verdict === 'misses'

/** What the rules were measured on, in a sentence. */
export function measuredOn(s: MeasureSources | null | undefined): string {
  if (!s?.sources) return ''
  const { sigma, attackSamples, attackData, attackDataWindows, evtxToMitre, baseline } = s.sources
  const recorded = [
    sigma?.recordings ? `${fmtNum(sigma.recordings)} SigmaHQ regression samples` : '',
    attackSamples?.recordings ? `${fmtNum(attackSamples.recordings)} EVTX-ATTACK-SAMPLES recordings` : '',
    attackData?.recordings ? `${fmtNum(attackData.recordings)} Microsoft 365 and Entra ID datasets of Splunk attack_data` : '',
    attackDataWindows?.recordings ? `${fmtNum(attackDataWindows.recordings)} Windows event-log datasets of Splunk attack_data` : '',
    evtxToMitre?.recordings ? `${fmtNum(evtxToMitre.recordings)} EVTX-to-MITRE-Attack recordings` : '',
  ].filter(Boolean)
  const list = recorded.length > 1 ? `${recorded.slice(0, -1).join(', ')} and ${recorded[recorded.length - 1]}` : (recorded[0] ?? '')
  const clean = baseline?.machines ? `, and on the logs of ${fmtNum(baseline.machines)} clean Windows machines of evtx-baseline ${baseline.tag} (${fmtNum(baseline.events)} events)` : ''
  return `Measured on ${s.measured}${list ? ` on ${list}` : ''}${clean}.`
}

/** How far a finding can be believed from its rule's measure (mirror of stories._PRECISION). */
const PRECISION = { detects: 1, unmeasured: 0.8, lead: 0.6, misses: 0.5 } as const

export interface RuleTrust {
  verdict: keyof typeof PRECISION
  noisy: boolean
  /** of the clean machines that log what it reads, the ones it fired on */
  machines?: number
  of?: number
  /** 0 to 1: what a finding of the rule weighs for its measure */
  precision: number
}

/**
 * How far a rule's findings can be believed, as the stories weigh them (mirror of
 * stories.measure_verdict): a rule seen to detect what it looks for, one never measured (its logic
 * changed since, it needs settings, it is the analyst's own), a lead, one that misses its own
 * sample. A rule that fired on the logs of clean machines loses a quarter, and half when it fired
 * on every one of them.
 */
export function ruleTrust(m: RuleMeasure | undefined): RuleTrust {
  const verdict: RuleTrust['verdict'] = !m || m.changed || m.settings?.length ? 'unmeasured' : m.hits ? 'detects' : m.own === false ? 'misses' : 'lead'
  const c = m?.clean
  let precision: number = PRECISION[verdict]
  if (!c?.findings) return { verdict, noisy: false, precision }
  const share = c.of ? Math.min(1, (c.machines ?? 0) / c.of) : 1
  precision *= 0.75 - 0.25 * share
  return { verdict, noisy: true, machines: c.machines, of: c.of, precision: Math.round(precision * 1000) / 1000 }
}
