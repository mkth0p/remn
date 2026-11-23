import type { Rule } from './engine'

/** The rule ids of Hayabusa's detections (services/analysis/hayabusa.py): its own rules, not REMN's. */
const HAYABUSA = 'engine:hayabusa:'

/**
 * What the interface and the exports say of the author of a Hayabusa detection. REMN reads
 * Hayabusa's verbose profile, whose output has no RuleAuthor column, so the author of the rule is
 * not known; a blank would read as a rule that names none.
 */
export const HAYABUSA_NO_AUTHOR = 'not recorded by Hayabusa, whose output REMN reads does not carry it'

/**
 * The author each rule names, by rule id. A rule converted from SigmaHQ keeps its Sigma header,
 * author included; REMN's own rules name none.
 */
export function ruleAuthors(rules: Iterable<Rule>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const rule of rules) {
    const sigma = 'sigma' in rule ? rule.sigma : undefined
    const author = sigma && typeof sigma === 'object' && 'author' in sigma ? sigma.author : undefined
    if (typeof author === 'string' && author.trim()) out[rule.id] = author.trim()
  }
  return out
}

/**
 * The author to give beside a finding of this rule: the one its rule names, that Hayabusa did not
 * record one (in the words given), or nothing for a rule that names none.
 */
export function ruleAuthorOf(ruleId: string, authors: Record<string, string>, noAuthor: string = HAYABUSA_NO_AUTHOR): string {
  return authors[ruleId] ?? (ruleId.startsWith(HAYABUSA) ? noAuthor : '')
}
