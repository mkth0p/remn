import type { Condition } from '../rules/filter'

/**
 * Toggle one facet value in a filter's conditions. Values picked in the same facet are
 * alternatives: one value is `eq`, several are `in`, and picking a picked value again takes it out.
 * Excluded values combine the same way (`ne`, then `nin`). The facets used to append a new `eq` for
 * every click, so a third user (Events) or a second sender (Mails) asked for rows equal to two
 * different values at once, and matched nothing.
 */
export function toggleFacetValue(conds: Condition[], field: string, value: string | number, negate = false): Condition[] {
  const single = negate ? 'ne' : 'eq'
  const multi = negate ? 'nin' : 'in'
  const same = (a: unknown) => String(a).toLowerCase() === String(value).toLowerCase()
  const idx = conds.findIndex((c) => c.field === field && (c.op === single || c.op === multi))
  if (idx < 0) return [...conds, { field, op: single, value }]
  const current = conds[idx]
  const values = Array.isArray(current.value) ? current.value : [current.value]
  const next = values.some(same) ? values.filter((v) => !same(v)) : [...values, value]
  const replaced: Condition | null = next.length === 0 ? null : next.length === 1 ? { field, op: single, value: next[0] } : { field, op: multi, value: next }
  return replaced ? conds.map((c, i) => (i === idx ? replaced : c)) : conds.filter((_, i) => i !== idx)
}
