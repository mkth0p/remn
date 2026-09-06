/** Link hygiene for values that come from data (reputation providers, pack manifests, rule ids). */

/** Only http(s) URLs are ever placed in an href; anything else (javascript:, data:, relative junk) yields undefined. */
export function safeHref(url: string | null | undefined): string | undefined {
  if (!url) return undefined
  try {
    const u = new URL(url)
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : undefined
  } catch {
    return undefined
  }
}

const ATTACK_ID = /^T\d{4}(?:\.\d{3})?$/

/** attack.mitre.org link for a technique id, or undefined when the id is not shaped like one. */
export function attackHref(id: string): string | undefined {
  return ATTACK_ID.test(id) ? `https://attack.mitre.org/techniques/${id.replace('.', '/')}/` : undefined
}
