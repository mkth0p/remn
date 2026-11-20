import DOMPurify from 'dompurify'

/**
 * A mail's HTML as a page that can be shown without running or fetching anything: scripts, frames,
 * forms, media and styles removed, every image blocked with its address in its place, every link
 * pointing nowhere with its address in its title, and a policy that loads nothing from outside.
 */
export function sanitizeMailHtml(html: string): string {
  const clean = DOMPurify.sanitize(html, {
    FORBID_TAGS: ['script', 'iframe', 'object', 'embed', 'form', 'input', 'button', 'video', 'audio', 'link', 'meta', 'base', 'svg', 'math', 'style'],
    FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'style', 'srcset', 'background', 'action', 'formaction', 'poster'],
    ALLOW_UNKNOWN_PROTOCOLS: false,
  })
  const doc = new DOMParser().parseFromString(clean, 'text/html')
  doc.querySelectorAll('img').forEach((img) => {
    const src = img.getAttribute('src') || ''
    img.setAttribute('alt', `[image blocked: ${src.slice(0, 80)}]`)
    img.removeAttribute('src')
    img.setAttribute('style', 'border:1px dashed #999;padding:4px;font:11px monospace;color:#666')
  })
  doc.querySelectorAll('a').forEach((a) => {
    const href = a.getAttribute('href') || ''
    a.setAttribute('title', href)
    a.setAttribute('href', '#')
    a.setAttribute('style', 'color:#0645ad;text-decoration:underline dotted;cursor:not-allowed')
  })
  return `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;"><style>body{font:13px/1.5 Arial,sans-serif;color:#111;background:#fff;padding:12px;margin:0;word-break:break-word}</style></head><body>${doc.body.innerHTML}</body></html>`
}
