import { toast } from '../../state/store'

/** The report in its own tab: the browser's own print-to-PDF, or to keep it open next to the case. */
export function openReport(html: string): void {
  const url = URL.createObjectURL(new Blob([html], { type: 'text/html' }))
  const w = window.open(url, '_blank')
  if (w) w.opener = null
  else toast('err', 'the browser blocked the new tab: allow pop-ups for this site, or use "download HTML"', 0)
  setTimeout(() => URL.revokeObjectURL(url), 120_000)
}

// the report is built from case data: it prints from a frame that runs no script (so nothing in it can
// reach the case database) but keeps the app's origin, which the browser needs before it lets the page
// call print() on the frame; a sandbox without allow-same-origin makes that call a SecurityError
export function printReport(html: string): void {
  const frame = document.createElement('iframe')
  frame.setAttribute('sandbox', 'allow-same-origin allow-modals')
  // laid out at full size (a zero-size frame prints blank in some browsers) but invisible and inert
  frame.style.cssText = 'position:fixed;inset:0;width:100vw;height:100vh;border:0;opacity:0;pointer-events:none;z-index:-1'
  frame.srcdoc = html
  frame.onload = () => {
    const win = frame.contentWindow
    try {
      win?.addEventListener('afterprint', () => frame.remove())
      win?.focus()
      win?.print()
    } catch (e) {
      frame.remove()
      toast('err', `the browser refused to print from the page (${(e as Error).message}); the report opens in a new tab, print it from there`, 0)
      openReport(html)
      return
    }
    setTimeout(() => frame.remove(), 120_000)
  }
  document.body.appendChild(frame)
}
