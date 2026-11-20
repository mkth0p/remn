/**
 * Where the focus goes when another page opens: to the page's heading, so a screen reader says
 * where the person now is and the next Tab starts in the page, or to the page area itself when the
 * page has no heading. A page's script and data can arrive after the address changed, so its
 * heading is waited for; the focus is not moved when the person has put it somewhere else since.
 */

// long enough for a page's script and first data on a slow machine, short enough to still be the answer to the click
const WAIT_MS = 2000

/** Focus `el` from a script only: the tabindex that makes it focusable goes again once it loses the focus. */
function focusOnce(el: HTMLElement): void {
  if (!el.hasAttribute('tabindex')) {
    el.setAttribute('tabindex', '-1')
    el.addEventListener('blur', () => el.removeAttribute('tabindex'), { once: true })
  }
  el.focus({ preventScroll: true })
}

/** Move the focus to the first heading in `page` now or once it appears; returns a function that stops waiting. */
export function focusPageHeading(page: HTMLElement, wait = WAIT_MS): () => void {
  const start = document.activeElement
  // the focus is still where the navigation left it, or on nothing because the old page took it away
  const untouched = () => {
    const now = document.activeElement
    return now === start || now === null || now === document.body
  }
  const heading = () => page.querySelector<HTMLElement>('h1')
  let done = false
  const finish = () => {
    done = true
    observer.disconnect()
    clearTimeout(timer)
  }
  const land = (el: HTMLElement) => {
    finish()
    if (untouched()) focusOnce(el)
  }
  const observer = new MutationObserver(() => {
    const h = heading()
    if (h) land(h)
  })
  // the body is no place to land: without a heading there, the focus stays where it is
  const timer = setTimeout(() => (page === document.body ? finish() : land(page)), wait)
  const now = heading()
  if (now) land(now)
  else observer.observe(page, { childList: true, subtree: true })
  return () => {
    if (!done) finish()
  }
}
