// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest'
import { focusPageHeading } from './viewFocus'

afterEach(() => {
  document.body.innerHTML = ''
})

/** The shell: a navigation button that had the focus, and the page area. */
function shell(page = '') {
  document.body.innerHTML = `<nav><button>Findings</button></nav><main>${page}</main>`
  const nav = document.querySelector('button')!
  nav.focus()
  return { nav, main: document.querySelector('main')! }
}
const settle = (ms = 0) => new Promise((r) => setTimeout(r, ms))

describe('focusPageHeading', () => {
  it("moves the focus to the page's heading, which only takes it from a script", () => {
    const { main } = shell('<div><h1>Findings</h1><button>run</button></div>')
    focusPageHeading(main)
    const h1 = main.querySelector('h1')!
    expect(document.activeElement).toBe(h1)
    expect(h1.getAttribute('tabindex')).toBe('-1')
    h1.blur()
    expect(h1.hasAttribute('tabindex')).toBe(false)
  })

  it('waits for a heading the page draws once its script or data has arrived', async () => {
    const { main } = shell('<div class="empty">loading the page…</div>')
    focusPageHeading(main, 1000)
    await settle()
    main.innerHTML = '<div><h1>Review</h1></div>'
    await settle()
    expect(document.activeElement).toBe(main.querySelector('h1'))
  })

  it('moves the focus to the page area when the page has no heading', async () => {
    const { main } = shell('<div>rows</div>')
    focusPageHeading(main, 20)
    await settle(40)
    expect(document.activeElement).toBe(main)
    main.blur()
    expect(main.hasAttribute('tabindex')).toBe(false)
  })

  it('leaves the focus where the person put it in the meantime', async () => {
    const { main } = shell('<div><input aria-label="search"></div>')
    focusPageHeading(main, 1000)
    main.querySelector('input')!.focus()
    main.insertAdjacentHTML('beforeend', '<h1>Events</h1>')
    await settle()
    expect(document.activeElement).toBe(main.querySelector('input'))
  })

  it('does nothing once cancelled, as when the page changes again', async () => {
    const { nav, main } = shell()
    const cancel = focusPageHeading(main, 20)
    cancel()
    main.innerHTML = '<h1>Graph</h1>'
    await settle(40)
    expect(document.activeElement).toBe(nav)
  })

  it('moves the focus from a control the old page took away with it', async () => {
    const { main } = shell('<button id="old">open the rows</button>')
    main.querySelector<HTMLButtonElement>('#old')!.focus()
    const cancel = focusPageHeading(main, 1000)
    main.innerHTML = '<h1>Events</h1>'
    await settle()
    expect(document.activeElement).toBe(main.querySelector('h1'))
    cancel()
  })
})
