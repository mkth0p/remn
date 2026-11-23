// @vitest-environment jsdom
import { describe, expect, it } from 'vitest'
import { sanitizeMailHtml } from './mailHtml'

/** The body of the page the mail's HTML is shown in, parsed back. */
function shown(html: string): { page: string; body: HTMLElement } {
  const page = sanitizeMailHtml(html)
  return { page, body: new DOMParser().parseFromString(page, 'text/html').body }
}

describe('sanitizeMailHtml', () => {
  it('keeps the text and plain markup of a message', () => {
    const { body } = shown('<p>Dear <b>customer</b>,</p><table><tr><td>invoice 42</td></tr></table>')
    expect(body.querySelector('b')?.textContent).toBe('customer')
    expect(body.querySelector('td')?.textContent).toBe('invoice 42')
  })

  it('removes scripts, frames, forms, embedded objects, media and style sheets', () => {
    const { body } = shown(
      [
        '<script>alert(1)</script>',
        '<iframe src="https://example.test/frame"></iframe>',
        '<form action="https://example.test/collect"><input name="password"><button>log in</button></form>',
        '<object data="x.swf"></object><embed src="x.swf">',
        '<video src="a.mp4"></video><audio src="a.mp3"></audio>',
        '<svg><circle r="1"></circle></svg><math><mi>x</mi></math>',
        '<style>body{display:none}</style><link rel="stylesheet" href="https://example.test/s.css">',
        '<meta http-equiv="refresh" content="0;url=https://example.test"><base href="https://example.test/">',
        '<p>kept</p>',
      ].join(''),
    )
    for (const tag of ['script', 'iframe', 'form', 'input', 'button', 'object', 'embed', 'video', 'audio', 'svg', 'math', 'style', 'link', 'meta', 'base']) expect(body.querySelector(tag)).toBeNull()
    expect(body.textContent).toContain('kept')
    expect(body.textContent).not.toContain('alert(1)')
  })

  it('removes event handlers, inline styles and the attributes that fetch or submit', () => {
    const { body } = shown(
      '<div onclick="steal()" onmouseover="steal()" style="position:fixed" background="https://example.test/bg.png">x</div><table background="https://example.test/t.png"><tr><td>y</td></tr></table>',
    )
    const div = body.querySelector('div')!
    for (const name of ['onclick', 'onmouseover', 'style', 'background']) expect(div.hasAttribute(name)).toBe(false)
    expect(body.querySelector('table')!.hasAttribute('background')).toBe(false)
  })

  it('blocks every image and names what it would have loaded', () => {
    const { body } = shown('<img src="https://tracker.example.test/pixel.gif?id=1" srcset="https://example.test/a.png 2x" onerror="steal()" alt="logo">')
    const img = body.querySelector('img')!
    expect(img.hasAttribute('src')).toBe(false)
    expect(img.hasAttribute('srcset')).toBe(false)
    expect(img.hasAttribute('onerror')).toBe(false)
    expect(img.getAttribute('alt')).toBe('[image blocked: https://tracker.example.test/pixel.gif?id=1]')
  })

  it('makes links go nowhere and shows where they pointed', () => {
    const { body } = shown('<a href="https://login.example.test/reset">reset your password</a><a href="javascript:alert(1)">run</a>')
    const [real, script] = [...body.querySelectorAll('a')]
    expect(real.getAttribute('href')).toBe('#')
    expect(real.getAttribute('title')).toBe('https://login.example.test/reset')
    expect(script.getAttribute('href')).toBe('#')
    expect(script.getAttribute('title')).toBe('')
  })

  it('wraps the message in a page whose policy loads nothing from outside', () => {
    const { page } = shown('<p>x</p>')
    expect(page.startsWith('<!doctype html>')).toBe(true)
    expect(page).toContain(`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;">`)
  })
})
