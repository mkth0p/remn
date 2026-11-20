import { describe, expect, it } from 'vitest'
import { EN, LOGO_MAX_BYTES, logoImage, reportText } from './reportText'

// invented images: a 4 by 2 pixel PNG and the header of a 20 by 10 pixel JPEG
const PNG_4X2 = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAQAAAACCAIAAADwyuo0AAAAEElEQVR4nGP4z8AARwzIHABvqgf5gNwAKAAAAABJRU5ErkJggg=='
const JPEG_20X10 = 'data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/wAARCAAKABQDASIAAhEBAxEB/9k='

describe('the report dictionaries', () => {
  it('writes numbers, times and sizes the way each language writes them', () => {
    const fr = reportText('fr')
    const at = Date.UTC(2026, 2, 1, 8, 5, 9)
    expect(EN.num(12345)).toBe('12,345')
    expect(fr.num(12345)).toBe((12345).toLocaleString('fr-FR'))
    expect(fr.num(12345)).not.toContain(',')
    expect(EN.ts(at)).toBe('2026-03-01 08:05:09Z')
    expect(fr.ts(at)).toBe('01/03/2026 08:05:09 UTC')
    expect(EN.bytes(1536)).toBe('1.50 KB')
    expect(fr.bytes(1536)).toBe('1,50 Ko')
    expect(fr.bytes(10)).toBe('10 o')
    expect(fr.day('2026-03-09')).toBe('09/03/2026')
    expect(EN.day('2026-03-09')).toBe('2026-03-09')
    // what the analyst typed that is not a date is printed as typed
    expect(fr.day('mi-mars')).toBe('mi-mars')
  })

  it('takes the singular in French for zero and one, as French does', () => {
    const fr = reportText('fr')
    expect(fr.verdict.pendingDetail(0)).toContain('0 élément sans')
    expect(fr.verdict.pendingDetail(1)).toContain('1 élément sans')
    expect(fr.verdict.pendingDetail(2)).toContain('2 éléments sans')
    expect(EN.verdict.pendingDetail(0)).toContain('0 items')
  })

  it('falls back to English for a language it does not have', () => {
    expect(reportText('de')).toBe(EN)
    expect(reportText(undefined)).toBe(EN)
    expect(reportText('fr').lang).toBe('fr')
  })
})

describe('the logo', () => {
  it('takes a PNG or a JPEG with the size the image states', () => {
    expect(logoImage(PNG_4X2)).toMatchObject({ mime: 'image/png', ext: 'png', width: 4, height: 2 })
    expect(logoImage(JPEG_20X10)).toMatchObject({ mime: 'image/jpeg', ext: 'jpeg', width: 20, height: 10 })
  })

  it('refuses what is not the image its type says, another type, and a file over the cap', () => {
    expect(logoImage(PNG_4X2.replace('image/png', 'image/jpeg'))).toBeNull()
    expect(logoImage('data:image/svg+xml;base64,PHN2Zy8+')).toBeNull()
    expect(logoImage(`data:image/png;base64,${btoa('not an image at all')}`)).toBeNull()
    expect(logoImage('javascript:alert(1)')).toBeNull()
    expect(logoImage(42)).toBeNull()
    // a PNG header followed by more bytes than the cap allows
    const big = new Uint8Array(LOGO_MAX_BYTES + 1)
    big.set(Uint8Array.from(atob(PNG_4X2.split(',')[1]), (c) => c.charCodeAt(0)))
    let bin = ''
    for (const b of big) bin += String.fromCharCode(b)
    expect(logoImage(`data:image/png;base64,${btoa(bin)}`)).toBeNull()
  })
})
