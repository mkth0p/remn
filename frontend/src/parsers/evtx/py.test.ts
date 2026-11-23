import { describe, expect, it } from 'vitest'
import { BigInteger, dumps, inValues, isDict, or, parseDecoded, pyInt, pyLen, pySlice, pyStr, strip, truthy } from './py'

describe('parseDecoded', () => {
  it('keeps the decoder big integers exact and leaves other objects alone', () => {
    const out = parseDecoded('{"a":{"$big":"18446744073709551615"},"b":{"$big":"1","c":2},"d":[{"$big":"7"}],"e":{"$big":3}}') as Record<string, unknown>
    expect(out.a).toBeInstanceOf(BigInteger)
    expect(String(out.a)).toBe('18446744073709551615')
    expect(out.b).toEqual({ $big: '1', c: 2 })
    expect((out.d as unknown[])[0]).toBeInstanceOf(BigInteger)
    expect(out.e).toEqual({ $big: 3 })
  })
})

describe('truthiness', () => {
  it('follows Python for the values JSON holds', () => {
    for (const v of [null, undefined, false, 0, '', [], {}]) expect(truthy(v)).toBe(false)
    for (const v of [true, 1, -1, 'a', ' ', [0], { a: null }, new BigInteger('0')]) expect(truthy(v)).toBe(true)
  })

  it('gives the first value when it is truthy and the second otherwise, as `or` does', () => {
    expect(or('a', 'b')).toBe('a')
    expect(or('', 'b')).toBe('b')
    expect(or(0, null)).toBeNull()
    expect(or([], 'empty')).toBe('empty')
  })

  it('counts only plain objects as dicts', () => {
    expect(isDict({})).toBe(true)
    expect(isDict([])).toBe(false)
    expect(isDict(null)).toBe(false)
    expect(isDict(new BigInteger('1'))).toBe(false)
  })
})

describe('strip', () => {
  it('removes the whitespace str.isspace() accepts from both ends only', () => {
    expect(strip(' \t\n\x0b\x0c\r\x1c\x85\xa0 　a b   ')).toBe('a b')
    expect(strip('a  b')).toBe('a  b')
    expect(strip('')).toBe('')
  })

  it('keeps the zero width space, which Python does not count as whitespace', () => {
    expect(strip('​a​')).toBe('​a​')
  })

  it('strips a long run of spaces inside a text in linear time', () => {
    const text = 'a' + ' '.repeat(100_000) + 'b'
    const start = performance.now()
    expect(strip(text)).toBe(text)
    expect(performance.now() - start).toBeLessThan(1000)
  })
})

describe('length and slicing by code point', () => {
  it('counts a surrogate pair as one character and a lone surrogate as one', () => {
    expect(pyLen('abc')).toBe(3)
    expect(pyLen('a\u{1F600}b')).toBe(3)
    expect(pyLen('\ud800x')).toBe(2)
    expect(pyLen('x\ud800')).toBe(2)
  })

  it('never cuts a surrogate pair in half', () => {
    expect(pySlice('\u{1F600}\u{1F600}\u{1F600}', 2)).toBe('\u{1F600}\u{1F600}')
    expect(pySlice('ab\u{1F600}c', 3)).toBe('ab\u{1F600}')
    expect(pySlice('abc', 5)).toBe('abc')
    expect(pySlice('abcdef', 0)).toBe('')
    expect(pySlice('\ud800abcdef', 2)).toBe('\ud800a')
  })
})

describe('dumps', () => {
  it('writes compact JSON without escaping non-ASCII text', () => {
    expect(dumps({ b: 'é', a: [1, true, null, undefined] })).toBe('{"b":"é","a":[1,true,null,null]}')
  })

  it('writes big integers as bare digits and non-finite numbers as Python does', () => {
    expect(dumps(new BigInteger('123456789012345678901'))).toBe('123456789012345678901')
    expect(dumps(NaN)).toBe('NaN')
    expect(dumps(Infinity)).toBe('Infinity')
    expect(dumps(-Infinity)).toBe('-Infinity')
  })

  it('sorts keys by code point when asked, nested objects included', () => {
    expect(dumps({ b: 1, a: { d: 1, c: 2 } }, true)).toBe('{"a":{"c":2,"d":1},"b":1}')
    // U+FF21 sorts before U+1F600 by code point, after it by UTF-16 unit
    expect(dumps({ '\u{1F600}': 1, Ａ: 2 }, true)).toBe('{"Ａ":2,"\u{1F600}":1}')
    expect(dumps({ ab: 1, a: 2 }, true)).toBe('{"a":2,"ab":1}')
  })
})

describe('pyStr', () => {
  it('writes scalars as str() does', () => {
    expect(pyStr(null)).toBe('None')
    expect(pyStr(undefined)).toBe('None')
    expect(pyStr(true)).toBe('True')
    expect(pyStr(false)).toBe('False')
    expect(pyStr('text')).toBe('text')
    expect(pyStr(42)).toBe('42')
    expect(pyStr(new BigInteger('99999999999999999999'))).toBe('99999999999999999999')
  })

  it('writes lists and dicts with the repr of their items', () => {
    expect(pyStr(['a', 1, null, true, false, { k: 'v' }])).toBe("['a', 1, None, True, False, {'k': 'v'}]")
    expect(pyStr({ a: [new BigInteger('5')] })).toBe("{'a': [5]}")
  })

  it('quotes and escapes strings inside a container as repr() does', () => {
    expect(pyStr(["it's"])).toBe('["it\'s"]')
    expect(pyStr(['say "hi" it\'s'])).toBe("['say \"hi\" it\\'s']")
    expect(pyStr(['a\\b\n\r\t\x01\x7f'])).toBe("['a\\\\b\\n\\r\\t\\x01\\x7f']")
  })
})

describe('pyInt', () => {
  it('reads decimal text with a sign, underscores and leading zeros', () => {
    expect(pyInt(' 42 ', 10)).toBe(42)
    expect(pyInt('-7', 10)).toBe(-7)
    expect(pyInt('+007', 10)).toBe(7)
    expect(pyInt('1_000', 10)).toBe(1000)
  })

  it('refuses what int() refuses', () => {
    for (const s of ['', '1.5', '1__0', '_1', '1_', '0x10', 'ten']) expect(pyInt(s, 10)).toBeNull()
    for (const s of ['', 'g', '0x', '0x_']) expect(pyInt(s, 16)).toBeNull()
  })

  it('reads hexadecimal text with or without the prefix', () => {
    expect(pyInt('0x1F', 16)).toBe(31)
    expect(pyInt('ff', 16)).toBe(255)
    expect(pyInt('-0X10', 16)).toBe(-16)
    expect(pyInt('0x_ff', 16)).toBe(255)
  })

  it('keeps integers past 2^53 as their digits', () => {
    const big = pyInt('0xFFFFFFFFFFFFFFFF', 16)
    expect(big).toBeInstanceOf(BigInteger)
    expect(String(big)).toBe('18446744073709551615')
    expect(String(pyInt('-9007199254740993', 10))).toBe('-9007199254740993')
    expect(pyInt('9007199254740991', 10)).toBe(9007199254740991)
  })
})

describe('inValues', () => {
  it('compares as Python equality, with None matching a missing value', () => {
    expect(inValues(null, [null, '-'])).toBe(true)
    expect(inValues(undefined, [null])).toBe(true)
    expect(inValues('-', [null, '-'])).toBe(true)
    expect(inValues('', [null, '-'])).toBe(false)
    expect(inValues(0, ['0'])).toBe(false)
  })
})
