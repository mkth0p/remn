import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { expect, it } from 'vitest'
import { flatten } from './flatten'
import type { Json } from './py'

// the cases tests/backend/test_evtx.py runs through the server's parser
const CASES = JSON.parse(readFileSync(join(__dirname, '../../../../tests/fixtures/evtx/product-fields.json'), 'utf-8')) as { name: string; event: Json; expect: Record<string, unknown> }[]

it.each(CASES.map((c) => [c.name, c] as const))('%s: SQL audit and sshd lines give who and from where', (_name, c) => {
  const row = flatten(c.event, null, false)
  expect(Object.fromEntries(Object.keys(c.expect).map((k) => [k, row[k] ?? null]))).toEqual(c.expect)
})
