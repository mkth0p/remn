import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { expect, it } from 'vitest'
import { EvtxDecoder } from './decoder'
import { BigInteger } from './py'
import { bytesSource, readEvtx } from './readEvtx'

/**
 * EVTX-ATTACK-SAMPLES through the browser path: every file parsed here gives, row for row, the rows
 * the server gave tools/evtx_attack_samples.py, as the case stores them, so the rules find the same
 * (src/rules/attackSamples.test.ts pins the engines to each other on those rows). Runs when
 * EVTX_ATTACK_OUT is that tool's output and EVTX_ATTACK_LIBRARY the library it read (CI does this).
 */
const OUT = process.env.EVTX_ATTACK_OUT ?? ''
const LIBRARY = process.env.EVTX_ATTACK_LIBRARY ?? ''

// what a stored row holds: numbers past 2^53 as the double JSON.parse makes of them, keys sorted
function canonical(v: unknown): unknown {
  if (v instanceof BigInteger) return Number(v.digits)
  if (Array.isArray(v)) return v.map(canonical)
  if (v && typeof v === 'object')
    return Object.fromEntries(
      Object.keys(v)
        .sort()
        .map((k) => [k, canonical((v as Record<string, unknown>)[k])]),
    )
  return v
}

it.skipIf(!OUT || !LIBRARY || !existsSync(join(OUT, 'index.json')))(
  'parses every attack sample into the rows the server makes of it',
  async () => {
    const decoder = await EvtxDecoder.load(readFileSync(join(__dirname, 'evtx.wasm')))
    const index = JSON.parse(readFileSync(join(OUT, 'index.json'), 'utf-8')) as { i: number; file: string; rows: number }[]
    const diffs: string[] = []
    let rows = 0
    for (const { i, file } of index) {
      const want = readFileSync(join(OUT, 'rows', `${i}.ndjson`), 'utf-8')
        .split('\n')
        .filter(Boolean)
        .map((l) => {
          const { id: _id, caseId: _c, evidenceId: _e, ...r } = JSON.parse(l) as Record<string, unknown>
          return JSON.stringify(canonical(r))
        })
      const name = file.split('/').pop()!
      const got: string[] = []
      for await (const r of readEvtx(bytesSource(new Uint8Array(readFileSync(join(LIBRARY, file)))), decoder, { sourceFile: name })) got.push(JSON.stringify(canonical(r)))
      rows += got.length
      const first = got.findIndex((g, n) => g !== want[n])
      if (got.length !== want.length || first >= 0) diffs.push(`${file}: ${got.length} rows here, ${want.length} on the server; first difference at row ${first}`)
    }
    expect(diffs, diffs.slice(0, 20).join('\n')).toEqual([])
    expect(rows).toBeGreaterThan(30_000)
  },
  1_800_000,
)
