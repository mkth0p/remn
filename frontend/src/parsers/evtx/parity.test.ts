import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { gunzipSync } from 'node:zlib'
import { describe, expect, it } from 'vitest'
import { EvtxDecoder } from './decoder'
import { Stats } from './ledger'
import { dumps } from './py'
import { bytesSource, readEvtx } from './readEvtx'

/**
 * Row parity with the server: the golden corpus froze a digest of every row the server's parser
 * makes of the synthetic lab (tools/golden_corpus.py), each row written as canonical JSON (sorted
 * keys, no spaces). The browser path has to give the same digest for every row.
 *
 * Defender.evtx of the lab is kept in tests/fixtures/evtx, so one file is checked on every run. The
 * whole lab is checked when REMN_EVTX_LAB names a generated quick-start folder:
 *   python samples/synthetic/make_linked_lab.py --quick-only --out /tmp/lab
 *   REMN_EVTX_LAB=/tmp/lab/quick-start npx vitest run src/parsers/evtx
 */
const ROOT = join(__dirname, '../../../..')
const golden = JSON.parse(gunzipSync(readFileSync(join(ROOT, 'tests/fixtures/golden/lab-quick-start.json.gz'))).toString('utf-8')) as {
  files: Record<string, { input: string; rows: number; sha256: string; rowDigests: string[] }>
}
const wasm = readFileSync(join(__dirname, 'evtx.wasm'))

async function digests(bytes: Uint8Array, name: string) {
  const decoder = await EvtxDecoder.load(wasm)
  const stats = new Stats()
  const out: string[] = []
  const whole = createHash('sha256')
  for await (const row of readEvtx(bytesSource(bytes), decoder, { sourceFile: name, stats })) {
    const line = dumps(row, true) + '\n'
    whole.update(line, 'utf-8')
    out.push(createHash('sha256').update(line, 'utf-8').digest('hex').slice(0, 16))
  }
  return { rows: out, whole: whole.digest('hex'), stats }
}

async function check(path: string, name: string) {
  const bytes = new Uint8Array(readFileSync(path))
  const frozen = golden.files[name]
  expect(createHash('sha256').update(bytes).digest('hex'), `${name} is not the lab file the corpus froze`).toBe(frozen.input)
  const got = await digests(bytes, name)
  const first = got.rows.findIndex((d, i) => d !== frozen.rowDigests[i])
  expect({ rows: got.rows.length, firstDifferentRow: first }).toEqual({ rows: frozen.rows, firstDifferentRow: -1 })
  expect(got.whole).toBe(frozen.sha256)
  return got
}

describe('EVTX parsed in the browser', () => {
  it('gives the rows the server gives for the lab Defender log', async () => {
    const got = await check(join(ROOT, 'tests/fixtures/evtx/lab-Defender.evtx'), 'Defender.evtx')
    const seq = got.stats.toDict().sequences as Record<string, unknown>[]
    expect(seq[0]).toMatchObject({ file: 'Defender.evtx', count: 10, missing: 0, checksums: { chunks: 1, fileHeader: true } })
    expect(seq[0].checksums).not.toHaveProperty('badData')
  })

  const lab = process.env.REMN_EVTX_LAB
  it.runIf(!!lab && existsSync(lab!))(
    'gives the rows the server gives for every event log of the lab',
    async () => {
      for (const name of Object.keys(golden.files).filter((n) => n.endsWith('.evtx'))) await check(join(lab!, name), name)
    },
    300_000,
  )
})
