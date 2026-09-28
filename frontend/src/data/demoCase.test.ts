import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { gunzipSync, gzipSync } from 'node:zlib'
import { expect, it, vi } from 'vitest'
import { defaultSettings, getDb, RemnDB, setDb } from '../db/schema'
import { DEMO_NAME, demoBundleFile, openDemoCase } from './demoCase'

const BUNDLE = path.resolve(__dirname, '../../public/demo/northstar-lab.remn.ndjson.gz')

it('the committed demo case is a whole, verified bundle of the lab and its five chains', () => {
  const text = gunzipSync(readFileSync(BUNDLE)).toString('utf8')
  const lines = text.split('\n').filter(Boolean)
  const header = JSON.parse(lines[0])
  expect(header).toMatchObject({ format: 'remn-case', version: 2 })
  // the checksum the restore verifies, over every line before it
  const last = JSON.parse(lines[lines.length - 1])
  const body = lines
    .slice(0, -1)
    .map((l) => l + '\n')
    .join('')
  expect(last.sha256).toBe(createHash('sha256').update(body).digest('hex'))
  const count: Record<string, number> = {}
  let chains: { severity: string; identity: string }[] = []
  for (const line of lines.slice(1, -1)) {
    const { table, row } = JSON.parse(line)
    count[table] = (count[table] ?? 0) + 1
    if (table === 'kv' && row.key === `chains-${header.case.id}`) chains = row.value.chains
  }
  expect(count.events).toBe(14_000)
  expect(count.mails).toBe(1_000)
  expect(count.evidence).toBe(8)
  expect(count.findings).toBeGreaterThan(0)
  expect(chains.map((c) => c.severity)).toEqual(['critical', 'critical', 'critical', 'critical', 'critical'])
})

it('decompresses the bundle here, or takes it as it is when the server already did', async () => {
  const plain = '{"format":"remn-case"}\n'
  for (const bytes of [gzipSync(plain), Buffer.from(plain)]) {
    const file = await demoBundleFile(new Response(new Uint8Array(bytes)))
    expect(await file.text()).toBe(plain)
  }
})

it('reopens the demo case this browser has, and restores it again when its evidence is gone', async () => {
  const db = new RemnDB(`demo-${Math.random()}`)
  setDb(db)
  const fetch = vi.fn(async () => new Response('', { status: 404 }))
  vi.stubGlobal('fetch', fetch)
  try {
    const whole = await db.cases.add({ name: DEMO_NAME, createdAt: 1, updatedAt: 1, storage: 'browser', settings: defaultSettings() })
    await db.evidence.add({ caseId: whole, name: 'lab.evtx', kind: 'evtx', status: 'done', count: 1 } as never)
    expect((await openDemoCase()).id).toBe(whole)
    expect(fetch).not.toHaveBeenCalled()
    await db.evidence.where('caseId').equals(whole).delete()
    await expect(openDemoCase()).rejects.toThrow('not on this server')
    expect(await getDb().cases.get(whole)).toBeUndefined()
  } finally {
    vi.unstubAllGlobals()
    await db.delete()
    setDb(null)
  }
})
