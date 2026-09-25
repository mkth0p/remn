import { defaultSettings, getDb, type Case } from '../db/schema'
import { restoreCaseBundle } from './caseBundle'

/**
 * The demo case: the synthetic linked lab (samples/synthetic/make_linked_lab.py), read by this app
 * in browser-only mode, its rules run and its chains built, then exported as a case bundle by
 * e2e/demo-bundle.spec.ts (npm run demo:bundle). Opening it restores that bundle in this browser:
 * nothing is uploaded and nothing is parsed, so it shows what REMN does before anyone trusts it
 * with evidence of their own.
 */
export const DEMO_URL = '/demo/northstar-lab.remn.ndjson.gz'
export const DEMO_NAME = 'Northstar lab (synthetic demo)'

/** The bundle as a file, decompressed here unless the server already did (Content-Encoding). */
export async function demoBundleFile(resp: Response): Promise<File> {
  const bytes = new Uint8Array(await resp.arrayBuffer())
  const gzip = bytes[0] === 0x1f && bytes[1] === 0x8b
  const body = gzip ? await new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'))).blob() : new Blob([bytes])
  return new File([body], 'northstar-lab.remn.ndjson')
}

/** Restore the demo case, or find it when this browser already has it. */
export async function openDemoCase(progress?: (message: string) => void): Promise<Case> {
  const db = getDb()
  let id = (await db.cases.filter((c) => c.name === DEMO_NAME).first())?.id
  if (id == null) {
    progress?.('Downloading the demo case…')
    const resp = await fetch(DEMO_URL)
    if (!resp.ok) throw new Error(`the demo case is not on this server (${resp.status})`)
    id = await restoreCaseBundle(await demoBundleFile(resp), progress)
    await db.cases.update(id, { name: DEMO_NAME, updatedAt: Date.now() })
  }
  await db.kv.put({ key: 'lastCase', value: id })
  const c = (await db.cases.get(id))!
  return { ...c, settings: { ...defaultSettings(), ...c.settings } }
}
