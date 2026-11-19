import wasmUrl from './evtx.wasm?url'
import { EvtxDecoder } from './decoder'

let loading: Promise<EvtxDecoder> | null = null

/** The decoder, fetched from this page's own origin the first time an EVTX file is parsed here, and
 * again after a file made it trap, so the next file is not read by an instance a panic aborted. */
export async function loadEvtxDecoder(): Promise<EvtxDecoder> {
  const current = loading
  if (current && (await current.catch(() => null))?.trapped && loading === current) loading = null
  loading ??= fetch(wasmUrl)
    .then((r) => {
      if (!r.ok) throw new Error(`the EVTX decoder could not be loaded (${r.status})`)
      return r.arrayBuffer()
    })
    .then((bytes) => EvtxDecoder.load(bytes))
  loading.catch(() => (loading = null))
  return loading
}
