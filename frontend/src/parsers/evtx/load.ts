import wasmUrl from './evtx.wasm?url'
import { EvtxDecoder } from './decoder'

let loading: Promise<EvtxDecoder> | null = null

/** The decoder, fetched from this page's own origin the first time an EVTX file is parsed here. */
export function loadEvtxDecoder(): Promise<EvtxDecoder> {
  loading ??= fetch(wasmUrl)
    .then((r) => {
      if (!r.ok) throw new Error(`the EVTX decoder could not be loaded (${r.status})`)
      return r.arrayBuffer()
    })
    .then((bytes) => EvtxDecoder.load(bytes))
  loading.catch(() => (loading = null))
  return loading
}
