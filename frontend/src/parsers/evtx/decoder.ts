/**
 * The Rust `evtx` crate compiled to WebAssembly (frontend/wasm/evtx), one 64 KiB chunk at a time.
 * The module is instantiated from its bytes, so the same code runs in the ingest worker and in
 * the tests; nothing it reads or writes leaves this page.
 */
import { parseDecoded, type Json } from './py'

interface Exports {
  memory: WebAssembly.Memory
  alloc(len: number): number
  parse_chunk(ptr: number, len: number): number
  out_ptr(): number
  out_len(): number
}

export interface DecodedRecord {
  id: number | null
  /** the record header's write time */
  t: string | null
  /** the event, as the JSON pyevtx-rs gives the server */
  d?: Json
  /** why the record could not be rendered */
  e?: string
}

export type ChunkResult = { ok: true; records: DecodedRecord[] } | { ok: false; error: string }

export class EvtxDecoder {
  private readonly x: Exports
  private readonly utf8 = new TextDecoder()

  private constructor(instance: WebAssembly.Instance) {
    this.x = instance.exports as unknown as Exports
  }

  static async load(bytes: BufferSource): Promise<EvtxDecoder> {
    let memory: WebAssembly.Memory | null = null
    const { instance } = await WebAssembly.instantiate(bytes, {
      env: {
        // ahash's hasher seeds
        random_fill: (ptr: number, len: number) => crypto.getRandomValues(new Uint8Array(memory!.buffer, ptr, len)),
      },
    })
    const dec = new EvtxDecoder(instance)
    memory = dec.x.memory
    return dec
  }

  /** Decode one chunk; the chunk is copied in, so the caller keeps its buffer. */
  chunk(bytes: Uint8Array): ChunkResult {
    const ptr = this.x.alloc(bytes.length)
    new Uint8Array(this.x.memory.buffer, ptr, bytes.length).set(bytes)
    const n = this.x.parse_chunk(ptr, bytes.length)
    // read after the call: the memory may have grown, which detaches earlier views
    const text = this.utf8.decode(new Uint8Array(this.x.memory.buffer, this.x.out_ptr(), this.x.out_len()))
    if (n < 0) return { ok: false, error: text }
    const records: DecodedRecord[] = []
    let start = 0
    while (start < text.length) {
      let end = text.indexOf('\n', start)
      if (end < 0) end = text.length
      if (end > start) records.push(parseDecoded(text.slice(start, end)) as unknown as DecodedRecord)
      start = end + 1
    }
    return { ok: true, records }
  }
}
