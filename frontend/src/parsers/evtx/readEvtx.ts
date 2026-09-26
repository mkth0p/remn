/**
 * An EVTX file to rows in the browser, as the server's iter_events makes them: the file is read in
 * 64 KiB chunks (an EVTX chunk is self-contained), each decoded by the WebAssembly build of the
 * server's decoder and flattened by the TypeScript port of its flattening. The same pass checks
 * the CRC32s the format defines and keeps the file's record numbering, for the completeness ledger.
 */
import { EvtxDecoder } from './decoder'
import { flatten, headerTime, parseTimestamp, type Row } from './flatten'
import { Lineage, Stats, type Checksums } from './ledger'

export const EVTX_HEADER = 4096
export const EVTX_CHUNK = 65536

/** The file, or any source of its bytes by range. */
export interface ByteSource {
  size: number
  read(start: number, end: number): Promise<Uint8Array>
}

export function blobSource(blob: Blob): ByteSource {
  return { size: blob.size, read: async (s, e) => new Uint8Array(await blob.slice(s, e).arrayBuffer()) }
}

export function bytesSource(bytes: Uint8Array): ByteSource {
  return { size: bytes.length, read: async (s, e) => bytes.subarray(s, e) }
}

// ---- CRC32 (IEEE), for the checksums the format defines
const CRC_TABLE = (() => {
  const t = new Uint32Array(256)
  for (let n = 0; n < 256; n++) {
    let c = n
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    t[n] = c >>> 0
  }
  return t
})()

export function crc32(...parts: Uint8Array[]): number {
  let c = 0xffffffff
  for (const p of parts) for (let i = 0; i < p.length; i++) c = CRC_TABLE[(c ^ p[i]) & 0xff] ^ (c >>> 8)
  return (c ^ 0xffffffff) >>> 0
}

const u32 = (b: Uint8Array, at: number) => new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(at, true)
const MAGIC_FILE = [0x45, 0x6c, 0x66, 0x46, 0x69, 0x6c, 0x65, 0x00] // "ElfFile\0"
const MAGIC_CHUNK = [0x45, 0x6c, 0x66, 0x43, 0x68, 0x6e, 0x6b, 0x00] // "ElfChnk\0"
const starts = (b: Uint8Array, magic: number[]) => magic.every((x, i) => b[i] === x)

export interface ReadOptions {
  includeRaw?: boolean
  /** the upload's counts; one FileSequence is added for this file */
  stats?: Stats
  /** the row's sourceFile, and the sequence's name */
  sourceFile: string
  /** bytes read so far, for progress */
  onBytes?: (done: number, total: number) => void
  signal?: { aborted: boolean }
}

/**
 * Rows from one EVTX file. Records that cannot be read are counted in stats.errors and skipped,
 * as on the server; a file whose header is not an EVTX header throws.
 */
export async function* readEvtx(src: ByteSource, decoder: EvtxDecoder, opts: ReadOptions): AsyncGenerator<Row> {
  const includeRaw = opts.includeRaw ?? true
  const stats = opts.stats
  const seq = stats?.beginFile(opts.sourceFile)
  const head = await src.read(0, Math.min(EVTX_HEADER, src.size))
  if (head.length < 128 || !starts(head, MAGIC_FILE)) throw new Error('not an EVTX file (no ElfFile header)')
  const checksums: Checksums = {
    chunks: 0,
    fileHeader: crc32(head.subarray(0, 120)) === u32(head, 124),
    // written while Windows still had the log open (a live copy): not a fault
    dirty: (u32(head, 120) & 1) === 1,
  }
  const badHeader: number[] = []
  const badData: number[] = []
  const lineage = new Lineage()
  // the decoder's chunk count: whole chunks after the header
  const count = Math.floor(Math.max(0, src.size - EVTX_HEADER) / EVTX_CHUNK)
  for (let index = 0; index < count; index++) {
    if (opts.signal?.aborted) throw new Error('aborted')
    const start = EVTX_HEADER + index * EVTX_CHUNK
    const chunk = await src.read(start, start + EVTX_CHUNK)
    opts.onBytes?.(start + EVTX_CHUNK, src.size)
    if (starts(chunk, MAGIC_CHUNK)) {
      checksums.chunks++
      if (crc32(chunk.subarray(0, 120), chunk.subarray(128, 512)) !== u32(chunk, 124)) badHeader.push(index)
      const free = u32(chunk, 48)
      if (!(free >= 512 && free <= EVTX_CHUNK) || crc32(chunk.subarray(512, free)) !== u32(chunk, 52)) badData.push(index)
    }
    // empty chunks sit in the middle of a dirty file; the decoder steps over them
    if (chunk.every((b) => b === 0)) continue
    const res = decoder.chunk(chunk)
    if (!res.ok) {
      if (stats) stats.errors++
      continue
    }
    for (const rec of res.records) {
      if (rec.d === undefined) {
        if (stats) stats.errors++
        continue
      }
      let row: Row
      try {
        row = flatten(rec.d, rec, includeRaw)
      } catch {
        if (stats) stats.errors++
        // the record is in the file even though its content could not be read
        seq?.add(rec.id, parseTimestamp(headerTime(rec.t))[0])
        continue
      }
      seq?.add(rec.id, parseTimestamp(headerTime(rec.t))[0], row)
      lineage.apply(row)
      stats?.add(row)
      row.sourceFile = opts.sourceFile
      yield row
    }
  }
  if (badHeader.length) Object.assign(checksums, { badHeader: badHeader.slice(0, 50), badHeaderCount: badHeader.length })
  if (badData.length) Object.assign(checksums, { badData: badData.slice(0, 50), badDataCount: badData.length })
  if (seq) seq.checksums = checksums
}
