import { createSHA256 } from 'hash-wasm'
import { API_HEADERS, readNdjsonBody } from '../api/client'
import { CASE_KV_KEYS, deleteCase, getDb, newServerKey, type Case } from '../db/schema'
import { caseRows, importServerBatch, type TransferRow } from './caseTransfer'

const TABLES = ['evidence', 'events', 'mails', 'mailBodies', 'attachments', 'urls', 'findings', 'iocs', 'facets', 'aiSessions', 'savedSearches', 'caseNotes', 'customRules', 'rowMarks']
type Sink = { write: (text: string) => Promise<unknown> }
type RecordLine = { table: string; row: TransferRow }

/** A checksum covers the exact bytes of every record, including the header. */
export async function writeCaseBundle(kase: Case, sink: Sink, progress?: (message: string) => void): Promise<void> {
  const hash = await createSHA256()
  hash.init()
  const write = async (value: unknown) => {
    const line = JSON.stringify(value) + '\n'
    hash.update(line)
    await sink.write(line)
  }
  await write({ format: 'remn-case', version: 2, case: kase, exportedAt: Date.now() })
  for (const table of TABLES) {
    if (kase.storage === 'server' && ['events', 'mails', 'mailBodies', 'attachments', 'urls'].includes(table)) continue
    progress?.(`Exporting ${table}…`)
    for await (const page of caseRows(table, kase.id!)) for (const row of page) await write({ table, row })
  }
  for (const key of CASE_KV_KEYS(kase.id!)) {
    if (key.startsWith('relationship-cache-')) continue // Rebuildable graph IDs belong to this database only.
    const row = await getDb().kv.get(key)
    if (row) await write({ table: 'kv', row })
  }
  if (kase.storage === 'server' && kase.serverKey) {
    progress?.('Exporting server evidence…')
    const response = await fetch(`/api/store/${kase.serverKey}/export`, { headers: API_HEADERS })
    if (!response.ok) throw new Error(`Server export failed (${response.status})`)
    await readNdjsonBody(response, (row) => write({ table: 'serverRows', row }))
  }
  await sink.write(JSON.stringify({ sha256: hash.digest('hex') }) + '\n')
}

/** Read bounded chunks. A damaged or truncated line is an error, never silently skipped. */
async function* lines(file: Blob): AsyncGenerator<string> {
  const reader = file.stream().getReader()
  const decoder = new TextDecoder('utf-8', { fatal: true })
  let rest = ''
  try {
    for (;;) {
      const { value, done } = await reader.read()
      if (done) break
      rest += decoder.decode(value, { stream: true })
      let end: number
      while ((end = rest.indexOf('\n')) >= 0) {
        yield rest.slice(0, end + 1)
        rest = rest.slice(end + 1)
      }
      if (rest.length > 64 * 1024 * 1024) throw new Error('Case bundle record exceeds 64 MB')
    }
    rest += decoder.decode()
    if (rest) throw new Error('Truncated case bundle')
  } finally {
    reader.releaseLock()
  }
}

function validateRecord(record: RecordLine): void {
  if (![...TABLES, 'kv', 'serverRows'].includes(record.table) || !record.row || typeof record.row !== 'object') throw new Error('Invalid case bundle record')
}

export async function restoreCaseBundle(file: File, progress?: (message: string) => void): Promise<number> {
  const prefix = await file.slice(0, 200).text()
  let kase: Case
  let records: () => AsyncGenerator<RecordLine>
  if (prefix.includes('"bundle":')) {
    // Compatibility with the old single-JSON format. New exports never allocate this large string.
    const text = await file.text()
    const wrapper = JSON.parse(text)
    const hash = await createSHA256()
    hash.init()
    hash.update(text.slice(text.indexOf('"bundle":') + 9, -1))
    if (hash.digest('hex') !== wrapper.sha256 || wrapper.bundle?.format !== 'remn-case') throw new Error('Case bundle hash mismatch')
    const b = wrapper.bundle
    kase = b.case
    if (b.serverRows?.some((r: TransferRow) => r.type !== 'evidence' && r.id == null))
      throw new Error('This legacy server backup omitted row IDs. Restore with the original case available; its investigation links cannot be reconstructed safely.')
    records = async function* () {
      for (const table of [...TABLES, 'kv', 'serverRows']) for (const row of b[table] ?? []) yield { table, row }
    }
  } else {
    progress?.('Verifying the complete backup before restoring…')
    const hash = await createSHA256()
    hash.init()
    let header: { format: string; version: number; case: Case } | undefined
    let verified = false
    for await (const line of lines(file)) {
      const record = JSON.parse(line)
      if (verified) throw new Error('Unexpected data after the backup checksum')
      if (!header) {
        if (record.format !== 'remn-case' || record.version !== 2 || !record.case) throw new Error('Unsupported case bundle')
        header = record
      } else if (record.sha256) {
        if (record.sha256 !== hash.digest('hex')) throw new Error('Case bundle hash mismatch')
        verified = true
        continue
      } else validateRecord(record)
      hash.update(line)
    }
    if (!header || !verified) throw new Error('Case bundle is incomplete: checksum missing')
    kase = header.case
    records = async function* () {
      let first = true
      for await (const line of lines(file)) {
        const record = JSON.parse(line)
        if (first) {
          first = false
          continue
        }
        if (record.sha256) break
        yield record
      }
    }
  }
  return restoreRecords(kase, records, progress)
}

/** Offset mappings are constant-size even for millions of evidence rows. */
async function restoreRecords(original: Case, records: () => AsyncGenerator<RecordLine>, progress?: (s: string) => void): Promise<number> {
  const db = getDb()
  const offsets: Record<string, number> = {}
  for (const name of TABLES) offsets[name] = Number((await db.table(name).orderBy(':id').last())?.id ?? 0)
  if (original.storage === 'server') offsets.events = offsets.mails = 0 // IDs are private to a fresh server store.
  const kase = { ...original, id: undefined, name: `${original.name} (imported)`, serverKey: original.storage === 'server' ? newServerKey() : undefined }
  const mapId = (table: string, id: unknown): unknown => {
    if (typeof id !== 'number') return id
    const mapped = id + (offsets[table] ?? 0)
    if (!Number.isSafeInteger(mapped) || mapped <= 0) throw new Error('Invalid or overflowing backup row ID')
    return mapped
  }
  const keyMap = new Map<string, string>()
  const mapTarget = (text: string): string => {
    if (keyMap.has(text)) return keyMap.get(text)!
    const [head, fragment] = text.split('#')
    if (keyMap.has(head)) return keyMap.get(head)! + (fragment == null ? '' : `#${fragment}`)
    return text.replace(/^(finding:|incident:mail:|mail:)(\d+)$/, (_, prefix: string, id: string) => prefix + mapId(prefix === 'finding:' ? 'findings' : 'mails', Number(id)))
  }
  // Metadata is much smaller than evidence. First collect its string-key mappings, which
  // are needed by chain reviews, notes and AI undo records regardless of export order.
  for await (const { table, row } of records()) {
    if (table === 'kv' && row.key === `finding-reviews-${original.id}`) {
      for (const [key, review] of Object.entries(row.value as Record<string, TransferRow>)) {
        const refs = review.refs as number[] | undefined
        if (review.source && refs?.length && key === `${review.ruleId}|${refs[0]}`) keyMap.set(key, `${review.ruleId}|${mapId(String(review.source), refs[0])}`)
      }
    }
    if (table === 'findings' && typeof row.key === 'string') {
      const refs = (row.refs as number[]) ?? []
      if (refs.length && row.key === `${row.ruleId}|${refs[0]}`) keyMap.set(row.key, `${row.ruleId}|${mapId(String(row.source), refs[0])}`)
    }
    if (table === 'kv' && row.key === `chains-${original.id}`) {
      for (const c of (row.value as { chains: TransferRow[] }).chains ?? []) {
        const seed = c.seed as TransferRow
        const id = mapId(String(seed.source ?? 'mails'), seed.id)
        const next = String(c.id).replace(/-\d+$/, `-${id}`)
        keyMap.set(String(c.id), next)
        keyMap.set(`chain:${c.id}`, `chain:${next}`)
        keyMap.set(`chain|${c.identity}|${seed.id}`, `chain|${c.identity}|${id}`)
      }
    }
  }
  const newId = await db.cases.add(kase)
  const remap = (value: unknown, table = '', parent = ''): unknown => {
    if (Array.isArray(value)) {
      if (['refs', 'unlink', 'unlinkedFindingIds'].includes(parent)) return value.map((id) => mapId(parent === 'refs' ? table : 'findings', id))
      return value.map((v) => remap(v, table, parent))
    }
    if (!value || typeof value !== 'object') return typeof value === 'string' && ['id', 'key', 'target'].includes(parent) ? mapTarget(value) : value
    const row = value as TransferRow
    const source = typeof row.source === 'string' ? row.source : table
    const out: TransferRow = {}
    for (const [key, v] of Object.entries(row)) {
      const mappedKey = mapTarget(key)
      if (key === 'caseId') out[mappedKey] = newId
      else if (key === 'evidenceId') out[mappedKey] = mapId('evidence', v)
      else if (key === 'mailId') out[mappedKey] = mapId('mails', v)
      else if (key === 'rowId') out[mappedKey] = mapId(source === 'mails' ? 'mails' : 'events', v)
      else if (key === 'id' && typeof v === 'number') out[mappedKey] = mapId(parent === 'findings' || parent === 'unlinked' ? 'findings' : table || source, v)
      else if (key === 'seed' || key === 'relatedSeeds') out[mappedKey] = remap(v, String((!Array.isArray(v) && (v as TransferRow)?.source) || 'mails'), key)
      else if (key === 'steps' || key === 'link') out[mappedKey] = remap(v, '', key)
      else out[mappedKey] = remap(v, key === 'findings' || key === 'unlinked' ? 'findings' : source, key)
    }
    return out
  }
  let batch: TransferRow[] = []
  let batchTable = ''
  let serverEvidence = -1
  const flush = async () => {
    if (!batch.length) return
    if (batchTable === 'serverRows') await importServerBatch(kase.serverKey!, serverEvidence, batch)
    else await db.table(batchTable).bulkAdd(batch)
    batch = []
  }
  try {
    for await (const { table, row } of records()) {
      validateRecord({ table, row })
      let mapped: TransferRow
      if (table === 'kv') {
        if (!CASE_KV_KEYS(original.id!).includes(String(row.key))) throw new Error('Backup contains a key outside this case')
        mapped = { key: String(row.key).replace(/-\d+$/, `-${newId}`), value: remap(row.value) }
      } else if (table === 'serverRows') {
        if (!kase.serverKey) throw new Error('Unexpected server data in a browser case')
        mapped = { ...row, evidenceId: mapId('evidence', row.evidenceId ?? row.id) }
        if (row.type === 'evidence') mapped.id = mapId('evidence', row.id)
      } else {
        mapped = { ...(remap(row, table) as TransferRow), caseId: newId }
      }
      const eid = Number(mapped.evidenceId ?? 0)
      if (batchTable !== table || (table === 'serverRows' && serverEvidence !== eid)) await flush()
      batchTable = table
      serverEvidence = eid
      batch.push(mapped)
      if (batch.length >= 500) {
        await flush()
        progress?.(`Restoring ${table}…`)
      }
    }
    await flush()
    return newId
  } catch (error) {
    await deleteCase(db, newId)
    if (kase.serverKey) await fetch(`/api/store/${kase.serverKey}`, { method: 'DELETE', headers: API_HEADERS }).catch(() => undefined)
    throw error
  }
}
