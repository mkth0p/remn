import type { Table } from 'dexie'
import { API_HEADERS } from '../api/client'
import { getDb } from '../db/schema'

export type TransferRow = Record<string, unknown>

/** Keyset pages keep exports and migrations bounded even for multi-million-row cases. */
export async function* caseRows(name: string, caseId: number, size = 500): AsyncGenerator<TransferRow[]> {
  const table = getDb().table(name) as Table<TransferRow, number>
  const pk = table.schema.primKey.name!
  const lastRow = await table.orderBy(':id').last()
  const upper = Number(lastRow?.[pk] ?? 0)
  let last = 0
  while (last < upper) {
    const page = await table
      .where(':id')
      .between(last, upper, false, true)
      .filter((r) => r.caseId === caseId)
      .limit(size)
      .toArray()
    if (!page.length) break
    last = Number(page[page.length - 1][pk])
    yield page
  }
}

export async function importServerBatch(key: string, evidenceId: number, rows: TransferRow[]): Promise<void> {
  if (!rows.length) return
  const response = await fetch(`/api/store/${key}/import?evidenceId=${evidenceId}&preserveIds=1`, {
    method: 'POST',
    headers: { ...API_HEADERS, 'Content-Type': 'application/x-ndjson' },
    body: rows.map((r) => JSON.stringify(r)).join('\n') + '\n',
  })
  if (!response.ok) throw new Error(`Server import failed (${response.status}): ${(await response.text()).slice(0, 200)}`)
  const count = (await response.json()) as { events: number; mails: number }
  if (count.events !== rows.filter((r) => r.type === 'event').length || count.mails !== rows.filter((r) => r.type === 'mail').length) throw new Error('Server import did not acknowledge every row')
}
