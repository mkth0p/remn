import type { EventRow } from '../db/schema'

/**
 * The Internet message ids a Microsoft 365 audit record names: the items MailItemsAccessed read,
 * the items a delete or move touched. The parser keeps them as data.InternetMessageId, written
 * the way the mailbox stores messageId, so they open the messages themselves. A record naming
 * more than the parser keeps says how many in data["InternetMessageId.total"].
 */
export function namedMessageIds(row: Pick<EventRow, 'data'>): { ids: string[]; total: number } {
  const data = row.data as Record<string, unknown> | undefined
  const v = data?.InternetMessageId
  const ids = typeof v === 'string' ? v.split(', ').filter(Boolean) : []
  const total = Number(data?.['InternetMessageId.total'] ?? ids.length)
  return { ids, total: Number.isFinite(total) && total > ids.length ? total : ids.length }
}
