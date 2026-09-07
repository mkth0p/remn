import { getDb, type CaseNote } from '../db/schema'

/** Analyst-authored case material: free-text notes, a task checklist and the curated timeline. */
export async function listNotes(caseId: number, kind?: CaseNote['kind']): Promise<CaseNote[]> {
  const db = getDb()
  const rows = kind ? await db.caseNotes.where('[caseId+kind]').equals([caseId, kind]).toArray() : await db.caseNotes.where('caseId').equals(caseId).toArray()
  return rows.sort((a, b) => (kind === 'timeline' ? a.ts - b.ts : b.createdAt - a.createdAt))
}

export async function addNote(caseId: number, kind: CaseNote['kind'], text: string, extra: Partial<CaseNote> = {}): Promise<number> {
  const now = Date.now()
  return getDb().caseNotes.add({ caseId, kind, text: text.trim(), ts: extra.ts ?? now, createdAt: now, updatedAt: now, ...extra })
}

export async function updateNote(id: number, patch: Partial<CaseNote>): Promise<void> {
  await getDb().caseNotes.update(id, { ...patch, updatedAt: Date.now() })
}

export async function deleteNote(id: number): Promise<void> {
  await getDb().caseNotes.delete(id)
}

/** Add a row, finding or chain to the curated timeline once; a second call for the same link is a no-op. */
export async function addTimelineEntry(caseId: number, entry: { ts: number; text: string; link?: CaseNote['link']; severity?: string }): Promise<'added' | 'exists'> {
  if (entry.link) {
    const dup = await getDb()
      .caseNotes.where('[caseId+kind]')
      .equals([caseId, 'timeline'])
      .filter((n) => n.link?.source === entry.link!.source && String(n.link?.id) === String(entry.link!.id))
      .first()
    if (dup) return 'exists'
  }
  await addNote(caseId, 'timeline', entry.text, { ts: entry.ts, link: entry.link, severity: entry.severity })
  return 'added'
}
