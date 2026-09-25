import { deleteEvidenceData, getDb, type Evidence } from '../db/schema'

/**
 * An import into a browser-store case writes its rows in batches as they arrive, and marks the
 * evidence done, with its facets and indicators, only at the end. A tab closed, reloaded or
 * crashed part-way used to leave the evidence "parsing" for good, rows no facet or indicator
 * counted, and a file that, added again, doubled them (the duplicate check waits for "done").
 *
 * So every import holds a Web Lock for as long as it runs, under a name the evidence carries; the
 * browser releases the lock when the tab goes, whatever the reason. At start-up, an evidence still
 * importing whose lock is free belongs to no live tab: its partial rows are removed and it is
 * marked as an import that stopped, so the case counts nothing twice and says what happened.
 */
export type Locks = Pick<LockManager, 'request'>

const UNFINISHED: Evidence['status'][] = ['hashing', 'uploading', 'parsing']
/** An import from before imports took a lock has no lock to ask about; past this age it is not running. */
const UNLOCKED_STALE_MS = 6 * 3600_000

function browserLocks(): Locks | null {
  try {
    // absent outside a secure context and in older browsers, whatever the type says
    const locks = typeof navigator !== 'undefined' ? (navigator as { locks?: LockManager }).locks : undefined
    return typeof locks?.request === 'function' ? locks : null
  } catch {
    return null
  }
}

/** Run an import holding its lock; `work` gets the lock's name to store on the evidence it creates. */
export async function whileImporting<T>(work: (lock: string | undefined) => Promise<T>, locks: Locks | null = browserLocks()): Promise<T> {
  if (!locks) return work(undefined)
  const name = `remn-import-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`
  return locks.request(name, () => work(name)) as Promise<T>
}

export interface StoppedImport {
  caseId: number
  evidenceId: number
  name: string
  /** partial rows removed */
  rows: number
  evidence: Evidence
}

/**
 * Mark the imports no live tab is running as stopped and remove the rows they had written.
 * Without Web Locks (an old browser, a page not served over HTTPS) a stopped import cannot be
 * told from one running in another tab, and nothing is touched.
 */
export async function stopInterruptedImports(locks: Locks | null = browserLocks(), now = Date.now()): Promise<StoppedImport[]> {
  if (!locks) return []
  const db = getDb()
  const open = await db.evidence.where('status').anyOf(UNFINISHED).toArray()
  const out: StoppedImport[] = []
  for (const ev of open) {
    const kase = await db.cases.get(ev.caseId)
    // a server-store import runs as a job on the server, not in the tab
    if (!kase || kase.storage === 'server') continue
    let stopped: StoppedImport | null = null
    if (ev.importLock) stopped = await locks.request(ev.importLock, { ifAvailable: true }, (lock) => (lock ? stop(ev.id!) : null))
    else if (now - ev.addedAt > UNLOCKED_STALE_MS) stopped = await stop(ev.id!)
    if (stopped) out.push(stopped)
  }
  return out
}

async function stop(evidenceId: number): Promise<StoppedImport | null> {
  const db = getDb()
  // read again under the lock: an import that finished since the list was taken is left alone
  const ev = await db.evidence.get(evidenceId)
  if (!ev || !UNFINISHED.includes(ev.status)) return null
  const rows = (await db.events.where('[caseId+evidenceId]').equals([ev.caseId, evidenceId]).count()) + (await db.mails.where('[caseId+evidenceId]').equals([ev.caseId, evidenceId]).count())
  await deleteEvidenceData(db, ev.caseId, evidenceId, true)
  const error = `the import stopped before it finished: the tab was closed, reloaded or crashed${
    rows ? `. The ${rows.toLocaleString('en-US')} row(s) it had written were removed, so nothing counts twice` : ''
  }. Add the file again to import it.`
  await db.evidence.update(evidenceId, { status: 'error', error, count: 0, progress: undefined })
  return { caseId: ev.caseId, evidenceId, name: ev.name, rows, evidence: ev }
}

/**
 * At start-up: stop the interrupted imports, then bring each case they belong to back in line
 * with its rows, as removing the evidence would (findings, facets and indicators, the staged
 * upload), and say so.
 */
export async function repairInterruptedImports(report: (s: StoppedImport) => void): Promise<StoppedImport[]> {
  const stopped = await stopInterruptedImports()
  if (!stopped.length) return stopped
  const { clearDerivedState } = await import('./caseState')
  const { forgetUpload } = await import('./upload')
  const { rebuildDerived } = await import('./ingest')
  for (const s of stopped) {
    await clearDerivedState(s.caseId, s.evidenceId)
    await forgetUpload(s.evidence).catch(() => false)
    report(s)
  }
  for (const caseId of new Set(stopped.map((s) => s.caseId))) await rebuildDerived(caseId)
  return stopped
}
