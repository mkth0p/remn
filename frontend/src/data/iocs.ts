import { lookupReputation, type LookupResponse } from '../api/client'
import { getDb, type Case, type Ioc } from '../db/schema'
import { log, toast } from '../state/store'
import { getSource } from './source'

const CHECK_KINDS = new Set(['ip', 'domain', 'url', 'hash'])

/** Look up reputation for IOCs (opt-in: the case must allow network). Results are stored by the data source (IndexedDB or server store). */
export async function checkReputation(kase: Case, iocs: Ioc[], onProgress?: (done: number, total: number) => void): Promise<number> {
  if (!kase.settings.networkAllowed) {
    toast('warn', 'External lookups are disabled for this case (Settings → allow network).')
    return 0
  }
  const items = iocs.filter((i) => CHECK_KINDS.has(i.kind))
  const providers = kase.settings.providers?.length ? kase.settings.providers : undefined
  const source = getSource(kase)
  let done = 0
  let checked = 0
  for (let i = 0; i < items.length; i += 25) {
    const slice = items.slice(i, i + 25)
    let resp: LookupResponse
    try {
      resp = await lookupReputation(slice.map((x) => ({ kind: x.kind, value: x.value })), providers)
    } catch (e) {
      log('err', `reputation lookup failed: ${(e as Error).message}`)
      toast('err', `reputation lookup failed: ${(e as Error).message}`)
      break
    }
    const now = Date.now()
    const results = slice.map((ioc) => {
      const key = `${ioc.kind}:${ioc.value}`
      const sum = resp.summary[key]
      const verdicts = resp.results.filter((r) => r.kind === ioc.kind && r.value === ioc.value)
      return { kind: ioc.kind, value: ioc.value, verdict: sum?.verdict ?? 'unknown', tags: sum?.tags ?? [], summary: sum ?? null, verdicts, checkedAt: now }
    })
    await source.setIocReputation(results)
    checked += results.length
    done += slice.length
    onProgress?.(done, items.length)
  }
  log('ok', `reputation: ${checked} indicator(s) checked`)
  return checked
}

/** Browser store only: copy the worst verdict of a mail's IOCs onto the mail row for the rules. */
export async function mirrorToMails(caseId: number): Promise<void> {
  const db = getDb()
  const iocs = await db.iocs.where('caseId').equals(caseId).filter((i) => !!i.verdict && i.verdict !== 'unknown').toArray()
  if (!iocs.length) return
  const byKey = new Map(iocs.map((i) => [`${i.kind}:${i.value}`, i.verdict as string]))
  const rank: Record<string, number> = { malicious: 3, suspicious: 2, clean: 1 }
  const mails = await db.mails.where('caseId').equals(caseId).toArray()
  const now = Date.now()
  for (const m of mails) {
    let worst = ''
    const consider = (v: string | undefined) => {
      if (v && (rank[v] ?? 0) > (rank[worst] ?? 0)) worst = v
    }
    const origin = m.originIp ? byKey.get(`ip:${m.originIp.toLowerCase()}`) : undefined
    consider(origin)
    for (const u of m.urls ?? []) {
      consider(byKey.get(`url:${(u.normalized || u.url).toLowerCase()}`))
      if (u.domain) consider(byKey.get(`domain:${u.domain.toLowerCase()}`))
    }
    for (const a of m.attachments ?? []) if (a.sha256) consider(byKey.get(`hash:${a.sha256.toLowerCase()}`))
    if (m.fromRegistrable) consider(byKey.get(`domain:${m.fromRegistrable.toLowerCase()}`))
    const rep = { originIp: origin ? { verdict: origin } : undefined, worst: worst || undefined, checkedAt: now }
    if (worst || origin) await db.mails.update(m.id!, { reputation: rep })
  }
}
