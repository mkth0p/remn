import { useEffect, useMemo, useState } from 'react'
import { getSource, type DataSource } from '../data/source'
import { getDb, type EventRow, type Finding, type MailRow } from '../db/schema'
import type { Filter } from '../rules/filter'
import { useStore, type EntityRef } from '../state/store'
import { fmtNum, fmtTs } from '../util/format'
import { Badge, Dot, Flyout, Sev, Tabs } from './ui'
import { IconAi, IconGlobe, IconHost, IconMail, IconUser } from './Icons'

export type EntityKind = EntityRef['kind']
export type { EntityRef }

/** Which entity page a field's value belongs to, or null when the field is not an entity. */
export function entityKind(field: string): EntityKind | null {
  const f = field.toLowerCase()
  if (/^(targetuser|subjectuser|user|membername|upn|username|account|identity)$/.test(f)) return 'user'
  if (/^(computer|host|hosts|workstation|hostname|sourcehostname|destinationhostname)$/.test(f)) return 'host'
  if (/^(ipaddress|ip|ips|sourceip|destinationip|originip|clientip)$/.test(f)) return 'ip'
  if (/^(fromaddr|attacker|attackeraddresses|replyto|sender|senders|toaddr|recipient)$/.test(f)) return 'address'
  if (/^(fromdomain|fromregistrable|domain|domains|registrable)$/.test(f)) return 'domain'
  return null
}

function eventFilter(e: EntityRef): Filter | null {
  const v = e.value
  switch (e.kind) {
    case 'user': {
      const local = v.includes('@') ? v.split('@')[0] : v.includes('\\') ? v.split('\\').pop()! : v
      return {
        conditions: [
          { field: 'targetUser', op: 'eq', value: local },
          { field: 'subjectUser', op: 'eq', value: local },
          { field: 'upn', op: 'eq', value: v },
          { field: 'targetUser', op: 'eq', value: v },
        ],
        logic: 'or',
        sort: { field: 'ts', dir: 'desc' },
      }
    }
    case 'host':
      return { conditions: [{ field: 'computer', op: 'startswith', value: v.split('.')[0] }], sort: { field: 'ts', dir: 'desc' } }
    case 'ip':
      return {
        conditions: [
          { field: 'ipAddress', op: 'eq', value: v },
          { field: 'sourceIp', op: 'eq', value: v },
          { field: 'destinationIp', op: 'eq', value: v },
        ],
        logic: 'or',
        sort: { field: 'ts', dir: 'desc' },
      }
    case 'domain':
      return {
        conditions: [
          { field: 'query', op: 'endswith', value: v },
          { field: 'destinationHostname', op: 'endswith', value: v },
        ],
        logic: 'or',
        sort: { field: 'ts', dir: 'desc' },
      }
    default:
      return null
  }
}
function mailFilter(e: EntityRef): Filter | null {
  const v = e.value
  switch (e.kind) {
    case 'address':
      return {
        conditions: [
          { field: 'fromAddr', op: 'eq', value: v },
          { field: 'to.addr', op: 'eq', value: v },
          { field: 'replyTo.addr', op: 'eq', value: v },
        ],
        logic: 'or',
        sort: { field: 'date', dir: 'desc' },
      }
    case 'user':
      return v.includes('@')
        ? {
            conditions: [
              { field: 'fromAddr', op: 'eq', value: v },
              { field: 'to.addr', op: 'eq', value: v },
            ],
            logic: 'or',
            sort: { field: 'date', dir: 'desc' },
          }
        : {
            conditions: [
              { field: 'to.addr', op: 'startswith', value: v + '@' },
              { field: 'fromAddr', op: 'startswith', value: v + '@' },
            ],
            logic: 'or',
            sort: { field: 'date', dir: 'desc' },
          }
    case 'domain':
      return {
        conditions: [
          { field: 'fromRegistrable', op: 'eq', value: v },
          { field: 'fromDomain', op: 'eq', value: v },
          { field: 'urls.domain', op: 'eq', value: v },
        ],
        logic: 'or',
        sort: { field: 'date', dir: 'desc' },
      }
    case 'ip':
      return { conditions: [{ field: 'originIp', op: 'eq', value: v }], sort: { field: 'date', dir: 'desc' } }
    default:
      return null
  }
}

interface Item {
  ts: number
  kind: 'finding' | 'mail' | 'event'
  sev?: string
  title: string
  sub?: string
  open: () => void
}

const KIND_ICON: Record<EntityKind, React.ComponentType> = { user: IconUser, host: IconHost, ip: IconGlobe, address: IconMail, domain: IconGlobe }

/**
 * Entity page as a flyout (Sentinel / Elastic convention): facts on top, a timeline of the
 * entity's findings, mails and events in the case, and insights (first/last seen, counts,
 * distinct hosts and addresses). Opened from any entity value; pivots to the full lists.
 */
export function EntityPanel() {
  const entity = useStore((s) => s.entity)
  const setEntity = useStore((s) => s.setEntity)
  const kase = useStore((s) => s.currentCase)
  const setView = useStore((s) => s.setView)
  const setEventsFilter = useStore((s) => s.setEventsFilter)
  const setMailsFilter = useStore((s) => s.setMailsFilter)
  const setFocus = useStore((s) => s.setFocus)
  const setAiPrompt = useStore((s) => s.setAiPrompt)
  const [tab, setTab] = useState<'timeline' | 'insights' | 'events' | 'mails'>('timeline')
  const [events, setEvents] = useState<EventRow[]>([])
  const [mails, setMails] = useState<MailRow[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [counts, setCounts] = useState<{ events: number | null; mails: number | null }>({ events: null, mails: null })
  const [aggs, setAggs] = useState<{ field: string; groups: { key: string; count: number }[] }[]>([])
  const [busy, setBusy] = useState(false)
  const ds: DataSource | null = useMemo(() => (kase ? getSource(kase) : null), [kase])
  const ef = useMemo(() => (entity ? eventFilter(entity) : null), [entity])
  const mf = useMemo(() => (entity ? mailFilter(entity) : null), [entity])

  useEffect(() => {
    if (!entity || !ds || !kase?.id) return
    let alive = true
    setBusy(true)
    setTab('timeline')
    setEvents([])
    setMails([])
    setAggs([])
    setCounts({ events: null, mails: null })
    const v = entity.value.toLowerCase()
    const local = v.includes('@') ? v.split('@')[0] : v.includes('\\') ? v.split('\\').pop()! : v
    ;(async () => {
      const [ev, ml, fs] = await Promise.all([
        ef
          ? ds
              .searchEvents(ef, 300)
              .then((r) => r.rows)
              .catch(() => [])
          : Promise.resolve([]),
        mf
          ? ds
              .searchMails(mf, 300)
              .then((r) => r.rows)
              .catch(() => [])
          : Promise.resolve([]),
        getDb()
          .findings.where('caseId')
          .equals(kase.id!)
          .filter((f) =>
            Object.values(f.entities).some((x) => {
              const s = String(x).toLowerCase()
              return s === v || s.split(/,\s*/).includes(v) || (entity.kind === 'user' && (s === local || s.endsWith('\\' + local) || s.startsWith(local + '@')))
            }),
          )
          .toArray(),
      ])
      if (!alive) return
      setEvents(ev)
      setMails(ml)
      setFindings(fs)
      setBusy(false)
      const [ce, cm] = await Promise.all([ef ? ds.countEvents(ef).catch(() => null) : Promise.resolve(null), mf ? ds.countMails(mf).catch(() => null) : Promise.resolve(null)])
      if (!alive) return
      setCounts({ events: ce, mails: cm })
      if (ef) {
        const fields = entity.kind === 'host' ? ['targetUser', 'ipAddress', 'eventId'] : entity.kind === 'ip' ? ['targetUser', 'computer', 'eventId'] : ['computer', 'ipAddress', 'eventId']
        const out = await Promise.all(
          fields.map(async (field) => ({
            field,
            groups: await ds
              .aggregateEvents(ef, field, 6)
              .then((a) => a.groups.map((g) => ({ key: String(g.value), count: g.count })))
              .catch(() => []),
          })),
        )
        if (alive) setAggs(out.filter((a) => a.groups.length))
      }
    })()
    return () => {
      alive = false
    }
  }, [entity, ds, kase?.id, ef, mf])

  if (!entity || !kase) return null
  const close = () => setEntity(null)
  const items: Item[] = [
    ...findings.map((f) => ({
      ts: f.ts ?? 0,
      kind: 'finding' as const,
      sev: f.status === 'false_positive' ? 'info' : f.severity,
      title: f.title,
      sub: `${f.ruleId} · ${fmtNum(f.count)} row(s)${f.status === 'false_positive' ? ' · marked false positive' : ''}`,
      open: () => {
        setView('findings')
      },
    })),
    ...mails.map((m) => ({
      ts: m.date ?? 0,
      kind: 'mail' as const,
      sev: m.risk >= 80 ? 'critical' : m.risk >= 60 ? 'high' : m.risk >= 40 ? 'medium' : 'info',
      title: m.subject || '(no subject)',
      sub: `${m.fromAddr} → ${(m.to ?? [])
        .map((t) => t.addr)
        .slice(0, 2)
        .join(', ')} · risk ${m.risk}`,
      open: () => {
        setFocus({ source: 'mails', id: m.id! })
        setView('mails')
        close()
      },
    })),
    ...events.map((e) => ({
      ts: e.ts ?? 0,
      kind: 'event' as const,
      title: String(e.summary ?? e.description ?? e.operation ?? e.eventId ?? ''),
      sub: [e.computer, e.ipAddress, e.provider].filter(Boolean).join(' · '),
      open: () => {
        setFocus({ source: 'events', id: e.id! })
        setView('events')
        close()
      },
    })),
  ].sort((a, b) => b.ts - a.ts)
  const seen = items.filter((i) => i.ts)
  const first = seen.length ? Math.min(...seen.map((i) => i.ts)) : null
  const last = seen.length ? Math.max(...seen.map((i) => i.ts)) : null
  const worst = findings
    .filter((f) => f.status !== 'false_positive')
    .reduce<string>((w, f) => (['critical', 'high', 'medium', 'low', 'info'].indexOf(f.severity) < ['critical', 'high', 'medium', 'low', 'info'].indexOf(w) ? f.severity : w), 'info')
  const Icon = KIND_ICON[entity.kind]
  const ask = () => {
    setAiPrompt(
      `Summarise what this ${entity.kind} did in the case and what to check next: ${entity.value}. ${findings.length} finding(s), ${counts.events ?? events.length} event(s), ${counts.mails ?? mails.length} mail(s) involve it; first seen ${first ? new Date(first).toISOString() : 'n/a'}, last seen ${last ? new Date(last).toISOString() : 'n/a'}.`,
    )
    setView('ai')
    close()
  }
  return (
    <Flyout
      width="min(720px, 58vw)"
      title={
        <span className="row" style={{ gap: 8 }}>
          <Icon />
          <span className="mono">{entity.value}</span>
          <Badge>{entity.kind}</Badge>
          {findings.length > 0 && <Sev sev={worst}>{findings.filter((f) => f.status !== 'false_positive').length} finding(s)</Sev>}
        </span>
      }
      meta={
        <>
          <span>first seen {first ? fmtTs(first) : '—'}</span>
          <span>last seen {last ? fmtTs(last) : '—'}</span>
          <span>{counts.events == null ? (busy ? '…' : fmtNum(events.length)) : fmtNum(counts.events)} event(s)</span>
          <span>{counts.mails == null ? (busy ? '…' : fmtNum(mails.length)) : fmtNum(counts.mails)} mail(s)</span>
        </>
      }
      tabs={
        <Tabs
          tabs={[
            {
              id: 'timeline',
              label: (
                <span>
                  Timeline <span className="n">{items.length}</span>
                </span>
              ),
            },
            { id: 'insights', label: 'Insights' },
            {
              id: 'events',
              label: (
                <span>
                  Events <span className="n">{events.length}</span>
                </span>
              ),
            },
            {
              id: 'mails',
              label: (
                <span>
                  Mails <span className="n">{mails.length}</span>
                </span>
              ),
            },
          ]}
          active={tab}
          onChange={setTab}
        />
      }
      onClose={close}
      footer={
        <>
          {ef && (
            <button
              className="btn sm"
              onClick={() => {
                setEventsFilter(ef)
                setView('events')
                close()
              }}
            >
              filter events
            </button>
          )}
          {mf && (
            <button
              className="btn sm"
              onClick={() => {
                setMailsFilter(mf)
                setView('mails')
                close()
              }}
            >
              filter mails
            </button>
          )}
          <span className="spacer" />
          <button className="btn sm" onClick={ask}>
            <IconAi /> ask the analyst
          </button>
        </>
      }
    >
      {tab === 'timeline' && (
        <div className="story">
          {busy && !items.length && <div className="muted">loading…</div>}
          {!busy && !items.length && <div className="muted">nothing in this case references {entity.value}</div>}
          {items.slice(0, 300).map((it, i) => (
            <div key={i} className="step" onClick={it.open} style={{ gridTemplateColumns: '150px 14px 1fr' }}>
              <span className="t">{fmtTs(it.ts)}</span>
              <Dot sev={it.kind === 'event' ? 'info' : it.sev} title={it.kind} />
              <span>
                <div className="title">
                  {it.title}
                  {it.kind === 'finding' && (
                    <Badge sev={it.sev} className="small" title="finding">
                      finding
                    </Badge>
                  )}
                </div>
                {it.sub && <div className="sub">{it.sub}</div>}
              </span>
            </div>
          ))}
          {items.length > 300 && (
            <div className="muted small" style={{ padding: 8 }}>
              {fmtNum(items.length - 300)} more - use the filter buttons below
            </div>
          )}
        </div>
      )}
      {tab === 'insights' && (
        <>
          <div className="section">
            <h3>Findings</h3>
            {!findings.length && <div className="muted">none reference this {entity.kind}</div>}
            {findings.slice(0, 20).map((f) => (
              <div key={f.id} className="row" style={{ gap: 8 }}>
                <Sev sev={f.severity} />
                <span className="ellipsis" style={{ flex: 1 }}>
                  {f.title}
                </span>
                <span className="mono small muted">{fmtTs(f.ts)}</span>
              </div>
            ))}
          </div>
          {aggs.map((a) => (
            <div className="section" key={a.field}>
              <h3>
                {a.field} seen with this {entity.kind}
              </h3>
              <div className="kv">
                {a.groups.map((g) => (
                  <div key={g.key} style={{ display: 'contents' }}>
                    <div className="k">{g.key || '(empty)'}</div>
                    <div className="v">{fmtNum(g.count)}</div>
                  </div>
                ))}
              </div>
            </div>
          ))}
          {mails.length > 0 && (
            <div className="section">
              <h3>Mail</h3>
              <div className="kv">
                <div className="k">highest risk</div>
                <div className="v">{Math.max(...mails.map((m) => m.risk))}</div>
                <div className="k">senders</div>
                <div className="v">
                  {Array.from(new Set(mails.map((m) => m.fromAddr)))
                    .slice(0, 6)
                    .join(', ')}
                </div>
                <div className="k">history</div>
                <div className="v">
                  {(() => {
                    const m = mails.find((x) => x.senderPrevalence)
                    return m
                      ? `${m.senderPrevalence} sender · ${m.senderPriorCount ?? 0} prior mail(s) · ${m.senderSolicited === true ? 'solicited' : m.senderSolicited === false ? 'unsolicited' : 'history unknown'}`
                      : 'run "baseline senders" for sender history'
                  })()}
                </div>
              </div>
            </div>
          )}
        </>
      )}
      {tab === 'events' && (
        <table className="table compact">
          <thead>
            <tr>
              <th>time (UTC)</th>
              <th>id</th>
              <th>computer</th>
              <th>ip</th>
              <th>summary</th>
            </tr>
          </thead>
          <tbody>
            {events.slice(0, 200).map((e) => (
              <tr
                key={e.id}
                onClick={() => {
                  setFocus({ source: 'events', id: e.id! })
                  setView('events')
                  close()
                }}
                style={{ cursor: 'pointer' }}
              >
                <td className="nowrap">{fmtTs(e.ts)}</td>
                <td>{String(e.eventId ?? e.operation ?? '')}</td>
                <td>{String(e.computer ?? '')}</td>
                <td>{String(e.ipAddress ?? '')}</td>
                <td className="sans">{String(e.summary ?? '')}</td>
              </tr>
            ))}
            {!events.length && (
              <tr>
                <td colSpan={5} className="muted sans">
                  no events
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}
      {tab === 'mails' && (
        <table className="table compact">
          <thead>
            <tr>
              <th>date (UTC)</th>
              <th>risk</th>
              <th>from</th>
              <th>subject</th>
            </tr>
          </thead>
          <tbody>
            {mails.slice(0, 200).map((m) => (
              <tr
                key={m.id}
                onClick={() => {
                  setFocus({ source: 'mails', id: m.id! })
                  setView('mails')
                  close()
                }}
                style={{ cursor: 'pointer' }}
              >
                <td className="nowrap">{fmtTs(m.date)}</td>
                <td>{m.risk}</td>
                <td>{m.fromAddr}</td>
                <td className="sans">{m.subject}</td>
              </tr>
            ))}
            {!mails.length && (
              <tr>
                <td colSpan={4} className="muted sans">
                  no mails
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}
    </Flyout>
  )
}
