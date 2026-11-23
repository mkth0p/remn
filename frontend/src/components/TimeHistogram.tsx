import { useEffect, useState, type KeyboardEvent } from 'react'
import type { DataSource } from '../data/source'
import type { Bucket } from '../data/queries'
import type { Filter } from '../rules/filter'
import { fmtNum, fmtTs } from '../util/format'

const SIZE: Record<Bucket, number> = { minute: 60_000, hour: 3_600_000, day: 86_400_000 }
const MAX_BARS = 140

/**
 * Distribution of the current result set over time, above the table (Kibana / Timesketch
 * convention). Buckets adapt to the span; clicking a bar, or Enter or Space on it, narrows the
 * filter to that bucket.
 */
export function TimeHistogram({ ds, source, filter, version, onRange }: { ds: DataSource; source: 'events' | 'mails'; filter: Filter; version: number; onRange?: (from: number, to: number) => void }) {
  const [bars, setBars] = useState<{ t: number; count: number; size: number }[]>([])
  const [busy, setBusy] = useState(false)
  // the bar the keyboard was last on
  const [tabStop, setTabStop] = useState<number | null>(null)
  useEffect(() => {
    let alive = true
    const ac = new AbortController()
    setBusy(true)
    const fetch = (b: Bucket) => (source === 'events' ? ds.timelineEvents(filter, b, ac.signal) : ds.timelineMails(filter, b, ac.signal))
    ;(async () => {
      try {
        let bucket: Bucket = 'day'
        let pts = await fetch('day')
        if (pts.length) {
          const span = pts[pts.length - 1].t - pts[0].t
          if (span <= 3 * SIZE.hour) bucket = 'minute'
          else if (span <= 3 * SIZE.day) bucket = 'hour'
          if (bucket !== 'day') pts = await fetch(bucket)
        }
        if (!alive) return
        const size = SIZE[bucket]
        if (!pts.length) return setBars([])
        // dense series: fill the gaps so the x axis is linear, then merge to MAX_BARS
        const t0 = pts[0].t
        const n = Math.floor((pts[pts.length - 1].t - t0) / size) + 1
        const dense = new Array<number>(Math.min(n, 100_000)).fill(0)
        for (const p of pts) {
          const i = Math.floor((p.t - t0) / size)
          if (i >= 0 && i < dense.length) dense[i] += p.count
        }
        const per = Math.ceil(dense.length / MAX_BARS)
        const out: { t: number; count: number; size: number }[] = []
        for (let i = 0; i < dense.length; i += per) {
          let c = 0
          for (let j = i; j < Math.min(i + per, dense.length); j++) c += dense[j]
          out.push({ t: t0 + i * size, count: c, size: size * per })
        }
        setBars(out)
      } catch {
        if (alive) setBars([])
      } finally {
        if (alive) setBusy(false)
      }
    })()
    return () => {
      alive = false
      ac.abort()
    }
  }, [ds, source, filter, version])
  if (!bars.length) return null
  const max = Math.max(...bars.map((b) => b.count), 1)
  const first = bars[0].t
  const last = bars[bars.length - 1].t + bars[bars.length - 1].size
  // the bars that narrow the range are buttons in one Tab stop, as a toolbar's are: the arrows, Home
  // and End move between them, so a hundred bars do not stand between the query bar and the table
  const live = onRange ? bars.filter((b) => b.count) : []
  const stop = live.some((b) => b.t === tabStop) ? tabStop : live[0]?.t
  const onKey = (e: KeyboardEvent<HTMLButtonElement>) => {
    const at = live.findIndex((b) => b.t === Number(e.currentTarget.dataset.t))
    const moves: Record<string, number> = { ArrowRight: at + 1, ArrowLeft: at - 1, Home: 0, End: live.length - 1 }
    const to = moves[e.key] as number | undefined
    if (to == null) return
    e.preventDefault()
    const bar = live[Math.max(0, Math.min(live.length - 1, to))]
    setTabStop(bar.t)
    e.currentTarget.parentElement?.querySelector<HTMLElement>(`[data-t="${bar.t}"]`)?.focus()
  }
  return (
    <div style={{ opacity: busy ? 0.6 : 1 }}>
      <div
        className="hist"
        role={onRange ? 'toolbar' : undefined}
        aria-label={onRange ? 'Results over time: a bar narrows the time range to it' : undefined}
        title="distribution of the current results over time - click a bar to narrow the time range"
      >
        {bars.map((b) => {
          const style = { height: `${Math.max(2, (b.count / max) * 100)}%`, opacity: b.count ? 1 : 0.15 }
          const what = `${fmtTs(b.t)} to ${fmtTs(b.t + b.size)} · ${fmtNum(b.count)}`
          return onRange && b.count ? (
            <button
              key={b.t}
              type="button"
              className="b"
              data-t={b.t}
              style={style}
              title={what}
              aria-label={what}
              tabIndex={b.t === stop ? 0 : -1}
              onClick={() => {
                setTabStop(b.t)
                onRange(b.t, b.t + b.size)
              }}
              onKeyDown={onKey}
            />
          ) : (
            <div key={b.t} className="b" style={style} title={what} aria-hidden="true" />
          )
        })}
      </div>
      <div className="hist-labels">
        <span>{fmtTs(first)}</span>
        <span>{fmtNum(bars.reduce((s, b) => s + b.count, 0))} in view</span>
        <span>{fmtTs(last)}</span>
      </div>
    </div>
  )
}
