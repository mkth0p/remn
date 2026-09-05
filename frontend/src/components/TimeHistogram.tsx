import { useEffect, useState } from 'react'
import type { DataSource } from '../data/source'
import type { Bucket } from '../data/queries'
import type { Filter } from '../rules/filter'
import { fmtNum, fmtTs } from '../util/format'

const SIZE: Record<Bucket, number> = { minute: 60_000, hour: 3_600_000, day: 86_400_000 }
const MAX_BARS = 140

/**
 * Distribution of the current result set over time, above the table (Kibana / Timesketch
 * convention). Buckets adapt to the span; clicking a bar narrows the filter to that bucket.
 */
export function TimeHistogram({ ds, source, filter, version, onRange }: { ds: DataSource; source: 'events' | 'mails'; filter: Filter; version: number; onRange?: (from: number, to: number) => void }) {
  const [bars, setBars] = useState<{ t: number; count: number; size: number }[]>([])
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    let alive = true
    setBusy(true)
    const fetch = (b: Bucket) => (source === 'events' ? ds.timelineEvents(filter, b) : ds.timelineMails(filter, b))
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
    }
  }, [ds, source, filter, version])
  if (!bars.length) return null
  const max = Math.max(...bars.map((b) => b.count), 1)
  const first = bars[0].t
  const last = bars[bars.length - 1].t + bars[bars.length - 1].size
  return (
    <div style={{ opacity: busy ? 0.6 : 1 }}>
      <div className="hist" title="distribution of the current results over time - click a bar to narrow the time range">
        {bars.map((b) => (
          <div key={b.t} className="b" style={{ height: `${Math.max(2, (b.count / max) * 100)}%`, opacity: b.count ? 1 : 0.15 }} title={`${fmtTs(b.t)} · ${fmtNum(b.count)}`} onClick={() => b.count && onRange?.(b.t, b.t + b.size)} />
        ))}
      </div>
      <div className="hist-labels">
        <span>{fmtTs(first)}</span>
        <span>{fmtNum(bars.reduce((s, b) => s + b.count, 0))} in view</span>
        <span>{fmtTs(last)}</span>
      </div>
    </div>
  )
}
