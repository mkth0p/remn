/**
 * REMN's mark: a block wearing away into dither, one fragment left. Drawn on a 5 × 5 grid of 8 × 8
 * character cells in the manner of the C64 character set: '#' a full block, ':' the checker, 'e' the
 * top-left quarter block and 'f' the bottom-right one, the fragment, drawn in the accent.
 */
const CELLS = ['####:', '###:e', '##:e.', '#:e..', ':e..f']
const S = 8

function cell(c: string, x: number, y: number): string {
  const h = S / 2
  const q = S / 4
  if (c === '#') return `M${x} ${y}h${S}v${S}h-${S}Z`
  if (c === 'e') return `M${x} ${y}h${h}v${h}h-${h}Z`
  if (c === 'f') return `M${x + h} ${y + h}h${h}v${h}h-${h}Z`
  if (c !== ':') return ''
  let d = ''
  for (let j = 0; j < 4; j++) for (let i = 0; i < 4; i++) if ((i + j) % 2 === 0) d += `M${x + i * q} ${y + j * q}h${q}v${q}h-${q}Z`
  return d
}

let block = ''
let fragment = ''
CELLS.forEach((row, j) =>
  [...row].forEach((c, i) => {
    if (c === 'f') fragment += cell(c, i * S, j * S)
    else block += cell(c, i * S, j * S)
  }),
)
const MARK_SIZE = CELLS.length * S

/** The mark in the current text colour, its fragment in `--remn-mark-accent` (theme.css). */
export function RemnMark({ size = 24, className, title }: { size?: number; className?: string; title?: string }) {
  return (
    <svg
      className={className ? `remn-mark ${className}` : 'remn-mark'}
      width={size}
      height={size}
      viewBox={`0 0 ${MARK_SIZE} ${MARK_SIZE}`}
      role={title ? 'img' : undefined}
      aria-hidden={title ? undefined : true}
      aria-label={title}
    >
      <path d={block} fill="currentColor" />
      <path d={fragment} fill="var(--remn-mark-accent, var(--accent))" />
    </svg>
  )
}
