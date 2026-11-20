/**
 * The figures of the committed rule measure (rules/measures.json and rules/measures-detail.json,
 * written by tools/measure_rules.py), counted as tests/backend/test_quoted_measures.py counts the
 * ones the README and docs/detection.md quote. The build reads the two files and the SigmaHQ packs
 * (vite.config.ts) and hands the result to the pages as the module `virtual:rule-measure`, so a new
 * measure changes the pages with no figure typed anywhere.
 */

/** rules/measures.json, as far as these figures read it. */
export interface MeasureFile {
  measured: string
  sources: Record<string, { repo: string; sha?: string; tag?: string; recordings?: number; machines?: number; events?: number; maxMb?: number; overSize?: number; missing?: number }>
  /** each rule's measure; one with `settings` cannot run without a case setting and was not measured */
  rules: Record<string, { hits?: number; settings?: string[] }>
}

/** rules/measures-detail.json: each rule's detected recordings ('<source>:<name>') and its findings on each clean machine. */
export interface MeasureDetail {
  rules: Record<string, { hits?: string[]; clean?: Record<string, number>; severity?: string }>
}

export interface LibraryFigure {
  key: string
  name: string
  /** the commit measured, shortened */
  ref: string
  recordings: number
  /** recordings on which a rule enabled by default, of the recording's technique, raised a finding of any severity */
  detected: number
  /** of those, the ones REMN's own rules detect */
  own: number
  /** no rule had been written against the library when it was first measured */
  heldOut: boolean
  /** what the library is to the rules, in a few words */
  note: string
}

/** Findings on the clean machines, at the severity each rule had when it was measured. */
export interface CleanFigure {
  /** rules that raised a finding there */
  rules: number
  highCritical: number
  mediumUp: number
}

export interface MeasureFigures {
  measured: string
  /** event rules measured */
  rules: number
  /** of those, the ones seen to fire on a recording of what they look for */
  detect: number
  libraries: LibraryFigure[]
  baseline: { tag: string; machines: number; events: number }
  /** REMN's own rules, and the rules enabled by default (REMN's own and the default SigmaHQ packs) */
  clean: { own: CleanFigure; defaults: CleanFigure }
  /** attack_data's Windows datasets left out of the measure: larger than maxMb, or missing at the pinned commit */
  attackDataWindows: { maxMb: number; overSize: number; missing: number }
}

/** The rule id prefixes of REMN's own rules. */
const OWN = ['win-', 'm365-', 'collection-', 'mail-']

/** The libraries in the order the pages show them: held out first. */
const LIBRARIES: { key: string; name: string; heldOut: boolean; note: string }[] = [
  { key: 'attackDataWindows', name: 'attack_data (Windows)', heldOut: true, note: 'no rule written against it before it was first measured' },
  { key: 'evtxToMitre', name: 'EVTX-to-MITRE-Attack', heldOut: true, note: 'no rule written against it before it was first measured' },
  { key: 'attackSamples', name: 'EVTX-ATTACK-SAMPLES', heldOut: false, note: 'the rules were reviewed against it' },
  { key: 'attackData', name: 'attack_data (Microsoft 365 and Entra ID)', heldOut: false, note: 'labelled by technique' },
  { key: 'sigma', name: 'SigmaHQ regression samples', heldOut: false, note: "each made by a rule's author for that rule" },
]

const HIGH = new Set(['high', 'critical'])
const MEDIUM_UP = new Set(['medium', 'high', 'critical'])

function clean(detail: MeasureDetail, take: (id: string) => boolean): CleanFigure {
  const out: CleanFigure = { rules: 0, highCritical: 0, mediumUp: 0 }
  for (const [id, d] of Object.entries(detail.rules)) {
    if (!take(id) || !d.clean) continue
    const n = Object.values(d.clean).reduce((a, b) => a + b, 0)
    if (!n) continue
    out.rules++
    if (HIGH.has(d.severity ?? '')) out.highCritical += n
    if (MEDIUM_UP.has(d.severity ?? '')) out.mediumUp += n
  }
  return out
}

/**
 * The figures of a measure. `off` holds the ids of the rules a new case does not enable (the packs
 * off by default, and rules switched off in their pack): their detections are not counted.
 */
export function measureFigures(measures: MeasureFile, detail: MeasureDetail, off: ReadonlySet<string>): MeasureFigures {
  const rules = Object.values(measures.rules)
  const measured = rules.filter((m) => !m.settings)
  const isOwn = (id: string) => OWN.some((p) => id.startsWith(p))
  const detected = new Map<string, Set<string>>()
  const ownDetected = new Map<string, Set<string>>()
  for (const [id, d] of Object.entries(detail.rules)) {
    if (off.has(id)) continue
    for (const hit of d.hits ?? []) {
      const at = hit.indexOf(':')
      const source = hit.slice(0, at)
      const name = hit.slice(at + 1)
      ;(detected.get(source) ?? detected.set(source, new Set()).get(source)!).add(name)
      if (isOwn(id)) (ownDetected.get(source) ?? ownDetected.set(source, new Set()).get(source)!).add(name)
    }
  }
  const s = measures.sources
  const windows = s.attackDataWindows
  return {
    measured: measures.measured,
    rules: rules.length,
    detect: measured.filter((m) => m.hits).length,
    libraries: LIBRARIES.filter((l) => s[l.key]?.recordings).map((l) => ({
      ...l,
      ref: (s[l.key].sha ?? '').slice(0, 7),
      recordings: s[l.key].recordings!,
      detected: detected.get(l.key)?.size ?? 0,
      own: ownDetected.get(l.key)?.size ?? 0,
    })),
    baseline: { tag: s.baseline?.tag ?? '', machines: s.baseline?.machines ?? 0, events: s.baseline?.events ?? 0 },
    clean: { own: clean(detail, isOwn), defaults: clean(detail, (id) => !off.has(id)) },
    attackDataWindows: { maxMb: windows?.maxMb ?? 0, overSize: windows?.overSize ?? 0, missing: windows?.missing ?? 0 },
  }
}
