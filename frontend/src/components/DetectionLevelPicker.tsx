import { DEFAULT_DETECTION_LEVEL, DETECTION_LEVELS, levelInfo, levelMeasured, MEASURED_ON, type DetectionLevel } from '../data/detectionLevel'

/**
 * The detection level as a five-stop slider: fewer lines to the left (the findings of noisy rules
 * folded, one per rule and host), every finding on its own to the right, with what the chosen level
 * keeps on its own and how many lines it was measured to give.
 */
export function DetectionLevelPicker({ value, onChange, disabled, compact }: { value: DetectionLevel; onChange: (l: DetectionLevel) => void; disabled?: boolean; compact?: boolean }) {
  const info = levelInfo(value)
  return (
    <div className="detection-level">
      <div className="row" style={{ gap: 10, alignItems: 'center' }}>
        <span className="small muted">fewer lines</span>
        <input
          type="range"
          min={1}
          max={5}
          step={1}
          value={value}
          disabled={disabled}
          aria-label="Detection level"
          aria-valuetext={`${value}: ${info.label}`}
          list="detection-level-stops"
          onChange={(e) => onChange(Number(e.target.value) as DetectionLevel)}
          style={{ flex: 1, minWidth: 120 }}
        />
        <datalist id="detection-level-stops">
          {DETECTION_LEVELS.map((l) => (
            <option key={l.level} value={l.level} label={String(l.level)} />
          ))}
        </datalist>
        <span className="small muted">every finding on its own</span>
      </div>
      <div className="small" style={{ marginTop: 4 }}>
        <b>
          Level {value}: {info.label}
        </b>
        {value === DEFAULT_DETECTION_LEVEL ? ' (default)' : ''}. {info.text}
      </div>
      {!compact && (
        <div className="small muted" style={{ marginTop: 2 }}>
          {levelMeasured(value)} Measured {MEASURED_ON.date}.
        </div>
      )}
    </div>
  )
}
