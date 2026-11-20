// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import measure from 'virtual:rule-measure'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { levelInfo } from '../data/detectionLevel'
import { fmtNum } from '../util/format'
import { DetectionLevelPicker } from './DetectionLevelPicker'

afterEach(cleanup)

describe('the detection level picker', () => {
  it('says what every level detects as the committed rule measure gives it', () => {
    const { container } = render(<DetectionLevelPicker value={2} onChange={() => {}} />)
    const text = container.textContent ?? ''
    for (const key of ['attackDataWindows', 'evtxToMitre', 'attackSamples']) {
      const l = measure.libraries.find((x) => x.key === key)!
      expect(text).toContain(`${fmtNum(l.detected)} of the ${fmtNum(l.recordings)} ${l.name}`)
    }
    expect(text).toContain(`rule measure of ${measure.measured}`)
  })

  it('gives the lines of the chosen level, from a run it names as not in the repository', () => {
    const { container } = render(<DetectionLevelPicker value={2} onChange={() => {}} />)
    const m = levelInfo(2).measured
    expect(container.textContent).toContain(`about ${fmtNum(m.perCleanMachine)} lines per clean machine, ${fmtNum(m.alone)} of them findings on their own`)
    expect(container.textContent).toContain('whose script and output are not in the repository')
  })

  it('moves along its five stops and leaves the measure out when compact', () => {
    const onChange = vi.fn()
    const { container } = render(<DetectionLevelPicker value={2} onChange={onChange} compact />)
    fireEvent.change(screen.getByRole('slider', { name: 'Detection level' }), { target: { value: '4' } })
    expect(onChange).toHaveBeenCalledWith(4)
    expect(container.textContent).toContain('Level 2: balanced (default)')
    expect(container.textContent).not.toContain('lines per clean machine')
  })
})
