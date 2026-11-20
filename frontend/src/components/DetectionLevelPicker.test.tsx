// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import measure from 'virtual:rule-measure'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { levelInfo } from '../data/detectionLevel'
import figures from '../data/detectionLevels.gen.json'
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

  it('gives the lines of the chosen level as the committed rule measure gives them', () => {
    const { container } = render(<DetectionLevelPicker value={2} onChange={() => {}} />)
    const m = levelInfo(2).measured
    expect(m).toEqual({ alone: figures.levels[1].alone, perCleanMachine: figures.levels[1].lines })
    expect(container.textContent).toContain(`On the ${figures.machines} clean machines of the rule measure of ${figures.measured}, this level gives about ${fmtNum(m.perCleanMachine)} lines`)
    expect(container.textContent).toContain(`${fmtNum(m.alone)} of them findings on their own (every medium and higher finding on its own: ${fmtNum(figures.mediumUp)})`)
    expect(container.textContent).not.toContain('not in the repository')
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
