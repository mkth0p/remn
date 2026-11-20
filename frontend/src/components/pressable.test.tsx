// @vitest-environment jsdom
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { pressable, pressableRow } from './pressable'

afterEach(cleanup)

describe('pressable', () => {
  it('makes an item the mouse presses a button Tab reaches and Enter and Space press', async () => {
    const user = userEvent.setup()
    const open = vi.fn()
    render(
      <div {...pressable} className="story-row" onClick={open}>
        Story ws-01
      </div>,
    )
    const item = screen.getByRole('button', { name: 'Story ws-01' })
    await user.tab()
    expect(document.activeElement).toBe(item)
    await user.keyboard('{Enter}')
    await user.keyboard(' ')
    expect(open).toHaveBeenCalledTimes(2)
  })

  it('leaves the keys of a control inside it to that control', async () => {
    const user = userEvent.setup()
    const open = vi.fn()
    const own = vi.fn()
    render(
      <div {...pressable} onClick={open}>
        <button onClick={own}>undo</button>
      </div>,
    )
    screen.getByText('undo').focus()
    await user.keyboard('{Enter}')
    expect(own).toHaveBeenCalledTimes(1)
    // the button's own click reaches the item as a mouse press would, but its keys are not pressed twice
    expect(open).toHaveBeenCalledTimes(1)
  })

  it('keeps a table row a row while Tab reaches it and Enter opens it', async () => {
    const user = userEvent.setup()
    const open = vi.fn()
    render(
      <table>
        <tbody>
          <tr {...pressableRow} onClick={open}>
            <td>mailbox.pst</td>
          </tr>
        </tbody>
      </table>,
    )
    const row = screen.getByRole('row', { name: 'mailbox.pst' })
    await user.tab()
    expect(document.activeElement).toBe(row)
    await user.keyboard('{Enter}')
    expect(open).toHaveBeenCalledTimes(1)
  })
})
