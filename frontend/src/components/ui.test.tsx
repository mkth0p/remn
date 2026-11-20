// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Chip, Kpi, KV, Modal, Toggle } from './ui'

afterEach(cleanup)

/** A page with a button that opens a dialog of two fields and a footer button. */
function Page({ autoFocusName = false }: { autoFocusName?: boolean }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <button onClick={() => setOpen(true)}>open the dialog</button>
      <button>elsewhere</button>
      {open && (
        <Modal title="Rename the case" onClose={() => setOpen(false)} footer={<button onClick={() => setOpen(false)}>save</button>}>
          <input aria-label="name" autoFocus={autoFocusName} />
          <input aria-label="note" />
        </Modal>
      )}
    </>
  )
}

function openDialog() {
  const opener = screen.getByText('open the dialog')
  opener.focus()
  fireEvent.click(opener)
  return { opener, dialog: screen.getByRole('dialog') }
}
const tab = (shiftKey = false) => fireEvent.keyDown(document.activeElement ?? document.body, { key: 'Tab', shiftKey })

describe('Modal', () => {
  it('is announced as a modal dialog named by its title', () => {
    render(<Page />)
    const { dialog } = openDialog()
    expect(dialog.getAttribute('aria-modal')).toBe('true')
    expect(screen.getByRole('dialog', { name: 'Rename the case' })).toBe(dialog)
  })

  it('takes the focus when it opens, and leaves it on a field that asked for it', () => {
    render(<Page />)
    const { dialog } = openDialog()
    expect(document.activeElement).toBe(dialog)
    cleanup()
    render(<Page autoFocusName />)
    openDialog()
    expect(document.activeElement).toBe(screen.getByLabelText('name'))
  })

  it('keeps Tab and Shift+Tab going round its own controls', () => {
    render(<Page />)
    const { dialog } = openDialog()
    const close = screen.getByLabelText('close')
    const save = screen.getByText('save')
    tab(true)
    expect(document.activeElement).toBe(save)
    tab()
    expect(document.activeElement).toBe(close)
    tab(true)
    expect(document.activeElement).toBe(save)
    screen.getByText('elsewhere').focus()
    tab()
    expect(document.activeElement).toBe(close)
    expect(dialog.contains(document.activeElement)).toBe(true)
  })

  it('gives the focus back to the control that opened it when it closes', () => {
    render(<Page />)
    const { opener } = openDialog()
    screen.getByLabelText('note').focus()
    fireEvent.click(screen.getByText('save'))
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(document.activeElement).toBe(opener)
    openDialog()
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(document.activeElement).toBe(opener)
  })

  it('closes on a press outside it but not on one inside it', () => {
    const onClose = vi.fn()
    render(
      <Modal title="t" onClose={onClose}>
        <p>body</p>
      </Modal>,
    )
    fireEvent.mouseDown(screen.getByText('body'))
    expect(onClose).not.toHaveBeenCalled()
    fireEvent.mouseDown(document.querySelector('.modal-bg')!)
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})

describe('Chip', () => {
  it('offers a remove control named for screen readers only when it can be removed', () => {
    const onRemove = vi.fn()
    const { rerender } = render(<Chip onRemove={onRemove}>eventId eq 4625</Chip>)
    fireEvent.click(screen.getByRole('button', { name: 'remove' }))
    expect(onRemove).toHaveBeenCalledTimes(1)
    rerender(<Chip>eventId eq 4625</Chip>)
    expect(screen.queryByRole('button', { name: 'remove' })).toBeNull()
  })
})

describe('Toggle', () => {
  /** A switch with its state, as a page holds it. */
  function Switch({ label, name }: { label?: string; name?: string }) {
    const [on, setOn] = useState(false)
    return <Toggle on={on} onChange={setOn} label={label} name={name} />
  }

  it('is a switch named by its label, which Tab reaches and Space and Enter flip', async () => {
    const user = userEvent.setup()
    render(<Switch label="external lookups" />)
    const sw = screen.getByRole('switch', { name: 'external lookups' })
    expect(sw.getAttribute('aria-checked')).toBe('false')
    await user.tab()
    expect(document.activeElement).toBe(sw)
    await user.keyboard(' ')
    expect(sw.getAttribute('aria-checked')).toBe('true')
    await user.keyboard('{Enter}')
    expect(sw.getAttribute('aria-checked')).toBe('false')
  })

  it('flips when its label is pressed, and takes a name when it shows no label', async () => {
    const user = userEvent.setup()
    render(<Switch label="external lookups" />)
    await user.click(screen.getByText('external lookups'))
    expect(screen.getByRole('switch').getAttribute('aria-checked')).toBe('true')
    cleanup()
    render(<Switch name="enable the pack" />)
    expect(screen.getByRole('switch', { name: 'enable the pack' })).toBeTruthy()
  })
})

describe('values and tiles that open something', () => {
  it('are buttons the keyboard reaches and presses', async () => {
    const user = userEvent.setup()
    const pivot = vi.fn()
    const open = vi.fn()
    render(
      <>
        <KV items={[['host', 'ws-01']]} onPivot={pivot} />
        <Kpi value="12" label="findings" onClick={open} />
        <Kpi value="3" label="evidence" />
      </>,
    )
    await user.tab()
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'ws-01' }))
    await user.keyboard('{Enter}')
    expect(pivot).toHaveBeenCalledWith('ws-01', 'host')
    await user.tab()
    expect(document.activeElement).toBe(screen.getByRole('button', { name: '12 findings' }))
    await user.keyboard(' ')
    expect(open).toHaveBeenCalledTimes(1)
    // a tile that opens nothing is not a button
    expect(screen.queryByRole('button', { name: '3 evidence' })).toBeNull()
  })

  it('lets the keyboard remove a chip', async () => {
    const user = userEvent.setup()
    const onRemove = vi.fn()
    render(<Chip onRemove={onRemove}>eventId eq 4625</Chip>)
    await user.tab()
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'remove' }))
    await user.keyboard('{Enter}')
    expect(onRemove).toHaveBeenCalledTimes(1)
  })
})
