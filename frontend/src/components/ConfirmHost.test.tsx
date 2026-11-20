// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { afterEach, describe, expect, it } from 'vitest'
import { confirmAction, useConfirmQuestion } from './confirm'
import { ConfirmHost } from './ConfirmHost'

afterEach(() => {
  cleanup()
  useConfirmQuestion.setState({ question: null })
})

/** A page whose button asks before it removes, with the dialog mounted as the app mounts it. */
function Page({ danger = true }: { danger?: boolean }) {
  const [said, setSaid] = useState('')
  return (
    <>
      <button onClick={() => void confirmAction('Remove "mailbox.pst" and all its rows?', { title: 'Remove the evidence', action: 'Remove', danger }).then((ok) => setSaid(ok ? 'removed' : 'kept'))}>
        remove
      </button>
      <output>{said}</output>
      <ConfirmHost />
    </>
  )
}

describe('ConfirmHost', () => {
  it('asks in a modal dialog named by its title, and goes ahead only on its button', async () => {
    render(<Page />)
    fireEvent.click(screen.getByText('remove'))
    const dialog = await screen.findByRole('dialog', { name: 'Remove the evidence' })
    expect(dialog.getAttribute('aria-modal')).toBe('true')
    expect(within(dialog).getByText('Remove "mailbox.pst" and all its rows?')).toBeTruthy()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Remove' }))
    await waitFor(() => expect(screen.getByRole('status').textContent).toBe('removed'))
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('takes Cancel, Escape and a press outside as no', async () => {
    render(<Page />)
    for (const close of [
      () => fireEvent.click(screen.getByRole('button', { name: 'Cancel' })),
      () => fireEvent.keyDown(window, { key: 'Escape' }),
      () => fireEvent.mouseDown(document.querySelector('.modal-bg')!),
    ]) {
      fireEvent.click(screen.getByText('remove'))
      await screen.findByRole('dialog')
      close()
      await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
      expect(screen.getByRole('status').textContent).toBe('kept')
    }
  })

  it('starts on Cancel before a removal and on the action otherwise, keeps Tab inside and gives the focus back', async () => {
    const user = userEvent.setup()
    render(<Page />)
    const opener = screen.getByText('remove')
    await user.click(opener)
    const dialog = await screen.findByRole('dialog')
    expect(document.activeElement).toBe(within(dialog).getByRole('button', { name: 'Cancel' }))
    await user.tab()
    expect(document.activeElement).toBe(within(dialog).getByRole('button', { name: 'Remove' }))
    await user.tab()
    expect(dialog.contains(document.activeElement)).toBe(true)
    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(document.activeElement).toBe(opener)
    cleanup()
    render(<Page danger={false} />)
    await user.click(screen.getByText('remove'))
    expect(document.activeElement).toBe(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Remove' }))
  })
})
