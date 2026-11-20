// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { useStore } from '../state/store'
import { ErrorBoundary } from './ErrorBoundary'

let broken = true
function Fragile() {
  if (broken) throw new Error('row 12 has no "computer" field')
  return <div>the view</div>
}

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  broken = true
})

describe('a page that throws while it renders', () => {
  it('shows what failed in place of the page, not a blank window, and says so in the console', () => {
    // React reports the caught error on the console as well; that is not what this test reads
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
    useStore.setState({ console: [] })
    render(
      <div>
        <nav>sidebar</nav>
        <ErrorBoundary what="The Events page">
          <Fragile />
        </ErrorBoundary>
      </div>,
    )
    expect(screen.getByText('sidebar')).toBeTruthy()
    expect(screen.getByRole('alert').textContent).toContain('The Events page failed')
    expect(screen.getByRole('alert').textContent).toContain('row 12 has no "computer" field')
    expect(useStore.getState().console.map((l) => l.text)).toContain('The Events page failed: row 12 has no "computer" field')
  })

  it('can be tried again once the cause is gone', () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
    render(
      <ErrorBoundary what="The Events page">
        <Fragile />
      </ErrorBoundary>,
    )
    broken = false
    fireEvent.click(screen.getByRole('button', { name: 'try again' }))
    expect(screen.getByText('the view')).toBeTruthy()
  })

  it('offers to go back to the page shown before it, when this tab has one', () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
    const back = vi.spyOn(history, 'back').mockImplementation(() => undefined)
    history.replaceState({ remn: 0 }, '')
    const first = render(
      <ErrorBoundary what="The Events page" back>
        <Fragile />
      </ErrorBoundary>,
    )
    expect(screen.queryByRole('button', { name: 'go back' })).toBeNull()
    first.unmount()
    history.replaceState({ remn: 1 }, '')
    render(
      <ErrorBoundary what="The Events page" back>
        <Fragile />
      </ErrorBoundary>,
    )
    fireEvent.click(screen.getByRole('button', { name: 'go back' }))
    expect(back).toHaveBeenCalled()
    history.replaceState(null, '')
  })
})
