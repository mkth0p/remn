// @vitest-environment jsdom
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it } from 'vitest'
import { SeenSet } from '../../ai/evidence'
import type { ChatMessage } from '../../ai/chat'
import { useStore } from '../../state/store'
import { AiMessage } from './AiMessage'
import { RefChips } from './refs'

afterEach(cleanup)

const answer = (cites: ChatMessage['cites']): ChatMessage => ({ role: 'assistant', content: 'The answer [ev:1].', final: true, cites })

describe('an answer of the agent', () => {
  it('counts its sentences by what reading them against their rows found, and calls none of them verified', () => {
    const { container } = render(
      <AiMessage
        m={answer({
          verified: 3,
          unverified: [],
          sentences: 3,
          holding: 1,
          nothingToCheck: 1,
          unsupported: [{ sentence: 'Then 198.51.100.9 logged on.', reason: 'it names 198.51.100.9, which none of its 1 row holds' }],
        })}
        seen={new SeenSet(['ev:1'])}
        showTools={false}
      />,
    )
    expect(
      screen.getByText(
        /3 sentence\(s\) read against the rows they cite: 1 whose rows hold the values they name, 1 naming no address, account or hash \(nothing to check\), 1 naming what those rows do not hold/,
      ),
    ).toBeTruthy()
    expect(container.querySelector('.ai-cite-check')?.textContent).not.toMatch(/sentence.*verified/)
  })

  it('reads a session saved before the counts were kept', () => {
    render(<AiMessage m={answer({ verified: 1, unverified: [], sentences: 2, unsupported: [] })} seen={new SeenSet(['ev:1'])} showTools={false} />)
    expect(screen.getByText(/2 sentence\(s\) read against the rows they cite: 0 naming what those rows do not hold/)).toBeTruthy()
  })
})

describe('the citations of an answer', () => {
  it('open the row they name from the keyboard, and an unverified one offers nothing to press', async () => {
    const user = userEvent.setup()
    useStore.setState({ view: 'ai', focusId: null })
    render(<AiMessage m={{ role: 'assistant', content: 'Two logons [ev:1] and [ev:9].', final: true }} seen={new SeenSet(['ev:1'])} showTools={false} />)
    const chip = screen.getByRole('button', { name: 'ev 1' })
    expect(screen.queryByRole('button', { name: /ev 9/ })).toBeNull()
    await user.tab()
    expect(document.activeElement).toBe(chip)
    await user.keyboard('{Enter}')
    expect(useStore.getState()).toMatchObject({ view: 'events', focusId: { source: 'events', id: 1 } })
  })

  it('of a proposal or a hypothesis open their row from the keyboard too', async () => {
    const user = userEvent.setup()
    useStore.setState({ view: 'ai', focusId: null })
    render(<RefChips refs={[{ source: 'mails', id: 3 }]} />)
    await user.tab()
    expect(document.activeElement).toBe(screen.getByRole('button', { name: 'mail 3' }))
    await user.keyboard(' ')
    expect(useStore.getState()).toMatchObject({ view: 'mails', focusId: { source: 'mails', id: 3 } })
  })
})
