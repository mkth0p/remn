import type { KeyboardEvent } from 'react'

/** Enter or Space on the element itself presses it, as they press a button: its own click handler runs. */
function pressOnKey(e: KeyboardEvent<HTMLElement>): void {
  if (e.target !== e.currentTarget || (e.key !== 'Enter' && e.key !== ' ')) return
  e.preventDefault()
  e.currentTarget.click()
}

/**
 * What an element the mouse presses (an item of a list, a value to pivot on, a tile) needs to be a
 * button for the keyboard and a screen reader too: Tab reaches it, Enter and Space press it, and it
 * is announced as a button. Spread it beside the element's onClick.
 */
export const pressable = { role: 'button', tabIndex: 0, onKeyDown: pressOnKey } as const

/**
 * The same for a table row that opens what it shows: the row keeps its row role, so a screen reader
 * still reads it as a row of its table, and Tab, Enter and Space reach and press it.
 */
export const pressableRow = { tabIndex: 0, onKeyDown: pressOnKey } as const
