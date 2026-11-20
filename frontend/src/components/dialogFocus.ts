import { useEffect, useState, type RefObject } from 'react'

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

/** The controls Tab reaches inside `root`, in document order. */
function tabbable(root: HTMLElement): HTMLElement[] {
  return [...root.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((el) => !el.closest('[hidden], [inert]'))
}

/**
 * Keeps the focus inside a modal dialog while it is open and gives it back afterwards: the dialog
 * takes the focus when it opens, unless a field inside it took it first; Tab and Shift+Tab go round
 * its controls; closing it returns the focus to the control that opened it. The dialog element
 * needs tabIndex -1 and aria-modal="true".
 */
export function useDialogFocus(ref: RefObject<HTMLElement | null>): void {
  // read while rendering, before a field of the dialog with autoFocus takes the focus
  const [opener] = useState(() => (typeof document === 'undefined' ? null : (document.activeElement as HTMLElement | null)))
  useEffect(() => {
    const dialog = ref.current
    if (!dialog) return
    if (!dialog.contains(document.activeElement)) dialog.focus({ preventScroll: true })
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return
      // a dialog opened from a dialog keeps the focus for itself
      const open = document.querySelectorAll('[aria-modal="true"]')
      if (open[open.length - 1] !== dialog) return
      const items = tabbable(dialog)
      const active = document.activeElement
      const inside = active !== null && dialog.contains(active)
      if (!items.length) {
        e.preventDefault()
        dialog.focus({ preventScroll: true })
      } else if (e.shiftKey && (!inside || active === dialog || active === items[0])) {
        e.preventDefault()
        items[items.length - 1].focus()
      } else if (!e.shiftKey && (!inside || active === items[items.length - 1])) {
        e.preventDefault()
        items[0].focus()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      // back to the opener, unless the person or the next page has put the focus elsewhere
      const active = document.activeElement
      if (opener?.isConnected && (active === null || active === document.body || dialog.contains(active))) opener.focus({ preventScroll: true })
    }
  }, [ref, opener])
}
