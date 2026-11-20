import { create } from 'zustand'

export interface ConfirmQuestion {
  text: string
  title: string
  /** the label of the button that goes ahead */
  action: string
  /** the action removes something: its button says so, and the focus starts on Cancel */
  danger: boolean
  answer: (ok: boolean) => void
}

/** The question the app's confirmation dialog (ConfirmHost) shows, if any. */
export const useConfirmQuestion = create<{ question: ConfirmQuestion | null }>(() => ({ question: null }))

/**
 * Ask the analyst before going on, in the app's own dialog rather than the browser's: it keeps the
 * focus inside while open, gives it back to the control that asked, and reads like the rest of the
 * page. Resolves true when the analyst goes ahead, false when they cancel, press Escape or click
 * outside. A second question cancels one still open.
 */
export function confirmAction(text: string, opts: { title?: string; action?: string; danger?: boolean } = {}): Promise<boolean> {
  return new Promise((resolve) => {
    useConfirmQuestion.getState().question?.answer(false)
    const answer = (ok: boolean) => {
      if (useConfirmQuestion.getState().question?.answer === answer) useConfirmQuestion.setState({ question: null })
      resolve(ok)
    }
    useConfirmQuestion.setState({ question: { text, title: opts.title ?? 'Please confirm', action: opts.action ?? 'Continue', danger: !!opts.danger, answer } })
  })
}
