import { afterEach, describe, expect, it } from 'vitest'
import { confirmAction, useConfirmQuestion } from './confirm'

afterEach(() => useConfirmQuestion.setState({ question: null }))

describe('confirmAction', () => {
  it('puts the question up for the dialog and resolves with the answer, then takes it down', async () => {
    const asked = confirmAction('Delete custom rule win-test?', { title: 'Delete the rule', action: 'Delete', danger: true })
    const q = useConfirmQuestion.getState().question!
    expect(q).toMatchObject({ text: 'Delete custom rule win-test?', title: 'Delete the rule', action: 'Delete', danger: true })
    q.answer(true)
    expect(await asked).toBe(true)
    expect(useConfirmQuestion.getState().question).toBeNull()
  })

  it('asks with a plain title and button when none is given', () => {
    void confirmAction('Check 400 indicators?')
    expect(useConfirmQuestion.getState().question).toMatchObject({ title: 'Please confirm', action: 'Continue', danger: false })
  })

  it('cancels a question still open when another is asked, and leaves the new one up', async () => {
    const first = confirmAction('first')
    const second = confirmAction('second')
    expect(await first).toBe(false)
    expect(useConfirmQuestion.getState().question?.text).toBe('second')
    useConfirmQuestion.getState().question!.answer(false)
    expect(await second).toBe(false)
  })
})
