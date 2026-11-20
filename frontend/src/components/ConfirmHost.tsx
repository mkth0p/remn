import { useConfirmQuestion } from './confirm'
import { Modal } from './ui'

/** The confirmation dialog of confirmAction, mounted once by the app. */
export function ConfirmHost() {
  const question = useConfirmQuestion((s) => s.question)
  if (!question) return null
  const { text, title, action, danger, answer } = question
  return (
    <Modal
      title={title}
      onClose={() => answer(false)}
      footer={
        <>
          <button className="btn" autoFocus={danger} onClick={() => answer(false)}>
            Cancel
          </button>
          <button className={danger ? 'btn danger' : 'btn primary'} autoFocus={!danger} onClick={() => answer(true)}>
            {action}
          </button>
        </>
      }
    >
      <p style={{ margin: 0, whiteSpace: 'pre-wrap' }}>{text}</p>
    </Modal>
  )
}
