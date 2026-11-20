import { Component, type ErrorInfo, type ReactNode } from 'react'
import { log } from '../state/store'
import { CopyButton } from './ui'

interface Props {
  /** what failed, as the sentence starts: "The Events page" */
  what: string
  children: ReactNode
}

/**
 * An exception thrown while a part of the page renders used to unmount the whole application and
 * leave a blank window, with reload (which also loses the view) as the only way back. The part
 * that failed now shows what happened in its place, with a way to try again and the details to
 * copy, and the rest of the page stays usable.
 */
export class ErrorBoundary extends Component<Props, { error: Error | null; stack: string }> {
  state = { error: null as Error | null, stack: '' }

  static getDerivedStateFromError(error: Error) {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    this.setState({ stack: `${error.stack ?? error.message}\n${info.componentStack ?? ''}`.trim() })
    log('err', `${this.props.what} failed: ${error.message}`)
  }

  render() {
    const { error, stack } = this.state
    if (!error) return this.props.children
    return (
      <div className="empty" role="alert">
        <div className="big">{this.props.what} failed</div>
        <div className="mono">{error.message}</div>
        <div className="row" style={{ justifyContent: 'center', gap: 8, marginTop: 12 }}>
          <button className="btn sm" onClick={() => this.setState({ error: null, stack: '' })}>
            try again
          </button>
          <button className="btn ghost sm" onClick={() => location.reload()}>
            reload the page
          </button>
          {stack && <CopyButton text={stack} label="copy details" />}
        </div>
      </div>
    )
  }
}
