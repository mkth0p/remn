import type { KeyboardEvent, MouseEvent } from 'react'
import { useStore } from '../../state/store'
import { parseRef, type RowRef } from '../../ai/evidence'

/** Open what a ref names: the event or mail in its page's detail, the finding, the chain. */
export function openRef(ref: RowRef | string): void {
  const r = typeof ref === 'string' ? parseRef(ref) : ref
  if (!r) return
  const st = useStore.getState()
  if (r.source === 'events' || r.source === 'mails') {
    st.setFocus({ source: r.source, id: Number(r.id) })
    st.setView(r.source)
  } else if (r.source === 'findings') {
    st.setFocusFinding(Number(r.id))
    st.setView('findings')
  } else {
    // a chain opens the story that holds it
    st.setFocusChain(String(r.id))
    st.setView('stories')
  }
}

/** Click handler for a block of rendered text holding citation chips (data-cite). */
export function onCiteClick(e: MouseEvent<HTMLElement>): void {
  const el = (e.target as HTMLElement).closest('[data-cite]') as HTMLElement | null
  if (!el || !el.classList.contains('ok')) return
  e.preventDefault()
  openRef(el.dataset.cite ?? '')
}

/** Key handler for the same block: Enter or Space on a citation chip opens it, as a press does. */
export function onCiteKey(e: KeyboardEvent<HTMLElement>): void {
  if (e.key !== 'Enter' && e.key !== ' ') return
  const el = e.target as HTMLElement
  if (!el.matches('[data-cite].ok')) return
  e.preventDefault()
  openRef(el.dataset.cite ?? '')
}
