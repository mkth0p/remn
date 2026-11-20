/**
 * Where the analyst is, kept in the page's address: the case, the page and, on the pages that open
 * one item at a time, that item. A reload opens the same place, Back and Forward move between the
 * pages as they were visited, and a link opens the same place in the browser that holds the case.
 *
 *   /                                  the start decides (the home page until a case holds evidence)
 *   /home                              the home page
 *   /case/<case>/<page>[?<item>=<id>]  a page of a case: ?finding=, ?story=, ?event= or ?mail=
 *
 * A case is named by its number in this browser and the time it was created, so a link from
 * another browser, where the same number is another case, is refused instead of opening that one.
 * Every way in (the start, Back and Forward) goes through openRoute, which opens only a case this
 * browser holds, as the case list does, and only an item that belongs to that case.
 */
import { useEffect, useRef } from 'react'
import { defaultSettings, getDb, type Case } from '../db/schema'
import { log, toast, useStore, type View } from './store'

/** The pages of a case, as the sidebar lists them. */
export const CASE_VIEWS: readonly View[] = [
  'dashboard',
  'evidence',
  'events',
  'mails',
  'timeline',
  'findings',
  'stories',
  'graph',
  'rules',
  'iocs',
  'ai',
  'review',
  'case',
  'questions',
  'report',
  'settings',
]

export type ItemKind = 'finding' | 'story' | 'event' | 'mail'
export interface RouteItem {
  kind: ItemKind
  id: string
}
export interface Route {
  /** null: the address names no page, the start decides */
  view: View | null
  /** the case the address names, as caseRef writes it */
  caseRef: string | null
  item: RouteItem | null
}

/** The item each page keeps in the address. */
export const ITEM_OF_VIEW: Partial<Record<View, ItemKind>> = { findings: 'finding', stories: 'story', events: 'event', mails: 'mail' }

export const NOT_HELD =
  'The link names a case this browser does not hold, so it was not opened. Cases live in the browser that created them: open the link there, or add a server case shared with you from "+ case".'

/** A case's name in the address: its number here and when it was created, so another browser's case of that number does not match. */
export function caseRef(c: Pick<Case, 'id' | 'createdAt'>): string {
  return `${c.id}-${Math.trunc(Number(c.createdAt) || 0).toString(36)}`
}

/** The case of this browser an address names, if it holds one. */
export function findCase<T extends Pick<Case, 'id' | 'createdAt'>>(cases: T[], ref: string): T | undefined {
  return cases.find((c) => c.id != null && caseRef(c) === ref)
}

export function parseRoute(pathname: string, search: string): Route {
  const parts = pathname.split('/').filter(Boolean).map(safeDecode)
  if (parts.length === 1 && parts[0] === 'home') return { view: 'home', caseRef: null, item: null }
  if (parts[0] !== 'case' || !parts[1] || parts.length > 3) return { view: null, caseRef: null, item: null }
  // a page this version does not have (an older link, a typing slip) opens the case's dashboard
  const view = parts[2] && CASE_VIEWS.includes(parts[2] as View) ? (parts[2] as View) : 'dashboard'
  const kind = ITEM_OF_VIEW[view]
  const id = kind ? new URLSearchParams(search).get(kind) : null
  return { view, caseRef: parts[1], item: kind && id ? { kind, id } : null }
}

export function formatRoute(view: View, kase: Pick<Case, 'id' | 'createdAt'> | null, item: RouteItem | null = null): string {
  if (view === 'home') return '/home'
  if (!kase?.id) return '/'
  const path = `/case/${encodeURIComponent(caseRef(kase))}/${view}`
  return item && ITEM_OF_VIEW[view] === item.kind ? `${path}?${item.kind}=${encodeURIComponent(item.id)}` : path
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s)
  } catch {
    return s
  }
}

/**
 * Hand an item of the address to its page, as a click elsewhere would: the page opens it when it
 * mounts. An item of another case is not handed on.
 */
export async function focusRouteItem(kase: Case, item: RouteItem): Promise<boolean> {
  const st = useStore.getState()
  const n = Number(item.id)
  if (item.kind === 'story') {
    st.setFocusChain(item.id)
    return true
  }
  if (!Number.isSafeInteger(n)) return false
  const db = getDb()
  if (item.kind === 'finding') {
    const f = await db.findings.get(n)
    if (f?.caseId !== kase.id) return false
    st.setFocusFinding(n)
    return true
  }
  // a server case's rows are read from its own store, where every id is of that case
  if (kase.storage !== 'server') {
    const row = item.kind === 'event' ? await db.events.get(n) : await db.mails.get(n)
    if (row?.caseId !== kase.id) return false
  }
  st.setFocus({ source: item.kind === 'event' ? 'events' : 'mails', id: n })
  return true
}

/**
 * Open what an address names: the case (only one this browser holds), the page and the item.
 * False when it names no case of this browser; the analyst is told, and nothing changes.
 */
export async function openRoute(route: Route): Promise<boolean> {
  const st = useStore.getState()
  if (route.view === 'home') {
    st.setView('home')
    return true
  }
  if (!route.caseRef) return false
  const kase = findCase(await getDb().cases.toArray(), route.caseRef)
  if (!kase) {
    toast('warn', NOT_HELD, 0)
    return false
  }
  const open = { ...kase, settings: { ...defaultSettings(), ...kase.settings } }
  if (st.currentCase?.id !== kase.id) st.setCurrentCase(open)
  if (route.item && !(await focusRouteItem(open, route.item))) log('warn', `the ${route.item.kind} the address names is not in case "${kase.name}", so it was not opened`)
  st.setView(route.view ?? 'dashboard')
  return true
}

// what the address carries beside the case and the page, as the page that shows it last said
let item: RouteItem | null = null
let syncing = false
let applying = false
let pending: 'push' | 'replace' | null = null
let timer: ReturnType<typeof setTimeout> | undefined

function here(): string {
  return location.pathname + location.search
}
function current(): string {
  const st = useStore.getState()
  return formatRoute(st.view, st.currentCase, item)
}
function depth(): number {
  const d = (history.state as { remn?: unknown } | null)?.remn
  return typeof d === 'number' ? d : 0
}
function flush() {
  const how = pending
  pending = null
  const url = current()
  if (url === here()) return
  if (how === 'push') history.pushState({ remn: depth() + 1 }, '', url)
  else history.replaceState({ remn: depth() }, '', url)
}
// a page change and the case change before it (a new case opens on its evidence) are one step of history
function schedule(how: 'push' | 'replace') {
  if (pending !== 'push') pending = how
  clearTimeout(timer)
  timer = setTimeout(flush, 0)
}

/** Whether Back stays in the application: an earlier page of this tab's visit is there. */
export function canGoBack(): boolean {
  return typeof history !== 'undefined' && depth() > 0
}

/**
 * Keep the address in step with the page from now on: a new page or case is a step of history, an
 * item opened on a page replaces the address in place. Back and Forward open the place they lead to
 * through openRoute. `opened` is the item the start handed to its page. Returns the function that
 * stops it.
 */
export function startHistorySync(opened: RouteItem | null = null): () => void {
  // the address as the start opened it: the item it named, when its page took it
  item = opened && ITEM_OF_VIEW[useStore.getState().view] === opened.kind ? opened : null
  history.replaceState({ remn: depth() }, '', current())
  syncing = true
  const unsubscribe = useStore.subscribe((s, prev) => {
    if (applying || (s.view === prev.view && s.currentCase?.id === prev.currentCase?.id)) return
    // the new page says which item is open, if any, once it has opened it
    item = null
    schedule('push')
  })
  const onPop = () => {
    clearTimeout(timer)
    pending = null
    const route = parseRoute(location.pathname, location.search)
    applying = true
    openRoute(route)
      .then((ok) => {
        const s = useStore.getState()
        item = ok && route.item && s.view === route.view ? route.item : null
      })
      .catch((e: Error) => log('err', `the address was not opened: ${e.message}`))
      .finally(() => {
        applying = false
        // what was opened, or the page still shown when the address named nothing of this browser
        history.replaceState(history.state, '', current())
      })
  }
  window.addEventListener('popstate', onPop)
  return () => {
    syncing = false
    clearTimeout(timer)
    pending = null
    unsubscribe()
    window.removeEventListener('popstate', onPop)
  }
}

/** A page says which item it has open (null: none); the address follows without a new step of history. */
export function setRouteItem(next: RouteItem | null): void {
  if (!syncing || applying) return
  if (next && ITEM_OF_VIEW[useStore.getState().view] !== next.kind) return
  if (next?.kind === item?.kind && next?.id === item?.id) return
  item = next
  schedule('replace')
}

/**
 * The page's open item, kept in the address. Nothing is written while the page opens empty, so an
 * item the address asked for is not dropped before the page has read it.
 */
export function useRouteItem(kind: ItemKind, id: string | number | null | undefined): void {
  const opened = useRef(false)
  useEffect(() => {
    if (id == null && !opened.current) return
    opened.current = true
    setRouteItem(id == null ? null : { kind, id: String(id) })
  }, [kind, id])
}
