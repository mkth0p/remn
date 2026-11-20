// @vitest-environment jsdom
import { act, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case } from '../db/schema'
import { useStore } from './store'
import { canGoBack, caseRef, findCase, formatRoute, openRoute, parseRoute, setRouteItem, startHistorySync, useRouteItem } from './route'

// invented cases: two of this browser, and one of another browser that has the same number as the first
const lab: Case = { id: 1, name: 'Lab', createdAt: 1_700_000_000_000, updatedAt: 1, settings: defaultSettings(), storage: 'browser' }
const second: Case = { id: 2, name: 'Second', createdAt: 1_700_000_500_000, updatedAt: 1, settings: defaultSettings(), storage: 'browser' }
const elsewhere: Case = { ...lab, name: 'Another browser', createdAt: 1_600_000_000_000 }

const tick = () => new Promise((r) => setTimeout(r, 5))
const popTo = async (url: string) => {
  history.pushState(null, '', url)
  window.dispatchEvent(new PopStateEvent('popstate'))
  for (let i = 0; i < 20 && location.pathname + location.search !== url; i++) await tick()
  await tick()
}
const here = () => location.pathname + location.search

let db: RemnDB
let stop: (() => void) | undefined
beforeEach(async () => {
  db = new RemnDB(`route-${Math.random()}`)
  setDb(db)
  await db.cases.bulkAdd([lab, second])
  history.replaceState(null, '', '/')
  useStore.setState({ currentCase: lab, view: 'dashboard', toasts: [], console: [], focusFinding: null, focusId: null, focusChain: null })
})
afterEach(async () => {
  stop?.()
  stop = undefined
  await db.delete()
})

describe('the address of a page', () => {
  it('names the case, the page and the open item, and reads back the same place', () => {
    const url = formatRoute('findings', lab, { kind: 'finding', id: '42' })
    expect(url).toBe(`/case/${caseRef(lab)}/findings?finding=42`)
    const [path, search] = url.split('?')
    expect(parseRoute(path, `?${search}`)).toEqual({ view: 'findings', caseRef: caseRef(lab), item: { kind: 'finding', id: '42' } })
  })

  it('keeps a story with its step, the "#" written so that the address does not cut it', () => {
    const url = formatRoute('stories', lab, { kind: 'story', id: 'story-7#step-2' })
    expect(url).toContain('?story=story-7%23step-2')
    const u = new URL(url, 'http://remn.localhost')
    expect(parseRoute(u.pathname, u.search).item).toEqual({ kind: 'story', id: 'story-7#step-2' })
  })

  it('reads only the item of the page it names', () => {
    expect(parseRoute(`/case/${caseRef(lab)}/events`, '?finding=3').item).toBeNull()
    expect(parseRoute(`/case/${caseRef(lab)}/report`, '?mail=3').item).toBeNull()
    expect(formatRoute('report', lab, { kind: 'mail', id: '3' })).toBe(`/case/${caseRef(lab)}/report`)
  })

  it('opens the dashboard for a page this version does not have, and leaves an address of no case to the start', () => {
    expect(parseRoute(`/case/${caseRef(lab)}/no-such-page`, '').view).toBe('dashboard')
    expect(parseRoute(`/case/${caseRef(lab)}`, '').view).toBe('dashboard')
    expect(parseRoute('/', '')).toEqual({ view: null, caseRef: null, item: null })
    expect(parseRoute('/somewhere/else', '')).toEqual({ view: null, caseRef: null, item: null })
    expect(parseRoute('/home', '')).toEqual({ view: 'home', caseRef: null, item: null })
    expect(formatRoute('home', lab)).toBe('/home')
  })

  it('holds no dot, so the servers that hand the page to every address without one serve it', () => {
    expect(formatRoute('questions', { id: 123, createdAt: 1_799_999_999_999.5 }, null)).not.toMatch(/\./)
  })

  it('does not match a case of the same number created in another browser', () => {
    expect(findCase([lab, second], caseRef(lab))).toBe(lab)
    expect(findCase([elsewhere], caseRef(lab))).toBeUndefined()
  })
})

describe('opening an address', () => {
  it('opens a case this browser holds on the page it names, and hands the finding to the page', async () => {
    const id = await db.findings.add({
      caseId: 2,
      key: 'k',
      ruleId: 'r',
      title: 't',
      severity: 'low',
      source: 'events',
      ts: 1,
      entities: {},
      count: 1,
      refs: [],
      attack: [],
      status: 'new',
      createdAt: 1,
    })
    expect(await openRoute({ view: 'findings', caseRef: caseRef(second), item: { kind: 'finding', id: String(id) } })).toBe(true)
    const st = useStore.getState()
    expect(st.currentCase?.id).toBe(2)
    expect(st.view).toBe('findings')
    expect(st.focusFinding).toBe(id)
  })

  it('does not hand on a finding of another case, as no click inside the case could open it', async () => {
    const id = await db.findings.add({
      caseId: 1,
      key: 'k',
      ruleId: 'r',
      title: 't',
      severity: 'low',
      source: 'events',
      ts: 1,
      entities: {},
      count: 1,
      refs: [],
      attack: [],
      status: 'new',
      createdAt: 1,
    })
    expect(await openRoute({ view: 'findings', caseRef: caseRef(second), item: { kind: 'finding', id: String(id) } })).toBe(true)
    expect(useStore.getState().focusFinding).toBeNull()
    expect(
      useStore
        .getState()
        .console.map((l) => l.text)
        .join('\n'),
    ).toContain('is not in case "Second"')
  })

  it('does not hand on a mail row of another case of the browser store', async () => {
    const mail = await db.mails.add({ caseId: 1, evidenceId: 1, date: 1 } as never)
    await openRoute({ view: 'mails', caseRef: caseRef(second), item: { kind: 'mail', id: String(mail) } })
    expect(useStore.getState().focusId).toBeNull()
    await openRoute({ view: 'mails', caseRef: caseRef(lab), item: { kind: 'mail', id: String(mail) } })
    expect(useStore.getState().focusId).toEqual({ source: 'mails', id: mail })
  })

  it('refuses a case this browser does not hold, says so, and changes nothing', async () => {
    await db.cases.clear()
    await db.cases.add(elsewhere)
    useStore.setState({ currentCase: second, view: 'events' })
    expect(await openRoute({ view: 'findings', caseRef: caseRef(lab), item: null })).toBe(false)
    const st = useStore.getState()
    expect(st.currentCase?.id).toBe(2)
    expect(st.view).toBe('events')
    expect(st.toasts.map((t) => t.text).join('\n')).toContain('does not hold')
  })
})

describe('the address following the pages', () => {
  it('writes the page shown at start, then makes each new page a step that Back returns from', async () => {
    stop = startHistorySync()
    expect(here()).toBe(`/case/${caseRef(lab)}/dashboard`)
    expect(canGoBack()).toBe(false)
    useStore.getState().setView('events')
    await tick()
    expect(here()).toBe(`/case/${caseRef(lab)}/events`)
    expect(canGoBack()).toBe(true)
    await popTo(`/case/${caseRef(lab)}/dashboard`)
    expect(useStore.getState().view).toBe('dashboard')
  })

  it('makes a case change and the page it opens on one step', async () => {
    stop = startHistorySync()
    const before = history.length
    useStore.getState().setCurrentCase(second)
    useStore.getState().setView('evidence')
    await tick()
    expect(here()).toBe(`/case/${caseRef(second)}/evidence`)
    expect(history.length).toBe(before + 1)
  })

  it('keeps the open item in place, without a new step', async () => {
    useStore.setState({ view: 'findings' })
    stop = startHistorySync()
    const before = history.length
    setRouteItem({ kind: 'finding', id: '9' })
    await tick()
    expect(here()).toBe(`/case/${caseRef(lab)}/findings?finding=9`)
    setRouteItem(null)
    await tick()
    expect(here()).toBe(`/case/${caseRef(lab)}/findings`)
    // an item of another page is not this page's
    setRouteItem({ kind: 'mail', id: '3' })
    await tick()
    expect(here()).toBe(`/case/${caseRef(lab)}/findings`)
    expect(history.length).toBe(before)
  })

  it('keeps the item the start opened, and drops it with the page', async () => {
    useStore.setState({ view: 'mails' })
    history.replaceState(null, '', `/case/${caseRef(lab)}/mails?mail=5`)
    stop = startHistorySync({ kind: 'mail', id: '5' })
    expect(here()).toBe(`/case/${caseRef(lab)}/mails?mail=5`)
    useStore.getState().setView('events')
    await tick()
    expect(here()).toBe(`/case/${caseRef(lab)}/events`)
  })

  it('stays where it is when Back leads to a case this browser no longer holds', async () => {
    stop = startHistorySync()
    await db.cases.delete(2)
    await popTo(`/case/${caseRef(second)}/findings`)
    expect(useStore.getState().currentCase?.id).toBe(1)
    expect(here()).toBe(`/case/${caseRef(lab)}/dashboard`)
    expect(
      useStore
        .getState()
        .toasts.map((t) => t.text)
        .join('\n'),
    ).toContain('does not hold')
  })

  it('opens the case and the page Back leads to, without adding a step of its own', async () => {
    stop = startHistorySync()
    const before = history.length
    await popTo(`/case/${caseRef(second)}/report`)
    expect(useStore.getState().currentCase?.id).toBe(2)
    expect(useStore.getState().view).toBe('report')
    await tick()
    // popTo itself pushed the entry the browser would already hold; opening it added none
    expect(history.length).toBe(before + 1)
  })

  it('leaves the item the address asked for while the page opens empty, then follows what the page opens', async () => {
    useStore.setState({ view: 'findings' })
    history.replaceState(null, '', `/case/${caseRef(lab)}/findings?finding=5`)
    stop = startHistorySync({ kind: 'finding', id: '5' })
    const page = renderHook(({ id }: { id: number | null }) => useRouteItem('finding', id), { initialProps: { id: null as number | null } })
    await act(tick)
    expect(here()).toBe(`/case/${caseRef(lab)}/findings?finding=5`)
    page.rerender({ id: 7 })
    await act(tick)
    expect(here()).toBe(`/case/${caseRef(lab)}/findings?finding=7`)
    page.rerender({ id: null })
    await act(tick)
    expect(here()).toBe(`/case/${caseRef(lab)}/findings`)
    page.unmount()
  })
})
