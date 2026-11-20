// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Health, ProviderInfo } from '../api/client'
import { defaultSettings, RemnDB, setDb, type Case } from '../db/schema'
import { useStore } from '../state/store'
import { SettingsView } from './SettingsView'
import { ConfirmHost } from '../components/ConfirmHost'

// the server answers the access of a shared case and the size of its store
const api = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('../api/client', async (importOriginal) => ({ ...(await importOriginal<typeof import('../api/client')>()), apiGet: api.get }))
// the model connection and the trusted-sender scan are answered here, not by a model or the evidence
const ai = vi.hoisted(() => ({ ping: vi.fn(), listModels: vi.fn(), claude: vi.fn(), suggest: vi.fn() }))
vi.mock('../ai/transport', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../ai/transport')>()),
  getTransport: () => ({ kind: 'browser', endpoint: 'http://localhost:11434', ping: ai.ping, listModels: ai.listModels }),
  fetchClaudeStatus: ai.claude,
}))
vi.mock('../data/trusted', () => ({ suggestTrustedSenders: ai.suggest }))

/** The page with the app's confirmation dialog, as App mounts it. */
const page = () => (
  <>
    <SettingsView />
    <ConfirmHost />
  </>
)
/** Answer the confirmation dialog the last action opened. */
const answer = async (button: 'Cancel' | 'Delete' | 'Remove') => fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: button }))

const kase: Case = { id: 1, name: 'Northwind intrusion', analyst: 'analyst one', notes: '', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
const provider = (name: string, configured: boolean): ProviderInfo => ({ name, kinds: ['ip'], configured, needsKey: configured ? null : 'EXAMPLE', description: name, homepage: '' })
const health = (over: Partial<Health> = {}): Health =>
  ({
    ok: true,
    name: 'remn',
    version: '0.0.0',
    stateless: false,
    mode: 'full',
    limits: { maxUploadMb: 512, inMemoryMb: 64 },
    ollama: { reachable: false, host: 'http://ollama.invalid', models: [], defaultModel: 'qwen3:8b' },
    optional: {},
    providers: [provider('alpha-lookup', true), provider('beta-lookup', true), provider('gamma-lookup', false)],
    ...over,
  }) as Health

let db: RemnDB
beforeEach(async () => {
  db = new RemnDB(`settings-${Math.random()}`)
  setDb(db)
  await db.cases.add(kase)
  useStore.setState({
    currentCase: kase,
    view: 'settings',
    health: health(),
    toasts: [],
    aiConfig: { transport: 'browser', ollamaUrl: 'http://localhost:11434', openaiUrl: 'http://localhost:1234/v1', model: '', numCtx: null, claudeModel: 'sonnet' },
    aiStatus: { reachable: null, checkedAt: 0 },
    storeThresholdMb: 150,
  })
  api.get.mockReset()
  ai.ping.mockReset()
  ai.listModels.mockReset()
  ai.claude.mockReset()
  ai.suggest.mockReset()
})
afterEach(async () => {
  cleanup()
  vi.restoreAllMocks()
  await new Promise((r) => setTimeout(r, 50))
  await db.delete()
})

const toasts = () => useStore.getState().toasts.map((t) => t.text)
const saved = async () => (await db.cases.get(1))!
const panel = (title: string) => Array.from(document.querySelectorAll('.panel')).find((p) => p.querySelector('.panel-h')?.textContent === title) as HTMLElement
const listInput = (placeholder: string) => screen.getByPlaceholderText((_, el) => el?.getAttribute('placeholder') === placeholder) as HTMLTextAreaElement
const setList = (placeholder: string, text: string) => {
  const el = listInput(placeholder)
  fireEvent.change(el, { target: { value: text } })
  fireEvent.blur(el)
}
const toggle = (label: string) => {
  const sw = Array.from(document.querySelectorAll('[role="switch"]')).find((s) => s.parentElement?.textContent?.includes(label))
  if (!sw) throw new Error(`no switch labelled ${label}`)
  fireEvent.click(sw)
}
const kv = async (key: string) => (await db.kv.get(key))?.value

describe('SettingsView', () => {
  it('saves the case’s name, analyst and notes, and keeps the old name when the new one is blank', async () => {
    render(<SettingsView />)
    const casePanel = panel('case')
    const [name, analyst] = Array.from(casePanel.querySelectorAll('input'))
    fireEvent.change(name, { target: { value: '   ' } })
    fireEvent.change(analyst, { target: { value: '  analyst two ' } })
    fireEvent.change(casePanel.querySelector('textarea')!, { target: { value: 'scope: the mail server' } })
    fireEvent.click(screen.getByText('save'))
    await waitFor(() => expect(toasts()).toContain('case saved'))
    const row = await saved()
    expect(row.name).toBe('Northwind intrusion')
    expect(row.analyst).toBe('analyst two')
    expect(row.notes).toBe('scope: the mail server')
    expect(useStore.getState().currentCase?.analyst).toBe('analyst two')
  })

  it('writes the organisation lists to the case, lower-casing domains and dropping a leading @', async () => {
    render(<SettingsView />)
    setList('company.com\ncompany.fr', '@Example.COM\nexample.org')
    setList('notifications.supplier.com\nfacture@partenaire.fr', '@Billing.Example.net')
    setList('mybank\nmysupplier', 'ExampleBank')
    setList('FR\nDE\nUS', 'fr\n de ')
    await waitFor(async () => expect((await saved()).settings.expectedCountries).toEqual(['FR', 'DE']))
    const s = (await saved()).settings
    expect(s.internalDomains).toEqual(['example.com', 'example.org'])
    expect(s.trustedSenders).toEqual(['billing.example.net'])
    expect(s.brands).toEqual(['examplebank'])
    expect(useStore.getState().currentCase?.settings.internalDomains).toEqual(['example.com', 'example.org'])
  })

  it('sets business hours and weekend days, and shows timestamps in local time on request', async () => {
    render(<SettingsView />)
    const time = panel('time')
    const [start, end] = Array.from(time.querySelectorAll('input[type="number"]'))
    fireEvent.change(start, { target: { value: '7' } })
    fireEvent.change(end, { target: { value: '19' } })
    const sat = Array.from(time.querySelectorAll('label.checkbox'))
      .find((l) => l.textContent?.trim() === 'Sat')!
      .querySelector('input')!
    const sun = Array.from(time.querySelectorAll('label.checkbox'))
      .find((l) => l.textContent?.trim() === 'Sun')!
      .querySelector('input')!
    const weekend = defaultSettings().weekendDays
    fireEvent.click(weekend.includes(6) ? sat : sun)
    await waitFor(async () => expect((await saved()).settings.weekendDays).toEqual(weekend.includes(6) ? weekend.filter((d) => d !== 6) : [...weekend, 0].sort()))
    expect((await saved()).settings.businessHours.end).toBe(19)
    toggle('display timestamps in local time')
    await waitFor(async () => expect(await kv('localTime')).toBe(true))
    expect(toasts()).toContain('timestamps shown in local time')
  })

  it('switches the analyst model’s transport, remembers it, and refuses a model server off this network', async () => {
    render(<SettingsView />)
    fireEvent.click(screen.getByLabelText(/Local OpenAI-compatible server/))
    await waitFor(async () => expect(await kv('aiTransport')).toBe('openai'))
    expect(useStore.getState().aiConfig.transport).toBe('openai')
    const url = screen.getByPlaceholderText('http://localhost:1234/v1')
    fireEvent.change(url, { target: { value: 'https://models.example.com/v1/' } })
    expect(screen.getByText(/not a local address: REMN only sends evidence to a model server/)).toBeTruthy()
    fireEvent.click(screen.getByText('llama.cpp'))
    await waitFor(async () => expect(await kv('aiOpenaiUrl')).toBe('http://localhost:8080/v1'))
    expect(screen.getByText(/llama-server -m model.gguf/)).toBeTruthy()
    fireEvent.change(screen.getByPlaceholderText('qwen3:8b'), { target: { value: 'example-model:7b' } })
    await waitFor(async () => expect(await kv('aiModel')).toBe('example-model:7b'))
  })

  it('offers only the page’s own model connections on a browser-only server', () => {
    useStore.setState({ health: health({ mode: 'browser-only' }) })
    render(<SettingsView />)
    expect(screen.getByText(/This server runs in browser-only mode/)).toBeTruthy()
    expect(screen.queryByText('Server proxy')).toBeNull()
    expect(screen.queryByText('Claude Code')).toBeNull()
    expect(screen.queryByText('convert this case to the server store')).toBeNull()
    expect(screen.getByText(/Reputation lookups are switched off on this server/)).toBeTruthy()
  })

  it('tests the model connection and lists the models it found', async () => {
    ai.ping.mockResolvedValue({ reachable: true, models: 2 })
    ai.listModels.mockResolvedValue([{ name: 'example-model:7b' }, { name: 'example-model:14b' }])
    render(<SettingsView />)
    fireEvent.click(screen.getByText('test connection'))
    await waitFor(() => expect(screen.getByText('✓ reachable · 2 model(s)')).toBeTruthy())
    expect(toasts()).toContain('Ollama reachable (http://localhost:11434) - 2 model(s)')
    expect(Array.from(document.querySelectorAll('#ai-models option')).map((o) => o.getAttribute('value'))).toEqual(['example-model:7b', 'example-model:14b'])
    ai.ping.mockResolvedValue({ reachable: false, error: 'connection refused' })
    fireEvent.click(screen.getByText('test connection'))
    await waitFor(() => expect(screen.getByText('✗ unreachable')).toBeTruthy())
    expect(toasts()).toContain('connection refused')
  })

  it('says whether Claude Code is ready on the server machine when it is the transport', async () => {
    useStore.setState({ aiConfig: { ...useStore.getState().aiConfig, transport: 'claude' } })
    ai.claude.mockResolvedValue({ enabled: true, available: true, loggedIn: true })
    render(<SettingsView />)
    await waitFor(() => expect(screen.getByText('installed and signed in')).toBeTruthy())
    fireEvent.change(document.querySelector('select.select')!, { target: { value: 'haiku' } })
    await waitFor(async () => expect(await kv('aiClaudeModel')).toBe('haiku'))
  })

  it('chooses reputation providers among those the server has configured, and remembers the store threshold', async () => {
    render(<SettingsView />)
    const lookups = panel('external lookups (opt-in)')
    const box = (name: string) =>
      Array.from(lookups.querySelectorAll('label.checkbox'))
        .find((l) => l.textContent?.includes(name))!
        .querySelector('input')!
    expect(box('alpha-lookup').checked).toBe(true)
    expect(box('gamma-lookup').disabled).toBe(true)
    expect(lookups.textContent).toContain('needs EXAMPLE key')
    fireEvent.click(box('beta-lookup'))
    await waitFor(async () => expect((await saved()).settings.providers).toEqual(['alpha-lookup']))
    toggle('allow reputation lookups')
    await waitFor(async () => expect((await saved()).settings.networkAllowed).toBe(!defaultSettings().networkAllowed))
    fireEvent.change(panel('storage').querySelector('input[type="number"]')!, { target: { value: '400' } })
    await waitFor(async () => expect(await kv('storeThresholdMb')).toBe(400))
    expect(useStore.getState().storeThresholdMb).toBe(400)
  })

  it('suggests trusted senders and adds only those left ticked', async () => {
    ai.suggest.mockResolvedValue([
      { registrable: 'supplier.example', count: 12, sample: 'billing@supplier.example' },
      { registrable: 'newsletter.example', count: 6, sample: 'news@newsletter.example' },
    ])
    render(<SettingsView />)
    fireEvent.click(screen.getByText('suggest trusted senders'))
    await waitFor(() => expect(screen.getByText('Suggested trusted senders')).toBeTruthy())
    expect(screen.getByText('add 2 to trusted senders')).toBeTruthy()
    fireEvent.click(
      Array.from(document.querySelectorAll('.modal label.checkbox'))
        .find((l) => l.textContent?.includes('newsletter.example'))!
        .querySelector('input')!,
    )
    fireEvent.click(screen.getByText('add 1 to trusted senders'))
    await waitFor(async () => expect((await saved()).settings.trustedSenders).toEqual(['supplier.example']))
    expect(screen.queryByText('Suggested trusted senders')).toBeNull()
    expect(toasts()).toContain('1 trusted sender(s) added. Use Mails → rescore + refresh findings to apply the changes.')
  })

  it('says so when the scan finds no trusted sender to suggest', async () => {
    ai.suggest.mockResolvedValue([])
    render(<SettingsView />)
    fireEvent.click(screen.getByText('suggest trusted senders'))
    await waitFor(() => expect(toasts()).toContain('no candidates: needs senders with 5+ mails, passing auth and no strong indicator'))
    expect(screen.queryByText('Suggested trusted senders')).toBeNull()
  })

  it('empties a browser case after confirmation and keeps the case itself', async () => {
    await db.events.add({ caseId: 1, ts: 1000, source: 'security', eventId: 4624, host: 'ws-01' } as never)
    render(page())
    fireEvent.click(screen.getByText('delete all case data from this browser'))
    expect(within(await screen.findByRole('dialog', { name: 'Delete the case data' })).getByText(/Delete ALL data of case "Northwind intrusion"/)).toBeTruthy()
    await answer('Cancel')
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(await db.events.count()).toBe(1)
    fireEvent.click(screen.getByText('delete all case data from this browser'))
    await answer('Delete')
    await waitFor(() => expect(toasts()).toContain('case data deleted'))
    expect(await db.events.count()).toBe(0)
    expect(await db.cases.get(1)).toBeTruthy()
  })

  it('deletes the case and opens the most recently updated one left', async () => {
    await db.cases.add({ ...kase, id: 2, name: 'Second case', updatedAt: 50 })
    render(page())
    fireEvent.click(screen.getByText('delete this case'))
    await answer('Delete')
    await waitFor(() => expect(toasts()).toContain('case "Northwind intrusion" deleted'))
    expect(await db.cases.get(1)).toBeUndefined()
    expect(useStore.getState().currentCase?.id).toBe(2)
    expect(useStore.getState().view).toBe('dashboard')
  })

  it('closes the owner’s actions to a member of a shared server case, who may remove it from this browser only', async () => {
    const shared: Case = { ...kase, storage: 'server', serverKey: 'case-key-1' }
    await db.cases.put(shared)
    useStore.setState({ currentCase: shared, health: health({ accounts: true, account: { name: 'member-b', role: 'analyst' } }) })
    api.get.mockImplementation(async (path: string) =>
      path.endsWith('/access') ? { key: 'case-key-1', name: 'Northwind intrusion', owner: 'owner-a', members: ['member-b'], may: { read: true, write: true, own: false } } : { sizeBytes: 2048 },
    )
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
    render(page())
    await waitFor(() => expect(screen.getByText('remove this case from this browser')).toBeTruthy())
    await waitFor(() => expect(screen.getByText('case-key-1 · 2.00 KB')).toBeTruthy())
    const wipe = screen.getByText('delete all case data (browser + server store)') as HTMLButtonElement
    expect(wipe.disabled).toBe(true)
    expect(wipe.title).toBe("Only the case's owner or an admin may do this.")
    expect((screen.getByText('delete this case') as HTMLButtonElement).disabled).toBe(true)
    fireEvent.click(screen.getByText('remove this case from this browser'))
    await answer('Remove')
    await waitFor(() => expect(toasts()).toContain('case "Northwind intrusion" removed from this browser'))
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(await db.cases.get(1)).toBeUndefined()
  })
})
