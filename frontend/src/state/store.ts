import { create } from 'zustand'
import type { Case, CaseSettings } from '../db/schema'
import type { Health, Meta } from '../api/client'
import type { Filter } from '../rules/filter'

export type View = 'dashboard' | 'evidence' | 'events' | 'mails' | 'findings' | 'timeline' | 'iocs' | 'ai' | 'report' | 'rules' | 'settings'

export interface ConsoleLine {
  id: number
  ts: number
  level: 'info' | 'ok' | 'warn' | 'err'
  text: string
}
export interface Toast {
  id: number
  kind: 'info' | 'ok' | 'warn' | 'err'
  text: string
}
export interface IngestJob {
  id: number
  evidenceId: number
  name: string
  kind: 'evtx' | 'mail'
  phase: 'hashing' | 'uploading' | 'parsing' | 'done' | 'error'
  progress: number // 0..1 for hashing, rows for parsing
  rows: number
  bytes: number
  error?: string
  startedAt: number
}

interface State {
  view: View
  setView: (v: View) => void
  currentCase: Case | null
  setCurrentCase: (c: Case | null) => void
  updateSettings: (patch: Partial<CaseSettings>) => void
  health: Health | null
  setHealth: (h: Health | null) => void
  meta: Meta | null
  setMeta: (m: Meta | null) => void
  console: ConsoleLine[]
  log: (level: ConsoleLine['level'], text: string) => void
  clearConsole: () => void
  toasts: Toast[]
  toast: (kind: Toast['kind'], text: string, ttl?: number) => void
  dismissToast: (id: number) => void
  jobs: IngestJob[]
  upsertJob: (job: Partial<IngestJob> & { id: number }) => void
  removeJob: (id: number) => void
  // cross-view navigation payloads
  eventsFilter: Filter
  setEventsFilter: (f: Filter | ((prev: Filter) => Filter)) => void
  mailsFilter: Filter
  setMailsFilter: (f: Filter | ((prev: Filter) => Filter)) => void
  focusId: { source: 'events' | 'mails'; id: number } | null
  setFocus: (f: { source: 'events' | 'mails'; id: number } | null) => void
  aiPrompt: string | null
  setAiPrompt: (p: string | null) => void
  counts: { events: number; mails: number; findings: number; iocs: number; evidence: number }
  setCounts: (c: Partial<State['counts']>) => void
  rulesVersion: number
  bumpRules: () => void
  storeThresholdMb: number
  setStoreThresholdMb: (mb: number) => void
  pendingIngest: { files: File[]; kindOverride?: 'evtx' | 'mail'; reason: 'big' | 'archive' } | null
  setPendingIngest: (p: State['pendingIngest']) => void
  aiConfig: { transport: 'browser' | 'server'; ollamaUrl: string; model: string; numCtx: number | null }
  setAiConfig: (patch: Partial<State['aiConfig']>) => void
  aiStatus: { reachable: boolean | null; error?: string; models?: number; checkedAt: number }
  setAiStatus: (s: State['aiStatus']) => void
  authRequired: boolean
  setAuthRequired: (v: boolean) => void
}

let seq = 1
export const useStore = create<State>((set) => ({
  view: 'dashboard',
  setView: (view) => set({ view }),
  currentCase: null,
  setCurrentCase: (currentCase) => set({ currentCase }),
  updateSettings: (patch) =>
    set((s) => (s.currentCase ? { currentCase: { ...s.currentCase, settings: { ...s.currentCase.settings, ...patch }, updatedAt: Date.now() } } : {})),
  health: null,
  setHealth: (health) => set({ health }),
  meta: null,
  setMeta: (meta) => set({ meta }),
  console: [],
  log: (level, text) => set((s) => ({ console: [...s.console.slice(-400), { id: seq++, ts: Date.now(), level, text }] })),
  clearConsole: () => set({ console: [] }),
  toasts: [],
  toast: (kind, text, ttl = 5000) => {
    const id = seq++
    set((s) => ({ toasts: [...s.toasts, { id, kind, text }] }))
    if (ttl > 0) setTimeout(() => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })), ttl)
  },
  dismissToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
  jobs: [],
  upsertJob: (job) =>
    set((s) => {
      const idx = s.jobs.findIndex((j) => j.id === job.id)
      if (idx === -1) return { jobs: [...s.jobs, { name: '', kind: 'evtx', evidenceId: 0, phase: 'hashing', progress: 0, rows: 0, bytes: 0, startedAt: Date.now(), ...job } as IngestJob] }
      const next = s.jobs.slice()
      next[idx] = { ...next[idx], ...job }
      return { jobs: next }
    }),
  removeJob: (id) => set((s) => ({ jobs: s.jobs.filter((j) => j.id !== id) })),
  eventsFilter: {},
  setEventsFilter: (f) => set((s) => ({ eventsFilter: typeof f === 'function' ? f(s.eventsFilter) : f })),
  mailsFilter: {},
  setMailsFilter: (f) => set((s) => ({ mailsFilter: typeof f === 'function' ? f(s.mailsFilter) : f })),
  focusId: null,
  setFocus: (focusId) => set({ focusId }),
  aiPrompt: null,
  setAiPrompt: (aiPrompt) => set({ aiPrompt }),
  counts: { events: 0, mails: 0, findings: 0, iocs: 0, evidence: 0 },
  setCounts: (c) => set((s) => ({ counts: { ...s.counts, ...c } })),
  rulesVersion: 0,
  bumpRules: () => set((s) => ({ rulesVersion: s.rulesVersion + 1 })),
  storeThresholdMb: 150,
  setStoreThresholdMb: (storeThresholdMb) => set({ storeThresholdMb }),
  pendingIngest: null,
  setPendingIngest: (pendingIngest) => set({ pendingIngest }),
  aiConfig: { transport: 'browser', ollamaUrl: 'http://localhost:11434', model: '', numCtx: null },
  setAiConfig: (patch) => set((s) => ({ aiConfig: { ...s.aiConfig, ...patch } })),
  aiStatus: { reachable: null, checkedAt: 0 },
  setAiStatus: (aiStatus) => set({ aiStatus }),
  authRequired: false,
  setAuthRequired: (authRequired) => set({ authRequired }),
}))

export const log = (level: ConsoleLine['level'], text: string) => useStore.getState().log(level, text)
export const toast = (kind: Toast['kind'], text: string, ttl?: number) => useStore.getState().toast(kind, text, ttl)
