import type { Health } from '../api/client'

/** The build of this page, stamped by vite.config.ts from the source commit ('' in development). */
export const PAGE_BUILD: string = typeof __REMN_BUILD__ === 'string' ? __REMN_BUILD__ : ''

export type Tier = 'this-machine' | 'uploaded-not-kept' | 'self-hosted'

export interface Deployment {
  tier: Tier
  /** the host that parses evidence, as the address bar shows it */
  host: string
  /** one sentence on where a file goes, for the places a visitor decides to add one */
  parsing: string
  /** where the rows of a browser-store case live */
  storage: string
  /** the server's build and the page's, and where the exact source can be read */
  build: string
  pageBuild: string
  source: string
  /** the page was built from a different commit than the server it talks to */
  mismatch: boolean
  /** the server says it runs the public profile: staging in RAM only, no route off the host */
  isolated: boolean
  /** how long an abandoned upload may stay staged, in minutes, when the server says */
  abandonedMinutes: number | null
}

const LOOPBACK = /^(localhost|127(?:\.\d{1,3}){3}|\[?::1\]?)$/i

/**
 * Where evidence is processed and kept, said the same way on every page. "Browser-only" names
 * where a case is stored: on a public instance every file is still uploaded to the server to be
 * parsed, and the copy must say so and name the host.
 */
export function deployment(health: Health | null | undefined, hostname: string = typeof location === 'undefined' ? 'localhost' : location.hostname): Deployment {
  const local = LOOPBACK.test(hostname)
  const browserOnly = health?.mode === 'browser-only'
  const tier: Tier = local ? 'this-machine' : browserOnly ? 'uploaded-not-kept' : 'self-hosted'
  const host = hostname || 'this server'
  const build = health?.build ?? (health?.version ? `${health.version}` : '')
  const serverCommit = build.split('+')[1] ?? ''
  const pageCommit = PAGE_BUILD.split('+')[1] ?? PAGE_BUILD
  const parsing =
    tier === 'this-machine'
      ? 'Files are hashed (SHA-256) in the browser and parsed by REMN on this machine.'
      : tier === 'uploaded-not-kept'
        ? `Files are hashed (SHA-256) in the browser, then uploaded to ${host}, which parses them and deletes them when the parse ends. It keeps no copy, no rows and no file names.`
        : `Files are hashed (SHA-256) in the browser, then uploaded to ${host}, the REMN server your organisation runs, to be parsed.`
  return {
    tier,
    host,
    parsing,
    storage: "The rows, findings and notes are stored only in this browser (IndexedDB), until the case is deleted or the browser's site data is cleared.",
    build,
    pageBuild: PAGE_BUILD,
    source: health?.source ?? 'https://github.com/mkth0p/remn',
    isolated: health?.profile === 'public',
    abandonedMinutes: health?.limits?.uploadMaxAgeS ? Math.round(health.limits.uploadMaxAgeS / 60) : null,
    mismatch: !!serverCommit && !!pageCommit && serverCommit !== 'unknown' && pageCommit !== 'unknown' && !serverCommit.startsWith(pageCommit) && !pageCommit.startsWith(serverCommit),
  }
}
