/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath, URL } from 'node:url'
import { execSync } from 'node:child_process'
import { readFileSync } from 'node:fs'

/**
 * Content Security Policy of the built app. No inline script anywhere (React refresh needs
 * them only in dev, so the tag is added at build time). WebAssembly for hash-wasm, blob workers
 * for the rule and ingest workers, http(s) connections for a browser-direct Ollama on any host,
 * frames only for the sandboxed mail / report documents. frame-ancestors is enforced by the
 * server header (a meta tag cannot carry it).
 */
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "connect-src 'self' http: https:",
  "worker-src 'self' blob:",
  "frame-src 'self' blob: data: about:",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
].join('; ')
const cspPlugin = () => ({
  name: 'remn-csp',
  apply: 'build' as const,
  transformIndexHtml: (html: string) => html.replace('<meta charset="UTF-8" />', `<meta charset="UTF-8" />\n    <meta http-equiv="Content-Security-Policy" content="${CSP}" />`),
})

const BUILD_ID = Date.now().toString(36)

/**
 * The source commit this page is built from, shown beside the server's so a visitor can check both
 * against the published source. The image build passes it (REMN_BUILD_ID: the checkout's .git is
 * not copied in); a checkout reads it from git.
 */
function sourceCommit(): string {
  const fromEnv = (process.env.REMN_BUILD_ID ?? '').trim().toLowerCase()
  if (/^[0-9a-f]{40}$/.test(fromEnv)) return fromEnv
  try {
    return execSync('git rev-parse HEAD', { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim()
  } catch {
    return ''
  }
}
const COMMIT = sourceCommit()
const VERSION = (JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf-8')) as { version: string }).version
const REMN_BUILD = `${VERSION}+${COMMIT ? COMMIT.slice(0, 12) : 'unknown'}`

export default defineConfig({
  plugins: [react(), cspPlugin()],
  define: { __REMN_BUILD__: JSON.stringify(REMN_BUILD) },
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8000', changeOrigin: false },
    },
  },
  // every build gets its own file names: assets are served immutable for a year, and a build that
  // changes only headers (a content security policy, say) must still reach browsers that cached the
  // previous one; index.html is served no-store and points at the new names
  worker: { format: 'es', rollupOptions: { output: { entryFileNames: `assets/[name]-[hash].${BUILD_ID}.js`, chunkFileNames: `assets/[name]-[hash].${BUILD_ID}.js` } } },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    chunkSizeWarningLimit: 1500,
    rollupOptions: {
      output: { entryFileNames: `assets/[name]-[hash].${BUILD_ID}.js`, chunkFileNames: `assets/[name]-[hash].${BUILD_ID}.js`, assetFileNames: `assets/[name]-[hash].${BUILD_ID}[extname]` },
    },
  },
  test: {
    environment: 'node',
    include: ['src/**/*.test.{ts,tsx}'],
    setupFiles: ['src/test/setup.ts'],
  },
})
