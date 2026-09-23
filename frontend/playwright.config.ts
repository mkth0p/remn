import { defineConfig } from '@playwright/test'
import path from 'node:path'

const python = process.env.REMN_TEST_PYTHON ?? (process.platform === 'win32' ? '../.venv/Scripts/python.exe' : '../.venv/bin/python')
const tmp = (name: string) => path.resolve('.e2e-tmp', name)
export default defineConfig({
  testDir: './e2e',
  timeout: 120_000,
  workers: 1,
  globalSetup: './e2e/global-setup.ts',
  use: { trace: 'retain-on-failure' },
  projects: [
    { name: 'full', testIgnore: /(browser-only|demo-bundle)\.spec\.ts/, use: { baseURL: 'http://127.0.0.1:8317' } },
    // what remn.tech runs; *.localhost reaches 127.0.0.1 but the page sees another host
    { name: 'browser-only', testMatch: /(browser-only|demo-bundle)\.spec\.ts/, use: { baseURL: 'http://remn.localhost:8318' } },
  ],
  webServer: [
    {
      command: `"${python}" ../backend/run.py --port 8317`,
      url: 'http://127.0.0.1:8317',
      reuseExistingServer: false,
      env: { FORENSIC_AUTH_TOKEN: '', FORENSIC_CASES_DIR: tmp('cases'), FORENSIC_TMP_DIR: tmp('uploads'), TLDEXTRACT_CACHE: tmp('tldextract') },
    },
    {
      command: `"${python}" ../backend/run.py --port 8318`,
      url: 'http://127.0.0.1:8318',
      reuseExistingServer: false,
      env: {
        FORENSIC_AUTH_TOKEN: '',
        FORENSIC_BROWSER_ONLY: '1',
        FORENSIC_PROFILE: 'public',
        FORENSIC_ALLOWED_HOSTS: 'remn.localhost',
        FORENSIC_TMP_DIR: tmp('uploads-public'),
        TLDEXTRACT_CACHE: tmp('tldextract'),
        HAYABUSA_ENABLED: '0',
      },
    },
  ],
})
