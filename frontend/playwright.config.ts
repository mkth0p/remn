import { defineConfig } from '@playwright/test'
import path from 'node:path'

const python = process.env.REMN_TEST_PYTHON ?? (process.platform === 'win32' ? '../.venv/Scripts/python.exe' : '../.venv/bin/python')
export default defineConfig({
  testDir: './e2e',
  timeout: 120_000,
  workers: 1,
  use: { baseURL: 'http://127.0.0.1:8317', trace: 'retain-on-failure' },
  webServer: {
    command: `"${python}" ../backend/run.py --port 8317`,
    url: 'http://127.0.0.1:8317',
    reuseExistingServer: false,
    env: { FORENSIC_AUTH_TOKEN: '', FORENSIC_CASES_DIR: path.resolve('.e2e-tmp/cases'), FORENSIC_TMP_DIR: path.resolve('.e2e-tmp/uploads'), TLDEXTRACT_CACHE: path.resolve('.e2e-tmp/tldextract') },
  },
})
