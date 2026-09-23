import { execFileSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import path from 'node:path'

/** The synthetic linked lab, generated once: the browser-only test reads it to its ground truth. */
export default function globalSetup(): void {
  const out = path.resolve('.e2e-tmp/lab')
  if (existsSync(path.join(out, 'quick-start', 'Security.evtx'))) return
  const python = process.env.REMN_TEST_PYTHON ?? (process.platform === 'win32' ? '../.venv/Scripts/python.exe' : '../.venv/bin/python')
  execFileSync(python, ['../samples/synthetic/make_linked_lab.py', '--quick-only', '--out', out], { stdio: 'inherit' })
}
