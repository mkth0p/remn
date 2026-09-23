import { expect, test, type Page } from '@playwright/test'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { gzipSync } from 'node:zlib'

/**
 * The demo case (src/data/demoCase.ts). The first test writes it, only when asked
 * (npm run demo:bundle): the linked lab is read by the built app in the browser-only
 * configuration, the rules run, the chains are built, and the case bundle the app exports is
 * what the demo button restores. The bundle is therefore what a visitor's own browser would have
 * made of the lab, not a second implementation of it. The second test opens it as a visitor would.
 */
const LAB = path.resolve('.e2e-tmp/lab/quick-start')
const FILES = ['Mailboxes.mbox', 'Security.evtx', 'Sysmon.evtx', 'PowerShell.evtx', 'System.evtx', 'Defender.evtx', 'M365-UnifiedAuditLog.csv', 'M365-EntraSignIns.jsonl']
const OUT = path.resolve('public/demo/northstar-lab.remn.ndjson.gz')

const chainLine = (page: Page) =>
  page
    .locator('.view-header .sub, h1 + .sub, .sub')
    .filter({ hasText: /chain\(s\) ·/ })
    .first()

test('writes the demo case from the linked lab, as this app reads it', async ({ page }, testInfo) => {
  test.skip(!process.env.REMN_WRITE_DEMO, 'rewrites public/demo: run npm run demo:bundle')
  test.setTimeout(900_000)
  // the streamed download, not the file picker a test cannot answer
  await page.addInitScript(() => Object.defineProperty(window, 'showSaveFilePicker', { value: undefined }))
  await page.goto('/')
  await page
    .locator('.dropzone input[type=file]')
    .first()
    .setInputFiles(FILES.map((n) => path.join(LAB, n)))
  await page.getByRole('button', { name: 'I understand, add the evidence' }).click()
  await page.getByText('Evidence', { exact: true }).first().click()
  await expect(page.locator('tr').filter({ hasText: 'verified' })).toHaveCount(FILES.length, { timeout: 600_000 })
  await expect(page.getByText(/finding\(s\) from \d+ rule\(s\)/).first()).toBeVisible({ timeout: 300_000 })
  await page.getByText('Chains', { exact: true }).first().click()
  await page.getByRole('button', { name: /build chains/ }).click()
  await expect(chainLine(page)).toContainText('5 chain(s) · 5 critical', { timeout: 180_000 })
  await page.getByText('Report', { exact: true }).first().click()
  const downloaded = page.waitForEvent('download')
  await page.getByRole('button', { name: /export case bundle/ }).click()
  const bundle = testInfo.outputPath('demo.remn.ndjson')
  await (await downloaded).saveAs(bundle)
  await mkdir(path.dirname(OUT), { recursive: true })
  await writeFile(OUT, gzipSync(await readFile(bundle), { level: 9 }))
})

test('the demo case opens in the browser, with nothing uploaded', async ({ page }) => {
  test.setTimeout(300_000)
  const sent: string[] = []
  page.on('request', (r) => {
    if (/\/api\/(ingest|upload)/.test(r.url())) sent.push(r.url())
  })
  await page.goto('/')
  await page.getByRole('button', { name: 'open the demo case' }).click()
  await expect(page.locator('.nav-item', { hasText: 'Events' })).toContainText('14,000', { timeout: 120_000 })
  await expect(page.locator('.nav-item', { hasText: 'Mails' })).toContainText('1,000')
  // restored with its chains built and its findings attached
  await expect(chainLine(page)).toContainText('5 chain(s) · 5 critical', { timeout: 60_000 })
  expect(sent).toEqual([])
})
