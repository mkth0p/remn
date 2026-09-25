import { expect, test } from '@playwright/test'
import { execFileSync } from 'node:child_process'
import path from 'node:path'

test('mixed package coverage and evidence-backed relationships explored in the built browser app', async ({ page }, testInfo) => {
  const target = testInfo.outputPath('investigation-package.zip')
  const python = process.env.REMN_TEST_PYTHON ?? (process.platform === 'win32' ? '../.venv/Scripts/python.exe' : '../.venv/bin/python')
  execFileSync(python, ['../samples/synthetic/make_package.py', '--out', target])
  await page.goto('/')
  await page.getByText('Evidence', { exact: true }).first().click()
  await page.locator('input[type=file]').first().setInputFiles(target)
  await expect(page.getByText('what is inside the archive(s)?')).toBeVisible()
  await expect(page.getByText('Investigation package (detect every member, including mixed mail and events)', { exact: true })).toBeAttached()
  // The package is small, so retain browser storage.
  await page
    .getByRole('button', { name: /ingest|import|continue/i })
    .filter({ hasNotText: 'folder' })
    .last()
    .click()
  const evidence = page.locator('tr').filter({ hasText: path.basename(target) })
  await expect(evidence).toContainText('done', { timeout: 90000 })
  await expect(evidence).toContainText('partial coverage')
  await evidence.click()
  await expect(page.getByRole('heading', { name: 'Package coverage' })).toBeVisible()
  await expect(page.locator('tr').filter({ hasText: 'Prefetch Files/POWERSHELL.pf' })).toContainText('parsed')
  await expect(page.locator('tr').filter({ hasText: 'Prefetch Files/unknown.bin' })).toContainText('unsupported')
  await page.getByRole('button', { name: 'close', exact: true }).last().click()

  // Explore, on the Stories page: the relationship graph is built once, then browsed entity by entity.
  await page.getByText('Stories', { exact: true }).first().click()
  await page.getByRole('button', { name: 'Explore', exact: true }).click()
  await page.getByRole('button', { name: 'Build relationships' }).click()
  // The attachment SHA-256 is also reported by a collected process row, so the digest ties two source files.
  await page.getByRole('combobox', { name: 'Entity type' }).selectOption('hash')
  await page
    .getByRole('button')
    .filter({ hasText: /^hash ·/ })
    .first()
    .click()
  await expect(page.getByRole('img', { name: 'Connections around the selected entity' })).toBeVisible()
  await expect(page.getByText('reported digest', { exact: true }).first()).toBeVisible()
  const link = page
    .locator('details')
    .filter({ has: page.getByText('attachment digest', { exact: true }) })
    .first()
  await expect(link).toBeVisible()
  await link.locator('summary').click()
  await link.getByLabel('Relationship decision').selectOption('accepted')
  await link.getByLabel('Include accepted link in report').check()
  await link.getByLabel('Relationship notes').fill('The collected process and attachment report the same SHA-256.')
  await link.getByRole('button', { name: 'Save relationship review' }).click()
  await expect(link.getByText('Saved', { exact: true })).toBeVisible()

  // the graph is kept for the next visit
  await page.getByText('Evidence', { exact: true }).first().click()
  await page.getByText('Stories', { exact: true }).first().click()
  await page.getByRole('button', { name: 'Explore', exact: true }).click()
  await expect(page.getByRole('button', { name: 'Rebuild relationships' })).toBeVisible()
  await page.getByText('Report', { exact: true }).first().click()
  const report = page.frameLocator('iframe[title="report preview"]')
  await expect(report.getByRole('heading', { name: /Reviewed evidence relationships/ })).toBeVisible()
  await expect(report.getByText('The collected process and attachment report the same SHA-256.', { exact: true })).toBeVisible()
  await page.screenshot({ path: testInfo.outputPath('relationships.png'), fullPage: true })
})
