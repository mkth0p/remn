import { expect, test } from '@playwright/test'
import path from 'node:path'

/**
 * The configuration remn.tech runs: FORENSIC_BROWSER_ONLY with the public profile, reached through a
 * host that is not loopback (Chromium sends *.localhost to 127.0.0.1, so the page sees a remote
 * server). What it checks is what a visitor relies on: the closed paths, the copy that names the
 * host, the notice before the first upload, no probe of their localhost, and the linked lab read to
 * its ground truth (14,000 events, 1,000 mails, the five planted attack chains).
 */
const LAB = path.resolve('.e2e-tmp/lab/quick-start')
const FILES = ['Mailboxes.mbox', 'Security.evtx', 'Sysmon.evtx', 'PowerShell.evtx', 'System.evtx', 'Defender.evtx', 'M365-UnifiedAuditLog.csv', 'M365-EntraSignIns.jsonl']
const HDR = { 'X-Forensic-Client': '1' }

test('a public browser-only instance says where evidence goes and reads the linked lab to its ground truth', async ({ page, request }) => {
  test.setTimeout(900_000)
  const health = await (await request.get('/api/health', { headers: HDR })).json()
  expect(health).toMatchObject({ mode: 'browser-only', profile: 'public' })
  expect(health.build).toMatch(/^\d+\.\d+\.\d+\+/)
  for (const closed of ['/api/store', '/api/jobs', '/api/reputation/providers', '/api/ai/models']) expect((await request.get(closed, { headers: HDR })).status()).toBe(403)

  const probes: string[] = []
  page.on('request', (r) => {
    if (r.url().includes(':11434')) probes.push(r.url())
  })
  await page.goto('/')
  await expect(page.getByText('parsing on remn.localhost')).toBeVisible()
  await expect(page.getByText(/uploaded to remn\.localhost/).first()).toBeVisible()
  await expect(page.getByText(/local server/)).toHaveCount(0)

  await page
    .locator('.dropzone input[type=file]')
    .first()
    .setInputFiles(FILES.map((n) => path.join(LAB, n)))
  await expect(page.getByText('Before you add evidence to remn.localhost')).toBeVisible()
  await page.getByRole('button', { name: 'I understand, add the evidence' }).click()

  await page.getByText('Evidence', { exact: true }).first().click()
  await expect(page.locator('tr').filter({ hasText: 'verified' })).toHaveCount(FILES.length, { timeout: 600_000 })
  await expect(page.locator('.nav-item', { hasText: 'Events' })).toContainText('14,000')
  await expect(page.locator('.nav-item', { hasText: 'Mails' })).toContainText('1,000')

  await page.getByText('Chains', { exact: true }).first().click()
  await page.getByRole('button', { name: /build chains/ }).click()
  await expect(page.getByText(/^5 chain\(s\)/)).toBeVisible({ timeout: 180_000 })

  expect(probes, 'a page served from another host must not probe the visitor’s localhost on its own').toEqual([])
})
