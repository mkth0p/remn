import { expect, test } from '@playwright/test'
import path from 'node:path'

/**
 * The configuration remn.tech runs: FORENSIC_BROWSER_ONLY with the public profile, reached through a
 * host that is not loopback (Chromium sends *.localhost to 127.0.0.1, so the page sees a remote
 * server). What it checks is what a visitor relies on: the closed paths, the copy that names the
 * host, the notice before the first upload, no probe of their localhost, and the linked lab read to
 * its ground truth (14,000 events, 1,000 mails, one story for each of the five planted attacks).
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
  // the Events page searches and counts in a query worker, off the page's thread
  await page.locator('.nav-item', { hasText: 'Events' }).click()
  await expect(page.getByText('14,000 matches')).toBeVisible({ timeout: 60_000 })
  await expect(page.getByText(/showing the first 3,000 rows/)).toBeVisible()

  // the rules run once the last file is in; stories read before that carry no findings
  await expect(page.getByText(/finding\(s\) from \d+ rule\(s\)/).first()).toBeVisible({ timeout: 300_000 })
  // a case with findings and no stories yet is read into stories when the page opens
  await page.getByText('Stories', { exact: true }).first().click()
  await expect(page.locator('.view-header .sub').filter({ hasText: /stor(y|ies) ·/ })).toContainText('6 stories · 6 critical', { timeout: 180_000 })
  // the ground truth: one story for each planted attack, and the other tenant's alice.martin, who
  // cleared a log on her own host, a story of her own that none of Northstar's holds
  for (const who of ['alice.martin', 'benoit.durand', 'carla.morel', 'daniel.roy', 'farah.benali'])
    await expect(page.getByRole('button', { name: `Story ${who}@northstar.example`, exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Story alice.martin@other-tenant.example', exact: true })).toBeVisible()
  // the password-spray victim's story reads as phases, with its RDP logon a step of it
  await page.getByRole('button', { name: 'Story daniel.roy@northstar.example', exact: true }).click()
  const rail = page.getByRole('list', { name: 'ATT&CK phases of the story' })
  for (const phase of ['Initial access', 'Credential access', 'Lateral movement', 'Defense impairment']) await expect(rail.getByRole('listitem').filter({ hasText: phase })).toBeEnabled()
  // the story opens on its spine, the way in first; the full timeline is a toggle away
  await expect(page.locator('.spine .spine-step').filter({ hasText: 'RemoteInteractive' }).first()).toBeVisible()
  await page.getByRole('group', { name: 'what the story shows' }).getByRole('button', { name: 'Full timeline' }).click()
  await expect(page.locator('.story .step').filter({ hasText: 'RemoteInteractive' }).first()).toBeVisible()

  expect(probes, 'a page served from another host must not probe the visitor’s localhost on its own').toEqual([])
})
