import { expect, test } from '@playwright/test'

test('the address keeps the case and the page across a reload, Back and Forward, and refuses the case of another browser', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: /^Open case/ }).click()
  const title = page.locator('.topbar .title')
  await page.getByText('Evidence', { exact: true }).first().click()
  await expect(page).toHaveURL(/\/case\/\d+-[0-9a-z]+\/evidence$/)
  await page.getByText('Case notes', { exact: true }).first().click()
  await expect(page).toHaveURL(/\/case\/\d+-[0-9a-z]+\/case$/)
  await expect(page).toHaveTitle('Case notes · REMN')
  await page.reload()
  await expect(title).toHaveText('Case notes')
  await page.goBack()
  await expect(title).toHaveText('Evidence')
  await page.goForward()
  await expect(title).toHaveText('Case notes')
  // the same case number, created at another time: a case of another browser
  const other = new URL(page.url()).pathname.replace(/^\/case\/(\d+)-[0-9a-z]+\//, '/case/$1-1/')
  await page.goto(other)
  await expect(page.getByText(/names a case this browser does not hold/)).toBeVisible()
  // the start goes on as without the link: no case holds evidence, so the home page
  await expect(page).toHaveURL(/\/home$/)
})
