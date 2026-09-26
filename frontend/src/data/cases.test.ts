import { afterEach, expect, it } from 'vitest'
import { defaultSettings, getDb } from '../db/schema'
import { casesWithEvidence, FIRST_CASE_NAME, startCase } from './cases'

afterEach(async () => {
  for (const table of getDb().tables) await table.clear()
})

const aCase = (name: string, extra: { notes?: string } = {}) => getDb().cases.add({ name, createdAt: 1, updatedAt: 1, settings: defaultSettings(), storage: 'browser', ...extra })
const evidence = (caseId: number) => getDb().evidence.add({ caseId, name: 'Security.evtx', kind: 'evtx', size: 1, status: 'done', integrity: 'verified', count: 1, addedAt: 1 })

it('lists the cases that hold evidence, each once', async () => {
  const a = await aCase('a')
  await aCase('b')
  const c = await aCase('c')
  await evidence(a)
  await evidence(a)
  await evidence(c)
  expect([...(await casesWithEvidence())].sort()).toEqual([a, c].sort())
})

it('finds none before anything is imported', async () => {
  await aCase(FIRST_CASE_NAME)
  expect((await casesWithEvidence()).size).toBe(0)
})

it("takes over the first visit's untouched case rather than leaving it empty beside the new one", async () => {
  const first = await aCase(FIRST_CASE_NAME)
  const c = await startCase('  Finance laptop ', 'server')
  expect(c.id).toBe(first)
  expect(c).toMatchObject({ name: 'Finance laptop', storage: 'server' })
  expect(c.serverKey).toBeTruthy()
  expect(await getDb().cases.count()).toBe(1)
  expect((await getDb().kv.get('lastCase'))?.value).toBe(first)
})

it('keeps the default name when none is given', async () => {
  const first = await aCase(FIRST_CASE_NAME)
  const c = await startCase('', 'browser')
  expect(c).toMatchObject({ id: first, name: FIRST_CASE_NAME, storage: 'browser' })
  expect(c.serverKey).toBeUndefined()
})

it('adds a case when the first one holds evidence, has notes, or is not the only one', async () => {
  const first = await aCase(FIRST_CASE_NAME)
  await evidence(first)
  const second = await startCase('', 'browser')
  expect(second.id).not.toBe(first)
  expect(second.name).toBe('Case 2')

  for (const table of getDb().tables) await table.clear()
  const noted = await aCase(FIRST_CASE_NAME, { notes: 'scope: finance' })
  expect((await startCase('x', 'browser')).id).not.toBe(noted)

  for (const table of getDb().tables) await table.clear()
  await aCase(FIRST_CASE_NAME)
  await aCase('other')
  const third = await startCase('', 'server')
  expect(third).toMatchObject({ name: 'Case 3', storage: 'server' })
  expect(third.serverKey).toBeTruthy()
  expect(await getDb().cases.count()).toBe(3)
  expect((await getDb().kv.get('lastCase'))?.value).toBe(third.id)
})
