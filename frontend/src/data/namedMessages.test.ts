import { expect, it } from 'vitest'
import { namedMessageIds } from './namedMessages'
import { matchCondition } from '../rules/filter'

it('reads the message ids a record names and opens exactly those messages', () => {
  const named = namedMessageIds({ data: { InternetMessageId: '<a@x>, <b@x>', 'InternetMessageId.total': 1200 } })
  expect(named).toEqual({ ids: ['<a@x>', '<b@x>'], total: 1200 })
  expect(namedMessageIds({ data: { Folders: '\\Inbox' } })).toEqual({ ids: [], total: 0 })
  const cond = { field: 'messageId', op: 'in' as const, value: named.ids }
  expect(matchCondition({ messageId: '<a@x>' }, cond)).toBe(true)
  expect(matchCondition({ messageId: '<a@x.other>' }, cond)).toBe(false)
  // and back: a message finds the records that name it
  expect(matchCondition({ data: { InternetMessageId: '<a@x>, <b@x>' } }, { field: 'data.InternetMessageId', op: 'contains', value: '<b@x>' })).toBe(true)
})
