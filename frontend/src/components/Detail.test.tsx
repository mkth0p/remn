// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { defaultSettings, RemnDB, setDb, type Case, type EventRow, type MailRow } from '../db/schema'
import { useStore } from '../state/store'
import { EventDetail, MailDetail } from './Detail'

let db: RemnDB
const kase: Case = { id: 1, name: 'c', storage: 'browser', createdAt: 1, updatedAt: 1, settings: defaultSettings() }
const T0 = Date.UTC(2026, 2, 3, 9, 15)

// an invented failed logon, with its EventData and no raw record kept
const EVENT: EventRow = {
  id: 7,
  caseId: 1,
  evidenceId: 1,
  ts: T0,
  eventId: 4625,
  channel: 'Security',
  computer: 'WS-017',
  targetUser: 'svc-backup',
  ipAddress: '10.0.0.5',
  summary: 'logon failed for svc-backup from 10.0.0.5',
  data: { LogonType: '3', Status: '0xc000006d' },
}

// an invented lure: a reply-to that differs, DKIM failing, a body and two hops
const MAIL: MailRow = {
  id: 3,
  caseId: 1,
  evidenceId: 2,
  folder: 'Inbox',
  subject: 'Supplier bank details',
  date: T0,
  fromName: 'Accounts',
  fromNameNorm: 'accounts',
  fromAddr: 'accounts@supplier.example',
  fromDomain: 'supplier.example',
  fromRegistrable: 'supplier.example',
  replyTo: [{ name: '', addr: 'pay@lure.example', domain: 'lure.example' }],
  returnPath: null,
  to: [{ name: 'M. Durand', addr: 'm.durand@corp.example', domain: 'corp.example' }],
  cc: [],
  bcc: [],
  recipientCount: 1,
  messageId: '<a1b2@supplier.example>',
  originIp: '203.0.113.50',
  hopCount: 2,
  hops: [
    { index: 1, from: 'mail.supplier.example', fromIp: '203.0.113.50', by: 'mx.corp.example', with: 'ESMTPS', delayS: 2 },
    { index: 2, from: 'mx.corp.example', by: 'store.corp.example', with: 'LMTP', delayS: -40 },
  ],
  auth: { spf: 'pass', dkim: 'fail', dmarc: 'none' },
  keywordHits: {},
  urls: [],
  urlCount: 0,
  attachments: [],
  attachmentCount: 0,
  maxAttachmentRisk: 0,
  lookalike: {},
  flags: ['reply_to_mismatch', 'url_tracking_pixel'],
  risk: 72,
}

beforeEach(async () => {
  db = new RemnDB(`detail-${Math.random()}`)
  setDb(db)
  await db.cases.add(kase)
  useStore.setState({ currentCase: kase, view: 'events', meta: null, aiPrompt: null, entity: null, eventsFilter: {}, mailsFilter: {} })
})
afterEach(async () => {
  cleanup()
  db.close()
  await db.delete()
})

describe('the event detail', () => {
  it('shows the event, its fields and its EventData, and says when the raw record was not kept', () => {
    render(<EventDetail row={EVENT} onClose={() => {}} />)
    expect(screen.getByText('logon failed for svc-backup from 10.0.0.5')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'WS-017' })).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'EventData' }))
    expect(screen.getByRole('button', { name: '0xc000006d' })).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Raw JSON' }))
    expect(screen.getByText('raw JSON was not stored for this evidence (lite mode)')).toBeTruthy()
  })

  it('pivots on a value to the events that hold it, and from its address to the mails', () => {
    render(<EventDetail row={EVENT} onClose={() => {}} />)
    fireEvent.click(screen.getByRole('button', { name: /targetUser: svc-backup/ }))
    expect(useStore.getState()).toMatchObject({ view: 'events', eventsFilter: { conditions: [{ field: 'targetUser', op: 'eq', value: 'svc-backup' }] } })
    fireEvent.click(screen.getByRole('button', { name: 'mails from 10.0.0.5' }))
    expect(useStore.getState()).toMatchObject({ view: 'mails', mailsFilter: { conditions: [{ field: 'originIp', op: 'eq', value: '10.0.0.5' }] } })
  })

  it('puts the event to the AI analyst, and closes on Escape', () => {
    let closed = 0
    render(<EventDetail row={EVENT} onClose={() => closed++} />)
    fireEvent.click(screen.getByRole('button', { name: /explain/ }))
    expect(useStore.getState().view).toBe('ai')
    expect(useStore.getState().aiPrompt).toContain('"eventId": 4625')
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(closed).toBe(1)
  })
})

describe('the mail detail', () => {
  it('shows the head of the mail: subject, sender, authentication and what differs', () => {
    render(<MailDetail row={MAIL} onClose={() => {}} />)
    expect(screen.getByTitle('Supplier bank details').textContent).toBe('Supplier bank details')
    expect(screen.getByText('spf pass')).toBeTruthy()
    expect(screen.getByText('dkim fail')).toBeTruthy()
    expect(screen.getByText('reply-to differs')).toBeTruthy()
    // a tracking pixel is a quiet observation, left behind "+1 more"
    expect(screen.queryByText(/tracking/)).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: '+1 more' }))
    expect(document.body.textContent).toMatch(/tracking/i)
  })

  it('reads its body and the findings on it from the case', async () => {
    await db.mails.add(MAIL)
    await db.mailBodies.add({ caseId: 1, mailId: 3, bodyText: 'Please use our new account from today.', bodyHtml: null, headersText: 'Received: from mail.supplier.example', visibleText: null })
    await db.findings.add({
      caseId: 1,
      key: 'k',
      ruleId: 'mail-bank-detail-change',
      title: 'Bank detail change request',
      source: 'mails',
      severity: 'high',
      refs: [3],
      entities: {},
      count: 1,
      attack: [],
      ts: T0,
      status: 'new',
      createdAt: 1,
    })
    render(<MailDetail row={MAIL} onClose={() => {}} />)
    expect(await screen.findByText('Please use our new account from today.')).toBeTruthy()
    expect(await screen.findByText('Bank detail change request')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Headers' }))
    expect(screen.getByText('Received: from mail.supplier.example')).toBeTruthy()
  })

  it('lists the hops with a negative delay marked, and opens an entity page from the sender', () => {
    render(<MailDetail row={MAIL} onClose={() => {}} />)
    fireEvent.click(screen.getByRole('button', { name: /^Hops/ }))
    const rows = within(document.querySelector('table')!).getAllByRole('row')
    expect(rows).toHaveLength(3)
    expect(within(rows[2]).getByText('-40s').getAttribute('style')).toContain('var(--danger)')
    fireEvent.click(screen.getByRole('button', { name: 'accounts@supplier.example' }))
    expect(useStore.getState().entity).toEqual({ kind: 'address', value: 'accounts@supplier.example' })
  })

  it('finds the audit records that name the message, and the events of its recipient around delivery', async () => {
    await db.events.add({ id: 9, caseId: 1, evidenceId: 1, ts: T0 + 60_000, eventId: 4624, targetUser: 'm.durand', summary: 'logon' } as EventRow)
    render(<MailDetail row={MAIL} onClose={() => {}} />)
    fireEvent.click(screen.getByRole('button', { name: /audit records naming it/ }))
    expect(useStore.getState()).toMatchObject({ view: 'events', eventsFilter: { conditions: [{ field: 'data.InternetMessageId', op: 'contains', value: '<a1b2@supplier.example>' }] } })
    fireEvent.click(screen.getByRole('button', { name: /^Related/ }))
    await waitFor(() => expect(screen.getByRole('button', { name: /^Related/ }).textContent).toBe('Related1'))
  })
})
