import { useStore } from '../state/store'

/**
 * Open the events or the mails view filtered on a value: on its field when one is named, else as a
 * text search. Mail fields go to the mails view, everything else to the events view.
 */
export function usePivot() {
  const setView = useStore((s) => s.setView)
  const setEventsFilter = useStore((s) => s.setEventsFilter)
  const setMailsFilter = useStore((s) => s.setMailsFilter)
  return (value: string, field?: string, target?: 'events' | 'mails') => {
    const v = value.trim()
    if (!v) return
    if (target === 'mails' || (!target && field && ['fromAddr', 'fromDomain', 'originIp', 'subject', 'fromName'].includes(field))) {
      setMailsFilter(field && !['summary'].includes(field) ? { conditions: [{ field, op: 'eq', value: v }] } : { text: v })
      setView('mails')
    } else {
      setEventsFilter(field && !['summary', 'raw', 'message', 'commandLine', 'scriptBlockText'].includes(field) ? { conditions: [{ field, op: 'eq', value: v }] } : { text: v })
      setView('events')
    }
  }
}
