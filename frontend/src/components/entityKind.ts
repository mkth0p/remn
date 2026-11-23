import type { EntityRef } from '../state/store'

/** Which entity page a field's value belongs to, or null when the field is not an entity. */
export function entityKind(field: string): EntityRef['kind'] | null {
  const f = field.toLowerCase()
  if (/^(targetuser|subjectuser|user|membername|upn|username|account|identity)$/.test(f)) return 'user'
  if (/^(computer|host|hosts|workstation|hostname|sourcehostname|destinationhostname)$/.test(f)) return 'host'
  if (/^(ipaddress|ip|ips|sourceip|destinationip|originip|clientip)$/.test(f)) return 'ip'
  if (/^(fromaddr|attacker|attackeraddresses|replyto|sender|senders|toaddr|recipient)$/.test(f)) return 'address'
  if (/^(fromdomain|fromregistrable|domain|domains|registrable)$/.test(f)) return 'domain'
  return null
}
