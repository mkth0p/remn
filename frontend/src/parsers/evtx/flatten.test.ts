import { describe as group, expect, it } from 'vitest'
import {
  describe,
  flatten,
  headerTime,
  kerberosFailureText,
  logonTypeName,
  normalizeIp,
  parseTimestamp,
  psPipeline,
  renderAccessList,
  scalar,
  statusText,
  str,
  summarize,
  ticketEncryptionName,
  toInt,
} from './flatten'
import { BigInteger, type Json } from './py'

const SECURITY = 'Microsoft-Windows-Security-Auditing'

group('parseTimestamp', () => {
  it('reads an event log time to epoch milliseconds and an ISO time cut to milliseconds', () => {
    expect(parseTimestamp('2026-03-04T05:06:07.1234567Z')).toEqual([Date.UTC(2026, 2, 4, 5, 6, 7, 123), '2026-03-04T05:06:07.123Z'])
  })

  it('moves a time with an offset to UTC, with or without the colon', () => {
    expect(parseTimestamp('2026-03-04T05:06:07+02:00')[1]).toBe('2026-03-04T03:06:07.000Z')
    expect(parseTimestamp('2026-03-04 05:06:07-0130')[1]).toBe('2026-03-04T06:36:07.000Z')
    expect(parseTimestamp('2026-03-04 05:06:07 UTC')[1]).toBe('2026-03-04T05:06:07.000Z')
  })

  it('crosses a day and a year when the offset asks for it', () => {
    expect(parseTimestamp('2027-01-01T00:30:00+01:00')[1]).toBe('2026-12-31T23:30:00.000Z')
  })

  it('gives nothing for an empty value or a text that is not an ISO time', () => {
    expect(parseTimestamp(null)).toEqual([null, null])
    expect(parseTimestamp(undefined)).toEqual([null, null])
    expect(parseTimestamp('')).toEqual([null, null])
    expect(parseTimestamp('yesterday at noon')).toEqual([null, null])
    expect(parseTimestamp(1700000000)).toEqual([null, null])
  })

  it('refuses dates and times that do not exist, as datetime() does', () => {
    expect(parseTimestamp('2026-02-29T00:00:00Z')).toEqual([null, null])
    expect(parseTimestamp('1900-02-29T00:00:00Z')).toEqual([null, null])
    expect(parseTimestamp('2026-13-01T00:00:00Z')).toEqual([null, null])
    expect(parseTimestamp('2026-04-31T00:00:00Z')).toEqual([null, null])
    expect(parseTimestamp('2026-01-01T24:00:00Z')).toEqual([null, null])
    expect(parseTimestamp('2026-01-01T00:60:00Z')).toEqual([null, null])
    expect(parseTimestamp('2026-01-01T00:00:60Z')).toEqual([null, null])
  })

  it('accepts the leap days the Gregorian calendar has', () => {
    expect(parseTimestamp('2024-02-29T12:00:00Z')[1]).toBe('2024-02-29T12:00:00.000Z')
    expect(parseTimestamp('2000-02-29T12:00:00Z')[1]).toBe('2000-02-29T12:00:00.000Z')
  })

  it('gives nothing for a time that falls before year one in UTC', () => {
    expect(parseTimestamp('0001-01-01T00:00:00+01:00')).toEqual([null, null])
  })

  it('fails on an offset of a day or more, as the server does', () => {
    expect(() => parseTimestamp('2026-01-01T00:00:00+24:00')).toThrow(/strictly between/)
  })
})

group('normalizeIp', () => {
  it('keeps IPv4 and IPv6 addresses, trimmed', () => {
    expect(normalizeIp(' 10.0.0.5 ')).toBe('10.0.0.5')
    expect(normalizeIp('2001:db8::1')).toBe('2001:db8::1')
    expect(normalizeIp('2001:db8:0:0:0:0:0:1')).toBe('2001:db8:0:0:0:0:0:1')
    expect(normalizeIp('fe80::1%12')).toBe('fe80::1%12')
    expect(normalizeIp('64:ff9b::192.0.2.33')).toBe('64:ff9b::192.0.2.33')
  })

  it('unwraps an IPv4-mapped address and names the loopback as IPv4', () => {
    expect(normalizeIp('::ffff:192.0.2.10')).toBe('192.0.2.10')
    expect(normalizeIp('::FFFF:192.0.2.10')).toBe('192.0.2.10')
    expect(normalizeIp('::1')).toBe('127.0.0.1')
  })

  it('gives nothing for the placeholders Windows writes for no address', () => {
    for (const v of [null, undefined, '', '-', '::', '::0', '0.0.0.0']) expect(normalizeIp(v)).toBeNull()
  })

  it('gives nothing for what is not an address', () => {
    for (const v of ['WS-07', '256.1.1.1', '010.0.0.1', '10.0.0', '1::2::3', ':1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8:9', 'fe80::1%', 'fe80::1%1%2', '2001:db8::zz']) expect(normalizeIp(v)).toBeNull()
  })
})

group('describe', () => {
  it('names an event by its provider and id', () => {
    expect(describe(SECURITY, 4624)).toEqual(['An account was successfully logged on', 'logon'])
  })

  it('gives nothing for an id the provider does not have, a missing id or a very large one', () => {
    expect(describe(SECURITY, 1)).toBeNull()
    expect(describe('', 4624)).toBeNull()
    expect(describe(SECURITY, null)).toBeNull()
    expect(describe(SECURITY, new BigInteger('99999999999999999999'))).toBeNull()
  })

  it('prefers the longest provider fragment when several match', () => {
    expect(describe('Sysmon Bits-Client', 4)).toEqual(['BITS job completed', 'download'])
  })
})

group('the code tables', () => {
  it('names a logon type given as a number or as text', () => {
    expect(logonTypeName(10)).toBe('RemoteInteractive')
    expect(logonTypeName('3')).toBe('Network')
    expect(logonTypeName(6)).toBeNull()
    expect(logonTypeName('network')).toBeNull()
    expect(logonTypeName(null)).toBeNull()
  })

  it('reads NTSTATUS codes in any case and with leading zeros', () => {
    expect(statusText('0xC000006A')).toBe('Wrong password')
    expect(statusText('0x00000000')).toBe('Success')
    expect(statusText(' 0xc0000234 ')).toBe('Account locked out')
    expect(statusText('0xdeadbeef')).toBeNull()
    expect(statusText('')).toBeNull()
    expect(statusText(null)).toBeNull()
  })

  it('reads Kerberos failure codes and ticket encryption types', () => {
    expect(kerberosFailureText('0x00000018')).toBe('Pre-authentication failed (wrong password)')
    expect(kerberosFailureText('0x0')).toBeNull()
    expect(ticketEncryptionName('0x17')).toBe('RC4-HMAC')
    expect(ticketEncryptionName('0xFFFFFFFF')).toBe('Audit failure (no encryption)')
  })
})

group('summarize', () => {
  it('writes a logon with its type, account, address and package', () => {
    const row = { eventId: 4624, provider: SECURITY, logonType: 10, targetUser: 'user1', targetDomain: 'EXAMPLE', ipAddress: '10.0.0.5', authPackage: 'Negotiate' }
    expect(summarize(row)).toBe('Logon RemoteInteractive as EXAMPLE\\user1 from 10.0.0.5 (Negotiate)')
  })

  it('writes a failed logon from a workstation with its reason', () => {
    const row = { eventId: 4625, provider: SECURITY, logonType: 3, targetUser: 'user1', targetDomain: '-', workstation: 'WS-07', subStatus: '0xc000006a' }
    expect(summarize(row)).toBe('Failed logon Network as user1 from WS-07 - Wrong password')
  })

  it('keeps an unnamed logon type as its number and drops a missing one', () => {
    expect(summarize({ eventId: 4625, provider: SECURITY, logonType: 6 })).toBe('Failed logon 6')
    expect(summarize({ eventId: 4625, provider: SECURITY, logonType: null })).toBe('Failed logon')
  })

  it('writes a Kerberos ticket request with its service, address and encryption', () => {
    const row = { eventId: 4769, provider: SECURITY, targetUser: 'user1', targetDomain: 'EXAMPLE', serviceName: 'svc-backup', ipAddress: '10.0.0.8', ticketEncryption: '0x17', status: '0x0' }
    expect(summarize(row)).toBe('Kerberos service ticket requested EXAMPLE\\user1 svc svc-backup from 10.0.0.8 [RC4-HMAC]')
  })

  it('writes a service installation from the Service Control Manager', () => {
    const row = { eventId: 7045, provider: 'Service Control Manager', serviceName: 'updater', serviceFile: 'C:\\Temp\\updater.exe' }
    expect(summarize(row)).toBe('Service installed updater -> C:\\Temp\\updater.exe')
  })

  it('cuts a script block to 160 characters on one line', () => {
    const text = 'Write-Output "a"\n' + 'x'.repeat(300)
    const out = summarize({ eventId: 4104, provider: 'Microsoft-Windows-PowerShell', scriptBlockText: text })
    expect(out.startsWith('Script block Write-Output "a" x')).toBe(true)
    expect(out).toHaveLength('Script block '.length + 160)
  })

  it('writes Sysmon events by their kind, and an unknown one by its number', () => {
    const sysmon = 'Microsoft-Windows-Sysmon'
    expect(summarize({ eventId: 3, provider: sysmon, image: 'C:\\Tools\\agent.exe', destinationIp: '192.0.2.9', destinationPort: 443 })).toBe(
      'Network connection C:\\Tools\\agent.exe -> 192.0.2.9:443',
    )
    expect(summarize({ eventId: 10, provider: sysmon, sourceImage: 'a.exe', targetImage: 'lsass.exe', grantedAccess: '0x1010' })).toBe(
      'ProcessAccess (process handle opened) a.exe -> lsass.exe (0x1010)',
    )
    expect(summarize({ eventId: 99, provider: sysmon, image: 'b.exe' })).toBe('Sysmon 99 b.exe')
  })

  it('falls back to the description or the event number and the account', () => {
    expect(summarize({ eventId: 9999, provider: 'Example-Provider', subjectUser: 'svc1' })).toBe('Event 9999 svc1')
    expect(summarize({ eventId: 6005, provider: 'EventLog' })).toBe('The Event log service was started')
  })
})

group('scalar', () => {
  it('collapses text nodes and attribute-only nodes, through lists and nesting', () => {
    expect(scalar({ '#text': 'value', '#attributes': { Name: 'x' } })).toBe('value')
    expect(scalar({ '#attributes': { Name: 'Provider-A', Guid: '{0}' } })).toEqual({ Name: 'Provider-A', Guid: '{0}' })
    expect(scalar({ a: { '#text': 1 }, '#attributes': { Name: 'x' } })).toEqual({ a: 1 })
    expect(scalar([{ '#text': 'a' }, 'b', null])).toEqual(['a', 'b', null])
    expect(scalar('plain')).toBe('plain')
    expect(scalar(undefined)).toBeUndefined()
  })

  it('keeps a key named __proto__ as a plain key', () => {
    const out = scalar(JSON.parse('{"__proto__": {"#text": "kept"}, "b": 1}') as Json) as Record<string, Json>
    expect(Object.hasOwn(out, '__proto__')).toBe(true)
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype)
    expect(Object.keys(out)).toEqual(['__proto__', 'b'])
  })
})

group('str and toInt', () => {
  it('gives text trimmed, without the dash placeholder, and cut with an ellipsis by code point', () => {
    expect(str(null)).toBeNull()
    expect(str('  -  ')).toBeNull()
    expect(str(' a ')).toBe('a')
    expect(str(true)).toBe('True')
    expect(str(['a', 1])).toBe('["a",1]')
    expect(str('abcdefgh', 5)).toBe('abcde…')
    expect(str('\u{1F600}\u{1F600}\u{1F600}', 2)).toBe('\u{1F600}\u{1F600}…')
  })

  it('reads integers as int() does and refuses what int() refuses', () => {
    expect(toInt(null)).toBeNull()
    expect(toInt('')).toBeNull()
    expect(toInt(true)).toBe(1)
    expect(toInt(7)).toBe(7)
    expect(toInt(1.5)).toBeNull()
    expect(toInt(' 42 ')).toBe(42)
    expect(toInt('4_2')).toBe(42)
    expect(toInt('0x1F')).toBe(31)
    expect(toInt('twelve')).toBeNull()
    expect(toInt({})).toBeNull()
    expect(String(toInt('99999999999999999999'))).toBe('99999999999999999999')
    const big = new BigInteger('123456789012345678901')
    expect(toInt(big)).toBe(big)
  })
})

group('renderAccessList and headerTime', () => {
  it('adds the names of the access codes it knows on a second line', () => {
    expect(renderAccessList('%%4416\n\t\t\t\t%%4417')).toBe('%%4416\n\t\t\t\t%%4417\nReadData (or ListDirectory) WriteData (or AddFile)')
    expect(renderAccessList('%%9999')).toBe('%%9999')
    expect(renderAccessList('none')).toBe('none')
    expect(renderAccessList(null)).toBeNull()
  })

  it('drops the UTC suffix and the zero time of filtered exports', () => {
    expect(headerTime('2026-01-02T03:04:05.000000Z UTC')).toBe('2026-01-02T03:04:05.000000Z')
    expect(headerTime('1601-01-01T00:00:00.000000Z UTC')).toBeNull()
    expect(headerTime(null)).toBeNull()
    expect(headerTime(undefined)).toBeNull()
  })
})

group('psPipeline', () => {
  it('writes switches bare, positional values quoted and quotes doubled, and leaves out the host commands', () => {
    const payload = [
      'CommandInvocation(Get-ChildItem): "Get-ChildItem"',
      'ParameterBinding(Get-ChildItem): name="Recurse"; value="True"',
      'ParameterBinding(Get-ChildItem): name=""; value="C:\\Users\\o\'brien"',
      'CommandInvocation(Out-Default): "Out-Default"',
      'ParameterBinding(Out-Default): name="InputObject"; value="x"',
    ].join('\r\n')
    expect(psPipeline(payload)).toBe("Get-ChildItem -Recurse 'C:\\Users\\o''brien'")
  })

  it('joins a value that runs over several lines and stops at an error line', () => {
    const payload = [
      'CommandInvocation(Set-Content): "Set-Content"',
      'ParameterBinding(Set-Content): name="Value"; value="line one',
      'line two"',
      'CommandInvocation(Select-Object): "Select-Object"',
      'ParameterBinding(Select-Object): name="First"; value="1',
      'NonTerminatingError(Select-Object): "stopped"',
      'not part of the value"',
    ].join('\n')
    expect(psPipeline(payload)).toBe("Set-Content -Value 'line one\nline two' | Select-Object -First '1'")
  })

  it('gives nothing when the payload records no command', () => {
    expect(psPipeline('ParameterBinding(x): name="a"; value="b"')).toBeNull()
    expect(psPipeline('CommandInvocation(Out-Default): "Out-Default"')).toBeNull()
  })
})

function securityEvent(eventId: Json, data: Record<string, Json>, system: Record<string, Json> = {}): Json {
  return {
    Event: {
      System: {
        Provider: { '#attributes': { Name: SECURITY, Guid: '{00000000-0000-0000-0000-000000000001}' } },
        EventID: eventId,
        TimeCreated: { '#attributes': { SystemTime: '2026-05-06T07:08:09.250000Z' } },
        EventRecordID: 501,
        Channel: 'Security',
        Computer: 'WS-07.example.test',
        ...system,
      },
      EventData: data,
    },
  }
}

group('flatten', () => {
  it('turns a failed logon into a row with its system fields, account, address, reason and summary', () => {
    const row = flatten(
      securityEvent(
        { '#text': 4625, '#attributes': { Qualifiers: '16384' } },
        { TargetUserName: 'user1', TargetDomainName: 'EXAMPLE', LogonType: '3', IpAddress: '::ffff:10.0.0.5', IpPort: '51234', Status: '0xc000006d', SubStatus: '0xC000006A', WorkstationName: '-' },
        { Level: 0, Execution: { '#attributes': { ProcessID: 4, ThreadID: '88' } }, Security: { '#attributes': { UserID: 'S-1-5-18' } } },
      ),
    )
    expect(row).toMatchObject({
      recordId: 501,
      ts: Date.UTC(2026, 4, 6, 7, 8, 9, 250),
      tsIso: '2026-05-06T07:08:09.250Z',
      eventId: 4625,
      qualifiers: 16384,
      level: 0,
      levelName: 'LogAlways',
      provider: SECURITY,
      providerGuid: '{00000000-0000-0000-0000-000000000001}',
      channel: 'Security',
      computer: 'WS-07.example.test',
      userSid: 'S-1-5-18',
      processId: 4,
      threadId: 88,
      targetUser: 'user1',
      targetDomain: 'EXAMPLE',
      logonType: 3,
      logonTypeName: 'Network',
      ipAddress: '10.0.0.5',
      ipPort: 51234,
      workstation: null,
      statusText: 'Wrong password',
      category: 'logon',
      description: 'An account failed to log on',
      summary: 'Failed logon Network as EXAMPLE\\user1 from 10.0.0.5 - Wrong password',
    })
    expect(row.data).toMatchObject({ TargetUserName: 'user1', IpAddress: '::ffff:10.0.0.5' })
    expect(typeof row.raw).toBe('string')
    expect(JSON.parse(row.raw as string).System.EventRecordID).toBe(501)
  })

  it('leaves out the raw event when asked', () => {
    expect(flatten(securityEvent(4624, {}), null, false)).not.toHaveProperty('raw')
  })

  it('takes the time and record number from the record header when the event has none', () => {
    const event = { Event: { System: { Provider: { '#attributes': { Name: SECURITY } }, EventID: 4624, Level: 9 } } }
    const row = flatten(event, { id: 77, t: '2026-05-06T07:08:09.000000Z UTC' })
    expect(row).toMatchObject({ recordId: 77, tsIso: '2026-05-06T07:08:09.000Z', level: 9, levelName: '9' })
    expect(flatten(event, { id: 78, t: '1601-01-01T00:00:00.000000Z UTC' })).toMatchObject({ recordId: 78, ts: null, tsIso: null })
  })

  it('reads an event given without the Event wrapper, with a plain provider name and time', () => {
    const row = flatten({ System: { Provider: 'Example-Provider', EventID: '12', TimeCreated: '2026-05-06T07:08:09Z' } })
    expect(row).toMatchObject({ provider: 'Example-Provider', providerGuid: null, eventId: 12, tsIso: '2026-05-06T07:08:09.000Z', summary: 'Event 12' })
  })

  it('takes the provider from EventSourceName when it has no Name', () => {
    const row = flatten({ System: { Provider: { '#attributes': { EventSourceName: 'Service Control Manager' } }, EventID: 7036 }, EventData: { param1: 'Print Spooler', param2: 'stopped' } })
    expect(row).toMatchObject({ provider: 'Service Control Manager', serviceName: 'Print Spooler', serviceState: 'stopped' })
  })

  it('keeps an address it cannot read as text, and drops the placeholders', () => {
    expect(flatten(securityEvent(4624, { IpAddress: 'host-name' })).ipAddress).toBe('host-name')
    expect(flatten(securityEvent(4624, { IpAddress: '-' })).ipAddress).toBeNull()
  })

  it('lets the first field that maps to a row key win, unless it was empty', () => {
    expect(flatten(securityEvent(4624, { TargetUserSid: 'S-1-5-21-1', TargetSid: 'S-1-5-21-2' })).targetSid).toBe('S-1-5-21-1')
    expect(flatten(securityEvent(4624, { TargetUserSid: '-', TargetSid: 'S-1-5-21-2' })).targetSid).toBe('S-1-5-21-2')
  })

  it('names the group of a group membership event and renders an access list', () => {
    expect(flatten(securityEvent(4732, { TargetUserName: 'Administrators', TargetDomainName: 'Builtin', MemberName: 'CN=user1' }))).toMatchObject({
      groupName: 'Administrators',
      groupDomain: 'Builtin',
      memberName: 'CN=user1',
    })
    expect(flatten(securityEvent(4663, { AccessList: '%%4416' })).accessList).toBe('%%4416\nReadData (or ListDirectory)')
  })

  it('reads a Kerberos failure code when the status is not an NTSTATUS', () => {
    expect(flatten(securityEvent(4771, { TargetUserName: 'user1', Status: '0x18' })).statusText).toBe('Pre-authentication failed (wrong password)')
  })

  it('unwraps UserData and keeps the name of its element', () => {
    const row = flatten({
      Event: {
        System: { Provider: { '#attributes': { Name: 'Microsoft-Windows-Eventlog' } }, EventID: 104, Channel: 'System' },
        UserData: { LogFileCleared: { '#attributes': { xmlns: 'urn:example' }, SubjectUserName: 'admin1', SubjectDomainName: 'EXAMPLE', Channel: 'Security' } },
      },
    })
    expect(row).toMatchObject({ subjectUser: 'admin1', subjectDomain: 'EXAMPLE', channelCleared: 'Security', summary: 'The event log file was cleared by EXAMPLE\\admin1 (Security)' })
    expect(row.data).toMatchObject({ _userDataType: 'LogFileCleared' })
  })

  it('reads the account, domain and address of an RDP authentication from its parameters', () => {
    const row = flatten({
      Event: {
        System: { Provider: { '#attributes': { Name: 'Microsoft-Windows-TerminalServices-RemoteConnectionManager' } }, EventID: 1149 },
        UserData: { EventXML: { Param1: 'user2', Param2: 'EXAMPLE', Param3: '192.0.2.7' } },
      },
    })
    expect(row).toMatchObject({ targetUser: 'user2', targetDomain: 'EXAMPLE', ipAddress: '192.0.2.7' })
  })

  it('takes the account of an RDP session event from User when there is no target', () => {
    const row = flatten({
      Event: {
        System: { Provider: { '#attributes': { Name: 'Microsoft-Windows-TerminalServices-LocalSessionManager' } }, EventID: 21 },
        UserData: { EventXML: { User: 'EXAMPLE\\user2', Address: '192.0.2.7' } },
      },
    })
    expect(row.targetUser).toBe('EXAMPLE\\user2')
  })

  it('splits the Sysmon user into domain and account', () => {
    const sysmon = (user: string) =>
      flatten({ System: { Provider: { '#attributes': { Name: 'Microsoft-Windows-Sysmon' } }, EventID: 1 }, EventData: { User: user, Image: 'C:\\Tools\\a.exe', CommandLine: 'a.exe -x' } })
    expect(sysmon('EXAMPLE\\user3')).toMatchObject({ subjectDomain: 'EXAMPLE', subjectUser: 'user3', summary: 'Process creation a.exe -x' })
    expect(sysmon('user3')).toMatchObject({ subjectUser: 'user3' })
  })

  it('joins the unnamed Data of a classic event into the message, and takes a bare payload as it is', () => {
    expect(flatten({ System: { Provider: 'Example-Provider', EventID: 1 }, EventData: { Data: ['first', null, { '#text': 'second' }] } }).message).toBe('first\nsecond')
    expect(flatten({ System: { Provider: 'Example-Provider', EventID: 1 }, EventData: 'only text' }).message).toBe('only text')
    expect(flatten({ System: { Provider: 'Example-Provider', EventID: 1 }, EventData: ['a', 'b'] }).message).toBe('a\nb')
  })

  it('rebuilds the command, user and script of a module logging event', () => {
    const row = flatten({
      System: { Provider: { '#attributes': { Name: 'Microsoft-Windows-PowerShell' } }, EventID: 4103 },
      EventData: {
        ContextInfo: '        Host Application = powershell.exe\n        User = EXAMPLE\\user4\n        Script Name = C:\\Scripts\\audit.ps1\n',
        Payload: 'CommandInvocation(Get-ADGroupMember): "Get-ADGroupMember"\nParameterBinding(Get-ADGroupMember): name="Identity"; value="Administrators"',
      },
    })
    expect(row).toMatchObject({ commandLine: "Get-ADGroupMember -Identity 'Administrators'", subjectDomain: 'EXAMPLE', subjectUser: 'user4', path: 'C:\\Scripts\\audit.ps1' })
  })

  it('prefers the command as typed in a pipeline execution event', () => {
    const row = flatten({
      System: { Provider: { '#attributes': { Name: 'PowerShell' } }, EventID: 800, Channel: 'Windows PowerShell' },
      EventData: { Data: ['Get-Process | Select -First 1', '\tUserId=EXAMPLE\\user5\n\tScriptName=\n', 'CommandInvocation(Get-Process): "Get-Process"'] },
    })
    expect(row).toMatchObject({ commandLine: 'Get-Process | Select -First 1', subjectDomain: 'EXAMPLE', subjectUser: 'user5' })
    expect(row.path).toBeUndefined()
  })

  it('reads who logged in from where out of a SQL Server audit record', () => {
    const message = [
      'action_id:LGIF',
      'class_type:LX',
      'server_principal_name:EXAMPLE\\user6',
      "statement:Login failed for user 'sa'. Reason: wrong password.",
      'additional_information:<action_info><address>192.0.2.44</address></action_info>',
    ].join('\n')
    const row = flatten({ System: { Provider: { '#attributes': { Name: 'MSSQLSERVER' } }, EventID: 33205 }, EventData: { Data: [message] } })
    expect(row).toMatchObject({ eventType: 'LGIF', objectType: 'LX', subjectDomain: 'EXAMPLE', subjectUser: 'user6', targetUser: 'sa', ipAddress: '192.0.2.44' })
  })

  it('reads the account and client of an sshd line', () => {
    const row = flatten({
      System: { Provider: { '#attributes': { Name: 'OpenSSH' } }, EventID: 4, Channel: 'OpenSSH/Operational' },
      EventData: { process: 'sshd', payload: 'Failed password for invalid user test from 192.0.2.9 port 60096 ssh2' },
    })
    expect(row).toMatchObject({ targetUser: 'test', ipAddress: '192.0.2.9', ipPort: 60096 })
  })

  it('keeps a key named __proto__ in the data without touching any prototype', () => {
    const row = flatten(JSON.parse('{"System": {"Provider": "Example-Provider", "EventID": 1}, "EventData": {"__proto__": "x", "Other": "y"}}') as Json)
    const data = row.data as Record<string, unknown>
    expect(Object.hasOwn(data, '__proto__')).toBe(true)
    expect(Object.getPrototypeOf(data)).toBe(Object.prototype)
    expect(({} as Record<string, unknown>).Other).toBeUndefined()
  })

  it('keeps a record number past 2^53 exact', () => {
    const row = flatten({ System: { Provider: 'Example-Provider', EventID: 1, EventRecordID: new BigInteger('12345678901234567890') } })
    expect(String(row.recordId)).toBe('12345678901234567890')
  })
})
