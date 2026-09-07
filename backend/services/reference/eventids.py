"""
Reference data for Windows event logs: event ID descriptions, logon types,
NTSTATUS failure reasons, investigative notes and one-line summaries used in
the events table and in tooltips.
"""

from __future__ import annotations

from typing import Any

LOGON_TYPES: dict[int, str] = {
    0: "System",
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
    12: "CachedRemoteInteractive",
    13: "CachedUnlock",
}

STATUS_CODES: dict[str, str] = {
    "0xc000005e": "No logon servers available",
    "0xc0000064": "User name does not exist",
    "0xc000006a": "Wrong password",
    "0xc000006d": "Bad user name or authentication information",
    "0xc000006e": "Account restriction (e.g. blank password not allowed)",
    "0xc000006f": "Logon outside authorized hours",
    "0xc0000070": "Workstation restriction / policy",
    "0xc0000071": "Password expired",
    "0xc0000072": "Account disabled",
    "0xc00000dc": "SAM server in wrong state",
    "0xc0000133": "Clock skew too great",
    "0xc000015b": "Logon type not granted",
    "0xc000018c": "Trust relationship failed",
    "0xc0000192": "Netlogon service not started",
    "0xc0000193": "Account expired",
    "0xc0000224": "Password change required at next logon",
    "0xc0000225": "Windows bug (unexpected)",
    "0xc0000234": "Account locked out",
    "0xc00002ee": "Unexpected error during logon",
    "0xc0000413": "Authentication firewall / restricted logon",
    "0x0": "Success",
}

KERBEROS_FAILURES: dict[str, str] = {
    "0x6": "Client not found in Kerberos database (bad username)",
    "0x7": "Server not found in Kerberos database",
    "0xc": "Workstation / time restriction",
    "0x12": "Client credentials revoked (disabled / locked / expired)",
    "0x17": "Password expired",
    "0x18": "Pre-authentication failed (wrong password)",
    "0x19": "Additional pre-authentication required",
    "0x1f": "Integrity check failed",
    "0x20": "Ticket expired",
    "0x25": "Clock skew too great",
    "0x29": "KRB_AP_ERR_MODIFIED",
}

TICKET_ENCRYPTION: dict[str, str] = {
    "0x1": "DES-CBC-CRC",
    "0x3": "DES-CBC-MD5",
    "0x11": "AES128-CTS-HMAC-SHA1-96",
    "0x12": "AES256-CTS-HMAC-SHA1-96",
    "0x17": "RC4-HMAC",
    "0x18": "RC4-HMAC-EXP",
    "0xffffffff": "Audit failure (no encryption)",
}

# (provider fragment, event id) -> (description, category). Provider fragment
# "" means any provider; more specific entries win.
_EVENTS: dict[tuple[str, int], tuple[str, str]] = {
    # --- Security ---------------------------------------------------------
    ("Security-Auditing", 1100): ("Event logging service has shut down", "log"),
    ("Security-Auditing", 1102): ("The audit log was cleared", "log-tampering"),
    ("Security-Auditing", 1104): ("Security log is now full", "log"),
    ("Security-Auditing", 1105): ("Event log automatic backup", "log"),
    ("Security-Auditing", 1108): ("Event logging service encountered an error", "log"),
    ("Security-Auditing", 4608): ("Windows is starting up", "system"),
    ("Security-Auditing", 4609): ("Windows is shutting down", "system"),
    ("Security-Auditing", 4616): ("System time was changed", "system"),
    ("Security-Auditing", 4624): ("An account was successfully logged on", "logon"),
    ("Security-Auditing", 4625): ("An account failed to log on", "logon"),
    ("Security-Auditing", 4634): ("An account was logged off", "logon"),
    ("Security-Auditing", 4647): ("User initiated logoff", "logon"),
    ("Security-Auditing", 4648): ("Logon attempted using explicit credentials", "logon"),
    ("Security-Auditing", 4656): ("A handle to an object was requested", "object"),
    ("Security-Auditing", 4657): ("A registry value was modified", "registry"),
    ("Security-Auditing", 4658): ("Handle to an object was closed", "object"),
    ("Security-Auditing", 4660): ("An object was deleted", "object"),
    ("Security-Auditing", 4663): ("Attempt to access an object", "object"),
    ("Security-Auditing", 4670): ("Permissions on an object were changed", "object"),
    ("Security-Auditing", 4672): ("Special privileges assigned to new logon", "privilege"),
    ("Security-Auditing", 4673): ("A privileged service was called", "privilege"),
    ("Security-Auditing", 4674): ("Operation attempted on a privileged object", "privilege"),
    ("Security-Auditing", 4688): ("A new process has been created", "process"),
    ("Security-Auditing", 4689): ("A process has exited", "process"),
    ("Security-Auditing", 4697): ("A service was installed in the system", "persistence"),
    ("Security-Auditing", 4698): ("A scheduled task was created", "persistence"),
    ("Security-Auditing", 4699): ("A scheduled task was deleted", "persistence"),
    ("Security-Auditing", 4700): ("A scheduled task was enabled", "persistence"),
    ("Security-Auditing", 4701): ("A scheduled task was disabled", "persistence"),
    ("Security-Auditing", 4702): ("A scheduled task was updated", "persistence"),
    ("Security-Auditing", 4703): ("A user right (token privilege) was adjusted", "privilege"),
    ("Security-Auditing", 4704): ("A user right was assigned", "privilege"),
    ("Security-Auditing", 4705): ("A user right was removed", "privilege"),
    ("Security-Auditing", 4706): ("A new trust was created to a domain", "domain"),
    ("Security-Auditing", 4713): ("Kerberos policy was changed", "policy"),
    ("Security-Auditing", 4719): ("System audit policy was changed", "policy"),
    ("Security-Auditing", 4720): ("A user account was created", "account"),
    ("Security-Auditing", 4722): ("A user account was enabled", "account"),
    ("Security-Auditing", 4723): ("Attempt to change an account's password", "account"),
    ("Security-Auditing", 4724): ("Attempt to reset an account's password", "account"),
    ("Security-Auditing", 4725): ("A user account was disabled", "account"),
    ("Security-Auditing", 4726): ("A user account was deleted", "account"),
    ("Security-Auditing", 4727): ("Security-enabled global group created", "group"),
    ("Security-Auditing", 4728): ("Member added to security-enabled global group", "group"),
    ("Security-Auditing", 4729): ("Member removed from security-enabled global group", "group"),
    ("Security-Auditing", 4730): ("Security-enabled global group deleted", "group"),
    ("Security-Auditing", 4731): ("Security-enabled local group created", "group"),
    ("Security-Auditing", 4732): ("Member added to security-enabled local group", "group"),
    ("Security-Auditing", 4733): ("Member removed from security-enabled local group", "group"),
    ("Security-Auditing", 4734): ("Security-enabled local group deleted", "group"),
    ("Security-Auditing", 4735): ("Security-enabled local group changed", "group"),
    ("Security-Auditing", 4737): ("Security-enabled global group changed", "group"),
    ("Security-Auditing", 4738): ("A user account was changed", "account"),
    ("Security-Auditing", 4739): ("Domain policy was changed", "policy"),
    ("Security-Auditing", 4740): ("A user account was locked out", "account"),
    ("Security-Auditing", 4741): ("A computer account was created", "account"),
    ("Security-Auditing", 4742): ("A computer account was changed", "account"),
    ("Security-Auditing", 4743): ("A computer account was deleted", "account"),
    ("Security-Auditing", 4754): ("Security-enabled universal group created", "group"),
    ("Security-Auditing", 4755): ("Security-enabled universal group changed", "group"),
    ("Security-Auditing", 4756): ("Member added to security-enabled universal group", "group"),
    ("Security-Auditing", 4757): ("Member removed from security-enabled universal group", "group"),
    ("Security-Auditing", 4758): ("Security-enabled universal group deleted", "group"),
    ("Security-Auditing", 4764): ("A group's type was changed", "group"),
    ("Security-Auditing", 4765): ("SID History was added to an account", "account"),
    ("Security-Auditing", 4766): ("Attempt to add SID History failed", "account"),
    ("Security-Auditing", 4767): ("A user account was unlocked", "account"),
    ("Security-Auditing", 4768): ("Kerberos authentication ticket (TGT) requested", "kerberos"),
    ("Security-Auditing", 4769): ("Kerberos service ticket requested", "kerberos"),
    ("Security-Auditing", 4770): ("Kerberos service ticket renewed", "kerberos"),
    ("Security-Auditing", 4771): ("Kerberos pre-authentication failed", "kerberos"),
    ("Security-Auditing", 4772): ("Kerberos TGT request failed", "kerberos"),
    ("Security-Auditing", 4773): ("Kerberos service ticket request failed", "kerberos"),
    ("Security-Auditing", 4776): ("Computer attempted to validate credentials (NTLM)", "ntlm"),
    ("Security-Auditing", 4777): ("Domain controller failed to validate credentials", "ntlm"),
    ("Security-Auditing", 4778): ("Session reconnected to a Window Station", "session"),
    ("Security-Auditing", 4779): ("Session disconnected from a Window Station", "session"),
    ("Security-Auditing", 4780): ("ACL set on members of administrators groups", "account"),
    ("Security-Auditing", 4781): ("The name of an account was changed", "account"),
    ("Security-Auditing", 4794): ("Attempt to set Directory Services Restore Mode password", "domain"),
    ("Security-Auditing", 4798): ("A user's local group membership was enumerated", "recon"),
    ("Security-Auditing", 4799): ("A security-enabled local group membership was enumerated", "recon"),
    ("Security-Auditing", 4800): ("The workstation was locked", "session"),
    ("Security-Auditing", 4801): ("The workstation was unlocked", "session"),
    ("Security-Auditing", 4802): ("The screen saver was invoked", "session"),
    ("Security-Auditing", 4803): ("The screen saver was dismissed", "session"),
    ("Security-Auditing", 4825): ("A user was denied access to Remote Desktop", "logon"),
    ("Security-Auditing", 4886): ("Certificate Services received a certificate request", "pki"),
    ("Security-Auditing", 4887): ("Certificate Services approved a request and issued a certificate", "pki"),
    ("Security-Auditing", 4902): ("Per-user audit policy table was created", "policy"),
    ("Security-Auditing", 4904): ("Attempt to register a security event source", "policy"),
    ("Security-Auditing", 4905): ("Attempt to unregister a security event source", "policy"),
    ("Security-Auditing", 4907): ("Auditing settings on object were changed", "policy"),
    ("Security-Auditing", 4912): ("Per-user audit policy was changed", "policy"),
    ("Security-Auditing", 4946): ("Windows Firewall exception list: rule added", "firewall"),
    ("Security-Auditing", 4947): ("Windows Firewall exception list: rule modified", "firewall"),
    ("Security-Auditing", 4948): ("Windows Firewall exception list: rule deleted", "firewall"),
    ("Security-Auditing", 4950): ("Windows Firewall setting changed", "firewall"),
    ("Security-Auditing", 4964): ("Special groups assigned to a new logon", "privilege"),
    ("Security-Auditing", 5024): ("Windows Firewall service started", "firewall"),
    ("Security-Auditing", 5025): ("Windows Firewall service stopped", "firewall"),
    ("Security-Auditing", 5031): ("Windows Firewall blocked an application from accepting connections", "firewall"),
    ("Security-Auditing", 5136): ("A directory service object was modified", "domain"),
    ("Security-Auditing", 5137): ("A directory service object was created", "domain"),
    ("Security-Auditing", 5138): ("A directory service object was undeleted", "domain"),
    ("Security-Auditing", 5139): ("A directory service object was moved", "domain"),
    ("Security-Auditing", 5140): ("A network share object was accessed", "share"),
    ("Security-Auditing", 5141): ("A directory service object was deleted", "domain"),
    ("Security-Auditing", 5142): ("A network share object was added", "share"),
    ("Security-Auditing", 5143): ("A network share object was modified", "share"),
    ("Security-Auditing", 5144): ("A network share object was deleted", "share"),
    ("Security-Auditing", 5145): ("Network share object was checked for access", "share"),
    ("Security-Auditing", 5152): ("Windows Filtering Platform blocked a packet", "network"),
    ("Security-Auditing", 5154): ("WFP permitted an application to listen on a port", "network"),
    ("Security-Auditing", 5156): ("WFP permitted a connection", "network"),
    ("Security-Auditing", 5157): ("WFP blocked a connection", "network"),
    ("Security-Auditing", 5158): ("WFP permitted a bind to a local port", "network"),
    ("Security-Auditing", 5379): ("Credential Manager credentials were read", "credential"),
    ("Security-Auditing", 5380): ("Vault Find Credential", "credential"),
    ("Security-Auditing", 5381): ("Vault credentials were read", "credential"),
    ("Security-Auditing", 5382): ("Vault credentials were read", "credential"),
    ("Security-Auditing", 5447): ("A Windows Filtering Platform filter has been changed", "network"),
    ("Security-Auditing", 6416): ("A new external device was recognized by the system", "device"),
    ("Security-Auditing", 6419): ("Request to disable a device", "device"),
    ("Security-Auditing", 6420): ("A device was disabled", "device"),
    ("Security-Auditing", 6421): ("Request to enable a device", "device"),
    ("Security-Auditing", 6422): ("A device was enabled", "device"),
    ("Security-Auditing", 6423): ("Installation of a device was forbidden by policy", "device"),
    ("Security-Auditing", 6424): ("Installation of a device was allowed after being forbidden", "device"),
    # --- System -------------------------------------------------------------
    ("Eventlog", 104): ("The event log file was cleared", "log-tampering"),
    ("Eventlog", 1100): ("Event logging service has shut down", "log"),
    ("Eventlog", 6005): ("The Event log service was started", "system"),
    ("Eventlog", 6006): ("The Event log service was stopped", "system"),
    ("Eventlog", 6008): ("The previous system shutdown was unexpected", "system"),
    ("Eventlog", 6009): ("OS version / boot information", "system"),
    ("Eventlog", 6013): ("System uptime", "system"),
    ("USER32", 1074): ("System shutdown / restart initiated by a process", "system"),
    ("Service Control Manager", 7000): ("Service failed to start", "service"),
    ("Service Control Manager", 7009): ("Timeout waiting for service to connect", "service"),
    ("Service Control Manager", 7022): ("Service hung on starting", "service"),
    ("Service Control Manager", 7023): ("Service terminated with an error", "service"),
    ("Service Control Manager", 7024): ("Service terminated with service-specific error", "service"),
    ("Service Control Manager", 7030): ("Service marked as interactive (not allowed)", "service"),
    ("Service Control Manager", 7031): ("Service terminated unexpectedly", "service"),
    ("Service Control Manager", 7034): ("Service terminated unexpectedly", "service"),
    ("Service Control Manager", 7035): ("Service control sent (start/stop)", "service"),
    ("Service Control Manager", 7036): ("Service entered running/stopped state", "service"),
    ("Service Control Manager", 7040): ("Service start type was changed", "service"),
    ("Service Control Manager", 7045): ("A new service was installed in the system", "persistence"),
    ("Kernel-General", 1): ("System time changed (kernel)", "system"),
    ("Kernel-General", 12): ("Operating system started (boot)", "system"),
    ("Kernel-General", 13): ("Operating system is shutting down", "system"),
    ("Kernel-Power", 41): ("System rebooted without cleanly shutting down", "system"),
    ("Kernel-Power", 42): ("System is entering sleep", "system"),
    ("Kernel-Power", 109): ("Kernel power manager initiated shutdown", "system"),
    ("BugCheck", 1001): ("The computer has rebooted from a bugcheck", "system"),
    ("DistributedCOM", 10016): ("DCOM permission error", "system"),
    ("Time-Service", 35): ("Time service synchronizing", "system"),
    ("Kerberos", 4): ("Kerberos client received a KRB_AP_ERR_MODIFIED error", "kerberos"),
    ("UserPnp", 20001): ("Driver management installed a driver", "device"),
    ("UserPnp", 20003): ("Driver management service installation", "device"),
    ("DNS-Client", 1014): ("Name resolution timed out", "network"),
    # --- Sysmon ---------------------------------------------------------------
    ("Sysmon", 1): ("Process creation", "process"),
    ("Sysmon", 2): ("A process changed a file creation time", "file"),
    ("Sysmon", 3): ("Network connection", "network"),
    ("Sysmon", 4): ("Sysmon service state changed", "sysmon"),
    ("Sysmon", 5): ("Process terminated", "process"),
    ("Sysmon", 6): ("Driver loaded", "driver"),
    ("Sysmon", 7): ("Image loaded", "process"),
    ("Sysmon", 8): ("CreateRemoteThread", "injection"),
    ("Sysmon", 9): ("RawAccessRead (raw disk access)", "file"),
    ("Sysmon", 10): ("ProcessAccess (process handle opened)", "injection"),
    ("Sysmon", 11): ("FileCreate", "file"),
    ("Sysmon", 12): ("Registry object added or deleted", "registry"),
    ("Sysmon", 13): ("Registry value set", "registry"),
    ("Sysmon", 14): ("Registry object renamed", "registry"),
    ("Sysmon", 15): ("FileCreateStreamHash (alternate data stream)", "file"),
    ("Sysmon", 16): ("Sysmon configuration changed", "sysmon"),
    ("Sysmon", 17): ("Named pipe created", "pipe"),
    ("Sysmon", 18): ("Named pipe connected", "pipe"),
    ("Sysmon", 19): ("WMI event filter registered", "persistence"),
    ("Sysmon", 20): ("WMI event consumer registered", "persistence"),
    ("Sysmon", 21): ("WMI consumer bound to filter", "persistence"),
    ("Sysmon", 22): ("DNS query", "network"),
    ("Sysmon", 23): ("File deleted (archived)", "file"),
    ("Sysmon", 24): ("Clipboard changed", "file"),
    ("Sysmon", 25): ("Process tampering (hollowing / herpaderping)", "injection"),
    ("Sysmon", 26): ("File delete detected", "file"),
    ("Sysmon", 27): ("File block executable", "file"),
    ("Sysmon", 28): ("File block shredding", "file"),
    ("Sysmon", 29): ("File executable detected", "file"),
    ("Sysmon", 255): ("Sysmon error", "sysmon"),
    # --- PowerShell -------------------------------------------------------------
    ("PowerShell", 4103): ("PowerShell module logging (pipeline execution)", "powershell"),
    ("PowerShell", 4104): ("PowerShell script block logged", "powershell"),
    ("PowerShell", 4105): ("PowerShell script block execution started", "powershell"),
    ("PowerShell", 4106): ("PowerShell script block execution completed", "powershell"),
    ("PowerShell", 40961): ("PowerShell console is starting up", "powershell"),
    ("PowerShell", 40962): ("PowerShell console is ready for user input", "powershell"),
    ("PowerShell", 53504): ("PowerShell named pipe IPC listener created", "powershell"),
    ("PowerShell", 400): ("PowerShell engine state changed to Available (session start)", "powershell"),
    ("PowerShell", 403): ("PowerShell engine state changed to Stopped (session end)", "powershell"),
    ("PowerShell", 600): ("PowerShell provider started", "powershell"),
    ("PowerShell", 800): ("PowerShell pipeline execution details", "powershell"),
    ("PowerShell", 8193): ("PowerShell runspace state changed", "powershell"),
    ("PowerShell", 8194): ("PowerShell runspace state changed", "powershell"),
    ("PowerShell", 8197): ("PowerShell runspace state changed", "powershell"),
    ("PowerShell", 24577): ("PowerShell remote session (WinRM) started", "powershell"),
    ("PowerShell", 24578): ("PowerShell remote session (WinRM) ended", "powershell"),
    # --- Remote Desktop ----------------------------------------------------------
    ("TerminalServices-LocalSessionManager", 21): ("RDP session logon succeeded", "rdp"),
    ("TerminalServices-LocalSessionManager", 22): ("RDP shell start notification received", "rdp"),
    ("TerminalServices-LocalSessionManager", 23): ("RDP session logoff succeeded", "rdp"),
    ("TerminalServices-LocalSessionManager", 24): ("RDP session has been disconnected", "rdp"),
    ("TerminalServices-LocalSessionManager", 25): ("RDP session reconnection succeeded", "rdp"),
    ("TerminalServices-LocalSessionManager", 39): ("RDP session disconnected by another session", "rdp"),
    ("TerminalServices-LocalSessionManager", 40): ("RDP session disconnected (reason code)", "rdp"),
    ("TerminalServices-LocalSessionManager", 41): ("RDP session start begins", "rdp"),
    ("TerminalServices-RemoteConnectionManager", 1149): ("RDP user authentication succeeded (network-level)", "rdp"),
    ("TerminalServices-RemoteConnectionManager", 261): ("RDP listener received a connection", "rdp"),
    ("RemoteDesktopServices-RdpCoreTS", 131): ("RDP server accepted a new TCP connection", "rdp"),
    ("RemoteDesktopServices-RdpCoreTS", 98): ("RDP TCP connection successfully established", "rdp"),
    ("RemoteDesktopServices-RdpCoreTS", 140): ("RDP connection failed (bad username/password)", "rdp"),
    ("TerminalServices-ClientActiveXCore", 1024): ("Outbound RDP connection attempted (client)", "rdp"),
    ("TerminalServices-ClientActiveXCore", 1102): ("Outbound RDP connection initiated (client)", "rdp"),
    ("TerminalServices-RDPClient", 1024): ("Outbound RDP connection attempted (client)", "rdp"),
    ("TerminalServices-RDPClient", 1102): ("Outbound RDP connection initiated (client)", "rdp"),
    # --- Windows Defender ----------------------------------------------------------
    ("Windows Defender", 1006): ("Malware or unwanted software detected", "defender"),
    ("Windows Defender", 1007): ("Action taken against malware", "defender"),
    ("Windows Defender", 1008): ("Action against malware failed", "defender"),
    ("Windows Defender", 1015): ("Suspicious behavior detected", "defender"),
    ("Windows Defender", 1116): ("Malware or unwanted software detected", "defender"),
    ("Windows Defender", 1117): ("Action taken to protect the system from malware", "defender"),
    ("Windows Defender", 1118): ("Action against malware failed", "defender"),
    ("Windows Defender", 1119): ("Critical error taking action against malware", "defender"),
    ("Windows Defender", 1121): ("Attack surface reduction rule blocked an event", "defender"),
    ("Windows Defender", 1122): ("Attack surface reduction rule audited an event", "defender"),
    ("Windows Defender", 5001): ("Real-time protection disabled", "defender-tampering"),
    ("Windows Defender", 5004): ("Real-time protection configuration changed", "defender-tampering"),
    ("Windows Defender", 5007): ("Antimalware platform configuration changed", "defender-tampering"),
    ("Windows Defender", 5010): ("Scanning for malware is disabled", "defender-tampering"),
    ("Windows Defender", 5012): ("Scanning for viruses is disabled", "defender-tampering"),
    ("Windows Defender", 5013): ("Tamper protection blocked a change", "defender-tampering"),
    # --- WinRM / WMI / BITS / tasks ---------------------------------------------------
    ("WinRM", 91): ("WinRM session created (remote shell request)", "remote"),
    ("WinRM", 168): ("WinRM authenticating user", "remote"),
    ("WinRM", 169): ("WinRM user authenticated successfully", "remote"),
    ("WinRM", 6): ("WinRM client creating a session (outbound)", "remote"),
    ("WMI-Activity", 5857): ("WMI provider started", "wmi"),
    ("WMI-Activity", 5858): ("WMI operation error", "wmi"),
    ("WMI-Activity", 5859): ("WMI permanent event subscription", "persistence"),
    ("WMI-Activity", 5860): ("WMI temporary event subscription", "wmi"),
    ("WMI-Activity", 5861): ("WMI permanent event consumer/filter binding created", "persistence"),
    ("Bits-Client", 59): ("BITS job started transfer (URL)", "download"),
    ("Bits-Client", 60): ("BITS job stopped transferring", "download"),
    ("Bits-Client", 3): ("BITS job created", "download"),
    ("Bits-Client", 4): ("BITS job completed", "download"),
    ("TaskScheduler", 106): ("Scheduled task registered", "persistence"),
    ("TaskScheduler", 129): ("Scheduled task launched a process", "process"),
    ("TaskScheduler", 140): ("Scheduled task updated", "persistence"),
    ("TaskScheduler", 141): ("Scheduled task deleted", "persistence"),
    ("TaskScheduler", 200): ("Scheduled task action started", "process"),
    ("TaskScheduler", 201): ("Scheduled task action completed", "process"),
    ("Windows Firewall With Advanced Security", 2004): ("Firewall rule added", "firewall"),
    ("Windows Firewall With Advanced Security", 2005): ("Firewall rule modified", "firewall"),
    ("Windows Firewall With Advanced Security", 2006): ("Firewall rule deleted", "firewall"),
    ("Windows Firewall With Advanced Security", 2033): ("All firewall rules deleted", "firewall"),
    ("Windows Firewall With Advanced Security", 2003): ("Firewall profile setting changed", "firewall"),
    ("AppLocker", 8002): ("AppLocker allowed an executable", "applocker"),
    ("AppLocker", 8003): ("AppLocker would have blocked an executable (audit)", "applocker"),
    ("AppLocker", 8004): ("AppLocker blocked an executable", "applocker"),
    ("AppLocker", 8006): ("AppLocker would have blocked a script/MSI (audit)", "applocker"),
    ("AppLocker", 8007): ("AppLocker blocked a script/MSI", "applocker"),
    ("CodeIntegrity", 3033): ("Code integrity: file did not meet signing requirements", "integrity"),
    ("CodeIntegrity", 3077): ("Code integrity: blocked a file (policy)", "integrity"),
    ("NTLM", 8001): ("NTLM client blocked audit (outgoing)", "ntlm"),
    ("NTLM", 8002): ("NTLM server blocked audit (incoming)", "ntlm"),
    ("NTLM", 8003): ("NTLM server blocked in domain audit", "ntlm"),
    ("NTLM", 8004): ("NTLM authentication in domain", "ntlm"),
    ("Security-Mitigations", 10): ("Exploit protection blocked a process", "mitigation"),
    ("SmartScreen", 1002): ("SmartScreen warning shown to the user", "download"),
    ("SMBServer", 1020): ("SMB server: file share access failed", "share"),
    ("SMBServer", 1024): ("SMB server: share access", "share"),
    ("PrintService", 316): ("Printer driver added or updated (PrintNightmare vector)", "persistence"),
    ("LSA", 6155): ("LSASS: process loaded a non-Microsoft plugin", "credential"),
    ("Kernel-PnP", 400): ("Device configured (Plug and Play)", "device"),
    ("Kernel-PnP", 410): ("Device started (Plug and Play)", "device"),
    ("DriverFrameworks-UserMode", 2003): ("USB device connected (UMDF host process)", "device"),
    ("DriverFrameworks-UserMode", 2100): ("USB device pnp/power operation", "device"),
    ("DriverFrameworks-UserMode", 2101): ("USB device pnp/power operation completed", "device"),
    ("Partition", 1006): ("Partition/diagnostic: disk (USB) attached", "device"),
    ("StorSvc", 1001): ("Storage service: new storage device", "device"),
    ("VHDMP", 1): ("Virtual disk (ISO/VHD) mounted", "device"),
    ("VHDMP", 12): ("Virtual disk (ISO/VHD) surfaced", "device"),
    ("VHDMP", 22): ("Virtual disk (ISO/VHD) unmounted", "device"),
    # --- Application ---------------------------------------------------------------------
    ("Application Error", 1000): ("Application crash", "application"),
    ("Application Hang", 1002): ("Application hang", "application"),
    ("Windows Error Reporting", 1001): ("Windows Error Reporting bucket", "application"),
    ("MsiInstaller", 11707): ("MSI installation completed successfully", "install"),
    ("MsiInstaller", 11724): ("MSI product removed", "install"),
    ("MsiInstaller", 1033): ("MSI product installed", "install"),
    ("MsiInstaller", 1034): ("MSI product removed", "install"),
    ("MsiInstaller", 1040): ("MSI transaction started", "install"),
    ("MsiInstaller", 1042): ("MSI transaction ended", "install"),
    ("ESENT", 327): ("ESENT database detached (ntds.dit / SAM dumping hint)", "credential"),
    ("ESENT", 325): ("ESENT database created", "credential"),
    ("ESENT", 326): ("ESENT database attached", "credential"),
    ("RestartManager", 10000): ("Restart Manager session started", "application"),
    ("Software Protection Platform Service", 16384): ("Software protection service scheduled", "application"),
    ("Microsoft Office Alerts", 300): ("Microsoft Office alert dialog", "application"),
    ("Outlook", 63): ("Outlook loaded an add-in", "application"),
}

# Investigative notes for the most useful IDs (shown in tooltips / detail).
NOTES: dict[int, str] = {
    1102: "Attackers clear the Security log to cover tracks. Who (SubjectUserName) and when? Correlate with 104 in System.",
    104: "System/Application log cleared. Rarely legitimate outside maintenance windows.",
    4624: "Check LogonType (3 network, 10 RDP, 9 runas /netonly, 2 interactive), source IP/workstation, AuthenticationPackage (NTLM vs Kerberos) and ElevatedToken.",
    4625: "Failed logon. Bursts per IP or per account indicate brute force / password spraying; look at Status/SubStatus (0xC000006A wrong password, 0xC0000064 unknown user).",
    4634: "Logoff. Pair with 4624 using TargetLogonId to compute session duration.",
    4648: "Explicit credentials (runas, scheduled task with creds, lateral movement tools). TargetServerName reveals the destination.",
    4672: "Admin-equivalent privileges assigned at logon. Unexpected for standard user accounts.",
    4688: "Process creation. CommandLine is only present if command-line auditing is enabled. Look at ParentProcessName chains (Office -> cmd/powershell).",
    4697: "Service installed via the Security log. PsExec (PSEXESVC), remote service creation, malware persistence.",
    4698: "Scheduled task created. Persistence: check the task XML for the command, trigger and author.",
    4719: "Audit policy changed: may be an attacker reducing visibility before acting.",
    4720: "User account created. Backdoor accounts often mimic service names.",
    4726: "User account deleted: cleanup after use.",
    4728: "Member added to global group (e.g. Domain Admins).",
    4732: "Member added to local group (e.g. Administrators, Remote Desktop Users).",
    4740: "Account lockout: usually the tail of a brute-force or a misconfigured service.",
    4756: "Member added to universal group (e.g. Enterprise Admins).",
    4768: "TGT request. Failures with 0x6 indicate username enumeration; RC4 (0x17) for AS-REP roasting.",
    4769: "Service ticket request. Many distinct services with RC4 (0x17) from one account = Kerberoasting.",
    4771: "Kerberos pre-auth failed: the Kerberos equivalent of 4625 (0x18 wrong password).",
    4776: "NTLM validation by a DC / local SAM. Bursts of failures = brute force; NTLM where Kerberos is expected = pass-the-hash suspicion.",
    4778: "RDP/session reconnect: ClientName and ClientAddress reveal the remote host.",
    4779: "Session disconnected (RDP).",
    4798: "Local group membership enumerated (net user, BloodHound, whoami /groups).",
    4799: "Security group membership enumerated (recon).",
    4825: "User denied RDP access (not in Remote Desktop Users).",
    5140: "Network share accessed. ADMIN$ / C$ / IPC$ from workstations = lateral movement.",
    5145: "Detailed share access: RelativeTargetName shows the file (PsExec drops PSEXESVC.exe on ADMIN$).",
    6416: "New external device (USB mass storage) recognized.",
    7045: "New service installed (System log). Look at ImagePath: random names, cmd /c, powershell, %COMSPEC%, temp paths = malicious.",
    7036: "Service state changes. Useful for timeline (PSEXESVC started/stopped).",
    4104: "Script block logging: decoded content of executed PowerShell. Search for EncodedCommand, IEX, DownloadString, Invoke-Mimikatz, bypass, hidden.",
    4103: "Module logging: parameters passed to cmdlets.",
    1149: "RDP network-level authentication succeeded: user + source IP, even before the session logon (21).",
    21: "RDP session logon succeeded: user and source network address.",
    25: "RDP session reconnected: user and source network address.",
    1116: "Defender detected malware: threat name, path, user, action.",
    1117: "Defender action taken (quarantine, remove).",
    5001: "Defender real-time protection disabled.",
    5007: "Defender configuration changed (exclusions added?).",
    91: "WinRM shell request: remote PowerShell / Evil-WinRM lateral movement.",
    2004: "Firewall rule added: attackers open ports for C2 or RDP.",
    1: "Sysmon 1 process creation: full command line, hashes, parent process. Also Kernel-General 1 (time change).",
    3: "Sysmon 3 network connection: process -> destination IP:port; C2 beacons.",
    7: "Sysmon 7 image loaded: DLL side-loading / unsigned modules.",
    8: "Sysmon 8 CreateRemoteThread: injection.",
    10: "Sysmon 10 process access: lsass.exe access with 0x1010/0x1fffff = credential dumping.",
    11: "Sysmon 11 file created: dropped payloads in Temp/Downloads/Startup.",
    13: "Sysmon 13 registry value set: Run keys, services, WDigest UseLogonCredential.",
    22: "Sysmon 22 DNS query: resolved domains per process.",
    4616: "System time changed: anti-forensics or timestomping context.",
    4657: "Registry value modified (needs SACL). Run keys / services persistence.",
    4663: "Object access (files, registry) with SACL: sensitive file reads.",
    5136: "AD object modified: GPO edits, ACL changes, delegation.",
    4794: "DSRM password set: DC persistence.",
    4765: "SID history added: privilege escalation / persistence in AD.",
    4964: "Special group logon (configured watch-list groups).",
    59: "BITS transfer started: downloads from unusual URLs (living-off-the-land).",
    106: "Scheduled task registered (TaskScheduler log). Persistence.",
    200: "Scheduled task action started: what executable ran.",
    5861: "WMI permanent event subscription created: fileless persistence.",
    8004: "AppLocker blocked an executable.",
    316: "Printer driver added: PrintNightmare exploitation vector.",
    327: "ESENT database detached: ntds.dit / SAM copy via VSS or ntdsutil.",
    140: "RDP connection failed: username/password (RdpCoreTS) - brute force over RDP without 4625 details. Also TaskScheduler 140 (task updated).",
    131: "RDP TCP connection accepted: ClientIP is the remote address, even for failed attempts.",
}


def _norm_provider(provider: str | None) -> str:
    return (provider or "").lower()


def describe(provider: str | None, event_id: int | None) -> tuple[str, str] | None:
    """Return (description, category) for a provider/event id pair, if known."""
    if event_id is None:
        return None
    prov = _norm_provider(provider)
    best: tuple[str, str] | None = None
    best_len = -1
    for (frag, eid), value in _EVENTS.items():
        if eid != event_id:
            continue
        frag_l = frag.lower()
        if frag_l and frag_l not in prov:
            continue
        if len(frag_l) > best_len:
            best, best_len = value, len(frag_l)
    return best


def description(provider: str | None, event_id: int | None) -> str | None:
    d = describe(provider, event_id)
    return d[0] if d else None


def category(provider: str | None, event_id: int | None) -> str | None:
    d = describe(provider, event_id)
    return d[1] if d else None


def note(event_id: int | None) -> str | None:
    if event_id is None:
        return None
    return NOTES.get(event_id)


def logon_type_name(value: Any) -> str | None:
    try:
        return LOGON_TYPES.get(int(value))
    except (TypeError, ValueError):
        return None


def _hex_norm(code: Any) -> str | None:
    if code is None:
        return None
    s = str(code).strip().lower()
    if not s:
        return None
    if s.startswith("0x"):
        try:
            s = "0x%x" % int(s, 16)
        except ValueError:
            pass
    return s


def status_text(code: Any) -> str | None:
    s = _hex_norm(code)
    return STATUS_CODES.get(s) if s else None


def kerberos_failure_text(code: Any) -> str | None:
    s = _hex_norm(code)
    return KERBEROS_FAILURES.get(s) if s else None


def ticket_encryption_name(code: Any) -> str | None:
    s = _hex_norm(code)
    return TICKET_ENCRYPTION.get(s) if s else None


def _user(ev: dict[str, Any], prefix: str) -> str | None:
    name = ev.get(f"{prefix}User")
    if not name or name in ("-",):
        return None
    dom = ev.get(f"{prefix}Domain")
    if dom and dom not in ("-",):
        return f"{dom}\\{name}"
    return name


def summarize(ev: dict[str, Any]) -> str:
    """One-line human summary built from the flattened event fields."""
    eid = ev.get("eventId")
    prov = ev.get("provider") or ""
    desc = description(prov, eid) or ""
    parts: list[str] = []
    tgt = _user(ev, "target")
    sub = _user(ev, "subject")
    ip = ev.get("ipAddress")
    ws = ev.get("workstation")
    lt = ev.get("logonType")
    ltn = logon_type_name(lt) if lt is not None else None
    is_security = "security-auditing" in prov.lower()
    is_sysmon = "sysmon" in prov.lower()

    if is_security and eid == 4624:
        parts.append(f"Logon {ltn or lt or ''}".strip())
        if tgt:
            parts.append(f"as {tgt}")
        if ip:
            parts.append(f"from {ip}")
        elif ws:
            parts.append(f"from {ws}")
        if ev.get("authPackage"):
            parts.append(f"({ev['authPackage']})")
    elif is_security and eid == 4625:
        parts.append(f"Failed logon {ltn or lt or ''}".strip())
        if tgt:
            parts.append(f"as {tgt}")
        if ip:
            parts.append(f"from {ip}")
        elif ws:
            parts.append(f"from {ws}")
        reason = status_text(ev.get("subStatus")) or status_text(ev.get("status"))
        if reason:
            parts.append(f"- {reason}")
    elif is_security and eid in (4634, 4647):
        parts.append("Logoff")
        if tgt:
            parts.append(tgt)
    elif is_security and eid == 4648:
        parts.append("Explicit credentials")
        if sub:
            parts.append(f"by {sub}")
        if tgt:
            parts.append(f"as {tgt}")
        if ev.get("targetServer"):
            parts.append(f"to {ev['targetServer']}")
        if ev.get("processName"):
            parts.append(f"via {ev['processName']}")
    elif is_security and eid == 4672:
        parts.append("Special privileges")
        if sub:
            parts.append(f"for {sub}")
    elif is_security and eid == 4688:
        parts.append("Process")
        parts.append(ev.get("processName") or "?")
        if ev.get("commandLine"):
            parts.append(f"- {ev['commandLine']}")
        if sub:
            parts.append(f"by {sub}")
    elif eid in (4697, 7045) and (is_security or "service control" in prov.lower()):
        parts.append("Service installed")
        if ev.get("serviceName"):
            parts.append(ev["serviceName"])
        if ev.get("serviceFile"):
            parts.append(f"-> {ev['serviceFile']}")
    elif (is_security and eid in (4698, 4699, 4700, 4701, 4702)) or ("taskscheduler" in prov.lower() and eid in (106, 140, 141)):
        parts.append(desc)
        if ev.get("taskName"):
            parts.append(ev["taskName"])
        if sub:
            parts.append(f"by {sub}")
    elif is_security and eid in (4720, 4722, 4725, 4726, 4738, 4740, 4767, 4781):
        parts.append(desc)
        if tgt:
            parts.append(tgt)
        if sub:
            parts.append(f"by {sub}")
    elif is_security and eid in (4728, 4729, 4732, 4733, 4756, 4757):
        parts.append(desc)
        if ev.get("memberName"):
            parts.append(ev["memberName"])
        if ev.get("groupName"):
            parts.append(f"-> {ev['groupName']}")
        if sub:
            parts.append(f"by {sub}")
    elif is_security and eid in (4768, 4769, 4770, 4771, 4772, 4773):
        parts.append(desc)
        if tgt:
            parts.append(tgt)
        if ev.get("serviceName"):
            parts.append(f"svc {ev['serviceName']}")
        if ip:
            parts.append(f"from {ip}")
        enc = ticket_encryption_name(ev.get("ticketEncryption"))
        if enc:
            parts.append(f"[{enc}]")
        fail = kerberos_failure_text(ev.get("status"))
        if fail:
            parts.append(f"- {fail}")
    elif is_security and eid == 4776:
        parts.append("NTLM validation")
        if tgt:
            parts.append(tgt)
        if ws:
            parts.append(f"from {ws}")
        reason = status_text(ev.get("status"))
        if reason:
            parts.append(f"- {reason}")
    elif is_security and eid in (5140, 5145):
        parts.append("Share access")
        if ev.get("shareName"):
            parts.append(ev["shareName"])
        if ev.get("relativeTargetName"):
            parts.append(f"/ {ev['relativeTargetName']}")
        if sub:
            parts.append(f"by {sub}")
        if ip:
            parts.append(f"from {ip}")
    elif (is_security and eid == 1102) or ("eventlog" in prov.lower() and eid == 104):
        parts.append(desc)
        if sub:
            parts.append(f"by {sub}")
        if ev.get("channelCleared"):
            parts.append(f"({ev['channelCleared']})")
    elif "powershell" in prov.lower() and eid == 4104:
        parts.append("Script block")
        txt = ev.get("scriptBlockText") or ""
        parts.append(txt[:160].replace("\n", " "))
    elif "terminalservices" in prov.lower() and eid in (21, 22, 23, 24, 25, 39, 40, 41, 1149):
        parts.append(desc)
        if ev.get("targetUser"):
            parts.append(ev["targetUser"])
        if ip:
            parts.append(f"from {ip}")
    elif "defender" in prov.lower() and eid in (1116, 1006):
        parts.append("Malware detected")
        if ev.get("threatName"):
            parts.append(ev["threatName"])
        if ev.get("path"):
            parts.append(f"at {ev['path']}")
    elif is_security and eid == 6416:
        parts.append("New device")
        if ev.get("deviceDescription"):
            parts.append(ev["deviceDescription"])
    elif is_security and eid == 4616:
        parts.append("Time changed")
        if ev.get("previousTime") and ev.get("newTime"):
            parts.append(f"{ev['previousTime']} -> {ev['newTime']}")
    elif is_sysmon:
        parts.append(desc or f"Sysmon {eid}")
        if eid == 1:
            parts.append(ev.get("commandLine") or ev.get("image") or "")
        elif eid == 3:
            parts.append(f"{ev.get('image') or ''} -> {ev.get('destinationIp') or ''}:{ev.get('destinationPort') or ''}")
        elif eid == 22:
            parts.append(f"{ev.get('image') or ''} ? {ev.get('query') or ''}")
        elif eid == 7:
            parts.append(ev.get("imageLoaded") or "")
        elif eid in (11, 23, 26):
            parts.append(ev.get("targetFilename") or "")
        elif eid in (12, 13, 14):
            parts.append(ev.get("targetObject") or "")
        elif eid == 10:
            parts.append(f"{ev.get('sourceImage') or ''} -> {ev.get('targetImage') or ''} ({ev.get('grantedAccess') or ''})")
        else:
            parts.append(ev.get("image") or "")
    else:
        parts.append(desc or f"Event {eid}")
        if tgt:
            parts.append(tgt)
        elif sub:
            parts.append(sub)
    return " ".join(p for p in parts if p).strip()


def reference(provider: str | None, event_id: int | None) -> dict[str, Any]:
    d = describe(provider, event_id)
    return {
        "eventId": event_id,
        "provider": provider,
        "description": d[0] if d else None,
        "category": d[1] if d else None,
        "note": note(event_id),
    }
