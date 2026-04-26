# Access Token Manipulation: [T1134](https://attack.mitre.org/techniques/T1134/)

## Detection Explanation

Access Token Manipulation occurs when adversaries modify Windows access tokens to operate under different security contexts, escalate privileges, or evade detection. Access tokens are kernel objects that describe the security context of a process or thread, containing information about the user's identity, group memberships, and privileges. By manipulating these tokens, attackers can impersonate other users, escalate from standard user to SYSTEM privileges, bypass User Account Control (UAC), or execute actions under alternate security contexts without proper authentication.

Attackers leverage token manipulation for multiple objectives including privilege escalation, defense evasion, and lateral movement. Common sub-techniques include Token Impersonation/Theft (T1134.001) where attackers duplicate tokens from privileged processes, Create Process with Token (T1134.002) to spawn processes using stolen tokens, Make and Impersonate Token (T1134.003) for creating new tokens from credentials, and Parent PID Spoofing (T1134.004) to disguise process lineage. This technique is frequently observed in the post-exploitation phase after initial access has been achieved, often following credential dumping or exploitation activities. Tools like Mimikatz, Cobalt Strike, Meterpreter, Incognito, and various PowerShell frameworks provide built-in token manipulation capabilities.

Token manipulation is particularly dangerous because it allows attackers to operate under legitimate security contexts, making their activities appear as authorized actions. This technique enables lateral movement without additional authentication, privilege escalation without exploiting vulnerabilities, and the ability to bypass many traditional security controls. Attackers commonly target high-value tokens from processes running as SYSTEM, domain administrators, or service accounts to gain elevated access across the environment.

Detecting token manipulation requires monitoring for suspicious use of Windows API calls (OpenProcessToken, DuplicateTokenEx, ImpersonateLoggedOnUser, CreateProcessWithToken), unusual parent-child process relationships, privilege assignments that don't match expected patterns, and processes operating under security contexts inconsistent with their typical behavior. The technique often generates specific security events related to privilege use, special logons, and handle operations that can reveal manipulation attempts.

---

## Key Detection Indicators & Areas to Investigate

### Summary of Indicators

1. Token impersonation through process handle operations (T1134.001)
2. Process creation with stolen or duplicated tokens (T1134.002)
3. Explicit credential use and token creation from logon sessions (T1134.003)
4. Parent Process ID (PPID) spoofing and process ancestry manipulation (T1134.004)
5. Suspicious use of SeDebugPrivilege and other sensitive privileges
6. Processes with mismatched integrity levels and security contexts
7. Named pipe impersonation for token theft
8. Token manipulation via known attack tools and frameworks
9. Unusual logon types and authentication patterns
10. Cross-session token operations and remote token manipulation

---

### 1. Token Impersonation Through Process Handle Operations (T1134.001)

**Windows Event Logs:**

- Event ID 4673 (Sensitive Privilege Use) - Use of `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeTcbPrivilege`
- Event ID 4703 (User Right Adjusted) - Token privileges adjusted
- Event ID 4688 (Process Creation) - Check for Token Elevation Type field indicating privilege changes

**Sysmon:**

- Event ID 10 (Process Access) - Process opening handles to privileged processes with specific access rights
    - `GrantedAccess`: `0x1410` (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
    - `GrantedAccess`: `0x1010` (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ)
    - `GrantedAccess`: `0x1400` or `0x1000` targeting SYSTEM processes
- Event ID 1 (Process Creation) - Check `IntegrityLevel` and `User` fields for mismatches

**EDR/API Monitoring:**

- API calls: `OpenProcessToken()`, `DuplicateTokenEx()`, `ImpersonateLoggedOnUser()`, `SetThreadToken()`
- Handle operations on privileged process tokens

**Focus on:**

- Non-administrative processes accessing tokens of SYSTEM processes
- Web application processes (w3wp.exe, apache, java) accessing privileged tokens
- User-mode applications opening handles to `lsass.exe`, `winlogon.exe`, `services.exe`
- Processes with Medium integrity accessing High or SYSTEM integrity processes

**Suspicious indicators:**

- `powershell.exe`, `cmd.exe`, or scripting engines accessing privileged process tokens
- Processes using `SeImpersonatePrivilege` outside expected service contexts (IIS, SQL Server)
- Token duplication from processes running as different users
- Multiple rapid token access attempts from the same process
- Process access patterns: Low-privilege process → `lsass.exe` → Token duplication → SYSTEM process creation
- Commands: `Invoke-TokenManipulation -CreateProcess`, `steal_token` (Cobalt Strike), `incognito.exe`

---

### 2. Process Creation with Stolen or Duplicated Tokens (T1134.002)

**Windows Event Logs:**

- Event ID 4688 (Process Creation) - New process with mismatched creator and process user
    - Check `Creator Process Name` vs `New Process Name` user contexts
    - Review `Token Elevation Type` field (values: 1=default, 2=elevated, 3=full)
- Event ID 4624 (Logon) - LogonType 9 (NewCredentials) indicating RunAs usage
- Event ID 4648 (Explicit Credential Logon) - Process started with alternate credentials

**Sysmon:**

- Event ID 1 (Process Creation) - Analyze `ParentImage`, `User`, `IntegrityLevel`, and `ParentUser` fields
    - Parent and child running as different users without corresponding logon events
    - Integrity level mismatches (Medium parent spawning High/SYSTEM child)

**EDR/Process Monitoring:**

- API calls: `CreateProcessWithTokenW()`, `CreateProcessAsUserW()`, `CreateProcessWithLogonW()`
- Process trees showing privilege escalation without authentication events

**Look for:**

- User processes spawning SYSTEM-level child processes without scheduled task or service context
- Processes created with tokens from different logon sessions
- Child processes with higher integrity than parent without UAC elevation
- Process creation lacking corresponding authentication events (Event ID 4624)

**Suspicious indicators:**

- `cmd.exe` or `powershell.exe` spawned as SYSTEM from non-service parent
- Interactive processes (explorer.exe) spawning SYSTEM children
- Web server processes spawning high-privilege command shells
- Process lineage showing privilege escalation: `user_process.exe` → `cmd.exe` (SYSTEM)
- Commands: `runas /user:DOMAIN\Administrator`, `CreateProcessWithToken` API usage
- Cobalt Strike beacon executing `spawn` or `spawnas` commands
- Metasploit `getsystem` or `steal_token` operations
- Tool artifacts: `Invoke-TokenManipulation -CreateProcess "cmd.exe" -ProcessId 1234`

---

### 3. Explicit Credential Use and Token Creation from Logon Sessions (T1134.003)

**Windows Event Logs:**

- Event ID 4624 (Logon) - LogonType 9 (NewCredentials) or LogonType 2 (Interactive) with `runas` context
- Event ID 4648 (Explicit Credential Logon) - Process spawned with explicit credentials
    - Review `Subject` (who initiated) vs `Target` (credentials used)
- Event ID 4672 (Special Privileges Assigned) - Administrative privileges assigned to new logon
- Event ID 4673 (Sensitive Privilege Use) - `SeTcbPrivilege` (Act as part of operating system)

**Sysmon:**

- Event ID 1 (Process Creation) - `runas.exe` execution or processes with `LogonId` mismatches
- Event ID 10 (Process Access) - Access to `lsass.exe` for credential extraction preceding token creation

**PowerShell Logs:**

- Event ID 4104 (Script Block Logging) - Scripts using `Make-Token`, `Invoke-TokenManipulation`, `New-Token`

**Focus on:**

- `runas.exe` execution from non-administrative contexts
- Token creation using credentials obtained through credential dumping
- Logon events (4624) occurring without corresponding network or interactive activity
- Processes making authentication API calls: `LogonUserW()`, `LogonUserExW()`

**Suspicious indicators:**

- Multiple Event ID 4648 events from same source without legitimate administrative activity
- `runas.exe` spawning processes as domain administrator from standard workstations
- Logon events with unusual LogonType combinations
- Token creation shortly after credential dumping indicators (access to lsass.exe)
- Commands: `runas /user:DOMAIN\Administrator /netonly cmd.exe`
- PowerShell: `Invoke-TokenManipulation -Username "DOMAIN\admin" -Password $pass`
- API patterns: `LogonUserW()` → `CreateProcessWithTokenW()` sequence
- Network logon (Type 3) without corresponding network connection
- Credentials used from memory without corresponding Event ID 4624 logon

---

### 4. Parent Process ID (PPID) Spoofing and Process Ancestry Manipulation (T1134.004)

**Sysmon:**

- Event ID 1 (Process Creation) - Analyze `ParentProcessId`, `ParentImage`, `ParentCommandLine`
    - Compare against expected parent-child relationships
    - Check for terminated parents spawning new children
- Event ID 5 (Process Terminated) - Correlate with Event ID 1 to identify dead parent processes

**Windows Event Logs:**

- Event ID 4688 (Process Creation) - Review `Creator Process ID` and `Creator Process Name`
    - Process lineage that doesn't match expected system behavior

**EDR/Process Monitoring:**

- Process tree analysis showing illogical parent-child relationships
- API calls: `UpdateProcThreadAttribute()` with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`
- Handle inheritance from unexpected processes

**Look for:**

- Critical processes with spoofed parents (cmd.exe parented to explorer.exe when it should be services.exe)
- Parent processes that terminated before child process creation timestamp
- System processes showing user applications as parents
- Processes with parent PIDs that don't exist or have been reused

**Suspicious indicators:**

- `cmd.exe` or `powershell.exe` with `ParentImage` of `explorer.exe` but created outside user logon context
- `svchost.exe` with parent other than `services.exe`
- High-privilege processes with low-privilege parents
- Process creation timestamp before parent process creation timestamp
- Parent PID pointing to terminated or non-existent process
- Cobalt Strike beacon spawning processes with PPID spoofing
- Commands showing spoofing indicators: `psinject` (Cobalt Strike), `--ppid` parameters
- Process trees missing intermediate processes: `explorer.exe` → `powershell.exe` (no cmd.exe)
- SYSTEM processes parented by user-mode applications without service installation

---

### 5. Suspicious Use of SeDebugPrivilege and Other Sensitive Privileges

**Windows Event Logs:**

- Event ID 4673 (Sensitive Privilege Use) - Monitor for:
    - `SeDebugPrivilege` - Debug programs (access any process)
    - `SeTcbPrivilege` - Act as part of operating system
    - `SeImpersonatePrivilege` - Impersonate a client after authentication
    - `SeAssignPrimaryTokenPrivilege` - Replace process-level token
    - `SeRestorePrivilege` - Restore files and directories (often abused)
    - `SeTakeOwnershipPrivilege` - Take ownership of objects
- Event ID 4672 (Special Privileges Assigned) - Administrative privileges assigned to logon session
- Event ID 4703 (User Right Adjusted) - Token privileges enabled or disabled

**Sysmon:**

- Event ID 10 (Process Access) - Correlation with privilege use
    - Processes accessing others after enabling `SeDebugPrivilege`

**Focus on:**

- Non-administrative processes using debug privileges
- Privilege use from unexpected executables (not debuggers, admin tools)
- Privilege escalation sequences: Enable privilege → Access process → Duplicate token
- Multiple privilege uses in rapid succession from same process

**Suspicious indicators:**

- PowerShell, scripting engines, or Office applications using `SeDebugPrivilege`
- Web application processes (w3wp.exe) using impersonation privileges outside normal operation
- User applications enabling `SeTcbPrivilege` (rare outside Windows components)
- Privilege use patterns: `SeDebugPrivilege` enabled → lsass.exe accessed → `SeImpersonatePrivilege` used
- Commands: `privilege::debug` (Mimikatz), `AdjustTokenPrivileges` API calls
- Tool execution: `procdump.exe`, `PsExec.exe`, `Invoke-Mimikatz` correlating with privilege events
- Multiple privilege adjustments from temporary directories (%TEMP%, %APPDATA%)
- Service accounts using privileges outside their defined scope

---

### 6. Processes with Mismatched Integrity Levels and Security Contexts

**Sysmon:**

- Event ID 1 (Process Creation) - Compare `IntegrityLevel` values across process tree
    - Values: Low, Medium, High, System
    - Parent-child integrity mismatches
- Event ID 10 (Process Access) - Cross-integrity process access

**Windows Event Logs:**

- Event ID 4688 (Process Creation) - `TokenElevationType` and `MandatoryLabel` fields
    - Type 1: Default token (non-elevated)
    - Type 2: Elevated token (UAC prompt)
    - Type 3: Full token (built-in administrator)

**EDR/Process Monitoring:**

- Security descriptor integrity level monitoring
- Token mandatory label inspection
- Process security context validation

**Look for:**

- Medium integrity parent spawning High or System integrity children without UAC
- User applications running with SYSTEM integrity
- Processes with integrity levels inconsistent with their signing or origin
- Token elevation without corresponding UAC consent events (Event ID 4703)

**Suspicious indicators:**

- User-initiated processes (Medium) spawning SYSTEM processes without service installation
- Low integrity processes (sandboxed applications) creating High integrity children
- Process trees showing escalation: Medium → High → SYSTEM without authentication
- Office applications (winword.exe, excel.exe) running as SYSTEM
- Browser processes spawning High integrity child processes
- Commands executed from Medium integrity spawning SYSTEM shells
- Processes in user directories (%APPDATA%, %LOCALAPPDATA%) running as SYSTEM
- Remote access tools (TeamViewer, AnyDesk) spawning processes with elevated integrity
- Token integrity modifications via `SetTokenInformation()` API

---

### 7. Named Pipe Impersonation for Token Theft

**Sysmon:**

- Event ID 17 (Pipe Created) - Creation of named pipes by suspicious processes
- Event ID 18 (Pipe Connected) - Connections to named pipes from privileged processes
- Event ID 1 (Process Creation) - Processes creating or connecting to pipes

**Windows Event Logs:**

- Event ID 4673 (Sensitive Privilege Use) - `SeImpersonatePrivilege` usage correlating with pipe operations
- Event ID 5145 (Network Share Access) - Access to IPC$ share and named pipes

**EDR/API Monitoring:**

- API calls: `CreateNamedPipe()`, `ConnectNamedPipe()`, `ImpersonateNamedPipeClient()`
- Named pipe operations followed by token manipulation

**Focus on:**

- User processes creating named pipes in unusual namespaces
- Pipe servers impersonating clients with elevated privileges
- Service processes connecting to user-created named pipes
- Pipe operations correlating with privilege escalation

**Suspicious indicators:**

- Named pipes with suspicious patterns: `\\.\pipe\MSSE-*`, `\\.\pipe\postex_*` (Cobalt Strike)
- User applications creating pipes and waiting for SYSTEM process connections
- Commands: `NamedPipeImpersonation`, exploitation of `Print Spooler` via named pipes
- Pipe impersonation tools: `RottenPotato`, `JuicyPotato`, `RoguePotato`
- PrintSpooler service (`spoolsv.exe`) connecting to unexpected named pipes
- RPC over named pipes from non-administrative contexts
- Pipe names matching exploit patterns: `\\.\pipe\random_string`, `\\.\pipe\spoolss`
- Rapid pipe creation and destruction cycles
- Local privilege escalation exploits (CVE-2019-1069, CVE-2019-1405) using pipe impersonation

---

### 8. Token Manipulation via Known Attack Tools and Frameworks

**Sysmon:**

- Event ID 1 (Process Creation) - Execution of token manipulation tools
- Event ID 7 (Image Loaded) - Loading of tool-specific DLLs
- Event ID 11 (File Create) - Creation of tool artifacts on disk

**PowerShell Logs:**

- Event ID 4104 (Script Block Logging) - PowerShell token manipulation modules
    - Scripts: `Invoke-TokenManipulation`, `Invoke-PrivescCheck`, `PowerUp.ps1`
    - Functions: `Get-System`, `Get-ProcessToken`, `Enable-Privilege`

**Windows Event Logs:**

- Event ID 4688 (Process Creation) - Tool execution with suspicious command lines
- Event ID 4673 (Sensitive Privilege Use) - Correlate with tool execution

**Network Logs:**

- Command and Control (C2) traffic patterns associated with token operations
- Cobalt Strike beacon traffic, Metasploit staging, Empire C2 channels

**Look for:**

- Known tool file names, hashes, or YARA signatures
- PowerShell modules loaded from GitHub repositories (PowerSploit, Empire, Nishang)
- Memory injection techniques preceding token operations
- C2 traffic correlating with privilege escalation activities

**Suspicious indicators:**

- **Mimikatz indicators:**
    - Commands: `token::elevate`, `token::run`, `token::list`, `privilege::debug`
    - Process: `mimikatz.exe`, `mimilib.dll` loaded
    - PowerShell: `Invoke-Mimikatz -Command privilege::debug`
- **Cobalt Strike indicators:**
    - Commands: `steal_token`, `make_token`, `getsystem`, `spawn`, `spawnas`
    - Named pipes: `\\.\pipe\MSSE-*`, `\\.\pipe\postex_*`, `\\.\pipe\msagent_*`
    - Beacon artifacts in memory
- **Metasploit indicators:**
    - Meterpreter commands: `getsystem`, `steal_token`, `getprivs`, `use incognito`
    - Process: `metsrv.dll`, staged payloads
- **PowerShell Empire indicators:**
    - Modules: `Invoke-TokenManipulation`, `Invoke-PrivescCheck`, agent commands
- **Incognito tool:**
    - Commands: `list_tokens`, `impersonate_token`
- **Custom tools:**
    - `TokenPlayer.exe`, `SweetPotato.exe`, token manipulation POCs from GitHub
- Reflective DLL injection preceding token operations
- Process hollowing with token assignment

---

### 9. Unusual Logon Types and Authentication Patterns

**Windows Event Logs:**

- Event ID 4624 (Successful Logon) - Analyze LogonType field:
    - **LogonType 2** (Interactive) - Physical or RDP logon
    - **LogonType 3** (Network) - Network resource access
    - **LogonType 4** (Batch) - Scheduled tasks
    - **LogonType 5** (Service) - Service startup
    - **LogonType 7** (Unlock) - Workstation unlock
    - **LogonType 9** (NewCredentials) - RunAs with /netonly
    - **LogonType 10** (RemoteInteractive) - RDP/Terminal Services
    - **LogonType 11** (CachedInteractive) - Cached credential logon
- Event ID 4648 (Explicit Credential Logon) - RunAs or secondary logon service usage
- Event ID 4672 (Special Privileges Assigned) - Administrative logon session

**Focus on:**

- LogonType 9 (NewCredentials) from non-administrative users
- Multiple LogonType 3 events without corresponding network activity
- Logon events lacking source network address or workstation name
- Authentication patterns inconsistent with user behavior baselines

**Suspicious indicators:**

- LogonType 9 followed immediately by privileged operations without network authentication
- Logon events with null or `0.0.0.0` source IP for network logons
- Multiple failed logon attempts (4625) followed by successful token-based access
- Interactive logon (Type 2) from service accounts
- Account logons outside normal working hours correlating with token operations
- Logon session IDs reused or duplicated across different processes
- Authentication to localhost from privileged accounts without legitimate admin activity
- Concurrent logon sessions from same user with different privilege levels
- Logon Type 3 from localhost immediately following privilege escalation
- Pass-the-Hash indicators: LogonType 3 with NTLM authentication, no prior Type 2 logon

---

### 10. Cross-Session Token Operations and Remote Token Manipulation

**Windows Event Logs:**

- Event ID 4624 (Logon) - Session ID analysis for cross-session activity
- Event ID 4778/4779 (Session Reconnect/Disconnect) - Terminal Services session changes
- Event ID 4688 (Process Creation) - Processes operating in different session contexts

**Sysmon:**

- Event ID 1 (Process Creation) - `LogonId` field showing session hopping
- Event ID 10 (Process Access) - Cross-session process access patterns
- Event ID 3 (Network Connection) - Remote token operations via SMB/RPC

**Network Logs:**

- SMB traffic (port 445) with suspicious RPC calls
- DCOM connections (port 135) for remote process manipulation
- WMI traffic indicating remote command execution

**Focus on:**

- Processes accessing tokens in different Terminal Services sessions
- Remote token duplication across systems
- Session 0 (services) interaction with user sessions (Session 1+)
- Token operations via remote procedure calls

**Suspicious indicators:**

- User processes in Session 1 accessing SYSTEM tokens in Session 0
- Token duplication from disconnected RDP sessions (4779 followed by token access)
- Remote process creation using stolen tokens: `PsExec`, `WMIC`, `WinRM` with token assignment
- Commands: `PsExec.exe \\remote-host -s cmd.exe` (run as SYSTEM)
- WMI process creation with token impersonation: `Invoke-WmiMethod -Class Win32_Process`
- Token operations following successful lateral movement (Event ID 4624 LogonType 3)
- Cross-session process injection (Session 0 → Session 1)
- Service processes creating GUI applications in user sessions
- Token theft from locked sessions (LogonType 7 unlock events)
- Remote registry access followed by token operations
- DCOM-based lateral movement with token impersonation
- Token replication across multiple systems in short timeframes

---

# Access Token Manipulation (T1134) Investigation Checklist

## 1. Process Handle Operations & Token Theft

- [ ]  Review Event ID 4673 for `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeTcbPrivilege` usage
- [ ]  Check Sysmon Event ID 10 for process access to `lsass.exe`, `winlogon.exe`, `services.exe` with `GrantedAccess` 0x1410/0x1010/0x1400
- [ ]  Search Event ID 4688/Sysmon Event ID 1 for processes with mismatched `IntegrityLevel` and `User` fields
- [ ]  Identify non-admin processes accessing SYSTEM process tokens (web apps, scripts, Office applications)
- [ ]  Look for Invoke-TokenManipulation, steal_token (Cobalt Strike), or incognito.exe in command lines

## 2. Process Creation with Stolen Tokens

- [ ]  Review Event ID 4688 for `Token Elevation Type` field showing elevation without UAC (Type 2 or 3)
- [ ]  Check Sysmon Event ID 1 for parent-child processes with different user contexts or integrity levels
- [ ]  Search for Event ID 4624 LogonType 9 (NewCredentials) indicating runas usage
- [ ]  Identify SYSTEM child processes spawned from Medium integrity parents without service context
- [ ]  Correlate process creation with lack of authentication events (Event ID 4624/4648)

## 3. Explicit Credentials & Token Creation

- [ ]  Review Event ID 4648 for explicit credential logon attempts from non-administrative users
- [ ]  Check Event ID 4624 LogonType 9 followed by privileged operations
- [ ]  Search PowerShell Event ID 4104 for Make-Token, Invoke-TokenManipulation, New-Token
- [ ]  Identify runas.exe execution spawning domain admin processes from standard workstations
- [ ]  Look for token creation following credential dumping (lsass.exe access)

## 4. Parent PID Spoofing Detection

- [ ]  Analyze Sysmon Event ID 1 for `ParentProcessId` pointing to terminated or non-existent processes
- [ ]  Check for critical processes with illogical parents (cmd.exe parented to explorer.exe in service context)
- [ ]  Correlate Sysmon Event ID 5 (process termination) with Event ID 1 to find orphaned children
- [ ]  Identify svchost.exe with parent other than services.exe
- [ ]  Search for process creation timestamps predating parent process creation

## 5. Sensitive Privilege Usage

- [ ]  Review Event ID 4673 for SeDebugPrivilege use from PowerShell, Office apps, or web applications
- [ ]  Check Event ID 4672 for special privileges assigned outside normal admin logons
- [ ]  Identify privilege enabling sequences: SeDebugPrivilege → lsass.exe access → SeImpersonatePrivilege
- [ ]  Search for SeTcbPrivilege (Act as OS) usage from non-Windows processes
- [ ]  Look for multiple rapid privilege adjustments from temporary directories (%TEMP%, %APPDATA%)

## 6. Integrity Level Mismatches

- [ ]  Check Sysmon Event ID 1 `IntegrityLevel` field for Medium parents spawning High/SYSTEM children
- [ ]  Review Event ID 4688 `TokenElevationType` showing elevation without UAC consent (Event ID 4703)
- [ ]  Identify user-initiated processes running with SYSTEM integrity
- [ ]  Search for Office applications (winword.exe, excel.exe) or browsers running as SYSTEM
- [ ]  Look for processes in user directories with High or SYSTEM integrity levels

## 7. Named Pipe Impersonation

- [ ]  Review Sysmon Event ID 17/18 for suspicious named pipe creation and connections
- [ ]  Check Event ID 4673 for SeImpersonatePrivilege correlating with pipe operations
- [ ]  Search for named pipes matching exploit patterns: `\\.\pipe\MSSE-*`, `\\.\pipe\postex-*`, `\\.\pipe\spoolss`
- [ ]  Identify Print Spooler (spoolsv.exe) connections to unexpected named pipes
- [ ]  Look for RottenPotato, JuicyPotato, RoguePotato tool execution

## 8. Attack Tool Artifacts

- [ ]  Search PowerShell Event ID 4104 for: Invoke-Mimikatz, Invoke-TokenManipulation, PowerUp.ps1, Get-System
- [ ]  Check Event ID 4688/Sysmon Event ID 1 for: mimikatz.exe, procdump -ma lsass, incognito commands
- [ ]  Review Sysmon Event ID 7 for mimilib.dll, metsrv.dll, or other tool-specific DLLs
- [ ]  Identify Cobalt Strike indicators: steal_token, make_token, getsystem, spawn commands
- [ ]  Search for Metasploit Meterpreter commands: getsystem, steal_token, getprivs, use incognito

## 9. Authentication Pattern Anomalies

- [ ]  Review Event ID 4624 for LogonType 9 (NewCredentials) from standard users
- [ ]  Check for LogonType 3 events without corresponding network connections
- [ ]  Identify logon events with null source IP (0.0.0.0) or missing workstation names
- [ ]  Search for multiple Event ID 4625 failures followed by token-based access without Event ID 4624
- [ ]  Look for off-hours administrative logons correlating with token manipulation events

## 10. Cross-Session & Remote Token Operations

- [ ]  Check Sysmon Event ID 1 `LogonId` field for processes hopping between sessions
- [ ]  Review Event ID 4778/4779 for session reconnect/disconnect followed by token access
- [ ]  Identify Session 0 (services) processes accessing user session (Session 1+) tokens
- [ ]  Search for remote token operations: PsExec \host -s, Invoke-WmiMethod with token assignment
- [ ]  Look for token theft from locked or disconnected RDP sessions