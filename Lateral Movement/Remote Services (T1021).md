# Remote Services: [T1021](https://attack.mitre.org/techniques/T1021/)

## Detection Explanation

Remote Services involves adversaries using legitimate remote access tools and protocols to move laterally across a network or maintain persistent access to compromised systems. This technique leverages built-in operating system features and commonly deployed remote administration tools, making malicious activity difficult to distinguish from legitimate administrative actions. Remote services are used throughout the attack lifecycle for initial access, lateral movement, and persistence.

Attackers exploit remote services because they provide authenticated access that appears legitimate to security controls. Common methods include Remote Desktop Protocol (RDP) (T1021.001), SMB/Windows Admin Shares (T1021.002), Distributed Component Object Model (DCOM) (T1021.003), SSH (T1021.004), VNC (T1021.005), Windows Remote Management (WinRM) (T1021.006), and cloud-based remote services. Tools like PsExec, legitimate RDP clients, SSH clients, PowerShell remoting, and third-party remote access software are frequently employed.

Successful use of remote services grants attackers the ability to execute commands, transfer files, deploy malware, and access resources on remote systems using valid credentials. This technique is particularly effective because it uses expected network traffic and authentication mechanisms, blending malicious activity with normal administrative operations. The impact includes widespread lateral movement, privilege escalation across multiple systems, persistent remote access, data exfiltration, and potential complete network compromise.

Detection requires establishing baselines for legitimate remote service usage patterns and monitoring for anomalies such as unusual source/destination pairs, access during off-hours, use of service accounts from unexpected locations, failed authentication attempts preceding success, and remote service usage from non-administrative systems. Organizations must correlate authentication events with process execution, file operations, and network connections to identify malicious remote access.

---

## Key Detection Indicators & Areas to Investigate

### Summary of Indicators

1. Remote Desktop Protocol (RDP) connections and anomalies (T1021.001)
2. SMB/Windows Admin Share access patterns (T1021.002)
3. PsExec and remote service creation (T1021.002)
4. PowerShell remoting and WinRM usage (T1021.006)
5. DCOM lateral movement and execution (T1021.003)
6. SSH connections and suspicious authentication (T1021.004)
7. Third-party remote access tool usage (VNC, TeamViewer, AnyDesk) (T1021.005)
8. Scheduled task creation via remote services (T1021.002, T1021.006)
9. WMI remote command execution (T1021.002)
10. Remote Registry access and manipulation

---

### 1. Remote Desktop Protocol (RDP) Connections and Anomalies

**Windows Event Logs (Security):**

- Event ID 4624 (Successful logon) - LogonType 10 (RemoteInteractive/RDP)
- Event ID 4625 (Failed logon) - Failed RDP authentication attempts
- Event ID 4778 (Session reconnected) - RDP session reconnection
- Event ID 4779 (Session disconnected) - RDP session disconnection
- Key fields: `SourceNetworkAddress`, `TargetUserName`, `LogonType`, `WorkstationName`

**Windows Event Logs (TerminalServices-RemoteConnectionManager):**

- Event ID 1149 (Remote Desktop Services user authentication succeeded)
- Event ID 261 (Listener received connection)

**Windows Event Logs (TerminalServices-LocalSessionManager):**

- Event ID 21 (Remote Desktop Services: Session logon succeeded)
- Event ID 22 (Remote Desktop Services: Shell start notification received)
- Event ID 24 (Remote Desktop Services: Session disconnected)
- Event ID 25 (Remote Desktop Services: Session reconnection succeeded)

**Sysmon:**

- Event ID 3 (Network connection) - Connections to port 3389
- Event ID 1 (Process creation) - Processes spawned in RDP sessions

**Network Logs:**

- Firewall logs - Inbound connections to TCP port 3389
- VPN logs - RDP connections through VPN tunnels
- Network flow data - RDP traffic patterns and volumes

**Focus on:**

- RDP connections from unexpected source IPs or geographic locations
- RDP access to systems that don't typically receive remote connections
- Multiple failed RDP attempts followed by successful authentication
- RDP connections during off-hours or from non-administrative users
- Lateral RDP connections between workstations

**Suspicious indicators:**

- RDP logons (Event ID 4624 LogonType 10) from external IP addresses not on VPN
- Failed RDP attempts (Event ID 4625) followed by success within short timeframe
- RDP connections from workstations to other workstations (peer-to-peer lateral movement)
- Service accounts authenticating via RDP (should use service logon types)
- RDP sessions from IP addresses in unusual geographic locations
- Multiple RDP connections to different systems from single source in short timeframe
- RDP authentication outside user's normal working hours
- Event ID 1149 showing authentication from internal reconnaissance activity
- BlueKeep or other RDP vulnerability exploitation indicators
- RDP connections using local administrator accounts instead of domain credentials

---

### 2. SMB/Windows Admin Share Access Patterns

**Windows Event Logs (Security):**

- Event ID 5140 (Network share accessed) - Access to admin shares (`C$`, `ADMIN$`, `IPC$`)
- Event ID 5145 (Network share object accessed) - Specific file/folder access on shares
- Event ID 4624 (Successful logon) - LogonType 3 (Network) for SMB authentication
- Event ID 4672 (Special privileges assigned) - Administrative privileges for share access
- Key fields: `ShareName`, `SourceAddress`, `SubjectUserName`, `ObjectType`

**Sysmon:**

- Event ID 3 (Network connection) - Connections to TCP ports 445 (SMB) and 139 (NetBIOS)
- Event ID 1 (Process creation) - Remote execution via SMB shares
- Event ID 11 (File created) - Files written to admin shares

**Network Logs:**

- Firewall logs - SMB traffic (TCP 445, 139) between systems
- IDS/IPS - SMB protocol anomalies and known attack patterns
- Netflow - SMB connection patterns and peer-to-peer communications

**Command-Line Patterns:**

- `net use \\target\C$ /user:domain\user`
- `copy malware.exe \\target\C$\Windows\Temp\`
- `dir \\target\C$`

**Focus on:**

- Access to administrative shares from non-server systems
- SMB connections between workstations (lateral movement)
- Admin share access from service accounts or non-privileged users
- File writes to `C$\Windows\Temp` or `ADMIN$` from remote systems
- Failed SMB authentication followed by successful access

**Suspicious indicators:**

- Event ID 5140 with `ShareName` of `C$`, `ADMIN$`, or `IPC$` from workstation IPs
- SMB access from systems that don't perform administrative functions
- Network logons (LogonType 3) to admin shares during off-hours
- Executable files written to `C$\Windows\Temp\` or `C$\ProgramData\` via SMB
- Multiple systems accessed via admin shares from single source in short timeframe
- SMB traffic between workstations rather than workstation-to-server
- Admin share access using local administrator accounts with same password (pass-the-hash)
- Event ID 5145 showing access to sensitive files via network shares
- SMB connections immediately following credential dumping activity
- Failed SMB authentication (Event ID 4625 LogonType 3) preceding successful access

---

### 3. PsExec and Remote Service Creation

**Windows Event Logs (Security):**

- Event ID 4697 (Service installed) - New service creation, especially PSEXESVC
- Event ID 4688 (Process creation) - PsExec execution and service processes
- Event ID 5145 (Network share object accessed) - ADMIN$ access by PsExec
- Key fields: `ServiceName`, `ServiceFileName`, `CommandLine`

**Windows Event Logs (System):**

- Event ID 7045 (Service installed) - New service installation
- Event ID 7036 (Service state change) - Service starting/stopping
- Event ID 7040 (Service startup type changed)

**Sysmon:**

- Event ID 1 (Process creation) - PsExec.exe execution and spawned processes
- Event ID 13 (Registry value set) - Service registry modifications
- Event ID 11 (File created) - PsExec executable copied to ADMIN$ share
- Event ID 17/18 (Pipe created/connected) - Named pipes used by PsExec

**Named Pipes to Monitor:**

- `\\.\pipe\PSEXESVC`
- `\\.\pipe\PAExec`
- Custom named pipes used by remote execution tools

**Command-Line Patterns:**

- `psexec.exe \\target -u domain\user -p password cmd.exe`
- `psexec.exe @targets.txt -d -c malware.exe`
- `psexec.exe \\target -s cmd.exe` (execute as SYSTEM)

**Focus on:**

- Creation of services with names like PSEXESVC, PAExec, RemCom
- Services with executable paths in ADMIN$ share or Windows\Temp
- Remote service creation from non-administrative systems
- Services starting with SYSTEM privileges immediately after creation
- Temporary services that are created, started, and deleted rapidly

**Suspicious indicators:**

- Event ID 7045 with `ServiceName` containing "PSEXESVC", "PAEXEC", or random characters
- Service `ImagePath` pointing to `\\127.0.0.1\ADMIN$\`, `C:\Windows\`, or `%TEMP%`
- Services created with startup type "Demand Start" or "Auto Start" by remote systems
- Event ID 4697 followed immediately by Event ID 7036 (service starting)
- Named pipe creation for `\\.\pipe\PSEXESVC` or similar patterns
- PsExec.exe in `C:\Windows\` or `C:\Windows\Temp\` directories
- Services with `LocalSystem` account executing commands from network shares
- Multiple systems showing identical service creation within minutes
- Service deletion shortly after execution (covering tracks)
- Command lines containing `-accepteula`, `-s`, `-d`, or `-c` PsExec parameters

---

### 4. PowerShell Remoting and WinRM Usage

**Windows Event Logs (Security):**

- Event ID 4624 (Successful logon) - LogonType 3 (Network) for WinRM
- Event ID 4648 (Logon with explicit credentials) - PowerShell remoting authentication
- Event ID 4656 (Handle to object requested) - WinRM service access

**PowerShell Logs:**

- Event ID 4104 (Script block logging) - Remote PowerShell commands
- Event ID 4103 (Module logging) - Remote session command execution
- Event ID 400 (Engine state changed) - Remote PowerShell session start
- Event ID 403 (Engine state stopped) - Remote PowerShell session termination

**Windows Event Logs (WinRM):**

- Event ID 6 (Creating WSMan shell) - Remote PowerShell session creation
- Event ID 8 (WSMan request) - WinRM activity
- Event ID 15 (WSMan receive request) - Commands received via WinRM
- Event ID 91 (Creating Runspace) - PowerShell runspace creation for remote execution

**Sysmon:**

- Event ID 3 (Network connection) - Connections to TCP port 5985 (HTTP) or 5986 (HTTPS)
- Event ID 1 (Process creation) - `wsmprovhost.exe` spawning commands

**Command-Line Patterns:**

- `Enter-PSSession -ComputerName target -Credential domain\user`
- `Invoke-Command -ComputerName target -ScriptBlock {commands}`
- `New-PSSession -ComputerName target`
- `winrs -r:target cmd.exe`

**Focus on:**

- WinRM connections from non-administrative workstations
- PowerShell remoting to multiple systems from single source
- Remote PowerShell execution during off-hours
- WinRM usage by non-privileged accounts
- Commands executed via PowerShell remoting

**Suspicious indicators:**

- Event ID 4624 LogonType 3 to port 5985/5986 from workstation IPs
- PowerShell Event ID 4104 with remote execution indicators: `Enter-PSSession`, `Invoke-Command`
- `wsmprovhost.exe` spawning `cmd.exe`, `powershell.exe`, or suspicious executables
- WinRM Event ID 6 showing session creation from unexpected source IPs
- Remote PowerShell commands containing credential dumping, reconnaissance, or malware
- Multiple systems showing WinRM activity from same source IP within short timeframe
- Base64-encoded commands executed via `Invoke-Command`
- WinRM connections outside standard administrative hours
- Service accounts used for interactive PowerShell remoting
- Event ID 91 showing runspace creation for malicious scripts

---

### 5. DCOM Lateral Movement and Execution

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Processes spawned via DCOM
- Event ID 4624 (Successful logon) - LogonType 3 (Network) for DCOM authentication
- Event ID 4672 (Special privileges assigned) - Privileges for DCOM execution

**Sysmon:**

- Event ID 1 (Process creation) - Parent process: `svchost.exe` with `-k DcomLaunch`
- Event ID 3 (Network connection) - Connections to TCP port 135 (RPC Endpoint Mapper)
- Event ID 11 (File created) - Files created via DCOM execution

**Windows Event Logs (System):**

- Event ID 10016 (DCOM permissions) - DCOM access denied/allowed

**DCOM Objects Used:**

- MMC20.Application (CLSID: `{49B2791A-B1AE-4C90-9B8E-E860BA07F889}`)
- ShellWindows (CLSID: `{9BA05972-F6A8-11CF-A442-00A0C90A8F39}`)
- ShellBrowserWindow (CLSID: `{C08AFD90-F2A1-11D1-8455-00A0C91F3880}`)
- Excel.Application, Word.Application (Office COM objects)

**Focus on:**

- Processes spawned by `svchost.exe` with DcomLaunch service group
- RPC connections (port 135) followed by dynamic high ports
- DCOM execution from non-administrative systems
- Office applications launched remotely via DCOM
- Unusual parent-child process relationships involving DCOM

**Suspicious indicators:**

- `svchost.exe -k DcomLaunch` spawning `cmd.exe`, `powershell.exe`, or executables
- Event ID 4688 with parent process `svchost.exe` and child process in `%TEMP%` or `%APPDATA%`
- Network connections to port 135 followed by execution on remote system
- MMC20.Application or ShellWindows DCOM objects used from remote systems
- Office applications (Excel, Word) launched via DCOM without user interaction
- DCOM execution during off-hours or from workstations
- Processes created with SYSTEM privileges via DCOM
- Event ID 10016 showing DCOM permission changes or unusual access patterns
- Remote DCOM calls creating persistence mechanisms
- Multiple systems showing DCOM activity from same source within short timeframe

---

### 6. SSH Connections and Suspicious Authentication

**Linux/Unix Logs:**

- `/var/log/auth.log` or `/var/log/secure` - SSH authentication events
- Look for: "Accepted publickey", "Accepted password", "Failed password"
- Key fields: source IP, username, authentication method

**Windows Event Logs (OpenSSH):**

- Event ID 4 (sshd) - SSH connection accepted
- OpenSSH logs in `%PROGRAMDATA%\ssh\logs\` - Authentication and session logs

**Sysmon (Windows):**

- Event ID 3 (Network connection) - Connections to TCP port 22
- Event ID 1 (Process creation) - SSH client execution or sshd spawning shells

**Network Logs:**

- Firewall logs - SSH traffic (TCP port 22) between systems
- IDS/IPS - SSH brute force attempts, tunneling patterns
- Netflow - SSH connection duration and data volumes

**Focus on:**

- SSH connections from unexpected source IPs or geographic locations
- Multiple failed SSH authentication attempts followed by success
- SSH connections between workstations (lateral movement)
- SSH key-based authentication from unauthorized systems
- Unusual SSH traffic patterns (tunneling, port forwarding)

**Suspicious indicators:**

- Multiple "Failed password" entries followed by "Accepted password" from same IP
- SSH connections from internal workstations rather than jump servers or bastion hosts
- Key-based authentication from IPs not authorized for key access
- SSH connections during off-hours or outside normal maintenance windows
- User accounts authenticating via SSH from multiple geographic locations simultaneously
- Root or privileged account SSH access from non-administrative systems
- SSH tunneling or port forwarding commands in shell history
- Newly added SSH public keys in `~/.ssh/authorized_keys`
- SSH connections immediately following credential dumping or password changes
- High-volume SSH connections suggesting automated lateral movement

---

### 7. Third-Party Remote Access Tool Usage

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Remote access tool execution
- Event ID 4697 (Service installed) - Remote access tool service installation
- Event ID 4624 (Successful logon) - Authentication via remote access tools

**Sysmon:**

- Event ID 1 (Process creation) - VNC, TeamViewer, AnyDesk, Remote Utilities execution
- Event ID 3 (Network connection) - Connections to remote access tool ports
- Event ID 11 (File created) - Remote access tool installation files
- Event ID 13 (Registry value set) - Remote access tool configuration

**Network Logs:**

- Firewall logs - Connections to VNC ports (5900+), TeamViewer, AnyDesk ports
- Proxy logs - Outbound connections to remote access service infrastructure
- DNS logs - Queries to remote access service domains

**Common Tool Ports:**

- VNC: TCP 5900-5909
- TeamViewer: TCP 5938, UDP 5938
- AnyDesk: TCP 6568, TCP 7070
- Remote Utilities: TCP 5650, 5655

**Registry Keys:**

- TeamViewer: `HKLM\Software\TeamViewer`
- AnyDesk: `HKLM\Software\AnyDesk`
- VNC: `HKLM\Software\RealVNC` or `HKLM\Software\TightVNC`

**Focus on:**

- Installation of remote access tools not approved by IT policy
- Remote access tools running on servers or critical systems
- Tools configured for unattended access or with weak passwords
- Remote access tools executed from temporary directories
- Tools configured to start automatically or run as services

**Suspicious indicators:**

- `teamviewer.exe`, `anydesk.exe`, `vncviewer.exe` executed from `%TEMP%` or user directories
- Remote access tool services installed without change management approval
- Tools configured with "permanent access" or "unattended mode"
- Network connections to remote access infrastructure from corporate systems
- Registry keys showing remote access tool IDs or partner IDs
- Remote access tools with no associated user sessions or scheduled maintenance
- Installation during off-hours or by non-administrative accounts
- Tools communicating with command and control infrastructure
- Multiple systems showing identical remote access tool installations
- Remote access tool logs showing connections from suspicious IPs or locations

---

### 8. Scheduled Task Creation via Remote Services

**Windows Event Logs (Security):**

- Event ID 4698 (Scheduled task created) - New task creation
- Event ID 4702 (Scheduled task updated) - Task modification
- Event ID 4699 (Scheduled task deleted) - Task deletion (covering tracks)
- Event ID 4700 (Scheduled task enabled) - Task activation
- Event ID 4701 (Scheduled task disabled) - Task deactivation
- Key fields: `TaskName`, `SubjectUserName`, `TaskContent`

**Windows Event Logs (TaskScheduler):**

- Event ID 106 (Task registered) - Task creation
- Event ID 200 (Task execution) - Task run
- Event ID 201 (Task completion) - Task finished

**Sysmon:**

- Event ID 1 (Process creation) - `schtasks.exe` or `taskeng.exe` execution
- Event ID 11 (File created) - Task XML files in `C:\Windows\System32\Tasks\`
- Event ID 13 (Registry value set) - Task scheduler registry modifications

**Command-Line Patterns:**

- `schtasks.exe /create /tn TaskName /tr "C:\malware.exe" /sc once /st 00:00 /s target /u domain\user /p password`
- `schtasks.exe /create /tn TaskName /tr "cmd.exe /c powershell.exe -enc <base64>" /sc daily`
- PowerShell: `Register-ScheduledTask -TaskName Name -Action (New-ScheduledTaskAction -Execute malware.exe)`

**Focus on:**

- Scheduled tasks created remotely via SMB or WinRM
- Tasks configured to run with SYSTEM or administrative privileges
- Tasks executing from unusual locations (TEMP, APPDATA, user directories)
- Tasks created during off-hours or from non-administrative systems
- Tasks with suspicious or obfuscated command lines

**Suspicious indicators:**

- Event ID 4698 showing task creation from remote IP addresses
- Task actions containing `powershell.exe -enc`, `cmd.exe /c`, or encoded commands
- Tasks executing files from `%TEMP%`, `%APPDATA%`, `C:\ProgramData\`
- `schtasks.exe` executed with `/s` parameter (remote system) from workstations
- Tasks configured to run as SYSTEM without legitimate business requirement
- Task names using random characters or mimicking legitimate Windows tasks
- Tasks created and executed within minutes (immediate execution)
- Task XML files showing network logon triggers or unusual execution schedules
- Tasks deleted shortly after execution (Event ID 4699 after 200/201)
- Multiple systems showing identical scheduled task creation within short timeframe

---

### 9. WMI Remote Command Execution

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - WMI-spawned processes
- Event ID 4624 (Successful logon) - LogonType 3 for WMI authentication
- Event ID 4672 (Special privileges assigned) - Elevated WMI execution

**Sysmon:**

- Event ID 1 (Process creation) - Parent process: `wmiprvse.exe` or `wmic.exe`
- Event ID 3 (Network connection) - Connections to TCP port 135 and DCOM ports
- Event ID 19/20/21 (WMI events) - WMI event filter, consumer, binding creation

**Windows Event Logs (WMI-Activity):**

- Event ID 5857 (WMI activity) - WMI provider operations
- Event ID 5860 (Temporary event consumer) - WMI event consumer registration
- Event ID 5861 (Permanent event consumer) - Persistent WMI event consumers

**Command-Line Patterns:**

- `wmic /node:target /user:domain\user process call create "cmd.exe /c malware.exe"`
- `wmic /node:target process call create "powershell.exe -enc <base64>"`
- PowerShell: `Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe" -ComputerName target`

**Focus on:**

- WMI command execution on remote systems from non-administrative workstations
- Processes spawned by `wmiprvse.exe` with suspicious command lines
- WMI event consumers used for persistence or lateral movement
- Remote WMI calls during off-hours or from unusual sources
- WMI execution creating files, modifying registry, or establishing persistence

**Suspicious indicators:**

- `wmiprvse.exe` spawning `cmd.exe`, `powershell.exe`, or executables from `%TEMP%`
- Event ID 4688 with parent process `wmiprvse.exe` and suspicious child processes
- `wmic.exe` executed with `/node:` parameter from workstations
- PowerShell commands using `Invoke-WmiMethod` or `Get-WmiObject` for remote execution
- WMI Event ID 5861 showing permanent event consumers for persistence
- Network connections to port 135 followed by process creation on remote system
- WMI queries for reconnaissance: `wmic /node:target os get`, `wmic /node:target process list`
- Base64-encoded commands executed via WMI
- Multiple systems showing WMI activity from same source IP within short timeframe
- WMI event filters with suspicious triggers (user logon, system start)

---

### 10. Remote Registry Access and Manipulation

**Windows Event Logs (Security):**

- Event ID 4656 (Handle to object requested) - Remote registry access
- Event ID 4657 (Registry value modification) - Remote registry changes
- Event ID 4663 (Access attempted to object) - Registry key access
- Event ID 4670 (Permissions changed) - Registry permissions modified

**Sysmon:**

- Event ID 12 (Registry object added/deleted) - Registry modifications from remote systems
- Event ID 13 (Registry value set) - Remote registry value changes
- Event ID 14 (Registry object renamed) - Remote registry key renames

**Network Logs:**

- Firewall logs - Connections to TCP port 445 for remote registry
- Netflow - SMB traffic patterns associated with registry access

**Command-Line Patterns:**

- `reg query \\target\HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `reg add \\target\HKLM\System\CurrentControlSet\Services\ServiceName`
- PowerShell: `Get-ItemProperty -Path "\\target\HKLM:\Software\..."`

**Registry Keys Commonly Targeted:**

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` - Persistence
- `HKLM\System\CurrentControlSet\Services\` - Service configuration
- `HKLM\SAM\SAM\Domains\Account` - Credential access
- `HKLM\Security\Policy\Secrets` - LSA secrets

**Focus on:**

- Remote registry access from non-administrative workstations
- Registry modifications for persistence or privilege escalation
- Access to sensitive registry keys (SAM, SECURITY, LSA secrets)
- Remote registry connections during off-hours
- Registry queries for reconnaissance or credential harvesting

**Suspicious indicators:**

- Remote registry access to `HKLM\SAM` or `HKLM\SECURITY` hives
- Registry Run key modifications from remote systems
- `reg.exe` executed with `\\target\` UNC paths from workstations
- Remote registry service (RemoteRegistry) started unexpectedly
- Registry queries for service configurations or autostart locations
- PowerShell remote registry access using `[Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey`
- Multiple systems accessed via remote registry from single source
- Registry access followed immediately by process creation or file modification
- Remote registry connections from systems not performing administrative functions
- Registry permissions modified to allow broader access from remote systems
---
# Remote Services Investigation Checklist

## 1. RDP Connections and Anomalies

- [ ] Review Event ID 4624 LogonType 10 from external IPs not on VPN
- [ ] Check Event ID 4625 (failed RDP) followed by Event ID 4624 within short timeframe
- [ ] Monitor Event ID 1149/261 for RDP authentication from unexpected sources
- [ ] Identify RDP connections from workstations to other workstations (lateral movement)
- [ ] Look for service accounts authenticating via RDP (incorrect logon type)
- [ ] Check for RDP sessions from unusual geographic locations
- [ ] Review RDP authentication outside normal working hours
- [ ] Monitor Sysmon Event ID 3 for connections to port 3389

## 2. SMB/Admin Share Access

- [ ] Review Event ID 5140 for access to C$, ADMIN$, IPC$ from workstation IPs
- [ ] Check Event ID 5145 for executable files written to C$\Windows\Temp, C$\ProgramData\
- [ ] Monitor Event ID 4624 LogonType 3 for admin share access during off-hours
- [ ] Identify SMB traffic between workstations (Sysmon Event ID 3 to TCP 445/139)
- [ ] Look for admin share access using local administrator accounts (pass-the-hash)
- [ ] Check for multiple systems accessed via admin shares from single source
- [ ] Review failed SMB authentication (Event ID 4625 LogonType 3) preceding success

## 3. PsExec and Remote Service Creation

- [ ] Check Event ID 7045/4697 for services named PSEXESVC, PAEXEC, or random characters
- [ ] Review service ImagePath pointing to \127.0.0.1\ADMIN$, C:\Windows, %TEMP%
- [ ] Monitor Sysmon Event ID 17/18 for named pipes: \.\pipe\PSEXESVC, \.\pipe\PAExec
- [ ] Identify services created with LocalSystem account from network shares
- [ ] Look for services created, started, and deleted rapidly (covering tracks)
- [ ] Check for PsExec.exe in C:\Windows\ or C:\Windows\Temp\ directories
- [ ] Review command lines with -accepteula, -s, -d, or -c parameters

## 4. PowerShell Remoting and WinRM

- [ ] Monitor Event ID 4624 LogonType 3 to ports 5985/5986 from workstation IPs
- [ ] Check PowerShell Event ID 4104 for Enter-PSSession, Invoke-Command patterns
- [ ] Review wsmprovhost.exe spawning cmd.exe, powershell.exe, or suspicious executables
- [ ] Identify WinRM Event ID 6 showing session creation from unexpected sources
- [ ] Look for Base64-encoded commands via Invoke-Command
- [ ] Check for multiple systems with WinRM activity from same source IP
- [ ] Monitor WinRM connections outside standard administrative hours

## 5. DCOM Lateral Movement

- [ ] Check for svchost.exe -k DcomLaunch spawning cmd.exe, powershell.exe
- [ ] Review Event ID 4688 with parent svchost.exe and child in %TEMP%, %APPDATA%
- [ ] Monitor Sysmon Event ID 3 for connections to port 135 followed by execution
- [ ] Identify MMC20.Application or ShellWindows DCOM object usage
- [ ] Look for Office applications (Excel, Word) launched via DCOM remotely
- [ ] Check Event ID 10016 for unusual DCOM permission changes
- [ ] Review processes with SYSTEM privileges created via DCOM

## 6. SSH Connections

- [ ] Review /var/log/auth.log for multiple "Failed password" followed by "Accepted password"
- [ ] Check for SSH connections from workstations instead of jump/bastion hosts
- [ ] Monitor SSH connections during off-hours or maintenance windows
- [ ] Identify key-based authentication from unauthorized IPs
- [ ] Look for root/privileged SSH access from non-administrative systems
- [ ] Check for newly added keys in ~/.ssh/authorized_keys
- [ ] Review Sysmon Event ID 3 for connections to TCP port 22 from unusual sources

## 7. Third-Party Remote Access Tools

- [ ] Check for teamviewer.exe, anydesk.exe, vncviewer.exe in %TEMP% or user directories
- [ ] Review Event ID 4697 for remote access tool service installations
- [ ] Monitor Sysmon Event ID 3 for connections to VNC (5900+), TeamViewer (5938), AnyDesk (6568)
- [ ] Identify tools configured with "permanent access" or "unattended mode"
- [ ] Look for remote access tool installation during off-hours
- [ ] Check registry keys: HKLM\Software\TeamViewer, HKLM\Software\AnyDesk
- [ ] Review tools communicating with external C2 infrastructure

## 8. Remote Scheduled Task Creation

- [ ] Check Event ID 4698 showing task creation from remote IP addresses
- [ ] Review task actions with powershell.exe -enc, cmd.exe /c, or encoded commands
- [ ] Monitor tasks executing from %TEMP%, %APPDATA%, C:\ProgramData\
- [ ] Identify schtasks.exe with /s parameter from workstations
- [ ] Look for tasks configured to run as SYSTEM without business justification
- [ ] Check for tasks created and executed within minutes
- [ ] Review Event ID 4699 (deletion) shortly after Event ID 200/201 (execution)

## 9. WMI Remote Execution

- [ ] Check for wmiprvse.exe spawning cmd.exe, powershell.exe, or executables from %TEMP%
- [ ] Review wmic.exe executed with /node: parameter from workstations
- [ ] Monitor PowerShell Invoke-WmiMethod or Get-WmiObject for remote execution
- [ ] Identify WMI Event ID 5861 for permanent event consumers (persistence)
- [ ] Look for connections to port 135 followed by process creation
- [ ] Check for Base64-encoded commands executed via WMI
- [ ] Review WMI queries for reconnaissance: wmic /node:target os get, process list

## 10. Remote Registry Access

- [ ] Check Event ID 4656/4657 for remote registry access to HKLM\SAM, HKLM\SECURITY
- [ ] Monitor Sysmon Event ID 13 for remote registry Run key modifications
- [ ] Review reg.exe with \target\ UNC paths from workstations
- [ ] Identify RemoteRegistry service starting unexpectedly
- [ ] Look for PowerShell [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey usage
- [ ] Check for registry access to HKLM\System\CurrentControlSet\Services\ remotely
- [ ] Monitor registry queries for credentials: HKLM\Security\Policy\Secrets

## 11. Cross-Service Correlation

- [ ] Timeline: Authentication (Event ID 4624) → Remote service usage → Process execution
- [ ] Correlate: Failed auth attempts → Successful access → Lateral movement
- [ ] Track: Single source IP → Multiple systems → Sequential access pattern
- [ ] Identify: Off-hours activity across multiple remote service types
- [ ] Monitor: Service account usage across RDP, WinRM, SMB simultaneously