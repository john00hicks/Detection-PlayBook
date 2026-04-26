# Indicator Removal: [T1070](https://attack.mitre.org/techniques/T1070/)

## Detection Explanation

Indicator Removal involves adversaries attempting to cover their tracks by deleting, clearing, or manipulating evidence of their activities on compromised systems. This technique is a clear indicator that an adversary is aware of forensic and detection capabilities and is actively working to evade investigation, hinder incident response, and remove artifacts that could reveal their presence, methods, or objectives. Indicator removal typically occurs throughout an intrusion but becomes particularly prevalent before exfiltration or when adversaries believe detection is imminent.

Attackers remove indicators because forensic artifacts, logs, and file timestamps provide critical evidence for incident response, threat hunting, and attribution. By clearing Windows Event Logs (T1070.001), clearing Linux or Mac logs (T1070.002), clearing command history (T1070.003), deleting files (T1070.004), modifying timestamps (T1070.006), or clearing network configuration (T1070.005), adversaries aim to eliminate evidence of compromise, complicate forensic analysis, and reduce the likelihood of detection. This technique demonstrates sophistication and intent to maintain long-term access or hide the full scope of compromise.

Successful indicator removal significantly hinders incident response by destroying evidence needed to understand attack timelines, identify compromised systems, determine data accessed or stolen, and attribute attacks to specific threat actors. This creates blind spots in investigations and can result in incomplete remediation, allowing adversaries to maintain persistent access even after partial detection. The impact includes loss of forensic evidence, inability to determine full attack scope, compromised legal proceedings requiring evidence, and extended dwell time due to incomplete attacker eviction.

Detection requires monitoring for log clearing activities, tracking file deletion patterns particularly for logs and forensic artifacts, identifying timestamp manipulation through file system anomalies, and correlating indicator removal attempts with other suspicious activities. Organizations should implement centralized logging with write-once storage, enable tamper protection on critical logs, and alert on any log clearing, large-scale file deletion, or timestamp modification activities.

---

## Key Detection Indicators & Areas to Investigate

### Summary of Indicators

1. Windows Event Log clearing (T1070.001)
2. Linux/Unix log file deletion or truncation (T1070.002)
3. Command history clearing (bash, PowerShell) (T1070.003)
4. Mass file deletion or wiping (T1070.004)
5. Timestamp manipulation (timestomp) (T1070.006)
6. Specific security log deletion or selective event removal
7. Log rotation manipulation or premature log rollover
8. USN journal deletion or volume shadow copy removal (T1070.004)
9. Prefetch file deletion or forensic artifact removal (T1070.004)
10. SIEM/logging agent tampering or log forwarding disruption

---

### 1. Windows Event Log Clearing

**Windows Event Logs (Security):**

- Event ID 1102 (Security audit log cleared) - Critical indicator
- Event ID 1100 (Event logging service shutdown)
- Event ID 4719 (System audit policy changed) - Often precedes clearing
- Key fields: `SubjectUserName`, `SubjectDomainName`, `SubjectLogonId`

**Windows Event Logs (System):**

- Event ID 104 (Log file cleared) - Individual log channel clearing
- Event ID 1102 (Audit log cleared) - System log specific

**Sysmon:**

- Event ID 1 (Process creation) - Log clearing commands
- Event ID 13 (Registry value set) - Event log registry modifications

**PowerShell Logs:**

- Event ID 4104 (Script block logging) - PowerShell log clearing commands

**Command-Line Patterns:**

- `wevtutil cl Security`
- `wevtutil cl System`
- `wevtutil cl Application`
- `wevtutil cl "Microsoft-Windows-Sysmon/Operational"`
- `Clear-EventLog -LogName Security`
- `Get-EventLog -List | ForEach-Object {Clear-EventLog $_.Log}`
- `wmic nteventlog where filename='Security' call cleareventlog`

**Focus on:**

- Security log clearing (highest priority)
- System and Application log clearing
- Sysmon operational log clearing
- Multiple logs cleared in sequence
- Log clearing by non-administrative accounts

**Suspicious indicators:**

- Event ID 1102 in Security log showing manual clearing without authorized change management
- Multiple logs cleared within 5-10 minute window (Security, System, Application, Sysmon)
- `wevtutil cl` commands executed during active intrusion or lateral movement
- PowerShell `Clear-EventLog` targeting Security or Sysmon logs
- Event ID 104 showing log clearing during off-hours (00:00-06:00)
- Log clearing immediately following credential dumping, file access, or exfiltration
- User accounts clearing logs that don't have legitimate administrative duties
- WMI-based log clearing: `wmic nteventlog ... cleareventlog`
- Log clearing from compromised service accounts
- Automated scripts clearing logs on multiple systems simultaneously

---

### 2. Linux/Unix Log File Deletion or Truncation

**Linux/Unix System Logs:**

- `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS) - Authentication logs
- `/var/log/syslog` or `/var/log/messages` - System logs
- `/var/log/wtmp` - Login records
- `/var/log/btmp` - Failed login attempts
- `/var/log/lastlog` - Last login information
- `~/.bash_history` - Command history

**Detection Methods:**

- File integrity monitoring (FIM) alerts on log file deletion
- Audit daemon (auditd) logs showing log file modifications
- Syslog forwarding gaps or interruptions
- File timestamps showing recent modification on historical logs

**Commands Used for Log Clearing:**

- `rm -rf /var/log/*`
- `echo "" > /var/log/auth.log`
- `cat /dev/null > /var/log/syslog`
- `truncate -s 0 /var/log/secure`
- `history -c` (clear command history)
- `rm ~/.bash_history`
- `ln -sf /dev/null ~/.bash_history` (prevent history logging)
- `unset HISTFILE` (disable history for session)

**Auditd Rules to Monitor:**

- `-w /var/log/ -p wa -k log_deletion`
- `-w /var/log/auth.log -p wa -k auth_log_tampering`
- `-w /var/log/secure -p wa -k secure_log_tampering`

**Focus on:**

- Authentication and authorization log deletion
- System log truncation or deletion
- Command history clearing
- Login record manipulation
- Log file permission changes preventing writing

**Suspicious indicators:**

- `/var/log/auth.log` or `/var/log/secure` suddenly empty or truncated
- `wtmp`, `btmp`, or `lastlog` files deleted or zeroed out
- `.bash_history` files deleted across multiple user accounts
- Log files showing recent modification timestamps but empty or minimal content
- Auditd detecting write access to log files by non-root or unexpected processes
- Symbolic links created from log files to `/dev/null`
- `HISTFILE` unset or pointing to `/dev/null` in bash sessions
- Log files with changed permissions preventing normal logging (chmod 000)
- Gaps in syslog forwarding to central logging infrastructure
- Log deletion following SSH access from external or suspicious IPs

---

### 3. Command History Clearing (bash, PowerShell)

**PowerShell Logs:**

- Event ID 4104 (Script block logging) - History clearing commands
- Absence of expected Event ID 4104 logs (history cleared)

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Commands clearing PowerShell history
- Event ID 4663 (Access attempted to object) - Access to history files

**Sysmon:**

- Event ID 1 (Process creation) - History clearing commands
- Event ID 11 (File created) - History file deletions or truncations
- Event ID 23 (File deleted) - PowerShell or bash history deletion

**PowerShell History Locations:**

- `$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
- PowerShell event logs (when cleared)

**Linux/Unix History Files:**

- `~/.bash_history`
- `~/.zsh_history`
- `~/.sh_history`
- `~/.mysql_history`
- `~/.python_history`

**Command Patterns:**

- Windows PowerShell:
    - `Clear-History`
    - `Remove-Item (Get-PSReadlineOption).HistorySavePath`
    - `Set-PSReadlineOption -HistorySaveStyle SaveNothing`
    - `del (Get-PSReadlineOption).HistorySavePath`
- Linux/Unix:
    - `history -c`
    - `rm ~/.bash_history`
    - `cat /dev/null > ~/.bash_history`
    - `unset HISTFILE`
    - `export HISTSIZE=0`

**Focus on:**

- PowerShell command history deletion
- Bash history clearing on Linux/Unix
- History settings changed to prevent logging
- Multiple user histories cleared simultaneously
- History clearing following suspicious command execution

**Suspicious indicators:**

- PowerShell `ConsoleHost_history.txt` deleted or truncated
- `Clear-History` or `Remove-Item` targeting PowerShell history file
- `Set-PSReadlineOption -HistorySaveStyle SaveNothing` preventing history saves
- `.bash_history` deleted on Linux systems following SSH access
- `history -c` command executed during active session
- `HISTFILE` environment variable unset or set to `/dev/null`
- Multiple user account history files deleted within short timeframe
- History files showing modification timestamps but minimal or no content
- History clearing immediately following credential dumping, lateral movement, or data exfiltration
- Sysmon Event ID 23 showing deletion of `ConsoleHost_history.txt` or `.bash_history`

---

### 4. Mass File Deletion or Wiping

**Sysmon:**

- Event ID 23 (File deleted) - High volume of file deletions
- Event ID 26 (File deleted - alternate stream) - ADS deletion
- Key fields: `TargetFilename`, `User`, `Image` (deleting process)

**Windows Event Logs (Security):**

- Event ID 4660 (Object deleted) - File deletion events
- Event ID 4663 (Access attempted to object) - Delete access requests

**Windows Event Logs (System):**

- USN Journal events showing mass deletions

**File System Forensics:**

- $MFT analysis showing deleted file entries
- Volume Shadow Copy Service events
- Recycle Bin bypass indicators

**Tools Used for Secure Deletion:**

- `sdelete.exe` (SysInternals)
- `cipher.exe /w` (Windows secure delete)
- `shred` (Linux)
- `wipe`, `srm` (Linux secure deletion)
- Custom scripts with file overwriting

**Command Patterns:**

- `del /f /s /q C:\folder\*`
- `rm -rf /path/*`
- `Get-ChildItem -Path C:\ -Recurse | Remove-Item -Force`
- `sdelete -s -r C:\Evidence\`
- `cipher /w:C:\folder`
- `shred -vfz -n 10 /path/to/file`

**Focus on:**

- Large numbers of files deleted in short timeframe
- Deletion of log files, forensic artifacts, or tools
- Secure deletion tools indicating intent to prevent recovery
- Deletion from temporary or staging directories
- System files or application data deleted

**Suspicious indicators:**

- Hundreds or thousands of files deleted within minutes (Sysmon Event ID 23 volume spike)
- Deletion of files from `%TEMP%`, `C:\Users\Public\`, `C:\ProgramData\` after data staging
- `sdelete.exe` or `cipher.exe /w` execution for secure wiping
- PowerShell recursive deletion: `Remove-Item -Recurse -Force`
- Deletion of forensic artifacts: Prefetch files, event logs, USN journal
- Mass deletion immediately following data exfiltration or archive creation
- Deletion of attacker tools and malware to remove evidence
- File deletion by processes in `%TEMP%` or user directories (cleanup scripts)
- Deletion patterns matching anti-forensics: `.log`, `.evtx`, `.etl` files
- Volume Shadow Copies deleted: `vssadmin delete shadows /all /quiet`

---

### 5. Timestamp Manipulation (Timestomp)

**Sysmon:**

- Event ID 2 (File creation time changed) - Direct timestomp detection
- Event ID 11 (File created) - Files with suspicious timestamps
- Key fields: `TargetFilename`, `CreationUtcTime`, `PreviousCreationUtcTime`

**Windows Event Logs (Security):**

- Event ID 4663 (Access attempted to object) - WRITE_ATTRIBUTES access

**File System Analysis:**

- $MFT analysis showing timestamp discrepancies
- File creation time later than modification time
- Timestamps predating file system creation
- Round timestamps (00:00:00) suggesting manipulation

**Tools Used:**

- Metasploit `timestomp` module
- `SetMACE.exe`
- PowerShell scripts: `(Get-Item file).CreationTime = "date"`
- Linux `touch` command with custom timestamps

**Command Patterns:**

- PowerShell:
    - `(Get-Item C:\file.exe).CreationTime = "01/01/2020 12:00:00"`
    - `(Get-Item file).LastWriteTime = (Get-Item legitimate.exe).LastWriteTime`
- Linux:
    - `touch -t 202001011200.00 /path/to/file`
    - `touch -r reference_file target_file`

**Focus on:**

- Files with manipulated creation, modification, or access times
- Timestamps matching legitimate system files (timestomp evasion)
- Suspicious timestamp patterns (very old or future dates)
- Timestamp changes to malware or attacker tools
- Bulk timestamp modifications

**Suspicious indicators:**

- Sysmon Event ID 2 showing file creation time changed for executables or scripts
- Files with creation times predating system installation or significantly in past
- Executables with timestamps matching Windows system files (timestomp to blend in)
- Files with creation time after last modification time (logical impossibility)
- Round timestamps (00:00:00.000) indicating manual manipulation
- Recently dropped malware with timestamps from years ago
- PowerShell commands modifying CreationTime, LastWriteTime, or LastAccessTime properties
- Multiple files timestomped to same timestamp within short period
- Timestamp manipulation immediately after malware deployment or tool staging
- MFT $STANDARD_INFORMATION timestamps differing from $FILE_NAME timestamps (NTFS anti-forensics)

---

### 6. Specific Security Log Deletion or Selective Event Removal

**Windows Event Logs:**

- Event ID 1102 (Audit log cleared) - Full log clearing
- Event gaps in sequential Event IDs
- Missing Event IDs in expected sequences

**SIEM/Log Analysis:**

- Gaps in event timelines
- Missing events in expected activity sequences
- Event ID sequences with numerical gaps

**PowerShell Logs:**

- Event ID 4104 (Script block logging) - Scripts selectively removing events

**Command Patterns:**

- `wevtutil qe Security /q:"*[System[(EventID=4624)]]" /f:text | wevtutil cl Security`
- PowerShell:
    - `Get-EventLog -LogName Security | Where-Object {$_.EventID -eq 4624} | Remove-ItemProperty`
    - Custom scripts parsing and rewriting event logs

**Tools:**

- `Invoke-Phant0m` (PowerShell script terminating Event Log threads)
- `Danderspritz EvtDiag` (NSA tool for log manipulation)
- Custom log editing tools

**Focus on:**

- Specific Event IDs missing from logs
- Suspicious gaps in event sequences
- Selective removal of credential access events
- Missing logon/logoff events during known activity
- Tools designed for surgical log manipulation

**Suspicious indicators:**

- Event ID sequence gaps: Event 1000, 1001, 1005 (missing 1002-1004)
- Missing Event ID 4624 (logon) events during period of known remote access
- Absence of Event ID 4688 (process creation) during malware execution timeframe
- PowerShell scripts filtering and removing specific Event IDs
- Event Log threads terminated via process injection (Invoke-Phant0m technique)
- Selective removal of Event ID 4672 (special privileges) or 4768 (Kerberos TGT)
- Missing Sysmon Event ID 1 (process creation) for known attacker tools
- Event gaps correlating with credential dumping, lateral movement, or exfiltration timing
- Tools like `Invoke-Phant0m` detected suspending Event Log service threads
- Registry modifications to Event Log file sizes forcing premature rollover

---

### 7. Log Rotation Manipulation or Premature Log Rollover

**Windows Event Logs:**

- Event log file size changes
- Unexpected log rollovers or archive operations
- Event ID 1104 (Log file rollover)

**Sysmon:**

- Event ID 13 (Registry value set) - Event log MaxSize modifications
- Event ID 255 (Error) - Sysmon configuration issues

**Windows Event Logs (System):**

- Event ID 6 (Event Log configuration changed)
- Event ID 104 (Log cleared) - Related to size manipulation

**Registry Keys:**

- `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security\MaxSize`
- `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System\MaxSize`
- `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\MaxSize`

**Command Patterns:**

- `reg add HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security /v MaxSize /t REG_DWORD /d 1048576 /f` (reduce to 1MB)
- `wevtutil sl Security /ms:1048576` (reduce max size)
- PowerShell: `Limit-EventLog -LogName Security -MaximumSize 1MB`

**Focus on:**

- Event log max size reduced dramatically
- Premature log rollovers during active intrusion
- Configuration changes forcing log data loss
- AutoBackupLogFiles setting disabled
- Retention settings modified

**Suspicious indicators:**

- Security log MaxSize registry value changed from default (20MB+) to minimal (1MB or less)
- `wevtutil sl` commands reducing log file maximum sizes
- Event log size reductions during active intrusion or lateral movement
- Multiple log channel sizes reduced simultaneously
- AutoBackupLogFiles disabled preventing log archival
- Log retention changed from "Archive" to "Overwrite" mode
- Event ID 1104 showing premature log rollover due to size constraints
- Registry modifications reducing Sysmon log size to minimal values
- Log size manipulation immediately preceding high-volume attacker activity
- Configuration changes forcing loss of forensic evidence through overwrites

---

### 8. USN Journal Deletion or Volume Shadow Copy Removal

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Commands affecting VSS or USN journal
- Event ID 4656 (Handle to object requested) - Access to volume devices

**Windows Event Logs (System):**

- Event ID 8222 (Shadow copy created) - VSS activity
- Event ID 8224 (Shadow copy deleted) - VSS deletion

**Sysmon:**

- Event ID 1 (Process creation) - VSS and USN journal commands
- Event ID 11 (File created) - USN journal file operations

**Command Patterns:**

- Volume Shadow Copy deletion:
    - `vssadmin delete shadows /all /quiet`
    - `wmic shadowcopy delete`
    - `Get-WmiObject Win32_ShadowCopy | ForEach-Object {$_.Delete()}`
- USN Journal deletion:
    - `fsutil usn deletejournal /D C:`
    - `fsutil usn deletejournal /N C:`

**Focus on:**

- Volume Shadow Copy deletion (removes backup/restore capability)
- USN journal deletion (removes file system change tracking)
- Commands targeting forensic data sources
- Deletion preventing system restore or recovery
- Anti-forensics intent

**Suspicious indicators:**

- `vssadmin delete shadows /all` removing all restore points
- WMI commands deleting shadow copies: `wmic shadowcopy delete`
- PowerShell deleting VSS: `Get-WmiObject Win32_ShadowCopy | Remove-WmiObject`
- `fsutil usn deletejournal` removing USN change journal
- Event ID 8224 showing shadow copy deletion during active intrusion
- VSS deletion immediately before ransomware deployment
- USN journal deletion to hide file access, creation, or deletion activity
- Multiple volumes having shadow copies deleted simultaneously
- Commands executed with `/quiet` parameter to suppress user notifications
- VSS and USN journal deletion combined with other anti-forensic techniques

---

### 9. Prefetch File Deletion or Forensic Artifact Removal

**Sysmon:**

- Event ID 23 (File deleted) - Prefetch, jump list, or MRU file deletion
- Event ID 26 (File deleted - alternate stream) - ADS removal
- Key fields: `TargetFilename`, pattern matching forensic paths

**Windows Event Logs (Security):**

- Event ID 4660 (Object deleted) - Deletion of forensic artifacts
- Event ID 4663 (Access attempted to object) - Access to forensic locations

**Forensic Artifact Locations:**

- Prefetch: `C:\Windows\Prefetch\*.pf`
- Jump Lists: `C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\`
- Recent files: `C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\`
- SRUM: `C:\Windows\System32\sru\SRUDB.dat`
- Amcache: `C:\Windows\AppCompat\Programs\Amcache.hve`
- ShimCache: Registry `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`

**Command Patterns:**

- `del /f /q C:\Windows\Prefetch\*.pf`
- `Remove-Item C:\Windows\Prefetch\* -Force`
- `del /f /q C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\*`
- `reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" /f`

**Focus on:**

- Prefetch file deletion (program execution history)
- Jump list deletion (file access history)
- Recent files/MRU deletion (user activity tracking)
- Amcache or ShimCache clearing (execution artifacts)
- SRUM database tampering (system resource usage)

**Suspicious indicators:**

- Mass deletion of `.pf` files from `C:\Windows\Prefetch\`
- Deletion of jump lists and recent file artifacts
- `del` or `Remove-Item` commands targeting forensic artifact directories
- Prefetch deletion immediately following malware execution or tool usage
- Selective deletion of specific prefetch files matching attacker tool names
- Jump list deletion for applications used during intrusion
- Amcache.hve deletion or modification to hide execution evidence
- Registry deletion of AppCompatCache (ShimCache) entries
- SRUM database deletion or corruption
- Deletion of artifacts from multiple user profiles simultaneously

---

### 10. SIEM/Logging Agent Tampering or Log Forwarding Disruption

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Commands affecting logging agents
- Event ID 4697 (Service installed) - Logging service modifications

**Windows Event Logs (System):**

- Event ID 7036 (Service state change) - Logging agent services stopped
- Event ID 7040 (Service startup type changed) - Agent disabled

**Sysmon:**

- Event ID 1 (Process creation) - Commands targeting logging infrastructure
- Event ID 5 (Process terminated) - Logging agent termination
- Event ID 255 (Error) - Sysmon service errors or tampering

**Network Logs:**

- Syslog forwarding interruptions
- Loss of log flow to SIEM
- Agent heartbeat failures

**Logging Agents:**

- Splunk Universal Forwarder: `splunkd.exe`, `SplunkForwarder` service
- Elastic Beats: `filebeat.exe`, `winlogbeat.exe`
- NXLog: `nxlog.exe`, `nxlog` service
- Sysmon: `Sysmon.exe`, `Sysmon` service
- Windows Event Forwarding (WEF): `wecsvc` service

**Command Patterns:**

- `net stop SplunkForwarder`
- `sc config SplunkForwarder start=disabled`
- `taskkill /F /IM splunkd.exe`
- `Stop-Service -Name nxlog -Force`
- `fltmc unload SysmonDrv` (Sysmon driver unload)

**Focus on:**

- Logging agent services stopped or disabled
- Log forwarding process termination
- Network connectivity disruption to SIEM
- Configuration file modification preventing forwarding
- Logging agent uninstallation

**Suspicious indicators:**

- Splunk, NXLog, or Elastic Beat services stopped (Event ID 7036)
- `net stop` or `sc config` commands targeting logging agent services
- `taskkill` terminating logging agent processes
- Sysmon service stopped or driver unloaded: `fltmc unload SysmonDrv`
- Gaps in log forwarding to SIEM during active intrusion
- Logging agent configuration files deleted or modified to disable forwarding
- Network connections from logging agents to SIEM interrupted
- Agent processes terminated by processes in `%TEMP%` or user directories
- Windows Event Forwarding (WEF) subscription disabled or source collector stopped
- Multiple systems showing logging agent failures simultaneously (coordinated attack)

---
# Indicator Removal (T1070) Investigation Checklist

## 1. Windows Event Log Clearing

- [ ]  Check Event ID 1102 in Security log for audit log cleared events
- [ ]  Review Event ID 104 in System log for individual log channel clearing
- [ ]  Search Event ID 4688 for: `wevtutil cl`, `Clear-EventLog`, `wmic nteventlog`
- [ ]  Review PowerShell Event ID 4104 for log clearing commands
- [ ]  Identify multiple logs cleared within 5-10 minute window
- [ ]  Correlate log clearing with credential dumping or exfiltration activity

## 2. Linux/Unix Log Deletion

- [ ]  Check file integrity monitoring (FIM) alerts for `/var/log/` modifications
- [ ]  Search auditd logs for: `-w /var/log/ -p wa -k log_deletion`
- [ ]  Verify `/var/log/auth.log` and `/var/log/secure` not truncated or deleted
- [ ]  Check for deleted/zeroed: `wtmp`, `btmp`, `lastlog` files
- [ ]  Review for symbolic links from log files to `/dev/null`
- [ ]  Identify gaps in syslog forwarding to central logging

## 3. Command History Clearing

- [ ]  Check Sysmon Event ID 23 for deletion of `ConsoleHost_history.txt` or `.bash_history`
- [ ]  Search PowerShell Event ID 4104 for: `Clear-History`, `Remove-Item (Get-PSReadlineOption).HistorySavePath`
- [ ]  Review Event ID 4688 for: `history -c`, `rm ~/.bash_history`, `unset HISTFILE`
- [ ]  Verify PowerShell history file exists: `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
- [ ]  Check for `Set-PSReadlineOption -HistorySaveStyle SaveNothing`
- [ ]  Identify history clearing following credential access or lateral movement

## 4. Mass File Deletion

- [ ]  Review Sysmon Event ID 23 for high-volume file deletions (spike detection)
- [ ]  Check Event ID 4660/4663 for deletion from `%TEMP%`, `C:\ProgramData\`, `C:\Users\Public\`
- [ ]  Search Event ID 4688 for: `sdelete`, `cipher /w`, `Remove-Item -Recurse -Force`
- [ ]  Identify deletion of `.log`, `.evtx`, `.etl`, `.pf` files (forensic artifacts)
- [ ]  Check for: `vssadmin delete shadows /all /quiet`
- [ ]  Correlate mass deletion with data exfiltration timing

## 5. Timestamp Manipulation

- [ ]  Review Sysmon Event ID 2 for file creation time changed on executables
- [ ]  Check for files with creation time > modification time (logical impossibility)
- [ ]  Identify executables with timestamps predating system installation
- [ ]  Search Event ID 4688 for PowerShell commands modifying: `CreationTime`, `LastWriteTime`
- [ ]  Review for round timestamps (00:00:00.000) indicating manual manipulation
- [ ]  Analyze $MFT for $STANDARD_INFORMATION vs $FILE_NAME timestamp discrepancies

## 6. Selective Event Removal

- [ ]  Identify sequential Event ID gaps (e.g., 1000, 1001, 1005 missing 1002-1004)
- [ ]  Check for missing Event ID 4624/4688 during known activity periods
- [ ]  Search PowerShell Event ID 4104 for scripts filtering/removing specific Event IDs
- [ ]  Review for tools: `Invoke-Phant0m`, Danderspritz EvtDiag
- [ ]  Correlate event gaps with credential dumping or lateral movement timing

## 7. Log Rotation Manipulation

- [ ]  Check Sysmon Event ID 13 for MaxSize modifications: `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security\MaxSize`
- [ ]  Review Event ID 1104 for premature log rollovers during intrusion
- [ ]  Search Event ID 4688 for: `wevtutil sl Security /ms:`, `Limit-EventLog`
- [ ]  Verify Security log MaxSize not reduced to minimal values (< 5MB)
- [ ]  Check AutoBackupLogFiles not disabled preventing archival

## 8. USN Journal & Shadow Copy Deletion

- [ ]  Check Event ID 8224 in System log for shadow copy deletions
- [ ]  Search Event ID 4688 for: `vssadmin delete shadows`, `wmic shadowcopy delete`, `fsutil usn deletejournal`
- [ ]  Review PowerShell Event ID 4104 for: `Get-WmiObject Win32_ShadowCopy | Remove-WmiObject`
- [ ]  Identify VSS deletion immediately before ransomware or during active intrusion
- [ ]  Check for USN journal deletion to hide file system activity

## 9. Forensic Artifact Removal

- [ ]  Review Sysmon Event ID 23 for deletion from: `C:\Windows\Prefetch\*.pf`
- [ ]  Check for deletion from: `C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\`
- [ ]  Search Event ID 4688 for: `del /f /q C:\Windows\Prefetch\`, `Remove-Item C:\Windows\Prefetch\*`
- [ ]  Verify Amcache.hve not deleted: `C:\Windows\AppCompat\Programs\Amcache.hve`
- [ ]  Check registry for AppCompatCache deletion: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`

## 10. SIEM/Logging Agent Tampering

- [ ]  Check Event ID 7036/7040 for logging agent services stopped: Splunk, NXLog, Elastic Beats, Sysmon
- [ ]  Search Event ID 4688 for: `net stop SplunkForwarder`, `sc config`, `taskkill /IM splunkd.exe`
- [ ]  Review Sysmon Event ID 5 for logging agent process termination
- [ ]  Check for Sysmon driver unload: `fltmc unload SysmonDrv`
- [ ]  Identify gaps in log forwarding to SIEM during active intrusion
- [ ]  Verify Windows Event Forwarding (WEF) subscriptions not disabled