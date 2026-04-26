# Impair Defenses: [T1562](https://attack.mitre.org/techniques/T1562/)

## Detection Explanation

Impair Defenses involves adversaries attempting to disable, modify, or otherwise interfere with security tools, logging systems, monitoring capabilities, and protective controls to evade detection and maintain persistence. This technique is a strong indicator of a sophisticated attacker who understands the defensive capabilities of the target environment and actively works to blind security operations. Impairment of defenses typically occurs after initial compromise and before executing primary objectives such as lateral movement, credential theft, or data exfiltration.

Attackers impair defenses because security tools and logging systems pose the greatest threat to their operations. By disabling antivirus, EDR agents, Windows Defender, firewalls, logging services, or security monitoring, adversaries reduce their risk of detection and create operational freedom to execute attacks without triggering alerts. Common methods include disabling or modifying security tools (T1562.001), disabling Windows Event Logging (T1562.002), impacting cloud-based security services (T1562.003), disabling or modifying system firewalls (T1562.004), and tampering with indicator blocking or event filtering (T1562.006).

Successful impairment of defenses creates significant blind spots in security monitoring, allowing attackers to operate undetected for extended periods. This technique dramatically increases attack success rates by neutralizing the defensive capabilities designed to detect and respond to threats. The impact includes undetected malware execution, unlogged attacker activity, disabled endpoint protection, compromised forensic evidence, and delayed incident response due to lack of visibility into attacker actions.

Detection requires monitoring for changes to security tool configurations, tracking service state changes for protective software, identifying tampering with logging systems, and alerting on unauthorized modifications to firewall rules or security policies. Organizations should establish baselines for security tool configurations, implement tamper protection where available, and correlate defense impairment attempts with other suspicious activities to identify active intrusions.

---

## Key Detection Indicators & Areas to Investigate

### Summary of Indicators

1. Security software disabled or terminated (T1562.001)
2. Windows Defender tampered or disabled (T1562.001)
3. EDR agent service stopped or removed (T1562.001)
4. Windows Event Log service disabled or cleared (T1562.002)
5. Firewall rules modified or disabled (T1562.004)
6. Security tool process termination attempts
7. Registry modifications disabling security features (T1562.001)
8. PowerShell commands targeting security tools
9. Group Policy changes affecting security settings
10. Audit policy modifications reducing logging (T1562.002)

---

### 1. Security Software Disabled or Terminated

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Commands targeting security software
- Event ID 4697 (Service installed) - Service modifications
- Event ID 7040 (Service startup type changed) - Security service disabled

**Windows Event Logs (System):**

- Event ID 7036 (Service state change) - Security services stopped
- Event ID 7034 (Service terminated unexpectedly) - Antivirus crashes
- Event ID 7045 (Service installed) - Suspicious service replacements

**Sysmon:**

- Event ID 1 (Process creation) - Commands disabling security tools
- Event ID 13 (Registry value set) - Registry changes disabling protections
- Event ID 12 (Registry object added/deleted) - Security registry key deletion

**Windows Event Logs (Application):**

- Antivirus/EDR specific event IDs indicating protection disabled
- Security software error or warning events

**Command-Line Patterns:**

- `net stop "Windows Defender"` or `net stop WinDefend`
- `sc config WinDefend start=disabled`
- `Stop-Service -Name WinDefend -Force`
- `taskkill /F /IM MsMpEng.exe` (Defender process)
- Antivirus-specific: `net stop "Sophos *"`, `net stop "Symantec *"`

**Focus on:**

- Security services being stopped or disabled
- Antivirus or EDR process termination
- Service startup type changes from automatic to disabled
- Multiple security tools targeted simultaneously
- Commands executed with administrative privileges

**Suspicious indicators:**

- Event ID 7036 showing security services transitioning to stopped state: `Windows Defender`, `SophosAgent`, `CylanceSvc`
- `sc.exe config` or `net.exe stop` commands targeting antivirus service names
- PowerShell `Stop-Service` commands targeting security tool services
- Event ID 7040 showing security service startup changed from `Automatic` to `Disabled`
- Multiple security services stopped within short timeframe (5-15 minutes)
- `taskkill` commands targeting security processes: `MsMpEng.exe`, `SenseIR.exe`, `CylanceUI.exe`
- Service state changes during off-hours or by non-administrative accounts
- Security software termination immediately following credential dumping or exploitation
- Registry modifications to service start values: `HKLM\SYSTEM\CurrentControlSet\Services\<SecurityService>\Start` set to 4 (disabled)
- Security tool configuration files deleted or modified

---

### 2. Windows Defender Tampered or Disabled

**Windows Event Logs (Microsoft-Windows-Windows Defender/Operational):**

- Event ID 5001 (Real-time protection disabled)
- Event ID 5010 (Scanning for malware and unwanted software disabled)
- Event ID 5012 (Antimalware platform will expire soon)
- Event ID 3002 (Real-time protection configuration changed)
- Event ID 5007 (Configuration changed)

**PowerShell Logs:**

- Event ID 4104 (Script block logging) - PowerShell commands disabling Defender
- Commands: `Set-MpPreference`, `Disable-WindowsDefender`

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Commands modifying Defender

**Sysmon:**

- Event ID 1 (Process creation) - Defender modification commands
- Event ID 13 (Registry value set) - Defender registry tampering

**Registry Keys:**

- `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware` set to 1
- `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring` set to 1
- `HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection` set to 0

**PowerShell Commands:**

- `Set-MpPreference -DisableRealtimeMonitoring $true`
- `Set-MpPreference -DisableIOAVProtection $true`
- `Set-MpPreference -DisableBehaviorMonitoring $true`
- `Add-MpPreference -ExclusionPath "C:\"`
- `Uninstall-WindowsFeature -Name Windows-Defender`

**Focus on:**

- Real-time protection being disabled
- Behavior monitoring disabled
- Cloud-delivered protection disabled
- Exclusion paths added to entire drives
- Tamper protection modifications

**Suspicious indicators:**

- Event ID 5001 (Real-time protection disabled) without legitimate administrative action
- PowerShell `Set-MpPreference` commands disabling multiple protection features
- Registry value `DisableAntiSpyware` set to 1 in Policies key
- Exclusion paths added for entire drives: `C:\`, `D:\`, or common malware staging locations
- Event ID 5007 showing configuration changes to disable scanning or monitoring
- `Set-MpPreference -DisableBehaviorMonitoring $true -DisableRealtimeMonitoring $true` in single command
- Tamper protection disabled via registry: `TamperProtection` value set to 0
- Defender exclusions added for suspicious paths: `%TEMP%`, `C:\Users\Public\`, `C:\ProgramData\`
- Multiple Defender features disabled simultaneously
- Defender configuration changes during active malware execution or lateral movement

---

### 3. EDR Agent Service Stopped or Removed

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Commands stopping EDR services
- Event ID 4697 (Service installed) - EDR service modifications
- Event ID 4673 (Sensitive privilege use) - Privileges used to stop services

**Windows Event Logs (System):**

- Event ID 7036 (Service state change) - EDR services stopped
- Event ID 7034 (Service terminated unexpectedly) - EDR crashes
- Event ID 7040 (Service startup type changed) - EDR disabled
- Event ID 7045 (Service installed) - Suspicious service installations

**Sysmon:**

- Event ID 1 (Process creation) - Commands targeting EDR
- Event ID 6 (Driver loaded) - EDR driver unloaded events
- Event ID 255 (Error) - Sysmon service tampering

**EDR Services to Monitor:**

- CrowdStrike: `CSFalconService`, `CSAgent`
- Carbon Black: `CarbonBlack`, `RepMgr`
- SentinelOne: `SentinelAgent`, `SentinelStaticEngine`
- Cylance: `CylanceSvc`, `CylanceUI`
- Defender ATP: `Sense`, `WdNisSvc`
- Microsoft Sysmon: `Sysmon`, `Sysmon64`

**Command-Line Patterns:**

- `sc stop <EDR_Service>`
- `net stop <EDR_Service>`
- `fltmc unload <EDR_Filter_Driver>`
- `sc delete <EDR_Service>`
- Process termination via Task Manager or `taskkill`

**Focus on:**

- EDR service state changes to stopped
- EDR driver unloading attempts
- EDR process termination
- Service startup type changes from automatic to disabled
- EDR agent uninstallation attempts

**Suspicious indicators:**

- Event ID 7036 showing EDR services stopping: `CSFalconService`, `SentinelAgent`, `CarbonBlack`
- Commands targeting EDR services: `sc stop CSFalconService`, `net stop CylanceSvc`
- EDR filter driver unloading: `fltmc unload SysmonDrv`, `fltmc unload CbFilter`
- Event ID 7040 showing EDR service startup changed to `Disabled`
- Multiple EDR components stopped simultaneously (service + driver + process)
- EDR agent uninstallation commands or MSI removal operations
- `taskkill` targeting EDR processes: `taskkill /F /IM CSFalconService.exe`
- Registry modifications to EDR service configurations
- EDR service crashes (Event ID 7034) during suspicious activity
- Sysmon Event ID 255 errors indicating Sysmon service tampering or unloading

---

### 4. Windows Event Log Service Disabled or Cleared

**Windows Event Logs (Security):**

- Event ID 1102 (Audit log cleared) - Event logs manually cleared
- Event ID 4688 (Process creation) - Commands clearing or disabling logs
- Event ID 4719 (System audit policy changed) - Audit policy modifications

**Windows Event Logs (System):**

- Event ID 7036 (Service state change) - Event Log service stopped
- Event ID 7040 (Service startup type changed) - Event Log service disabled
- Event ID 104 (Log cleared) - Individual log channels cleared

**Sysmon:**

- Event ID 1 (Process creation) - Log clearing commands
- Event ID 13 (Registry value set) - Event log registry tampering
- Event ID 12 (Registry object added/deleted) - Event log configuration changes

**PowerShell Logs:**

- Event ID 4104 (Script block logging) - PowerShell log clearing commands

**Command-Line Patterns:**

- `wevtutil cl Security`
- `wevtutil cl System`
- `wevtutil cl "Microsoft-Windows-Sysmon/Operational"`
- `Clear-EventLog -LogName Security`
- `Get-EventLog -LogName * | Clear-EventLog`
- `net stop eventlog`
- `sc config eventlog start=disabled`

**Registry Keys:**

- `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security\MaxSize` (size manipulation)
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\*\Enabled` set to 0

**Focus on:**

- Security, System, or Sysmon logs being cleared
- Event Log service being stopped or disabled
- Audit policies being modified to reduce logging
- Log file size limits being reduced
- Event channels being disabled

**Suspicious indicators:**

- Event ID 1102 (Security log cleared) without authorized change management
- Multiple logs cleared in sequence: Security, System, Application, Sysmon
- `wevtutil cl` commands targeting critical log channels
- PowerShell `Clear-EventLog` commands clearing Security or System logs
- Event Log service stopped (Event ID 7036) during active intrusion
- Event ID 104 showing individual log channels cleared
- `sc config eventlog start=disabled` attempting to prevent log service restart
- Log clearing immediately following credential dumping, lateral movement, or exploitation
- Registry modifications disabling event channels: `Enabled` value set to 0
- Audit policy changes (Event ID 4719) reducing success/failure logging

---

### 5. Firewall Rules Modified or Disabled

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Commands modifying firewall
- Event ID 4946 (Windows Firewall exception list change) - Rule additions
- Event ID 4947 (Windows Firewall rule modified)
- Event ID 4948 (Windows Firewall exception list change deleted)
- Event ID 4950 (Windows Firewall setting changed)
- Event ID 4954 (Windows Firewall Group Policy settings changed)

**Windows Event Logs (Microsoft-Windows-Windows Firewall With Advanced Security/Firewall):**

- Event ID 2003 (Windows Firewall state changed to disabled)
- Event ID 2004 (Firewall rule added)
- Event ID 2005 (Firewall rule modified)
- Event ID 2006 (Firewall rule deleted)

**Sysmon:**

- Event ID 1 (Process creation) - Firewall modification commands
- Event ID 13 (Registry value set) - Firewall registry changes

**PowerShell Logs:**

- Event ID 4104 (Script block logging) - PowerShell firewall commands

**Command-Line Patterns:**

- `netsh advfirewall set allprofiles state off`
- `netsh advfirewall firewall add rule name="Allow All" dir=in action=allow`
- `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False`
- `New-NetFirewallRule -DisplayName "Malware" -Direction Inbound -Action Allow`
- `netsh firewall set opmode mode=disable`

**Focus on:**

- Firewall being completely disabled
- Permissive rules allowing all inbound traffic
- Rules allowing specific malware ports or services
- Firewall profile state changes
- Group Policy firewall modifications

**Suspicious indicators:**

- Event ID 2003 (Firewall disabled) for Domain, Private, or Public profiles
- `netsh advfirewall set allprofiles state off` disabling all firewall profiles
- PowerShell `Set-NetFirewallProfile -Enabled False` commands
- Event ID 4946/2004 showing rules allowing all inbound traffic on all ports
- Firewall rules added for suspicious ports: 4444, 31337, 8080 (common C2 ports)
- Rule names suggesting malware: "Allow All", "Backdoor", "Update", generic names
- Firewall rules allowing inbound traffic to `cmd.exe`, `powershell.exe`, or suspicious executables
- Event ID 4950 showing firewall settings changed to less restrictive configurations
- Multiple firewall rules added in rapid succession
- Firewall modifications during active lateral movement or C2 communication

---

### 6. Security Tool Process Termination Attempts

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - `taskkill` or process termination tools
- Event ID 4689 (Process exited) - Security processes terminating

**Sysmon:**

- Event ID 1 (Process creation) - Process termination commands
- Event ID 5 (Process terminated) - Security tool processes ending
- Event ID 10 (ProcessAccess) - Handle requests to security processes

**Windows Event Logs (Application):**

- Application error events for security software
- Crash reports for security tools

**Command-Line Patterns:**

- `taskkill /F /IM MsMpEng.exe` (Defender)
- `taskkill /F /IM csfalconservice.exe` (CrowdStrike)
- `taskkill /F /IM SentinelAgent.exe` (SentinelOne)
- `Stop-Process -Name "SecurityProcess" -Force`
- `wmic process where name="antivirus.exe" delete`

**Security Processes to Monitor:**

- Windows Defender: `MsMpEng.exe`, `NisSrv.exe`, `SecurityHealthService.exe`
- CrowdStrike: `CSFalconService.exe`, `CSFalconContainer.exe`
- Carbon Black: `cb.exe`, `RepMgr.exe`
- SentinelOne: `SentinelAgent.exe`, `SentinelServiceHost.exe`
- Symantec: `ccSvcHst.exe`, `SymCorpUI.exe`
- McAfee: `McShield.exe`, `mfemms.exe`

**Focus on:**

- Process termination commands targeting security software
- Forceful process kills (`/F` parameter)
- Multiple security processes terminated simultaneously
- Process access attempts to security tools for termination
- Termination attempts using administrative privileges

**Suspicious indicators:**

- `taskkill /F /IM` targeting security process names
- PowerShell `Stop-Process -Force` commands terminating antivirus or EDR
- WMI process deletion: `wmic process where name="MsMpEng.exe" delete`
- Sysmon Event ID 10 showing process handle requests with TERMINATE access to security tools
- Multiple security processes terminated within 5-minute window
- Process termination from unexpected parent processes: Office apps, browsers, scripts
- Event ID 5 showing security tool processes terminating unexpectedly
- Process termination immediately before malware execution or lateral movement
- Repeated termination attempts indicating persistence mechanisms targeting security tools
- Security process crashes correlated with attacker activity

---

### 7. Registry Modifications Disabling Security Features

**Sysmon:**

- Event ID 12 (Registry object added/deleted) - Security registry key deletion
- Event ID 13 (Registry value set) - Security settings modified
- Event ID 14 (Registry object renamed) - Security key renaming

**Windows Event Logs (Security):**

- Event ID 4657 (Registry value modification) - Security registry changes
- Event ID 4688 (Process creation) - `reg.exe` commands modifying security

**PowerShell Logs:**

- Event ID 4104 (Script block logging) - PowerShell registry modifications

**Critical Registry Keys:**

- Windows Defender:
    - `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware` = 1
    - `HKLM\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection` = 0
- UAC:
    - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA` = 0
    - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` = 0
- Windows Firewall:
    - `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\EnableFirewall` = 0
- Audit Policy:
    - `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\AuditBaseObjects` = 0

**Command-Line Patterns:**

- `reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f`
- `reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f`
- PowerShell: `Set-ItemProperty -Path "HKLM:\SOFTWARE\..." -Name DisableAntiSpyware -Value 1`

**Focus on:**

- Registry keys controlling security tool behavior
- UAC settings being weakened
- Audit and logging settings being reduced
- Firewall registry modifications
- Tamper protection being disabled

**Suspicious indicators:**

- `DisableAntiSpyware` registry value set to 1 (disables Windows Defender)
- `EnableLUA` set to 0 (disables User Account Control)
- `TamperProtection` set to 0 (allows Defender tampering)
- Firewall `EnableFirewall` values set to 0 for all profiles
- `ConsentPromptBehaviorAdmin` set to 0 (no UAC prompts for administrators)
- `reg.exe` commands modifying security-related registry keys
- PowerShell `Set-ItemProperty` modifying Defender, UAC, or firewall keys
- Multiple security registry keys modified in sequence
- Registry modifications immediately preceding malware execution
- Changes to audit policy registry keys reducing logging verbosity

---

### 8. PowerShell Commands Targeting Security Tools

**PowerShell Logs:**

- Event ID 4104 (Script block logging) - Full command content
- Event ID 4103 (Module logging) - Cmdlet execution
- Event ID 4105 (Script start) - Script execution
- Event ID 4106 (Script stop) - Script termination

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - PowerShell execution
- Event ID 4672 (Special privileges assigned) - Elevated PowerShell sessions

**Sysmon:**

- Event ID 1 (Process creation) - PowerShell with suspicious parameters
- Event ID 3 (Network connection) - PowerShell downloading disabler scripts

**PowerShell Commands Targeting Security:**

- `Set-MpPreference -DisableRealtimeMonitoring $true`
- `Stop-Service -Name WinDefend -Force`
- `Uninstall-WindowsFeature -Name Windows-Defender`
- `Get-Service *defender* | Stop-Service -Force`
- `Set-NetFirewallProfile -Enabled False`
- `Disable-WindowsOptionalFeature -Online -FeatureName Windows-Defender`
- `Add-MpPreference -ExclusionPath "C:\"`

**Focus on:**

- PowerShell cmdlets disabling security features
- Service manipulation targeting security tools
- Registry modifications via PowerShell
- Exclusion additions for broad paths
- Multiple security features targeted in single script

**Suspicious indicators:**

- `Set-MpPreference` with multiple disabling parameters in single command
- PowerShell `Stop-Service` targeting security service names
- `Get-Service` filtering for security tools followed by `Stop-Service`
- `Uninstall-WindowsFeature -Name Windows-Defender` removing Defender entirely
- Base64-encoded PowerShell commands decoding to security tool disabling
- `Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False`
- PowerShell adding broad exclusions: `Add-MpPreference -ExclusionPath "C:\", "D:\"`
- Scripts combining multiple security impairment techniques
- PowerShell downloading and executing security disabling scripts from external sources
- `-EncodedCommand` or `-WindowStyle Hidden` parameters with security tool targeting

---

### 9. Group Policy Changes Affecting Security Settings

**Windows Event Logs (Security):**

- Event ID 4719 (System audit policy changed) - Audit policy modifications
- Event ID 4739 (Domain policy changed) - Domain-wide policy changes
- Event ID 4954 (Windows Firewall Group Policy changed)
- Event ID 5136 (Directory service object modified) - GPO modifications in AD
- Event ID 5137 (Directory service object created) - New GPO creation

**Windows Event Logs (System):**

- Event ID 1500 (Group Policy processing) - GPO application
- Event ID 1501 (Group Policy error) - GPO processing failures

**Active Directory Logs (on Domain Controllers):**

- GPO modification events in AD
- SYSVOL changes to GPO files

**PowerShell Logs:**

- Event ID 4104 (Script block logging) - GPO modification scripts

**Focus on:**

- Group Policy changes affecting security tools
- Audit policy reductions via GPO
- Firewall settings modified via Group Policy
- AppLocker or application control policy changes
- Security baseline GPO modifications

**Suspicious indicators:**

- Event ID 4719 showing audit policy success/failure logging reduced or disabled
- GPO modifications disabling Windows Defender across domain
- Event ID 4954 showing firewall Group Policy changes to permissive settings
- Event ID 5136 showing GPO object modifications in AD: `CN=Policies,CN=System,DC=...`
- New GPOs created (Event ID 5137) with security-impacting settings
- GPO changes disabling User Account Control domain-wide
- Audit policy GPO modifications reducing object access, process tracking, or logon event logging
- PowerShell scripts using `Set-GPRegistryValue` to disable security features
- GPO links modified to apply permissive security policies to sensitive OUs
- SYSVOL changes to `Registry.pol` files containing security setting reductions

---

### 10. Audit Policy Modifications Reducing Logging

**Windows Event Logs (Security):**

- Event ID 4719 (System audit policy changed) - Critical audit policy indicator
- Event ID 4902 (Per-user audit policy table created)
- Event ID 4906 (CrashOnAuditFail value changed)
- Event ID 4912 (Per-User Audit Policy changed)

**Windows Event Logs (System):**

- Event ID 1102 (Audit log cleared) - Often follows audit reduction

**Command-Line Patterns:**

- `auditpol /set /category:"Logon/Logoff" /success:disable /failure:disable`
- `auditpol /clear /y` (clears all audit settings)
- `auditpol /set /subcategory:"Process Creation" /success:disable`
- `reg add HKLM\System\CurrentControlSet\Control\Lsa /v AuditBaseObjects /t REG_DWORD /d 0`

**Sysmon:**

- Event ID 1 (Process creation) - `auditpol.exe` execution
- Event ID 13 (Registry value set) - Audit registry modifications

**Audit Categories Commonly Targeted:**

- Logon/Logoff events
- Process Tracking (process creation)
- Object Access (file/registry access)
- Privilege Use
- Account Logon events

**Focus on:**

- Audit policies being disabled or reduced
- Success and/or failure logging disabled
- Critical security event categories disabled
- Registry modifications affecting audit behavior
- Audit policy cleared entirely

**Suspicious indicators:**

- Event ID 4719 showing audit policy subcategory changed to "No Auditing"
- `auditpol /set` commands disabling Process Creation (subcategory `{0CCE922B-69AE-11D9-BED3-505054503030}`)
- Audit policy changes disabling Logon/Logoff events during active intrusion
- `auditpol /clear` clearing all audit configurations
- Multiple audit subcategories disabled in sequence
- Audit policy modifications immediately following credential dumping or lateral movement
- Event ID 4719 showing both success and failure auditing disabled for critical categories
- Registry modifications to `HKLM\System\CurrentControlSet\Control\Lsa\AuditBaseObjects` set to 0
- Audit policy changes via Group Policy affecting multiple systems simultaneously
- Per-user audit policies (Event ID 4912) configured to reduce logging for specific accounts

---
# Impair Defenses Investigation Checklist

## 1. Security Software Disabled/Terminated

- [ ] Review Event ID 7036 for security services stopping: Windows Defender, SophosAgent, CylanceSvc
- [ ] Check sc.exe config or net.exe stop commands targeting antivirus services
- [ ] Monitor PowerShell Stop-Service commands targeting security tools
- [ ] Identify Event ID 7040 for startup changes from Automatic to Disabled
- [ ] Look for multiple security services stopped within 5-15 minutes
- [ ] Check taskkill commands targeting: MsMpEng.exe, SenseIR.exe, CylanceUI.exe
- [ ] Review service state changes during off-hours or by non-administrative accounts
- [ ] Monitor registry modifications to service Start values (set to 4 - disabled)

## 2. Windows Defender Tampered/Disabled

- [ ] Check Event ID 5001 (Real-time protection disabled) without legitimate admin action
- [ ] Review PowerShell Set-MpPreference commands disabling multiple features
- [ ] Monitor registry: DisableAntiSpyware set to 1 in Policies key
- [ ] Identify exclusion paths for entire drives: C:, D:, or staging locations
- [ ] Look for Event ID 5007 showing configuration changes to disable scanning
- [ ] Check TamperProtection registry value set to 0
- [ ] Review exclusions for suspicious paths: %TEMP%, C:\Users\Public, C:\ProgramData\
- [ ] Monitor multiple Defender features disabled simultaneously

## 3. EDR Agent Service Stopped/Removed

- [ ] Review Event ID 7036 for EDR services stopping: CSFalconService, SentinelAgent, CarbonBlack
- [ ] Check commands: sc stop CSFalconService, net stop CylanceSvc
- [ ] Monitor EDR filter driver unloading: fltmc unload SysmonDrv, fltmc unload CbFilter
- [ ] Identify Event ID 7040 for EDR startup changed to Disabled
- [ ] Look for multiple EDR components stopped (service + driver + process)
- [ ] Check taskkill targeting: taskkill /F /IM CSFalconService.exe
- [ ] Review Sysmon Event ID 255 errors indicating Sysmon tampering
- [ ] Monitor EDR crashes (Event ID 7034) during suspicious activity

## 4. Event Log Service Disabled/Cleared

- [ ] Review Event ID 1102 (Security log cleared) without authorized change management
- [ ] Check multiple logs cleared in sequence: Security, System, Application, Sysmon
- [ ] Monitor wevtutil cl commands targeting critical log channels
- [ ] Identify PowerShell Clear-EventLog commands clearing Security/System logs
- [ ] Look for Event Log service stopped (Event ID 7036)
- [ ] Check Event ID 104 showing individual log channels cleared
- [ ] Review sc config eventlog start=disabled attempts
- [ ] Monitor log clearing following credential dumping or lateral movement

## 5. Firewall Rules Modified/Disabled

- [ ] Review Event ID 2003 (Firewall disabled) for Domain, Private, or Public profiles
- [ ] Check netsh advfirewall set allprofiles state off commands
- [ ] Monitor PowerShell Set-NetFirewallProfile -Enabled False
- [ ] Identify Event ID 4946/2004 showing rules allowing all inbound traffic
- [ ] Look for firewall rules for suspicious ports: 4444, 31337, 8080
- [ ] Check rule names: "Allow All", "Backdoor", "Update", generic names
- [ ] Review rules allowing inbound to cmd.exe, powershell.exe, suspicious executables
- [ ] Monitor multiple firewall rules added in rapid succession

## 6. Security Process Termination

- [ ] Check taskkill /F /IM targeting security process names
- [ ] Review PowerShell Stop-Process -Force terminating antivirus or EDR
- [ ] Monitor WMI process deletion: wmic process where name="MsMpEng.exe" delete
- [ ] Identify Sysmon Event ID 10 with TERMINATE access to security tools
- [ ] Look for multiple security processes terminated within 5-minute window
- [ ] Check process termination from unexpected parents: Office apps, browsers, scripts
- [ ] Review Event ID 5 showing security processes terminating unexpectedly
- [ ] Monitor termination immediately before malware execution or lateral movement

## 7. Security Registry Modifications

- [ ] Check DisableAntiSpyware registry value set to 1 (disables Defender)
- [ ] Review EnableLUA set to 0 (disables User Account Control)
- [ ] Monitor TamperProtection set to 0 (allows Defender tampering)
- [ ] Identify Firewall EnableFirewall values set to 0 for all profiles
- [ ] Look for ConsentPromptBehaviorAdmin set to 0 (no UAC prompts)
- [ ] Check reg.exe commands modifying security-related registry keys
- [ ] Review PowerShell Set-ItemProperty modifying Defender, UAC, firewall keys
- [ ] Monitor multiple security registry keys modified in sequence

## 8. PowerShell Security Tool Targeting

- [ ] Review Set-MpPreference with multiple disabling parameters in single command
- [ ] Check PowerShell Stop-Service targeting security service names
- [ ] Monitor Get-Service filtering security tools followed by Stop-Service
- [ ] Identify Uninstall-WindowsFeature -Name Windows-Defender
- [ ] Look for Base64-encoded PowerShell decoding to security disabling
- [ ] Check Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
- [ ] Review Add-MpPreference with broad exclusions: C:, D:\
- [ ] Monitor -EncodedCommand or -WindowStyle Hidden with security targeting

## 9. Group Policy Security Changes

- [ ] Review Event ID 4719 showing audit policy success/failure logging reduced
- [ ] Check GPO modifications disabling Windows Defender across domain
- [ ] Monitor Event ID 4954 for firewall Group Policy changes
- [ ] Identify Event ID 5136 showing GPO modifications: CN=Policies,CN=System,DC=...
- [ ] Look for new GPOs (Event ID 5137) with security-impacting settings
- [ ] Check GPO changes disabling User Account Control domain-wide
- [ ] Review audit policy GPO modifications reducing logging
- [ ] Monitor PowerShell Set-GPRegistryValue disabling security features

## 10. Audit Policy Modifications

- [ ] Review Event ID 4719 showing audit subcategory changed to "No Auditing"
- [ ] Check auditpol /set commands disabling Process Creation events
- [ ] Monitor audit policy changes disabling Logon/Logoff during intrusion
- [ ] Identify auditpol /clear clearing all audit configurations
- [ ] Look for multiple audit subcategories disabled in sequence
- [ ] Check audit modifications following credential dumping or lateral movement
- [ ] Review Event ID 4719 with both success and failure auditing disabled
- [ ] Monitor registry: HKLM\System\CurrentControlSet\Control\Lsa\AuditBaseObjects set to 0