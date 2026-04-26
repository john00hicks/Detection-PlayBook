# Boot or Logon Autostart Execution: [T1547](https://attack.mitre.org/techniques/T1547/)

## Detection Explanation

Adversaries may configure system settings to automatically execute a program during system boot or user logon to maintain persistence. This technique encompasses various autostart execution mechanisms including registry run keys, startup folders, authentication packages, BITS jobs, kernel modules, port monitors, security support providers, shortcut modifications, and other Windows mechanisms that enable automatic execution.

## Key Detection Indicators & Areas to Investigate

### Registry Run Keys and Startup Keys (T1547.001)

**Registry locations to monitor:**

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`

**Windows Event Logs:**

- Event ID 4657 (Registry value modification) - Run key modifications
- Event ID 13 (Sysmon - Registry value set) - New or modified autostart entries

**Sysmon:**

- Event ID 12 (Registry object added/deleted)
- Event ID 13 (Registry value set)
- Event ID 14 (Registry object renamed)

**Suspicious indicators:**

- Executables in unusual locations: `%TEMP%`, `%APPDATA%`, user profile directories
- Commands using `cmd.exe`, `powershell.exe`, `mshta.exe`, `regsvr32.exe`
- Encoded or obfuscated commands
- Executables without digital signatures
- Recently created executables referenced in Run keys

**Service Creation and Modification:**

- Event ID 7045 (Service installed)
- Event ID 4697 (Service installed)
- Registry: `HKLM\System\CurrentControlSet\Services`
- Services with unusual binaries, paths, or start types
### Scheduled Tasks and Jobs

**Windows Event Logs:**

- Event ID 4698 (Scheduled task created)
- Event ID 4702 (Scheduled task updated)
- Event ID 4699 (Scheduled task deleted)
- Event ID 106 (Task Scheduler - Task registered)
- Event ID 200 (Task Scheduler - Task executed)
- Event ID 201 (Task Scheduler - Task completed)

**Sysmon:**

- Event ID 1 (Process creation) - `schtasks.exe` or `taskeng.exe` execution

**Task Scheduler logs:**

- `Microsoft-Windows-TaskScheduler/Operational`

**Suspicious indicators:**

- Tasks created by non-administrative users
- Tasks with SYSTEM or high privilege execution
- Tasks running from unusual locations: `%TEMP%`, `%APPDATA%`
- Tasks with suspicious triggers (every minute, on logon)
- Tasks executing PowerShell, scripts, or unsigned executables
- Hidden tasks (not visible in Task Scheduler GUI)

**Task XML analysis:**

- Review task definitions in `C:\Windows\System32\Tasks\`
- Check for encoded commands in task actions
- Verify task authors and creation dates

---

### Startup Folder Modifications (T1547.001)

**Startup folder locations:**

- `C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
- `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
- `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
- `%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Startup`

**Sysmon:**

- Event ID 11 (File creation) - New files in startup folders
- Event ID 2 (File creation time changed) - Timestamp modification of startup files

**Windows Event Logs:**

- Event ID 4663 (Object access) - File writes to startup folders

**Suspicious files:**

- `.exe`, `.bat`, `.cmd`, `.vbs`, `.js`, `.lnk` files
- Scripts or executables from unknown/untrusted sources
- Files with misleading names or icons
- Hidden or system-attributed files

--- 
### Authentication Package (T1547.002)

**Registry locations:**

- `HKLM\System\CurrentControlSet\Control\Lsa\Authentication Packages`
- `HKLM\System\CurrentControlSet\Control\Lsa\Notification Packages`
- `HKLM\System\CurrentControlSet\Control\Lsa\Security Packages`

**Sysmon:**

- Event ID 13 (Registry value set) - Modifications to LSA authentication packages

**Windows Event Logs:**

- Event ID 4657 (Registry value modification) - LSA registry changes
- Event ID 4614 (Notification package loaded) - Authentication package loaded by LSA

**DLL locations:**

- `%SystemRoot%\System32\` - Where authentication packages should reside
- Unusual DLL names or locations referenced

**Indicators:**

- New or modified authentication packages
- DLLs loaded by `lsass.exe` from non-standard locations
- Unsigned or recently compiled DLLs

---

### Winlogon Helper DLL (T1547.004)

**Registry locations:**

- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\TaskMan`

**Sysmon:**

- Event ID 13 (Registry value set) - Winlogon registry modifications

**Windows Event Logs:**

- Event ID 4657 (Registry value modification) - Winlogon key changes

**Legitimate values:**

- `Userinit`: typically `C:\Windows\system32\userinit.exe`
- `Shell`: typically `explorer.exe`

**Suspicious indicators:**

- Multiple comma-separated executables in values
- Non-standard paths or executable names
- Additional programs appended to legitimate entries
- Modifications to these keys outside of system updates

---

### Security Support Provider (T1547.005)

**Registry locations:**

- `HKLM\System\CurrentControlSet\Control\Lsa\Security Packages`
- `HKLM\System\CurrentControlSet\Control\Lsa\OSConfig\Security Packages`

**Sysmon:**

- Event ID 13 (Registry value set) - Security package modifications
- Event ID 7 (Image loaded) - DLLs loaded by `lsass.exe`

**Windows Event Logs:**

- Event ID 4657 (Registry value modification) - Security package registry changes

**Known legitimate SSPs:**

- `msv1_0.dll`, `kerberos.dll`, `schannel.dll`, `wdigest.dll`

**Suspicious indicators:**

- Unknown DLLs added to Security Packages
- Custom SSP DLLs (often used for credential theft)
- SSPs loaded from non-system directories

---

### Kernel Modules and Extensions (T1547.006)

**Windows Driver Loading:**

- Event ID 6 (Sysmon - Driver loaded)
- Event ID 7045 (Windows - Service installed) for driver services

**Registry locations:**

- `HKLM\System\CurrentControlSet\Services` - Driver and service entries

**Suspicious indicators:**

- Unsigned or self-signed drivers
- Drivers loaded from non-standard locations
- Recently created driver files
- Drivers with no company information or suspicious metadata
- Rootkit-associated driver names

**Boot driver verification:**

- Check `%SystemRoot%\System32\drivers\` directory for unknown drivers
- Review driver signing status
- Analyze driver load order

---

### Port Monitors (T1547.010)

**Registry locations:**

- `HKLM\System\CurrentControlSet\Control\Print\Monitors`

**Sysmon:**

- Event ID 13 (Registry value set) - New port monitor entries
- Event ID 7 (Image loaded) - DLLs loaded by `spoolsv.exe` (Print Spooler)

**Windows Event Logs:**

- Event ID 4657 (Registry value modification) - Print monitor registry changes

**DLL locations:**

- `%SystemRoot%\System32\` - Standard location for port monitor DLLs

**Suspicious indicators:**

- New port monitors with unusual names
- DLLs loaded by Print Spooler from non-standard locations
- Unsigned or recently created monitor DLLs
- Port monitors added outside of printer installation

---

### Print Processors (T1547.012)

**Registry locations:**

- `HKLM\System\CurrentControlSet\Control\Print\Environments\[Environment]\Print Processors`

**Sysmon:**

- Event ID 13 (Registry value set) - Print processor modifications
- Event ID 7 (Image loaded) - DLLs loaded by `spoolsv.exe`

**Windows Event Logs:**

- Event ID 4657 (Registry value modification) - Print processor registry changes

**Indicators:**

- Non-standard print processors
- Print processor DLLs outside `%SystemRoot%\System32\spool\prtprocs\`
- Unsigned print processor DLLs

---

### Shortcut Modification (T1547.009)

**Locations to monitor:**

- Desktop: `C:\Users\[Username]\Desktop\`
- Start Menu: `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\`
- Quick Launch: `C:\Users\[Username]\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\`
- Taskbar pins and recent items

**Sysmon:**

- Event ID 11 (File creation) - `.lnk` file creation or modification
- Event ID 2 (File creation time changed) - LNK timestamp manipulation

**Shortcut analysis:**

- Target path pointing to malicious executables
- Arguments containing suspicious commands or scripts
- Working directory in unusual locations
- Icon location discrepancies
- Hidden or system attributes on shortcuts

**Forensic artifacts:**

- LNK file metadata analysis
- Recent file lists: `%APPDATA%\Microsoft\Windows\Recent\`
- Jump lists: `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\`

---

### Time Providers (T1547.003)

**Registry locations:**

- `HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders`

**Sysmon:**

- Event ID 13 (Registry value set) - Time provider modifications
- Event ID 7 (Image loaded) - DLLs loaded by time service

**Windows Event Logs:**

- Event ID 4657 (Registry value modification) - Time provider registry changes

**Indicators:**

- Unknown time provider DLLs
- DLLs loaded by `w32time` service from non-standard locations
- Recently added time providers

---

### BITS Jobs (Background Intelligent Transfer Service)

**Windows Event Logs:**

- Event ID 59 (BITS - Job created)
- Event ID 60 (BITS - Job started)
- Event ID 61 (BITS - Job stopped)
- Event ID 64 (BITS - Job canceled)

**BITS PowerShell cmdlets for hunting:**

- `Get-BitsTransfer` - List active BITS jobs
- Review job owners, file locations, and download sources

**Suspicious indicators:**

- BITS jobs downloading executables or scripts
- Jobs with unusual source URLs
- Persistent BITS jobs (survive reboots)
- BITS jobs created by suspicious processes
- Jobs downloading to writable system directories

**Sysmon:**

- Event ID 1 (Process creation) - `bitsadmin.exe` usage
- Event ID 3 (Network connection) - BITS service network activity

---

### Active Setup (T1547.014)

**Registry locations:**

- `HKLM\Software\Microsoft\Active Setup\Installed Components`
- `HKCU\Software\Microsoft\Active Setup\Installed Components`

**Sysmon:**

- Event ID 13 (Registry value set) - Active Setup modifications

**Windows Event Logs:**

- Event ID 4657 (Registry value modification) - Active Setup registry changes

**Key values:**

- `StubPath` - Command executed on user logon

**Suspicious indicators:**

- New Active Setup entries
- StubPath containing scripts, encoded commands, or unusual executables
- Executables in non-standard locations

---

### AppInit DLLs (T1547.008)

**Registry locations:**

- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`
- `HKLM\Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`
- `HKLM\System\CurrentControlSet\Control\Session Manager\AppCertDlls`

**Sysmon:**

- Event ID 13 (Registry value set) - AppInit DLL modifications
- Event ID 7 (Image loaded) - DLLs loaded into all processes

**Windows Event Logs:**

- Event ID 4657 (Registry value modification) - AppInit DLL registry changes

**Indicators:**

- New DLLs added to AppInit_DLLs
- Unsigned or malicious DLLs
- DLLs from non-system directories
- AppCertDlls entries (often abused for persistence)

---

### Screensaver Hijacking (T1547.002)

**Registry locations:**

- `HKCU\Control Panel\Desktop\SCRNSAVE.EXE`
- `HKCU\Control Panel\Desktop\ScreenSaveActive`
- `HKCU\Control Panel\Desktop\ScreenSaverIsSecure`
- `HKCU\Control Panel\Desktop\ScreenSaveTimeOut`

**Sysmon:**

- Event ID 13 (Registry value set) - Screensaver modifications

**Windows Event Logs:**

- Event ID 4657 (Registry value modification) - Screensaver registry changes

**Suspicious indicators:**

- Screensaver pointing to non-.scr executables
- Screensaver files in unusual locations
- Recent screensaver changes not initiated by user
- Executables masquerading as .scr files

---

### Boot/Logon Script Execution

**Group Policy Script Locations:**

- `%SystemRoot%\System32\GroupPolicy\Machine\Scripts\Startup\`
- `%SystemRoot%\System32\GroupPolicy\Machine\Scripts\Shutdown\`
- `%SystemRoot%\System32\GroupPolicy\User\Scripts\Logon\`
- `%SystemRoot%\System32\GroupPolicy\User\Scripts\Logoff\`

**Registry locations:**

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logoff`

**Windows Event Logs:**

- Event ID 4688 (Process creation) - Script execution at logon/boot
- Event ID 4104 (PowerShell script block logging) - Script content

**Sysmon:**

- Event ID 1 (Process creation) - Scripts executed during boot/logon

**Suspicious indicators:**

- New logon scripts not deployed via Group Policy
- Scripts in user-writable locations
- Obfuscated or encoded scripts
- Scripts downloading or executing additional payloads

---

## Additional Investigation Areas

**WMI Event Subscriptions:**

- `ROOT\subscription` namespace queries
- Event consumers, filters, and bindings
- Sysmon Event ID 19, 20, 21 (WMI event monitoring)

**COM Object Hijacking:**

- Registry: `HKLM\Software\Classes\CLSID`
- Registry: `HKCU\Software\Classes\CLSID`
- Modifications to COM object registrations

**Browser Extensions:**

- Extension installation in Chrome, Firefox, Edge
- Browser policy modifications
- Extension directories monitoring

**Office Add-ins:**

- Registry: Office add-in locations
- VBA macros with AutoOpen/AutoExec
- Office template modifications

**Correlation Opportunities:**

- Autostart creation → Network beaconing at boot/logon
- Registry modification → Process execution at next boot
- File creation in startup → User logon → Malicious process execution
- Privilege escalation → Persistence mechanism installation → Credential access

**Baseline Establishment:**

- Catalog all legitimate autostart entries
- Track changes to baseline over time
- Alert on deviations from known-good state
- Regular audits of persistence mechanisms
# Boot or Logon Autostart Execution Investigation Checklist

## 1. Registry Run Keys

- [ ]  Check Sysmon Event ID 13 for modifications to HKLM/HKCU...\CurrentVersion\Run, RunOnce
- [ ]  Review Event ID 4657 for registry value modifications to Run keys
- [ ]  Search for executables in unusual locations: %TEMP%, %APPDATA%, user profile directories
- [ ]  Identify commands using cmd.exe, powershell.exe, mshta.exe, regsvr32.exe in Run keys
- [ ]  Verify digital signatures on executables referenced in Run keys
- [ ]  Check for encoded or obfuscated commands in registry values

## 2. Scheduled Tasks

- [ ]  Review Event ID 4698/4702 for scheduled task creation and updates
- [ ]  Check Event ID 106/200/201 in Microsoft-Windows-TaskScheduler/Operational log
- [ ]  Identify tasks created by non-administrative users
- [ ]  Search for tasks running from %TEMP%, %APPDATA% locations
- [ ]  Look for tasks with suspicious triggers (every minute, on logon)
- [ ]  Review task XML files in C:\Windows\System32\Tasks\ for encoded commands
- [ ]  Check for hidden tasks not visible in Task Scheduler GUI

## 3. Startup Folder Files

- [ ]  Review Sysmon Event ID 11 for files in %APPDATA%...\Startup\ and C:\ProgramData...\StartUp\
- [ ]  Check Event ID 4663 for file writes to startup folders
- [ ]  Identify suspicious file types: .exe, .bat, .cmd, .vbs, .js, .lnk
- [ ]  Look for files with misleading names or icons
- [ ]  Verify files aren't hidden or have system attributes set

## 4. Services

- [ ]  Review Event ID 7045/4697 for new service installations
- [ ]  Check HKLM\System\CurrentControlSet\Services registry for unusual entries
- [ ]  Identify services with binaries in non-standard locations
- [ ]  Look for services with suspicious names or start types (AUTO_START)
- [ ]  Verify service binary digital signatures

## 5. Authentication and Security Packages

- [ ]  Check Sysmon Event ID 13 for HKLM\System\CurrentControlSet\Control\Lsa\ modifications
- [ ]  Review Authentication Packages, Notification Packages, Security Packages registry keys
- [ ]  Verify Event ID 4614 for notification packages loaded by LSA
- [ ]  Look for DLLs loaded by lsass.exe from non-standard locations
- [ ]  Check for unsigned or recently compiled authentication package DLLs

## 6. Winlogon Helper DLL

- [ ]  Monitor Sysmon Event ID 13 for HKLM...\Winlogon registry modifications
- [ ]  Check Userinit (should be C:\Windows\system32\userinit.exe)
- [ ]  Review Shell value (should be explorer.exe)
- [ ]  Identify multiple comma-separated executables in Winlogon values
- [ ]  Look for additional programs appended to legitimate entries

## 7. Kernel Modules and Drivers

- [ ]  Review Sysmon Event ID 6 for driver loads
- [ ]  Check Event ID 7045 for driver service installations
- [ ]  Verify HKLM\System\CurrentControlSet\Services for unknown driver entries
- [ ]  Identify unsigned or self-signed drivers
- [ ]  Look for drivers loaded from non-standard locations or with suspicious metadata

## 8. Print Services Abuse

- [ ]  Check Sysmon Event ID 13 for HKLM\System\CurrentControlSet\Control\Print\ modifications
- [ ]  Review Monitors and Print Processors registry keys
- [ ]  Monitor Sysmon Event ID 7 for DLLs loaded by spoolsv.exe from unusual locations
- [ ]  Identify unsigned or recently created monitor/processor DLLs

## 9. Shortcut Modification

- [ ]  Review Sysmon Event ID 11 for .lnk file creation on Desktop, Start Menu, Quick Launch
- [ ]  Check Sysmon Event ID 2 for LNK timestamp manipulation
- [ ]  Analyze LNK files for target paths pointing to malicious executables
- [ ]  Look for arguments containing suspicious commands or scripts
- [ ]  Review %APPDATA%\Microsoft\Windows\Recent\ for recent LNK files

## 10. BITS Jobs

- [ ]  Review Event ID 59/60/61/64 for BITS job creation, start, stop, cancel
- [ ]  Use Get-BitsTransfer PowerShell cmdlet to list active BITS jobs
- [ ]  Identify BITS jobs downloading executables or scripts
- [ ]  Check for persistent BITS jobs that survive reboots
- [ ]  Look for jobs with unusual source URLs or downloading to system directories

## 11. Active Setup and AppInit DLLs

- [ ]  Check Sysmon Event ID 13 for HKLM\Software\Microsoft\Active Setup\Installed Components
- [ ]  Review StubPath values for scripts, encoded commands, or unusual executables
- [ ]  Monitor HKLM...\Windows\AppInit_DLLs and AppCertDlls registry modifications
- [ ]  Identify unsigned DLLs or DLLs from non-system directories
- [ ]  Review Sysmon Event ID 7 for DLLs loaded into all processes

## 12. WMI Event Subscriptions

- [ ]  Query ROOT\subscription namespace for event consumers, filters, and bindings
- [ ]  Review Sysmon Event ID 19/20/21 for WMI event monitoring
- [ ]  Identify suspicious WMI event consumers with malicious payloads
- [ ]  Check for WMI persistence mechanisms outside of legitimate management tools

## 13. Additional Persistence Mechanisms

- [ ]  Check HKCU\Control Panel\Desktop\SCRNSAVE.EXE for screensaver hijacking
- [ ]  Review Group Policy script locations: %SystemRoot%\System32\GroupPolicy...\Scripts\
- [ ]  Monitor HKLM/HKCU\Software\Classes\CLSID for COM object hijacking
- [ ]  Check browser extension installations and policy modifications
- [ ]  Review Office add-in registry locations and VBA macros with AutoOpen/AutoExec

## 14. Timeline Correlation

- [ ]  Correlate autostart creation with network beaconing at boot/logon
- [ ]  Timeline: Registry modification → Next boot/logon → Process execution
- [ ]  Check for privilege escalation followed by persistence installation
- [ ]  Identify baseline deviations and changes to known-good autostart state