# Input Capture: [T1056](https://attack.mitre.org/techniques/T1056/)

## Detection Explanation

Input Capture involves adversaries using methods to capture user input to obtain credentials, sensitive information, or other data entered by users. This technique enables attackers to intercept keystrokes, GUI input, web portal credentials, and other forms of user interaction with systems and applications. Input capture is commonly used during credential access and collection phases of an attack to steal authentication credentials, capture sensitive data as it's typed, and monitor user activity.

Attackers employ input capture to steal credentials as users type them, bypassing many security controls that protect stored credentials. Common methods include keylogging (T1056.001), GUI input capture (T1056.002), web portal capture (T1056.003), and credential API hooking (T1056.004). Tools range from commercial keyloggers and custom malware to PowerShell scripts and browser-based credential phishing. Hardware keyloggers can also be physically installed on target systems, though software-based keylogging is far more common in enterprise compromises.

Successful input capture provides attackers with plaintext credentials, sensitive communications, confidential data, and other information users type or input into systems. Unlike credential dumping, input capture obtains credentials as they are actively used, often capturing multi-factor authentication codes, password manager master passwords, and credentials for systems not yet accessed by the attacker. The impact includes credential theft enabling further access, data exfiltration of typed communications and documents, privacy violations through monitoring all user input, and the ability to capture authentication to external services and applications.

Detection requires monitoring for keylogging software installation, suspicious API hooking, unauthorized input method editors (IMEs), browser extensions with excessive permissions, and behavioral anomalies in input handling. Organizations should establish baselines for legitimate input capture tools used for accessibility or monitoring purposes and alert on unauthorized installations or suspicious input handling patterns such as hooks on keyboard APIs, processes accessing raw input devices, or clipboard monitoring by unexpected applications.

---

## Key Detection Indicators & Areas to Investigate

### Summary of Indicators

1. Keylogging software installation and execution (T1056.001)
2. API hooking for keystroke interception (T1056.001)
3. Low-level keyboard hooks and event monitoring (T1056.001)
4. Browser extensions with input capture capabilities (T1056.003)
5. PowerShell-based keylogging scripts (T1056.001)
6. Registry modifications for keyboard and input method persistence
7. Clipboard monitoring and capture activity
8. Credential harvesting from web forms (T1056.003)
9. Process memory access to password manager applications (T1056.002)
10. Raw input device access and monitoring

---

### 1. Keylogging Software Installation and Execution

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Keylogger executable creation
- Event ID 4697 (Service installed) - Keylogger service installation
- Event ID 7045 (System log) - Service installation with keylogger characteristics
- Key fields: `NewProcessName`, `ServiceName`, `CommandLine`

**Sysmon:**

- Event ID 1 (Process creation) - Keylogger process execution
- Event ID 6 (Driver loaded) - Keylogger kernel drivers
- Event ID 11 (File created) - Keylog file creation
- Event ID 13 (Registry value set) - Keylogger persistence registry changes

**Windows Event Logs (System):**

- Event ID 7045 (Service installed) - New keylogger services
- Event ID 7036 (Service state change) - Keylogger service starts

**File Paths to Monitor:**

- Common keylogger installation directories: `%PROGRAMFILES%`, `%APPDATA%`, `%TEMP%`
- Keylog output files: `.log`, `.txt`, `.dat` in user directories or hidden folders
- Hidden directories containing keylogger files: `C:\$Recycle.Bin\`, application data folders

**Focus on:**

- Installation of known keylogger applications by name or file hash
- Execution of unsigned or recently created executables with input capture capabilities
- Services or drivers with suspicious names related to keyboard or input monitoring
- File creation patterns indicating log storage of captured keystrokes
- Network connections from keylogger processes (exfiltrating captured data)

**Suspicious indicators:**

- Known keylogger names: `keylogger.exe`, `refog.exe`, `ardamax.exe`, `spyrix.exe`, `kgb.exe`, `revealer.exe`
- Processes with names containing "key", "log", "monitor", "capture", "spy", "input"
- Executables in `%APPDATA%` or `%TEMP%` with keyboard monitoring capabilities
- Services with startup type set to automatic for persistence
- Kernel drivers loaded from non-standard locations: `%APPDATA%\drivers\`, `%TEMP%\`
- File creation of hidden log files: `.log`, `keystrokes.txt`, `capture.dat` in hidden folders
- Processes running with SYSTEM privileges for input capture from all users
- Installation from removable media or downloaded archives without digital signatures
- Registry modifications for service or driver persistence under `HKLM\System\CurrentControlSet\Services\`
- Network connections from keylogger processes to external IPs (exfiltration)

---

### 2. API Hooking for Keystroke Interception

**Sysmon:**

- Event ID 7 (Image loaded) - DLL injection for API hooking
- Event ID 8 (CreateRemoteThread) - Remote thread injection into processes
- Event ID 10 (ProcessAccess) - Process access for hook installation
- Key fields: `TargetImage`, `SourceImage`, `CallTrace`, `GrantedAccess`

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Processes performing API hooking
- Event ID 4656 (Handle to object requested) - Process handle requests for injection

**Endpoint Detection and Response (EDR):**

- API hooking detection for `GetAsyncKeyState`, `GetKeyboardState`, `GetKeyState`
- Hooking of `SetWindowsHookEx` with `WH_KEYBOARD` or `WH_KEYBOARD_LL` parameters
- Inline hooking of user32.dll or kernel32.dll functions

**API Functions Commonly Hooked:**

- `GetAsyncKeyState` - Query key state asynchronously
- `GetKeyboardState` - Retrieve all key states
- `GetKeyState` - Query specific key state
- `SetWindowsHookEx` - Install keyboard hooks
- `GetMessage` / `PeekMessage` - Message queue interception
- `TranslateMessage` - Keyboard message translation

**Focus on:**

- DLL injection into processes handling user input (explorer.exe, browser processes)
- Remote thread creation in system or application processes
- API hooks on keyboard and input-related Windows API functions
- Memory modifications in processes handling input
- CallTrace showing injection through suspicious DLLs

**Suspicious indicators:**

- DLL injection into `explorer.exe`, `winlogon.exe`, or browser processes for input monitoring
- CreateRemoteThread targeting processes with user input handling capabilities
- Hooking of `GetAsyncKeyState`, `GetForegroundWindow`, `GetWindowText` APIs
- `SetWindowsHookEx` with `WH_KEYBOARD_LL` (low-level keyboard hook) from unexpected processes
- CallTrace through unknown or unsigned DLLs in `%TEMP%`, `%APPDATA%`, or user directories
- Memory writes to input-related API function entry points (inline hooks)
- Processes accessing multiple application processes for hook installation
- DLLs loaded from `%TEMP%` or `%APPDATA%` into system processes like `explorer.exe`
- API hooks installed by PowerShell or scripting engines
- Hooks persisting across process restarts or system reboots (persistence mechanism)

---

### 3. Low-Level Keyboard Hooks and Event Monitoring

**Sysmon:**

- Event ID 10 (ProcessAccess) - Process access for hook installation
- Event ID 7 (Image loaded) - user32.dll loading for hook APIs
- Event ID 8 (CreateRemoteThread) - Thread injection for hook installation

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Processes installing keyboard hooks
- Event ID 4656 (Handle to object requested) - Process handle requests

**Endpoint Detection and Response (EDR):**

- Detection of `SetWindowsHookEx` API calls with `WH_KEYBOARD_LL` parameter
- Monitoring for `WH_KEYBOARD` (legacy) and `WH_KEYBOARD_LL` (low-level) hooks
- Detection of global hooks affecting all applications

**Hook Types:**

- `WH_KEYBOARD_LL` (13) - Low-level keyboard hook (most common for keyloggers)
- `WH_KEYBOARD` (2) - Standard keyboard hook (legacy)
- `WH_GETMESSAGE` (3) - Message hook (can intercept keyboard messages)
- `WH_CALLWNDPROC` (4) - Window procedure hook

**API Calls to Monitor:**

- `SetWindowsHookEx(WH_KEYBOARD_LL, ...)` - Install low-level keyboard hook
- `SetWindowsHookEx(WH_KEYBOARD, ...)` - Install standard keyboard hook
- `CallNextHookEx` - Hook chain processing
- `UnhookWindowsHookEx` - Remove hook (cleanup)

**Focus on:**

- Installation of low-level keyboard hooks from unexpected processes
- Global hooks affecting all running applications
- Hook procedures in DLLs from non-standard locations
- Hooks persisting beyond normal application lifecycle
- Multiple keyboard hooks from same suspicious process

**Suspicious indicators:**

- `SetWindowsHookEx` called with `WH_KEYBOARD_LL` from PowerShell or script interpreters
- Keyboard hooks installed by processes in `%TEMP%`, `%APPDATA%`, or user directories
- Global keyboard hooks from unsigned executables or recently created files
- Hooks installed by processes without legitimate input handling requirements (not accessibility tools)
- Hook procedures located in DLLs from user-writable directories
- Multiple keyboard hooks installed simultaneously by single process
- Hooks that persist after parent process termination (orphaned hooks)
- Remote thread creation installing hooks in other processes
- Hooks installed during user logon or system startup for persistence
- Processes without GUI installing keyboard hooks (no visible windows)

---

### 4. Browser Extensions with Input Capture Capabilities

**Windows Event Logs (Security):**

- Event ID 4663 (Access attempted to object) - File access to browser extension directories
- Event ID 4656 (Handle to object requested) - Access to extension manifests

**Sysmon:**

- Event ID 11 (File created) - New browser extension installation
- Event ID 1 (Process creation) - Browser processes loading extensions
- Event ID 3 (Network connection) - Extension communication to external servers
- Event ID 13 (Registry value set) - Extension installation registry changes

**File Paths to Monitor:**

- Chrome extensions: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions\`
- Firefox extensions: `%APPDATA%\Mozilla\Firefox\Profiles\*.default\extensions\`
- Edge extensions: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Extensions\`

**Registry Keys:**

- Chrome policies: `HKLM\Software\Policies\Google\Chrome\ExtensionInstallForcelist`
- Firefox policies: `HKLM\Software\Policies\Mozilla\Firefox\Extensions\Install`

**Extension Manifest Analysis:**

- `manifest.json` permissions requesting excessive access
- Content scripts with wildcard URL patterns
- Background scripts with keyboard event listeners

**Focus on:**

- Installation of extensions requesting excessive permissions
- Extensions with content script injection capabilities
- Side-loaded or developer mode extensions
- Extensions communicating with suspicious external domains
- Extensions with obfuscated JavaScript code

**Suspicious indicators:**

- Extensions requesting permissions: `"tabs"`, `"webRequest"`, `"webRequestBlocking"`, `"<all_urls>"`
- Manifest.json files with content_scripts matching all URLs: `"matches": ["<all_urls>"]` or `"matches": ["http://*/*", "https://*/*"]`
- Extensions loaded in developer mode or unpacked from local directories
- Recently installed extensions from unknown publishers without Chrome Web Store or Firefox Add-on IDs
- Extensions with obfuscated JavaScript code (base64, hex encoding, or minification beyond normal)
- Network connections from browser processes to suspicious domains after extension installation
- Extensions modifying form input fields or intercepting form submissions
- Registry-forced extension installations via Group Policy from non-corporate sources
- Extensions without store IDs (indicating side-loading)
- Background scripts with keyboard event listeners: `addEventListener('keydown')`, `addEventListener('keyup')`, `addEventListener('keypress')`

---

### 5. PowerShell-Based Keylogging Scripts

**PowerShell Logs:**

- Event ID 4104 (Script block logging) - PowerShell keylogging script content
- Event ID 4103 (Module logging) - API calls for input capture
- Event ID 400 (PowerShell engine state) - PowerShell session tracking

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - PowerShell with suspicious parameters
- Event ID 4656 (Handle to object requested) - PowerShell accessing input APIs

**Sysmon:**

- Event ID 1 (Process creation) - PowerShell execution with keylogging indicators
- Event ID 3 (Network connection) - PowerShell exfiltrating captured keystrokes
- Event ID 11 (File created) - PowerShell creating log files for captured input

**Script Content to Monitor:**

- `[Windows.Input.Keyboard]`, `[System.Windows.Forms.Keys]`
- `GetAsyncKeyState`, `GetKeyState`, `GetKeyboardState`
- `Add-Type -MemberDefinition` with user32.dll imports
- `[Windows.Forms.SendKeys]::SendWait`

**API Imports:**

- `[DllImport("user32.dll")]` declarations
- P/Invoke signatures for keyboard APIs
- .NET reflection accessing input methods

**Focus on:**

- PowerShell scripts calling Windows API functions for keyboard state
- Scripts with infinite loops monitoring keyboard input
- PowerShell accessing user32.dll for input capture
- Base64-encoded commands decoding to keylogging functionality
- Scripts writing captured input to files or network

**Suspicious indicators:**

- Script blocks containing `GetAsyncKeyState`, `GetKeyboardState`, user32.dll imports
- PowerShell commands with `Add-Type` defining keyboard input structures or P/Invoke signatures
- Scripts using `System.Windows.Forms.Keys` enumeration for key monitoring
- Infinite loops with `Start-Sleep` and keyboard state checking: `while($true) { ... Start-Sleep -Milliseconds 100 }`
- PowerShell writing captured keystrokes to log files in `%TEMP%`, `%APPDATA%`, or hidden directories
- Base64-encoded commands decoding to keylogger code
- Scripts downloading keylogging modules from external sources: `IEX (New-Object Net.WebClient).DownloadString('http://...')`
- Commands using .NET reflection to access input APIs
- PowerShell hooking keyboard events via Windows Forms
- Script blocks with output to network sockets or HTTP POST requests exfiltrating captured data

---

### 6. Registry Modifications for Keyboard and Input Method Persistence

**Windows Event Logs (Security):**

- Event ID 4657 (Registry value modification) - Registry changes for persistence
- Event ID 4656 (Handle to object requested) - Registry key access

**Sysmon:**

- Event ID 12 (Registry object added/deleted) - New registry entries
- Event ID 13 (Registry value set) - Registry value modifications
- Event ID 14 (Registry object renamed) - Registry key changes

**Registry Keys to Monitor:**

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` - Keylogger autostart
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` - User-level persistence
- `HKLM\System\CurrentControlSet\Control\Keyboard Layout` - Keyboard layout modifications
- `HKCU\Keyboard Layout\Preload` - Input method editor (IME) changes
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\IMM` - IME registration
- `HKLM\System\CurrentControlSet\Services\` - Driver/service persistence

**Command-Line Patterns:**

- `reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v KeyLogger /d "C:\malware.exe"`
- `reg add "HKCU\Keyboard Layout\Preload" /v 1 /d "malicious_ime"`
- PowerShell: `Set-ItemProperty -Path "HKLM:\Software\..." -Name Keylogger -Value "C:\path\to\malware.exe"`

**Focus on:**

- Registry Run key modifications pointing to suspicious executables
- Changes to keyboard layout or IME configurations
- Persistence mechanisms for input capture tools
- Installation of malicious input method editors
- Service registration for keylogging drivers

**Suspicious indicators:**

- Run key entries with executables in `%TEMP%`, `%APPDATA%`, `C:\Users\Public\`, or `C:\ProgramData\`
- Registry values pointing to unsigned or recently created executables with suspicious names
- Keyboard Layout modifications installing custom IME DLLs from non-standard directories
- IME registration pointing to user-writable directories or suspicious DLL paths
- Registry changes from PowerShell or script interpreters rather than legitimate installers
- Scheduled task creation via registry for keylogger execution
- Debugger registry keys for persistence: `Image File Execution Options` with keylogger
- Registry modifications during off-hours or by non-administrative users
- Multiple registry persistence locations modified simultaneously
- Encoded registry values containing keylogger paths or obfuscated commands

---

### 7. Clipboard Monitoring and Capture Activity

**Sysmon:**

- Event ID 7 (Image loaded) - DLLs with clipboard access capabilities
- Event ID 10 (ProcessAccess) - Process access for clipboard monitoring
- Event ID 11 (File created) - Clipboard content written to files

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Processes with clipboard monitoring capabilities
- Event ID 4656 (Handle to object requested) - Clipboard access attempts

**PowerShell Logs:**

- Event ID 4104 (Script block logging) - PowerShell clipboard access scripts

**API Calls to Monitor:**

- `GetClipboardData` - Retrieve clipboard content
- `OpenClipboard` / `CloseClipboard` - Clipboard access
- `SetClipboardViewer` - Register for clipboard notifications
- `AddClipboardFormatListener` - Monitor clipboard changes
- .NET: `System.Windows.Forms.Clipboard.GetText()`, `Clipboard.GetImage()`

**Focus on:**

- Processes continuously monitoring clipboard contents
- Scripts capturing clipboard data at regular intervals
- Clipboard content written to log files or transmitted over network
- Processes installing clipboard format listeners
- Clipboard chains being hijacked or monitored

**Suspicious indicators:**

- PowerShell scripts using `Get-Clipboard` or `[System.Windows.Forms.Clipboard]::GetText()`
- Processes calling `SetClipboardViewer` from unexpected applications (not clipboard managers)
- Infinite loops monitoring clipboard: `while($true) { Get-Clipboard; Start-Sleep -Seconds 5 }`
- Clipboard data written to files in `%TEMP%`, `%APPDATA%`, or hidden directories
- Network connections immediately after clipboard access (exfiltration)
- Processes hooking clipboard chain for continuous monitoring
- Scripts capturing clipboard at regular intervals (every few seconds)
- Clipboard content included in HTTP POST requests to external IPs
- Executables from `%TEMP%` or user directories accessing clipboard APIs repeatedly
- Multiple processes accessing clipboard simultaneously from same parent process

---

### 8. Credential Harvesting from Web Forms

**Network Logs:**

- Proxy logs - HTTP/HTTPS POST requests to suspicious domains
- Web application firewall - Form submissions to non-legitimate endpoints
- DNS logs - Queries to phishing or credential harvesting domains

**Sysmon:**

- Event ID 3 (Network connection) - Browser connections to credential phishing sites
- Event ID 22 (DNS query) - DNS queries for phishing domains

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Browser processes accessing suspicious URLs

**Browser/Web Server Logs:**

- Form submissions with credential field names to unexpected URLs
- JavaScript injection modifying form action attributes
- XHR/Fetch requests exfiltrating form data to external servers

**Focus on:**

- Browser extensions or injected scripts modifying form submission behavior
- Credentials submitted to domains not matching legitimate service URLs
- Man-in-the-browser attacks intercepting form data
- Fake login pages mimicking legitimate services
- Form data exfiltration to attacker-controlled infrastructure

**Suspicious indicators:**

- Form POST requests to IP addresses instead of domain names
- Submissions to domains with typosquatting patterns: `g00gle.com`, `micros0ft.com`, `paypa1.com`
- JavaScript form modifications via browser extensions or injected scripts
- Credentials submitted over HTTP instead of HTTPS
- Form actions modified to point to attacker-controlled domains
- Duplicated form submissions (legitimate site + attacker site)
- Browser extensions with `"webRequest"` permissions intercepting form data
- Network traffic showing credentials sent to multiple destinations
- DNS queries to newly registered domains during login attempts
- Certificate warnings or SSL errors during credential submission

---

### 9. Process Memory Access to Password Manager Applications

**Sysmon:**

- Event ID 10 (ProcessAccess) - Process memory access to password managers
- TargetImage: Password manager executables (`KeePass.exe`, `1Password.exe`, etc.)
- Key fields: `SourceImage`, `GrantedAccess`, `CallTrace`

**Windows Event Logs (Security):**

- Event ID 4656 (Handle to object requested) - Process handle requests
- Event ID 4663 (Access attempted to object) - Process memory access

**Endpoint Detection and Response (EDR):**

- Process memory access telemetry for password manager applications
- API call monitoring for `OpenProcess`, `ReadProcessMemory`

**Password Manager Processes:**

- KeePass: `KeePass.exe`, `KeePassXC.exe`
- 1Password: `1Password.exe`
- LastPass: Browser-based (monitor browser processes)
- Bitwarden: `Bitwarden.exe`, browser extensions
- Dashlane: `Dashlane.exe`

**Focus on:**

- Non-legitimate processes accessing password manager process memory
- Memory read access to processes with unlocked password databases
- Injection attempts into password manager processes
- Memory dumps of password manager applications
- Unusual parent-child relationships involving password managers

**Suspicious indicators:**

- `powershell.exe`, `cmd.exe`, or unknown processes accessing password manager memory
- GrantedAccess values indicating full memory read: `0x1FFFFF`, `0x1010`, `0x1438`, `0x1F0FFF`
- Remote thread creation in password manager processes (Sysmon Event ID 8)
- Memory dumping tools accessing password manager processes: `procdump.exe`, `sqldumper.exe`
- CallTrace through suspicious or unsigned DLLs in `%TEMP%` or user directories
- Access from recently created executables to password manager memory
- Processes requesting `PROCESS_VM_READ` access to KeePass, 1Password, Bitwarden
- Memory access when password database is unlocked (active user session with vault open)
- DLL injection into password manager processes
- Debugger attachment to password manager applications: `PROCESS_ALL_ACCESS` with `DEBUG` privileges

---

### 10. Raw Input Device Access and Monitoring

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Processes accessing raw input
- Event ID 4656 (Handle to object requested) - Device handle requests

**Sysmon:**

- Event ID 1 (Process creation) - Processes with raw input access
- Event ID 13 (Registry value set) - Raw input device registration

**Windows Event Logs (System):**

- Device connection events - New input device installations
- HID device events - Human Interface Device activity

**API Calls to Monitor:**

- `RegisterRawInputDevices` - Register for raw input
- `GetRawInputData` - Retrieve raw input data
- `GetRawInputDeviceInfo` - Query input device information
- Direct device access via `CreateFile` on HID devices

**Device Paths:**

- `\\?\HID#*` - Human Interface Devices
- `\\.\keyboard` - Keyboard device
- Devices under `HKLM\SYSTEM\CurrentControlSet\Enum\HID\`

**Focus on:**

- Processes registering for raw keyboard input
- Direct access to input device handles
- Raw input capture bypassing normal message queue
- Processes accessing multiple input devices
- Unauthorized raw input monitoring

**Suspicious indicators:**

- `RegisterRawInputDevices` called by processes in `%TEMP%`, `%APPDATA%`, or user directories
- Raw input registration for keyboard devices (usage page 0x01, usage 0x06)
- Processes accessing `\\?\HID#*` device paths for keyboards
- Direct device file access: `CreateFile("\\.\keyboard")` from non-system processes
- Multiple input devices registered simultaneously by single suspicious process
- Raw input capture from processes without legitimate UI or input handling
- Device access from PowerShell or script interpreters
- Raw input registration during logon or startup for persistence
- Processes capturing raw input and writing to files or network connections
- Service-level processes accessing raw input devices (unusual for services)
---
# Input Capture Investigation Checklist

## 1. Keylogger Software Detection

- [ ] Check for known keylogger names: keylogger.exe, refog.exe, ardamax.exe, spyrix.exe, kgb.exe
- [ ] Review processes with names containing: "key", "log", "monitor", "capture", "spy", "input"
- [ ] Monitor executables in %APPDATA%, %TEMP% with keyboard monitoring capabilities
- [ ] Identify services with automatic startup for persistence
- [ ] Look for kernel drivers loaded from non-standard locations
- [ ] Check file creation of hidden logs: .log, keystrokes.txt, capture.dat
- [ ] Review processes running with SYSTEM privileges for input capture
- [ ] Monitor network connections from keylogger processes to external IPs

## 2. API Hooking Detection

- [ ] Check DLL injection into explorer.exe, winlogon.exe, or browser processes
- [ ] Review Sysmon Event ID 8 (CreateRemoteThread) targeting input-handling processes
- [ ] Monitor hooking of GetAsyncKeyState, GetForegroundWindow, GetWindowText APIs
- [ ] Identify SetWindowsHookEx with WH_KEYBOARD_LL from unexpected processes
- [ ] Look for CallTrace through unknown/unsigned DLLs in %TEMP%, %APPDATA%
- [ ] Check memory writes to input-related API function entry points
- [ ] Review DLLs loaded from user directories into system processes
- [ ] Monitor API hooks installed by PowerShell or scripting engines

## 3. Low-Level Keyboard Hooks

- [ ] Check SetWindowsHookEx with WH_KEYBOARD_LL from PowerShell/script interpreters
- [ ] Review keyboard hooks from processes in %TEMP%, %APPDATA%, user directories
- [ ] Monitor global keyboard hooks from unsigned executables
- [ ] Identify hooks from processes without legitimate input handling requirements
- [ ] Look for hook procedures in DLLs from user-writable directories
- [ ] Check multiple keyboard hooks installed by single process
- [ ] Review hooks persisting after parent process termination
- [ ] Monitor hooks installed during logon or startup for persistence

## 4. Browser Extension Input Capture

- [ ] Check extensions requesting: "tabs", "webRequest", "webRequestBlocking", "<all_urls>"
- [ ] Review manifest.json with content_scripts matching: ["<all_urls>"] or ["http://_/_", "https://_/_"]
- [ ] Monitor extensions loaded in developer mode or unpacked from local directories
- [ ] Identify recently installed extensions from unknown publishers without store IDs
- [ ] Look for extensions with obfuscated JavaScript (base64, hex encoding)
- [ ] Check network connections to suspicious domains after extension installation
- [ ] Review extensions modifying form input or intercepting form submissions
- [ ] Monitor background scripts with: addEventListener('keydown'), addEventListener('keyup')

## 5. PowerShell Keylogging Scripts

- [ ] Review Event ID 4104 for: GetAsyncKeyState, GetKeyboardState, user32.dll imports
- [ ] Check PowerShell Add-Type defining keyboard input structures or P/Invoke
- [ ] Monitor scripts using System.Windows.Forms.Keys enumeration
- [ ] Identify infinite loops with keyboard checking: while($true) { ... Start-Sleep }
- [ ] Look for PowerShell writing keystrokes to %TEMP%, %APPDATA%, hidden directories
- [ ] Check Base64-encoded commands decoding to keylogger code
- [ ] Review scripts downloading keylogging modules: IEX (New-Object Net.WebClient).DownloadString
- [ ] Monitor PowerShell with HTTP POST requests exfiltrating captured data

## 6. Registry Persistence Modifications

- [ ] Check Run keys with executables in %TEMP%, %APPDATA%, C:\Users\Public\
- [ ] Review registry values pointing to unsigned or recently created executables
- [ ] Monitor Keyboard Layout modifications installing custom IME DLLs
- [ ] Identify IME registration pointing to user-writable directories
- [ ] Look for registry changes from PowerShell/scripts vs. legitimate installers
- [ ] Check Image File Execution Options with keylogger debugger entries
- [ ] Review registry modifications during off-hours or by non-administrative users
- [ ] Monitor multiple registry persistence locations modified simultaneously

## 7. Clipboard Monitoring

- [ ] Check PowerShell using: Get-Clipboard or [System.Windows.Forms.Clipboard]::GetText()
- [ ] Review processes calling SetClipboardViewer from unexpected applications
- [ ] Monitor infinite loops: while($true) { Get-Clipboard; Start-Sleep -Seconds 5 }
- [ ] Identify clipboard data written to files in %TEMP%, %APPDATA%, hidden directories
- [ ] Look for network connections immediately after clipboard access
- [ ] Check processes hooking clipboard chain for continuous monitoring
- [ ] Review clipboard content in HTTP POST to external IPs
- [ ] Monitor executables from %TEMP% accessing clipboard APIs repeatedly

## 8. Web Form Credential Harvesting

- [ ] Check form POST requests to IP addresses instead of domain names
- [ ] Review submissions to typosquatting domains: g00gle.com, micros0ft.com, paypa1.com
- [ ] Monitor JavaScript form modifications via browser extensions/injected scripts
- [ ] Identify credentials submitted over HTTP instead of HTTPS
- [ ] Look for form actions modified to attacker-controlled domains
- [ ] Check duplicated form submissions (legitimate + attacker sites)
- [ ] Review browser extensions with "webRequest" permissions intercepting forms
- [ ] Monitor DNS queries to newly registered domains during login attempts

## 9. Password Manager Memory Access

- [ ] Review Sysmon Event ID 10 for memory access to KeePass.exe, 1Password.exe, Bitwarden.exe
- [ ] Check GrantedAccess: 0x1FFFFF, 0x1010, 0x1438, 0x1F0FFF (full memory read)
- [ ] Monitor powershell.exe, cmd.exe, unknown processes accessing password manager memory
- [ ] Identify Sysmon Event ID 8 (remote thread) in password manager processes
- [ ] Look for memory dumping tools: procdump.exe, sqldumper.exe accessing password managers
- [ ] Check CallTrace through suspicious DLLs in %TEMP% or user directories
- [ ] Review memory access when password database unlocked (active session)
- [ ] Monitor DLL injection or debugger attachment to password managers

## 10. Raw Input Device Access

- [ ] Check RegisterRawInputDevices by processes in %TEMP%, %APPDATA%, user directories
- [ ] Review raw input registration for keyboards (usage page 0x01, usage 0x06)
- [ ] Monitor processes accessing \?\HID#* device paths for keyboards
- [ ] Identify CreateFile("\.\keyboard") from non-system processes
- [ ] Look for multiple input devices registered by single suspicious process
- [ ] Check raw input capture from processes without legitimate UI
- [ ] Review device access from PowerShell or script interpreters
- [ ] Monitor raw input registration during logon/startup for persistence