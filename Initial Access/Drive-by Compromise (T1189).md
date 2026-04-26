# Drive-by Compromise: [T1189](https://attack.mitre.org/techniques/T1189/)

## Detection Explanation

Drive-by Compromise involves adversaries gaining access to systems through users visiting malicious or compromised websites. This technique enables attackers to exploit browser vulnerabilities, browser plugin weaknesses, or social engineering to execute code on victim systems without requiring intentional user action beyond browsing to a webpage. Drive-by compromise is commonly used during the initial access phase and represents a significant threat because it requires minimal user interaction and can affect many users visiting popular compromised websites.

Attackers use drive-by compromise because it provides broad access to potential victims through legitimate websites, exploits trust users place in familiar sites, leverages vulnerabilities in ubiquitous software (browsers, Flash, Java, PDF readers), and can deliver malware silently without user awareness. Common methods include exploit kits (like RIG, Magnitude, or Neutrino) that test for multiple vulnerabilities, watering hole attacks targeting specific user populations, malvertising campaigns serving exploits through legitimate ad networks, and compromised legitimate websites injected with malicious JavaScript or iframes redirecting to exploit servers.

Successful drive-by compromise grants adversaries initial code execution on victim systems, often with the privileges of the browser process, enabling them to download and execute malware, establish command and control, escalate privileges, and begin reconnaissance. This technique is particularly dangerous because it targets users during normal web browsing activity, requires no user action beyond visiting a page, can affect many victims through single compromised sites, and leverages legitimate sites users trust. The impact includes widespread malware distribution, targeted attacks on specific organizations (watering holes), credential theft, ransomware deployment, and establishment of persistent access across many systems.

Detection requires monitoring for browser exploitation indicators, tracking downloads and execution from browser processes, identifying suspicious JavaScript execution patterns, detecting exploit kit communication patterns, and correlating web activity with subsequent malicious behavior. Organizations should monitor browser crash patterns indicating exploitation attempts, track unusual child processes spawned from browsers, analyze network traffic for exploit kit indicators, and alert on browser-initiated downloads followed by immediate execution.

---

## Key Detection Indicators & Areas to Investigate

### Summary of Indicators

1. Browser process crashes and abnormal terminations
2. Suspicious child processes spawned from browsers
3. Browser downloads immediately followed by execution
4. Exploit kit network traffic patterns and indicators
5. JavaScript obfuscation and suspicious script execution
6. Browser plugin crashes (Flash, Java, PDF readers)
7. Malicious iframe injection and redirection chains
8. Heap spray and shellcode patterns in browser memory
9. Browser-initiated file writes to suspicious locations
10. Exploit mitigation triggers (DEP, ASLR, EMET violations)

---

### 1. Browser Process Crashes and Abnormal Terminations

**Windows Event Logs (Application):**

- Event ID 1000 (Application Error) - Browser crashes
- Event ID 1001 (Windows Error Reporting) - Crash reports
- Key fields: `Faulting application`, `Exception code`, `Faulting module`

**Windows Event Logs (System):**

- Event ID 1001 (BugCheck) - System crashes from browser exploitation

**Sysmon:**

- Event ID 1 (Process creation) - Browser restart after crash
- Event ID 5 (Process terminated) - Browser abnormal termination
- Event ID 10 (ProcessAccess) - Memory access preceding crashes

**Browser Crash Indicators:**

- Chrome: `chrome.exe` crash dumps in `%LOCALAPPDATA%\Google\Chrome\User Data\Crashpad\`
- Firefox: `firefox.exe` crash reports in `%APPDATA%\Mozilla\Firefox\Crash Reports\`
- Edge: `msedge.exe` crashes
- Internet Explorer: `iexplore.exe` crashes

**Exception Codes:**

- `0xc0000005` - Access violation (common in exploitation)
- `0xc0000409` - Stack buffer overrun detected
- `0xc000001d` - Illegal instruction
- `0xc0000374` - Heap corruption

**Focus on:**

- Repeated browser crashes in short timeframe
- Crashes with specific exception codes indicating exploitation
- Browser crashes followed immediately by new process creation
- Crash patterns across multiple systems (widespread exploitation)
- Crashes correlating with visits to specific URLs

**Suspicious indicators:**

- Event ID 1000 showing browser crashes with exception code `0xc0000005` (access violation)
- Multiple browser crashes within 5-10 minute window from same user or system
- Crashes in browser components: `ntdll.dll`, `kernel32.dll`, rendering engines
- Browser crash immediately followed by `cmd.exe`, `powershell.exe`, or unknown executable creation
- Faulting module showing browser plugin DLLs: Flash, Java, PDF reader plugins
- Crash patterns affecting multiple users visiting same website or domain
- Event ID 1001 Windows Error Reporting for browsers with exploitation signatures
- Browser process termination (Event ID 5) followed immediately by suspicious process creation
- Crash dump files created in `%LOCALAPPDATA%` or `%TEMP%` showing exploit artifacts
- Exception addresses pointing to heap spray regions or ROP gadgets

---

### 2. Suspicious Child Processes Spawned from Browsers

**Sysmon:**

- Event ID 1 (Process creation) - Processes spawned from browsers
- Key fields: `ParentImage`, `Image`, `CommandLine`, `IntegrityLevel`

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Process creation with browser parent
- Key fields: `ParentProcessName`, `NewProcessName`, `ProcessCommandLine`

**Browser Processes:**

- Chrome: `chrome.exe`
- Firefox: `firefox.exe`
- Edge: `msedge.exe`
- Internet Explorer: `iexplore.exe`
- Safari: `safari.exe`

**Legitimate vs. Suspicious Child Processes:**

- Legitimate: Helper processes, updaters, specific utilities
- Suspicious: Shells, scripting engines, system utilities

**Focus on:**

- Browsers spawning command shells or scripting engines
- System utilities launched from browser processes
- Executables from temporary or user directories
- Multiple suspicious processes in sequence
- Command-line parameters indicating malicious activity

**Suspicious indicators:**

- `chrome.exe`, `firefox.exe`, or `msedge.exe` spawning `cmd.exe`, `powershell.exe`, `wscript.exe`
- Browsers launching system utilities: `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `certutil.exe`
- Parent process `iexplore.exe` with child processes from `%TEMP%` or `%APPDATA%`
- Command lines showing encoded commands: `powershell.exe -enc`, `cmd.exe /c <base64>`
- Browsers spawning `net.exe`, `whoami.exe`, `ipconfig.exe` (reconnaissance)
- Multiple suspicious child processes in sequence: browser → cmd → powershell → malware
- Processes spawned with different integrity levels (privilege escalation indicators)
- Browser launching executables from `%TEMP%\Low\` or browser cache directories
- Immediate execution of recently downloaded files without user interaction
- Browser processes spawning LOLBins (Living Off the Land Binaries)

---

### 3. Browser Downloads Immediately Followed by Execution

**Sysmon:**

- Event ID 11 (File created) - Downloaded files
- Event ID 1 (Process creation) - File execution
- Event ID 15 (File stream created) - Zone.Identifier (Mark of the Web)

**Windows Event Logs (Security):**

- Event ID 4663 (Access attempted to object) - File creation in downloads
- Event ID 4688 (Process creation) - Downloaded file execution

**Browser Download Locations:**

- Chrome: `%USERPROFILE%\Downloads\`, `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache\`
- Firefox: `%USERPROFILE%\Downloads\`, `%LOCALAPPDATA%\Mozilla\Firefox\Profiles\*\cache2\`
- Edge: `%USERPROFILE%\Downloads\`, `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache\`

**Correlation Pattern:**

- File creation (Event ID 11) → Immediate execution (Event ID 1) within seconds/minutes
- Browser process network activity → File download → Execution without user interaction

**Focus on:**

- Downloaded files executed within minutes of creation
- Executables downloaded to temporary or cache directories
- Automatic execution without user save/open dialog
- Missing or manipulated Zone.Identifier streams
- Downloads followed by process chains indicating compromise

**Suspicious indicators:**

- File created (Event ID 11) in Downloads or cache directory followed within 30 seconds by Event ID 1 execution
- Executables downloaded to `%TEMP%`, browser cache, or `%APPDATA%` with immediate execution
- Missing Zone.Identifier alternate data stream (Mark of the Web bypass)
- Zone.Identifier showing `ZoneId=2` (trusted sites) for suspicious downloads
- File downloads with suspicious names: random characters, system-like names, double extensions
- Downloads immediately executed without user "Open" action (automatic exploitation)
- Browser network connection to suspicious IP → File download → Execution chain
- Multiple files downloaded and executed sequentially (staged payload delivery)
- Downloaded files with no digital signature or invalid signatures executing immediately
- Parent process showing browser spawning downloaded executable directly

---

### 4. Exploit Kit Network Traffic Patterns and Indicators

**Network Logs:**

- Proxy logs - Exploit kit landing pages and redirections
- DNS logs - Exploit kit domain resolution patterns
- Firewall logs - Connections to exploit kit infrastructure
- IDS/IPS - Exploit kit signatures and patterns

**Sysmon:**

- Event ID 3 (Network connection) - Browser connections to exploit kit domains
- Event ID 22 (DNS query) - DNS queries for exploit kit domains

**Exploit Kit Indicators:**

- Gate/landing page patterns
- Multiple HTTP redirections
- Obfuscated JavaScript/Flash/Java content
- Specific URL patterns and file extensions
- Payload delivery mechanisms

**Common Exploit Kits:**

- RIG Exploit Kit
- Magnitude Exploit Kit
- Fallout Exploit Kit
- GrandSoft Exploit Kit
- Purple Fox Exploit Kit

**Focus on:**

- Redirection chains leading to exploit delivery
- HTTP responses with heavily obfuscated content
- Connections to known exploit kit infrastructure
- URL patterns matching exploit kit signatures
- Flash, Java, or PDF file requests with suspicious parameters

**Suspicious indicators:**

- Multiple HTTP 302 redirects in sequence: legitimate site → compromised site → exploit kit gate
- URLs with random-looking parameters: `?id=MTIzNDU2Nzg=`, `?key=a3f7d9e2`
- HTTP responses containing heavily obfuscated JavaScript (multiple encoding layers)
- Connections to recently registered domains or domains with poor reputation
- URL patterns matching exploit kits: `/gate.php`, `/landing.php`, `/main.php`, `/keitaro/`
- HTTP requests for Flash files (`.swf`) from suspicious domains
- Java applet downloads from untrusted sources
- PDF file requests with exploit kit fingerprinting parameters
- Network traffic to IP addresses hosting multiple exploit kit domains
- User-agent based filtering (exploit kits serve different content based on UA)

---

### 5. JavaScript Obfuscation and Suspicious Script Execution

**Browser Developer Tools:**

- Console errors from malicious scripts
- Network activity showing script loads
- JavaScript debugger showing obfuscation

**Network Traffic Analysis:**

- HTTP responses containing heavily obfuscated JavaScript
- Script content with multiple encoding layers
- Eval chains and dynamic code execution

**Sysmon:**

- Event ID 3 (Network connection) - JavaScript file downloads
- Event ID 22 (DNS query) - Script source domain resolution

**Obfuscation Techniques:**

- Multiple encoding layers (base64, hex, unicode escape)
- Variable name randomization
- String concatenation and manipulation
- Eval chains: `eval(unescape(...))`
- Document.write with encoded content
- Array-based obfuscation

**JavaScript Patterns:**

- Heap spray techniques
- ROP chain preparation
- Shellcode embedding
- Exploit triggering code
- Anti-debugging techniques

**Focus on:**

- Scripts with excessive obfuscation
- JavaScript downloading or executing additional code
- Heap spray patterns in scripts
- Browser plugin exploitation attempts
- Fingerprinting and profiling scripts

**Suspicious indicators:**

- JavaScript with multiple nested `eval()` calls
- Scripts using `unescape()`, `String.fromCharCode()` extensively
- Long base64 or hex-encoded strings in JavaScript
- Array initialization with large blocks of NOP sleds or shellcode patterns
- Scripts detecting browser version, plugins, and OS (fingerprinting)
- Obfuscated variable names: `var _0x1a2b3c`, single-character variables
- Dynamic iframe creation pointing to external domains
- JavaScript redirecting to different sites based on system configuration
- XOR or other custom encoding/decoding routines in scripts
- Scripts with anti-debugging or VM detection code

---

### 6. Browser Plugin Crashes (Flash, Java, PDF Readers)

**Windows Event Logs (Application):**

- Event ID 1000 (Application Error) - Plugin crashes
- Event ID 1001 (Windows Error Reporting) - Plugin crash reports
- Key fields: `Faulting application`, `Faulting module`

**Sysmon:**

- Event ID 1 (Process creation) - Plugin process creation
- Event ID 5 (Process terminated) - Plugin abnormal termination

**Browser Plugin Processes:**

- Flash: `FlashPlayerPlugin*.exe`, `plugin-container.exe` (Firefox)
- Java: `jp2launcher.exe`, `javaw.exe`, `java.exe`
- PDF: `AcroRd32.exe`, `RdrCEF.exe` (Acrobat Reader)

**Common Plugin Vulnerabilities:**

- Flash: Use-after-free, type confusion, integer overflow
- Java: Deserialization, sandbox escape, arbitrary code execution
- PDF: JavaScript execution, buffer overflow, object confusion

**Focus on:**

- Plugin crashes with exploitation indicators
- Repeated plugin crashes from specific websites
- Plugin crashes followed by malicious activity
- Exception codes indicating memory corruption
- Plugin processes spawning suspicious child processes

**Suspicious indicators:**

- Flash Player crashes with exception code `0xc0000005` (access violation)
- Java plugin crashes immediately after visiting specific websites
- PDF reader crashes when opening files from browser
- Multiple plugin crashes in short timeframe across different users
- Plugin crash followed by browser spawning `cmd.exe` or `powershell.exe`
- Faulting module showing plugin DLLs with known vulnerabilities
- Plugin processes spawning unexpected child processes after crash
- Crash dump analysis showing heap spray, ROP chains, or shellcode
- Plugin crashes correlating with connections to known exploit kit infrastructure
- Repeated crashes of same plugin component across multiple systems

---

### 7. Malicious Iframe Injection and Redirection Chains

**Network Traffic Analysis:**

- Proxy logs - HTTP responses with injected iframes
- Content inspection - Iframe tags in unexpected pages
- DNS logs - Iframe source domain resolution

**Sysmon:**

- Event ID 3 (Network connection) - Connections to iframe sources
- Event ID 22 (DNS query) - DNS resolution for redirect domains

**Web Server Logs (if monitoring compromised sites):**

- Unexpected iframe tags in page content
- Modified page sizes or checksums
- Unauthorized file modifications

**Iframe Injection Patterns:**

- Hidden iframes: `width="0" height="0"` or `style="display:none"`
- Iframes with suspicious source URLs
- Multiple redirect layers
- Dynamically created iframes via JavaScript

**Redirection Chain Indicators:**

- HTTP 302 redirects in sequence
- Meta refresh tags
- JavaScript-based redirects
- Multiple domain hops

**Focus on:**

- Legitimate sites serving injected iframes
- Iframe sources pointing to suspicious domains
- Hidden or zero-pixel iframes
- Redirection chains to exploit kit infrastructure
- Dynamic iframe creation via obfuscated JavaScript

**Suspicious indicators:**

- Trusted websites returning content with `<iframe>` tags not in original design
- Iframe tags with `width="0"` or `height="0"` attributes (hidden from users)
- Iframe sources pointing to recently registered domains or suspicious TLDs
- Multiple HTTP redirects: trusted site → compromised site → exploit kit gate → exploit delivery
- JavaScript dynamically creating iframes: `document.createElement('iframe')`
- Iframe sources with obfuscated or encoded URLs
- Meta refresh tags redirecting to external domains: `<meta http-equiv="refresh" content="0;url=...">`
- Redirection chains with random-looking domain names
- DNS queries showing progression through multiple domains in seconds
- Network connections to iframe sources immediately causing browser crashes or suspicious activity

---

### 8. Heap Spray and Shellcode Patterns in Browser Memory

**Endpoint Detection and Response (EDR):**

- Memory scanning for heap spray patterns
- Shellcode detection in browser process memory
- NOP sled identification
- ROP chain detection

**Windows Event Logs (Application):**

- Event ID 1000 with memory addresses in heap spray regions

**Memory Analysis Indicators:**

- Large repeated memory allocations
- NOP sleds (0x90 repeated)
- Shellcode signatures
- ROP gadget chains
- Executable memory in unexpected regions

**Heap Spray Techniques:**

- JavaScript heap spraying
- Flash Vector heap spraying
- Java array heap spraying
- Typed array allocation patterns

**Shellcode Characteristics:**

- Position-independent code (PIC)
- API resolution via PEB walking
- Egg hunters
- Encoded or obfuscated shellcode

**Focus on:**

- Browser memory containing spray patterns
- Executable memory regions with shellcode
- Memory allocations preceding exploitation
- ROP chains in browser memory
- Post-exploitation shellcode execution

**Suspicious indicators:**

- Browser memory containing large blocks of repeated patterns (NOP sleds: 0x90909090)
- Heap spray patterns: repeated addresses like 0x0c0c0c0c, 0x20202020
- Memory regions with PAGE_EXECUTE_READWRITE permissions in browser processes
- Shellcode signatures detected in browser memory: GetProcAddress resolution, PEB walking
- ROP gadget chains in memory preceding exploitation
- Memory allocations of specific sizes commonly used in heap sprays (several MB)
- JavaScript or Flash allocating large arrays or strings
- Memory containing egg hunters or shellcode stubs
- Executable code in heap regions not backed by legitimate modules
- Post-exploitation: browser memory containing Metasploit, Cobalt Strike, or custom shellcode patterns

---

### 9. Browser-Initiated File Writes to Suspicious Locations

**Sysmon:**

- Event ID 11 (File created) - Files created by browser processes
- Key fields: `Image`, `TargetFilename`, `User`

**Windows Event Logs (Security):**

- Event ID 4663 (Access attempted to object) - File writes by browsers
- Event ID 4656 (Handle to object requested) - File handles from browsers

**Suspicious File Locations:**

- `%TEMP%` - Temporary directory
- `%APPDATA%\Local\Temp\` - Local temporary app data
- `%LOCALAPPDATA%\Temp\` - Local temporary data
- Startup folders - Persistence locations
- System directories - Privilege escalation attempts

**File Types:**

- Executables: `.exe`, `.dll`, `.scr`
- Scripts: `.ps1`, `.vbs`, `.js`, `.bat`
- Archives: `.zip`, `.rar`, `.7z` (containing malware)
- Office documents with macros
- Shortcut files: `.lnk` (for persistence)

**Focus on:**

- Browser processes writing executables to disk
- Files written to startup or persistence locations
- Multiple files written in sequence (staged delivery)
- Files written to system directories
- File writes followed immediately by execution

**Suspicious indicators:**

- Browser processes creating `.exe`, `.dll`, or `.scr` files in `%TEMP%` or `%APPDATA%`
- Files written to startup folders: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\`
- Browser writing files to system directories: `C:\Windows\`, `C:\Windows\System32\`
- Multiple files created sequentially: dropper → payload → configuration
- File creation in browser cache directories that are executables rather than typical cache files
- Files written with system-like names: `svchost.exe`, `explorer.exe`, `update.exe`
- Browser creating `.lnk` (shortcut) files in startup locations
- Files written to scheduled task directories: `C:\Windows\System32\Tasks\`
- File writes to `%APPDATA%\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`
- Browser writing files then immediately another process (not browser) accessing them

---

### 10. Exploit Mitigation Triggers (DEP, ASLR, EMET Violations)

**Windows Event Logs (Application):**

- Event ID 1000 (Application Error) - Crashes from mitigation triggers
- Event ID 1001 (Windows Error Reporting) - Exploitation attempt reports

**Windows Event Logs (Security):**

- Event ID 1116 (Windows Defender Exploit Guard) - Exploit protection triggers

**EMET (Enhanced Mitigation Experience Toolkit) Logs:**

- EMET mitigation events - If EMET installed
- Specific mitigation violations

**Windows Defender Exploit Guard:**

- Exploit protection audit/block events
- Attack Surface Reduction (ASR) triggers

**Mitigation Types:**

- DEP (Data Execution Prevention) - NX bit violations
- ASLR (Address Space Layout Randomization) - Address prediction attempts
- CFG (Control Flow Guard) - Control flow violations
- Stack cookies / GS - Stack buffer overflow detection
- SEHOP (SEH Overwrite Protection) - Exception handler protection

**Exception Codes:**

- `0xc0000005` - Access violation (DEP violation)
- `0xc0000409` - Stack buffer overrun (stack cookie/GS)
- `0xc0000374` - Heap corruption detected
- `0xc000001d` - Illegal instruction

**Focus on:**

- Browser crashes from mitigation triggers
- Repeated exploitation attempts blocked by mitigations
- Mitigation bypasses indicating sophisticated exploits
- Correlation with network activity to exploit kits
- Multiple systems showing same mitigation triggers

**Suspicious indicators:**

- Browser crashes with DEP violations: exception code `0xc0000005` with execution attempted in non-executable memory
- Windows Defender Exploit Guard blocking browser exploitation attempts
- Event ID 1116 showing exploit protection triggers for browser processes
- Stack canary violations: exception code `0xc0000409` in browser or plugin processes
- CFG (Control Flow Guard) violations in browsers with this mitigation enabled
- EMET logs showing mitigation triggers: EAF, EAF+, BottomUpASLR, NullPage
- Multiple exploitation attempts blocked within short timeframe
- Mitigation triggers correlating with visits to specific websites
- ROP chain detection by exploit mitigations
- Heap corruption detected: exception code `0xc0000374` in browser processes
- ---
# Drive-by Compromise Investigation Checklist

## 1. Browser Process Crashes

- [ ] Review Event ID 1000 for browser crashes with exception code 0xc0000005 (access violation)
- [ ] Check multiple browser crashes within 5-10 minute window from same user/system
- [ ] Monitor crashes in ntdll.dll, kernel32.dll, rendering engines
- [ ] Identify browser crash followed by cmd.exe, powershell.exe creation
- [ ] Look for faulting modules: Flash, Java, PDF reader plugins
- [ ] Check crash patterns affecting multiple users visiting same website
- [ ] Review browser process termination (Event ID 5) followed by suspicious processes
- [ ] Monitor exception addresses pointing to heap spray regions or ROP gadgets

## 2. Suspicious Browser Child Processes

- [ ] Check chrome.exe, firefox.exe, msedge.exe spawning cmd.exe, powershell.exe, wscript.exe
- [ ] Review browsers launching: mshta.exe, rundll32.exe, regsvr32.exe, certutil.exe
- [ ] Monitor Parent iexplore.exe with children from %TEMP% or %APPDATA%
- [ ] Identify encoded commands: powershell.exe -enc, cmd.exe /c <base64>
- [ ] Look for browsers spawning net.exe, whoami.exe, ipconfig.exe
- [ ] Check multiple suspicious children in sequence: browser → cmd → powershell → malware
- [ ] Review browser spawning executables from %TEMP%\Low\ or cache directories
- [ ] Monitor immediate execution of downloaded files without user interaction

## 3. Browser Downloads to Execution

- [ ] Timeline: File creation (Event ID 11) → Execution (Event ID 1) within 30 seconds
- [ ] Check executables downloaded to %TEMP%, browser cache, %APPDATA% with immediate execution
- [ ] Review missing Zone.Identifier alternate data stream (MotW bypass)
- [ ] Monitor Zone.Identifier with ZoneId=2 (trusted sites) for suspicious downloads
- [ ] Identify downloads with suspicious names: random characters, double extensions
- [ ] Look for downloads executed without user "Open" action
- [ ] Check browser network connection → Download → Execution chain
- [ ] Review multiple files downloaded and executed sequentially

## 4. Exploit Kit Network Traffic

- [ ] Check multiple HTTP 302 redirects: legitimate site → compromised site → exploit kit
- [ ] Review URLs with random parameters: ?id=MTIzNDU2Nzg=, ?key=a3f7d9e2
- [ ] Monitor HTTP responses with heavily obfuscated JavaScript (multiple encoding layers)
- [ ] Identify connections to recently registered domains or poor reputation domains
- [ ] Look for URL patterns: /gate.php, /landing.php, /main.php, /keitaro/
- [ ] Check HTTP requests for Flash files (.swf) from suspicious domains
- [ ] Review PDF requests with exploit kit fingerprinting parameters
- [ ] Monitor user-agent based filtering (different content per UA)

## 5. JavaScript Obfuscation

- [ ] Review JavaScript with multiple nested eval() calls
- [ ] Check scripts using unescape(), String.fromCharCode() extensively
- [ ] Monitor long base64 or hex-encoded strings in JavaScript
- [ ] Identify array initialization with NOP sleds or shellcode patterns
- [ ] Look for scripts detecting browser version, plugins, OS (fingerprinting)
- [ ] Check obfuscated variable names: var _0x1a2b3c, single-character variables
- [ ] Review dynamic iframe creation pointing to external domains
- [ ] Monitor scripts with anti-debugging or VM detection code

## 6. Browser Plugin Crashes

- [ ] Check Flash Player crashes with exception code 0xc0000005
- [ ] Review Java plugin crashes after visiting specific websites
- [ ] Monitor PDF reader crashes when opening files from browser
- [ ] Identify multiple plugin crashes in short timeframe across users
- [ ] Look for plugin crash followed by browser spawning cmd.exe/powershell.exe
- [ ] Check faulting module showing plugin DLLs with known vulnerabilities
- [ ] Review plugin processes spawning unexpected child processes
- [ ] Monitor repeated crashes of same plugin component across systems

## 7. Malicious Iframe Injection

- [ ] Check trusted websites returning content with unexpected <iframe> tags
- [ ] Review iframe tags with width="0" or height="0" (hidden)
- [ ] Monitor iframe sources pointing to recently registered domains
- [ ] Identify multiple HTTP redirects: trusted → compromised → exploit kit → exploit
- [ ] Look for JavaScript dynamically creating iframes: document.createElement('iframe')
- [ ] Check iframe sources with obfuscated or encoded URLs
- [ ] Review meta refresh tags: <meta http-equiv="refresh" content="0;url=...">
- [ ] Monitor DNS queries showing progression through multiple domains in seconds

## 8. Heap Spray and Shellcode Patterns

- [ ] Review browser memory with large blocks of repeated patterns (NOP sleds: 0x90909090)
- [ ] Check heap spray patterns: repeated addresses like 0x0c0c0c0c, 0x20202020
- [ ] Monitor memory regions with PAGE_EXECUTE_READWRITE permissions in browsers
- [ ] Identify shellcode signatures: GetProcAddress resolution, PEB walking
- [ ] Look for ROP gadget chains in memory preceding exploitation
- [ ] Check JavaScript or Flash allocating large arrays or strings
- [ ] Review memory containing egg hunters or shellcode stubs
- [ ] Monitor browser memory with Metasploit, Cobalt Strike, or custom shellcode

## 9. Browser File Writes to Suspicious Locations

- [ ] Check browser processes creating .exe, .dll, .scr in %TEMP% or %APPDATA%
- [ ] Review files written to startup: %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\
- [ ] Monitor browser writing to system directories: C:\Windows, C:\Windows\System32\
- [ ] Identify multiple files created sequentially: dropper → payload → configuration
- [ ] Look for executables in browser cache vs. typical cache files
- [ ] Check files with system-like names: svchost.exe, explorer.exe, update.exe
- [ ] Review browser creating .lnk files in startup locations
- [ ] Monitor browser writing files then other processes immediately accessing them

## 10. Exploit Mitigation Triggers

- [ ] Review browser crashes with DEP violations: exception 0xc0000005 in non-executable memory
- [ ] Check Windows Defender Exploit Guard blocking browser exploitation
- [ ] Monitor Event ID 1116 showing exploit protection triggers for browsers
- [ ] Identify stack canary violations: exception 0xc0000409 in browser/plugin processes
- [ ] Look for CFG (Control Flow Guard) violations in browsers
- [ ] Check EMET logs: EAF, EAF+, BottomUpASLR, NullPage mitigation triggers
- [ ] Review multiple exploitation attempts blocked within short timeframe
- [ ] Monitor mitigation triggers correlating with visits to specific websites