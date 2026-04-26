# Masquerading: [T1036](https://attack.mitre.org/techniques/T1036/)

## Detection Explanation

Masquerading involves adversaries manipulating file names, locations, process names, metadata, or digital signatures to make malicious artifacts appear legitimate. This technique enables attackers to evade detection by blending malicious files and processes with expected system activity, bypassing security controls that rely on name-based detection, and confusing analysts during incident response. Masquerading is commonly used throughout the attack lifecycle for defense evasion and persistence.

Attackers use masquerading because security tools and analysts often rely on file names, process names, and digital signatures to determine legitimacy. By mimicking legitimate system files (T1036.005), using invalid or fake code signatures (T1036.001), renaming malicious files to match system processes, placing files in expected system directories, or manipulating metadata, adversaries can evade automated detection and create doubt during manual analysis. Common methods include naming malware as system processes like `svchost.exe` or `explorer.exe`, placing files in `C:\Windows\System32\` or similar trusted locations, and using stolen or fake digital certificates.

Successful masquerading allows adversaries to execute malicious code while appearing as legitimate system processes, persist on systems by mimicking expected files and services, evade signature-based detection through filename variations, confuse incident responders investigating suspicious activity, and bypass application whitelisting controls that rely on file names or locations. The impact includes undetected malware execution, persistent access masquerading as system services, delayed incident response due to confusion with legitimate processes, and compromised forensic analysis when malicious files blend with system files.

Detection requires monitoring for file and process anomalies such as mismatched names and locations, validating digital signatures, tracking file metadata inconsistencies, identifying unusual parent-child process relationships, and correlating masquerading indicators with other suspicious activities. Organizations should baseline legitimate system file locations and names, implement strict code signing verification, and alert on anomalies such as system process names executing from user directories, invalid signatures on executables, or metadata mismatches.

---

## Key Detection Indicators & Areas to Investigate

### Summary of Indicators

1. System process names executing from non-system locations (T1036.005)
2. Invalid or mismatched digital signatures (T1036.001)
3. Misspelled system process names (T1036.005)
4. Wrong file extensions for executables
5. Metadata mismatches (original filename vs actual name)
6. Right-to-left override (RTLO) character obfuscation
7. Executables in user-writable directories mimicking system files
8. Space padding or special characters in filenames
9. Process masquerading with unusual parent relationships
10. Trusted directory masquerading

---

### 1. System Process Names Executing from Non-System Locations

**Sysmon:**

- Event ID 1 (Process creation) - Process execution with location analysis
- Key fields: `Image`, `OriginalFileName`, `CommandLine`, `CurrentDirectory`

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Process creation with path information
- Key fields: `NewProcessName`, `ProcessCommandLine`

**Common System Process Names Abused:**

- `svchost.exe` - Should only run from `C:\Windows\System32\`
- `explorer.exe` - Should run from `C:\Windows\`
- `lsass.exe` - Should only run from `C:\Windows\System32\`
- `csrss.exe` - Should only run from `C:\Windows\System32\`
- `winlogon.exe` - Should only run from `C:\Windows\System32\`
- `services.exe` - Should only run from `C:\Windows\System32\`
- `taskmgr.exe` - Should run from `C:\Windows\System32\`
- `rundll32.exe` - Should run from `C:\Windows\System32\`

**Legitimate Locations:**

- `C:\Windows\System32\` - Primary system binaries
- `C:\Windows\SysWOW64\` - 32-bit binaries on 64-bit systems
- `C:\Windows\` - Core Windows processes (explorer.exe)

**Focus on:**

- System process names running from user directories
- Critical system processes from temporary locations
- Multiple instances of single-instance processes
- System process names in non-standard paths
- Processes masquerading as security tools

**Suspicious indicators:**

- `svchost.exe` running from `%TEMP%`, `%APPDATA%`, `C:\Users\`, `C:\ProgramData\`
- `explorer.exe` executing from anywhere except `C:\Windows\`
- `lsass.exe` or `csrss.exe` from any location other than `C:\Windows\System32\`
- `winlogon.exe` running from user-writable directories
- System process names with full path in non-system locations: `C:\Users\Public\svchost.exe`
- Multiple instances of `csrss.exe` or `lsass.exe` (should be single instance per session)
- Process names like `chrome.exe`, `firefox.exe` from `%TEMP%` or suspicious directories
- `taskmgr.exe` or `notepad.exe` launching from downloads or temp folders
- Security tool names (`MsMpEng.exe`, `avp.exe`) from non-installation directories
- Critical processes with .exe extension running from directories without .exe files typically

---

### 2. Invalid or Mismatched Digital Signatures

**Sysmon:**

- Event ID 1 (Process creation) - Process signature validation
- Event ID 7 (Image loaded) - DLL signature validation
- Key fields: `Signed`, `Signature`, `SignatureStatus`

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Can correlate with signature checks
- Event ID 6416 (New external device) - Device driver signatures

**PowerShell Logs:**

- Event ID 4104 (Script block logging) - Script signature validation
- Unsigned or invalidly signed scripts executing

**Signature Status Values:**

- `Valid` - Properly signed and trusted
- `Invalid` - Signature present but verification failed
- `Expired` - Certificate expired
- `Revoked` - Certificate revoked
- `Untrusted` - Certificate chain not trusted
- No signature field - Unsigned

**Tools for Signature Validation:**

- `sigcheck.exe` (Sysinternals) - Command-line signature verification
- PowerShell: `Get-AuthenticodeSignature`
- Windows API: `WinVerifyTrust`

**Focus on:**

- Executables with invalid signatures masquerading as signed software
- Expired certificates on recently created files
- Self-signed certificates on system-like process names
- Signature mismatches (signer name doesn't match expected vendor)
- Unsigned executables with system process names

**Suspicious indicators:**

- Event ID 1 showing `Signed=false` for processes named like system files: `svchost.exe`, `explorer.exe`
- SignatureStatus showing `Invalid` or `Expired` on executables pretending to be Microsoft software
- Files named `chrome.exe`, `firefox.exe` without valid Google/Mozilla signatures
- `Signature` field showing unexpected companies for well-known software names
- System process names (`rundll32.exe`, `cmd.exe`) unsigned running from user directories
- Security tool names (`MsMpEng.exe`, `CylanceSvc.exe`) with invalid or no signatures
- Recently created files with expired certificates (timestamp before file creation)
- Self-signed certificates on files masquerading as commercial software
- Signature field populated but SignatureStatus shows verification failure
- Code signing certificates issued to individuals or suspicious organizations for system process names

---

### 3. Misspelled System Process Names

**Sysmon:**

- Event ID 1 (Process creation) - Process name analysis
- Event ID 11 (File created) - File creation with name analysis
- Key fields: `Image`, `TargetFilename`

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Process creation with typosquatting
- Event ID 4663 (Object access) - File access with similar names

**Common Typosquatting Patterns:**

- Character substitution: `svch0st.exe` (zero for 'o'), `exp1orer.exe` (one for 'l')
- Character addition: `svchostt.exe`, `exploreer.exe`
- Character omission: `svhost.exe`, `explrer.exe`
- Character transposition: `scvhost.exe`, `expolrer.exe`
- Similar character substitution: `svcnost.exe` (n for h), `exp|orer.exe` (pipe for l)
- Case variation: `Svchost.exe`, `EXPLORER.EXE` (unusual casing)

**Common Misspellings:**

- `svchost.exe` → `svch0st.exe`, `scvhost.exe`, `svchosl.exe`, `svchostt.exe`
- `explorer.exe` → `exp1orer.exe`, `explorar.exe`, `iexplorer.exe`
- `lsass.exe` → `1sass.exe`, `isass.exe`, `lssas.exe`, `lsaas.exe`
- `csrss.exe` → `cssrs.exe`, `csrs.exe`, `csrss32.exe`
- `winlogon.exe` → `winlog0n.exe`, `winlogin.exe`, `logonwin.exe`
- `taskmgr.exe` → `taskmang.exe`, `taskmagr.exe`, `taskmrg.exe`

**Focus on:**

- Processes with names similar to system processes
- Character substitutions using visually similar characters
- Deliberate misspellings intended to deceive
- Mixed case or unusual casing patterns
- Process names with extra characters

**Suspicious indicators:**

- Process names with zero (`0`) substituted for letter 'o': `svch0st.exe`, `micr0soft.exe`
- Number '1' or pipe '|' substituted for letter 'l': `exp1orer.exe`, `exp|orer.exe`
- Common system names with extra characters: `svchostt.exe`, `exploreer.exe`
- Transposed characters: `scvhost.exe` instead of `svchost.exe`
- Similar characters: `rn` for `m`, `vv` for `w`: `svchosf.exe`, `vvinlogon.exe`
- Unicode lookalike characters: Cyrillic or Greek characters resembling Latin
- Unexpected casing: `SvcHost.exe`, `SVCHOST.exe` from user directories
- Double extensions attempting concealment: `document.pdf.exe` appearing as `doc.pdf`
- Extra spaces in names: `svchost .exe` (space before extension)
- Mixed legitimate and typo: `system32svchost.exe`, `windowsexplorer.exe`

---

### 4. Wrong File Extensions for Executables

**Sysmon:**

- Event ID 1 (Process creation) - Process execution analysis
- Event ID 11 (File created) - File creation with extension mismatches
- Key fields: `Image`, `OriginalFileName`, `TargetFilename`

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Executable extension analysis
- Event ID 4663 (Object access) - File access with extension checks

**Extension Masquerading Patterns:**

- Double extensions: `invoice.pdf.exe`, `report.docx.exe`, `image.jpg.exe`
- Non-executable extensions for executables: `.txt`, `.pdf`, `.doc` hiding PE files
- Unusual executable extensions: `.pif`, `.scr`, `.com` (less common)
- Missing extensions: Executable without `.exe` extension
- Spaces before extensions: `malware .exe`, `payload .scr`

**NTFS Alternate Data Streams (ADS):**

- Executables hidden in ADS: `file.txt:malware.exe`
- Zone.Identifier stream manipulation

**Focus on:**

- Executable files with misleading extensions
- PE files not using standard executable extensions
- Double extension techniques
- Files executed without visible .exe extension
- Hidden executables in alternate data streams

**Suspicious indicators:**

- Files with double extensions executing as processes: `document.pdf.exe`, `invoice.doc.exe`
- Event ID 1 showing Image path ending in `.txt`, `.pdf`, `.jpg` but executing as process
- OriginalFileName showing `.exe` but actual filename using document extension
- `.scr` (screensaver), `.pif`, `.com` files executing from downloads or user directories
- Processes running from files without extensions in user-writable directories
- Executable content detected in files with document extensions (PE header in .txt file)
- Spaces or special characters before extension: `malware .exe`, `payload..exe`
- Files with visual confusion: `document.pdf .exe` (extra space)
- Zone.Identifier alternate data stream missing or manipulated on downloaded executables
- Sysmon Event ID 15 showing executable ADS: `file.txt:hidden.exe:$DATA`

---

### 5. Metadata Mismatches (Original Filename vs Actual Name)

**Sysmon:**

- Event ID 1 (Process creation) - Metadata analysis
- Key fields: `Image`, `OriginalFileName`, `Product`, `Company`, `Description`

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Process metadata correlation

**File Metadata Fields:**

- `OriginalFileName` - Name compiled into executable
- `InternalName` - Internal product name
- `ProductName` - Product description
- `CompanyName` - Company/author
- `FileDescription` - File description
- `FileVersion` - Version number

**Analysis Methods:**

- PowerShell: `(Get-Item file.exe).VersionInfo`
- Sysinternals: `sigcheck.exe -a file.exe`
- PE analysis tools: Check PE resource section

**Focus on:**

- OriginalFileName not matching actual filename
- System process names with non-Microsoft metadata
- Metadata claiming legitimacy on suspicious files
- Generic or missing metadata on renamed system-named files
- Product/Company mismatches with filename

**Suspicious indicators:**

- Process named `svchost.exe` with OriginalFileName showing `malware.exe` or random name
- OriginalFileName field showing `payload.exe` but file renamed to `chrome.exe`
- CompanyName showing non-Microsoft company for files named as Windows system processes
- System process names (`explorer.exe`, `rundll32.exe`) with missing metadata fields
- Generic metadata: ProductName "Application", Company "User", on system-named files
- OriginalFileName showing legitimate name but file renamed to confuse: `chrome.exe` with OriginalFileName `legitimate-tool.exe`
- Metadata showing one product but filename suggesting another: `firefox.exe` with metadata for different browser
- FileDescription claiming "Windows System File" on files from user directories
- Version information showing `0.0.0.0` or missing on files masquerading as established software
- Company field showing individual names or unknown entities for system process names

---

### 6. Right-to-Left Override (RTLO) Character Obfuscation

**Sysmon:**

- Event ID 11 (File created) - File creation with RTLO detection
- Event ID 1 (Process creation) - Process with RTLO in path
- Key fields: `TargetFilename`, `Image` (check for Unicode U+202E)

**Windows Event Logs (Security):**

- Event ID 4663 (Object access) - File access with RTLO names

**RTLO Technique:**

- Unicode character U+202E reverses text display direction
- Makes `malwareEXE.txt` appear as `malwaretxt.EXE`
- Actual filename: `photo[U+202E]gpj.exe`
- Displayed filename: `photoxe.jpg` (reversed from RTLO point)

**Common RTLO Patterns:**

- `document[U+202E]fdp.exe` displays as `documentexe.pdf`
- `invoice[U+202E]cod.scr` displays as `invoicercs.doc`
- `report[U+202E]XE.txt` displays as `reporttxt.EXE`

**Detection Methods:**

- Hex analysis of filenames looking for 0x202E bytes
- Unicode normalization checks
- String analysis for directional override characters
- File listing with raw bytes display

**Focus on:**

- Files with RTLO characters in names
- Executables appearing as documents via RTLO
- Downloads or email attachments using RTLO
- Files in user directories with RTLO obfuscation
- Execution of RTLO-named files

**Suspicious indicators:**

- Filenames containing Unicode character U+202E (right-to-left override)
- Files appearing as `.pdf`, `.doc`, `.jpg` but actually `.exe` after RTLO
- Event ID 11 showing TargetFilename with hex bytes `E2 80 AE` (UTF-8 for U+202E)
- Process execution (Event ID 1) with Image path containing RTLO character
- Email attachments with RTLO in filename attempting to disguise executables
- Downloads from web with RTLO characters making `.exe` appear as documents
- File created events showing reversed extensions after RTLO point
- Security warnings suppressed due to apparent document extension (actually executable)
- Multiple files with RTLO patterns in same directory (campaign indicator)
- RTLO combined with other masquerading techniques (misspelling, wrong location)

---

### 7. Executables in User-Writable Directories Mimicking System Files

**Sysmon:**

- Event ID 1 (Process creation) - Process location analysis
- Event ID 11 (File created) - File creation in suspicious locations
- Key fields: `Image`, `TargetFilename`, `User`

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Process execution locations
- Event ID 4663 (Object access) - File creation and access
- Event ID 4656 (Handle requested) - File handle requests

**User-Writable Directories:**

- `%TEMP%` or `%TMP%` - Temporary directories
- `%APPDATA%` - User application data
- `%LOCALAPPDATA%` - Local application data
- `C:\Users\Public\` - Publicly accessible location
- `C:\ProgramData\` - Program data directory
- `C:\Users\<username>\Downloads\` - Downloads folder
- `C:\Users\<username>\Desktop\` - Desktop folder
- `C:\Perflogs\` - Performance logs (often abused)

**Focus on:**

- System process names in user-writable locations
- Executables in temp directories with system names
- Downloads folder containing system-named executables
- Public or ProgramData containing masquerading files
- Recently created files with system process names

**Suspicious indicators:**

- `svchost.exe`, `explorer.exe`, `lsass.exe` in `%TEMP%`, `%APPDATA%`, or `C:\Users\Public\`
- System process names executing from `C:\ProgramData\` without legitimate installation
- `rundll32.exe`, `cmd.exe`, `powershell.exe` copies in user directories
- Downloads folder containing files named as Windows system processes
- Desktop folder with executables named like system files
- `C:\Perflogs\` containing executables (legitimate use is rare)
- Security tool names in user directories without proper installation paths
- Recently created timestamp (within 24-48 hours) on system-named files in user locations
- Multiple system process names in same suspicious directory
- Execution from temporary directories immediately after download or document opening

---

### 8. Space Padding or Special Characters in Filenames

**Sysmon:**

- Event ID 11 (File created) - File creation with name analysis
- Event ID 1 (Process creation) - Process with unusual naming
- Key fields: `TargetFilename`, `Image` (check for spaces, special characters)

**Windows Event Logs (Security):**

- Event ID 4663 (Object access) - File operations with special names
- Event ID 4688 (Process creation) - Process names with padding

**Space Padding Techniques:**

- Trailing spaces: `malware.exe` (spaces after extension)
- Leading spaces: `svchost.exe` (spaces before name)
- Internal spacing: `svc host.exe` (space within name)
- Multiple spaces: `svchost .exe` (spaces before extension)

**Special Characters:**

- Null bytes: Filename truncation in some tools
- Non-printable characters: ASCII control characters
- Unicode spaces: U+00A0 (non-breaking space), U+2000-U+200B (various spaces)
- Reserved characters in unusual context: `svchost<.exe`, `explorer>.exe`
- Homoglyph characters: Visually similar but different Unicode

**Detection Challenges:**

- Some tools truncate or normalize display
- Console vs. GUI display differences
- Explorer hiding known extensions

**Focus on:**

- Filenames with excessive whitespace
- Non-printable or unusual Unicode characters
- Files attempting to evade simple string matching
- Executables with visually confusing names
- Name variations exploiting display differences

**Suspicious indicators:**

- File or process names with trailing spaces: `malware.exe` (spaces not visible in Explorer)
- Leading spaces in filenames making them sort differently or hide in listings
- Multiple consecutive spaces: `svchost .exe`, `explorer .exe`
- Unicode non-breaking spaces (U+00A0) instead of regular spaces
- Files with null bytes or control characters in names (hex analysis required)
- Executables with tab characters: `svchost\t.exe` (tab before extension)
- Mixed visible and zero-width Unicode characters
- Filenames exploiting case sensitivity issues: `SvcHost.exe` vs `svchost.exe`
- Special characters making files difficult to delete or analyze: `svchost?.exe`
- Homoglyph substitutions: Cyrillic 'о' (U+043E) for Latin 'o', Greek 'ο' (U+03BF)

---

### 9. Process Masquerading with Unusual Parent Relationships

**Sysmon:**

- Event ID 1 (Process creation) - Parent-child relationships
- Key fields: `Image`, `ParentImage`, `ParentCommandLine`, `IntegrityLevel`

**Windows Event Logs (Security):**

- Event ID 4688 (Process creation) - Process hierarchy
- Key fields: `NewProcessName`, `ParentProcessName`

**Expected Parent-Child Relationships:**

- `services.exe` → `svchost.exe` (legitimate service hosts)
- `explorer.exe` → User applications (desktop apps)
- `winlogon.exe` → `userinit.exe` → `explorer.exe` (logon sequence)
- `svchost.exe` → Service processes (depending on service)
- `wininit.exe` → `services.exe`, `lsass.exe` (system initialization)

**Suspicious Parent-Child Patterns:**

- System processes spawned from user applications
- Multiple instances of single-instance processes
- Wrong parent for critical processes
- Orphaned processes with no parent
- Process injection masquerading indicators

**Focus on:**

- System processes with unexpected parents
- Critical processes spawned from Office apps, browsers
- Multiple instances of unique system processes
- Parent process termination but child continues (orphaned)
- Privilege level mismatches between parent and child

**Suspicious indicators:**

- `svchost.exe` with parent other than `services.exe` (indicates masquerading or injection)
- `lsass.exe` with parent other than `wininit.exe` (malicious process)
- `csrss.exe` spawned after system boot or from non-`smss.exe` parent
- System process names spawned from `winword.exe`, `excel.exe`, `outlook.exe`
- `explorer.exe` with parent other than `userinit.exe` (session 0) or another `explorer.exe`
- Multiple instances of `csrss.exe` or `lsass.exe` (should be one per session/boot)
- `winlogon.exe` spawned during runtime rather than at boot
- System processes with SYSTEM privileges spawned from user-level parents
- ParentImage showing `<unknown>` or terminated process for critical system processes
- Process chains: `winword.exe` → `svchost.exe` → `cmd.exe` (masquerading + execution)

---

### 10. Trusted Directory Masquerading

**Sysmon:**

- Event ID 11 (File created) - Files created in system directories
- Event ID 1 (Process creation) - Execution from system-like paths
- Key fields: `TargetFilename`, `Image`

**Windows Event Logs (Security):**

- Event ID 4663 (Object access) - File creation in protected directories
- Event ID 4656 (Handle requested) - Write access to system directories

**Trusted Directory Patterns:**

- `C:\Windows\System32\` - Primary system directory
- `C:\Windows\SysWOW64\` - 32-bit compatibility on 64-bit
- `C:\Program Files\` - Application installations
- `C:\Program Files (x86)\` - 32-bit applications on 64-bit

**Masquerading Directory Techniques:**

- Similar names: `C:\Windows\System32s\`, `C:\Windows\System33\`
- Extra directories: `C:\Windows\System32\Config\`, `C:\Windows\System32\Tasks\` (writable)
- Lowercase variations: `C:\windows\system32\`
- Spaces: `C:\Windows \System32\`, `C:\Windows\System32 \`
- Alternate paths: `C:\Windows.old\System32\` (Windows upgrade remnant)

**Writable Subdirectories:**

- `C:\Windows\Tasks\` - Task files (user-writable)
- `C:\Windows\System32\Tasks\` - Scheduled tasks
- `C:\Windows\System32\spool\` - Print spooler
- `C:\Windows\Temp\` - Temporary files

**Focus on:**

- Executables in directory names resembling system paths
- Files in writable subdirectories of system directories
- Directory name variations exploiting typos
- Executables claiming to be in System32 but actually elsewhere
- New files created in typically read-only system directories

**Suspicious indicators:**

- Executables in `C:\Windows\System33\`, `C:\Windows\Sys32\`, or similar typos
- Files in `C:\Windows\System32\Tasks\` that are executables (not task definitions)
- Process execution from `C:\Windows\` subdirectories not typically containing executables
- Newly created executables in `C:\Windows\Fonts\`, `C:\Windows\Help\`, or other unusual subdirs
- Files in `C:\Program Files\Common Files\` without associated installed application
- `C:\Windows.old\System32\` containing recently created executables (post-upgrade hiding)
- Lowercase or mixed-case system paths: `c:\windows\system32\`, `C:\WINDOWS\System32\`
- Executables in `C:\Windows\System32\spool\drivers\` without printer driver context
- Files in `C:\Windows\Debug\`, `C:\Windows\Registration\` (rarely contain executables)
- Event ID 11 showing file creation in protected system directories by non-system processes
---
# Masquerading [T1036] Investigation Checklist

## 1. System Processes from Wrong Locations

- [ ] Search Event ID 4688/Sysmon Event ID 1 for `svchost.exe`, `lsass.exe`, `csrss.exe` outside `C:\Windows\System32\`
- [ ] Check for `explorer.exe` running from anywhere except `C:\Windows\`
- [ ] Review `winlogon.exe`, `services.exe`, `taskmgr.exe` in `%TEMP%`, `%APPDATA%`, `C:\Users\`, `C:\ProgramData\`
- [ ] Identify multiple instances of single-instance processes (`csrss.exe`, `lsass.exe`)
- [ ] Look for security tool names (`MsMpEng.exe`, `avp.exe`) from non-installation directories

## 2. Invalid Digital Signatures

- [ ] Filter Sysmon Event ID 1 for `Signed=false` on system-named processes
- [ ] Check SignatureStatus for `Invalid`, `Expired`, `Revoked`, `Untrusted` values
- [ ] Review signature mismatches (non-Microsoft Company on Windows process names)
- [ ] Identify unsigned executables named `chrome.exe`, `firefox.exe` without vendor signatures
- [ ] Verify recently created files with expired certificates (timestamp before creation date)

## 3. Typosquatting & Misspelled Names

- [ ] Search for character substitutions: `svch0st.exe`, `exp1orer.exe`, `1sass.exe`, `cssrs.exe`
- [ ] Check for extra characters: `svchostt.exe`, `exploreer.exe`, `lsaas.exe`
- [ ] Identify transposed characters: `scvhost.exe`, `expolrer.exe`, `lssas.exe`
- [ ] Look for similar character swaps: `exp|orer.exe`, `svcnost.exe`, `winlog0n.exe`
- [ ] Review unusual casing patterns: `SvcHost.exe`, `EXPLORER.EXE` from user directories

## 4. Wrong File Extensions

- [ ] Search Sysmon Event ID 1/11 for double extensions: `invoice.pdf.exe`, `report.docx.exe`
- [ ] Check for executables using `.scr`, `.pif`, `.com` from downloads/user directories
- [ ] Identify Image paths ending in document extensions (`.txt`, `.pdf`, `.jpg`) but executing
- [ ] Review OriginalFileName vs actual filename extension mismatches
- [ ] Look for spaces before extensions: `malware .exe`, `payload..exe`

## 5. Metadata Anomalies

- [ ] Compare OriginalFileName to actual filename in Sysmon Event ID 1
- [ ] Check CompanyName field for non-Microsoft values on system process names
- [ ] Identify missing or generic metadata: ProductName "Application", FileVersion `0.0.0.0`
- [ ] Review FileDescription claiming "Windows System File" on user directory executables
- [ ] Verify Product/Company mismatches with expected vendors

## 6. RTLO & Special Character Obfuscation

- [ ] Search Sysmon Event ID 11 filenames for Unicode U+202E (hex bytes `E2 80 AE`)
- [ ] Check for executables appearing as documents via RTLO reversal
- [ ] Review downloads/email attachments with RTLO characters in names
- [ ] Identify trailing/leading spaces in process names: `svchost .exe`, `explorer.exe`
- [ ] Look for homoglyph substitutions: Cyrillic 'о' (U+043E) for Latin 'o'

## 7. User-Writable Directory Execution

- [ ] Check Event ID 4688/Sysmon Event ID 1 for system names in `%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%`
- [ ] Review executables in `C:\Users\Public\`, `C:\Users\<username>\Downloads\`, `C:\ProgramData\`
- [ ] Identify system process names in `C:\Perflogs\` (rarely legitimate)
- [ ] Look for recently created (24-48 hours) system-named files in user locations
- [ ] Check Desktop folder for executables mimicking system files

## 8. Abnormal Parent-Child Relationships

- [ ] Verify `svchost.exe` parent is `services.exe` (not Office apps, browsers)
- [ ] Check `lsass.exe` parent is `wininit.exe` (only one instance at boot)
- [ ] Identify `csrss.exe` spawned after boot or from non-`smss.exe` parent
- [ ] Review system processes spawned from `winword.exe`, `excel.exe`, `outlook.exe`, `chrome.exe`
- [ ] Look for orphaned processes: ParentImage `<unknown>` for critical system processes

## 9. Trusted Directory Masquerading

- [ ] Search for executables in directory typos: `C:\Windows\System33\`, `C:\Windows\Sys32\`
- [ ] Check writable subdirectories: `C:\Windows\Tasks\`, `C:\Windows\System32\Tasks\` for executables
- [ ] Review `C:\Windows\Fonts\`, `C:\Windows\Help\`, `C:\Windows\Debug\` for new executables
- [ ] Identify files in `C:\Windows.old\System32\` with recent creation timestamps
- [ ] Look for lowercase variations: `c:\windows\system32\`, `C:\WINDOWS\System32\`

## 10. Correlation & Timeline Analysis

- [ ] Timeline: File creation → Process execution → Network/credential activity
- [ ] Cross-reference suspicious filenames with threat intelligence (hash lookups)
- [ ] Correlate multiple masquerading techniques on same host (combined indicators)
- [ ] Check for lateral movement using masqueraded executables across systems
- [ ] Review persistence mechanisms (scheduled tasks, services) using masqueraded names