# Replication Through Removable Media: [T1091](https://attack.mitre.org/techniques/T1091/)

## Detection Explanation

Adversaries may move onto systems by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executed. This technique is commonly used to spread malware in air-gapped or highly secure environments where network-based initial access is restricted.

**Key Detection Indicators:**

- Unusual executable files or scripts written to removable media (USB drives, external HDDs, optical media)
- Autorun.inf files created on removable drives
- Processes spawning from removable media locations
- High volumes of file writes to removable devices
- Suspicious DLL or executable files with names mimicking legitimate system files
- Registry modifications related to AutoRun functionality
- Lateral movement patterns originating from removable media execution

**Detection Strategy:** Focus on monitoring file system activity on removable drives, process execution from external media paths, and registry changes that enable AutoRun. Cross-reference with device connection logs to establish a timeline of removable media insertion and subsequent suspicious activity.
 
## Areas to Investigate

### Unusual executable files or scripts written to removable media

**Windows Event Logs:**

- Event ID 4663 (Object access) - File writes to removable drive letters
- Event ID 6416 (External device recognized) - New device detection

**Sysmon:**

- Event ID 11 (File creation) - Monitor drive letters typically assigned to removable media: `D:\`, `E:\`, `F:\`, `G:\`, `H:\`

**File patterns to monitor:**

- Extensions: `.exe`, `.dll`, `.bat`, `.cmd`, `.vbs`, `.js`, `.ps1`, `.scr`, `.pif`, `.com`
- Hidden files or system files on removable media
- Files with double extensions: `document.pdf.exe`, `photo.jpg.scr`
- Executables with misleading icons (appearing as documents/folders)

**USBStor Registry:**

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` - Track USB device history
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB` - USB device enumeration

---

### Autorun.inf files created on removable drives

**Sysmon:**

- Event ID 11 (File creation) - Specifically monitor for `autorun.inf` file creation on any drive

**Windows Event Logs:**

- Event ID 4663 (Object access) - `autorun.inf` file writes

**File system monitoring:**

- Look for `autorun.inf` in root directory of removable drives
- Check for `desktop.ini` files that can be abused similarly
- Monitor for hidden/system attribute set on autorun files

**Autorun.inf indicators:**

- `[autorun]` section with `open=`, `shellexecute=`, or `action=` directives
- References to executables on the removable media
- Icon files that mask malicious content

---

### Processes spawning from removable media locations

**Windows Event Logs:**

- Event ID 4688 (Process creation) - Processes with working directory on removable drives

**Sysmon:**

- Event ID 1 (Process creation) - Filter for `Image` or `CurrentDirectory` fields pointing to removable drive letters

**Focus on:**

- Executable paths starting with removable drive letters: `D:\malware.exe`, `E:\setup.exe`
- Parent processes launching from removable media
- Command-line parameters indicating execution from USB drives
- Scripts (PowerShell, VBScript) executing from removable media

**Legitimate vs. suspicious:**

- Software installers (expected) vs. random executables (suspicious)
- Known vendor executables vs. oddly-named files
- Digital signatures on executables from removable media

---

### High volumes of file writes to removable devices

**Sysmon:**

- Event ID 11 (File creation) - Count file operations to removable drive letters within time windows

**Windows Event Logs:**

- Event ID 4663 (Object access) - Aggregate write operations to removable media

**Performance Monitor:**

- Disk Write Bytes/sec for removable disk volumes
- File system activity metrics for USB drives

**Indicators:**

- Rapid file creation (hundreds of files in minutes)
- Large file transfers to USB drives from sensitive directories
- Copying of entire directory structures to removable media
- Files being written by system processes or services (unusual for normal USB use)

---

### Suspicious DLL or executable files with names mimicking legitimate system files

**File naming patterns on removable media:**

- System file names: `svchost.exe`, `explorer.exe`, `lsass.exe`, `csrss.exe` on removable drives (red flag)
- Misspellings: `svchast.exe`, `exploren.exe`, `isass.exe`
- Generic names: `update.exe`, `setup.exe`, `install.exe`, `readme.exe`

**Sysmon:**

- Event ID 11 (File creation) combined with Event ID 1 (Process creation) - Correlate file writes with execution

**File analysis indicators:**

- No digital signatures or invalid signatures
- Mismatched file metadata (wrong version info, company names)
- Recently compiled executables (check PE timestamps)
- Packed or obfuscated binaries (high entropy)

**Windows Event Logs:**

- Event ID 8003/8004 (Windows Defender) - Malware detection on removable media
- Event ID 1116/1117 (Windows Defender) - Malware remediation actions

---

### Registry modifications related to AutoRun functionality

**Registry keys to monitor:**

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun`
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf`
- `HKLM\SYSTEM\CurrentControlSet\Services\cdrom\AutoRun`

**Windows Event Logs:**

- Event ID 4657 (Registry value modification) - Changes to AutoRun policies

**Sysmon:**

- Event ID 12 (Registry object added/deleted)
- Event ID 13 (Registry value set)
- Event ID 14 (Registry object renamed)

**Suspicious changes:**

- Disabling AutoRun protections
- Modifying AutoRun behavior to enable execution
- Creating run keys that reference removable media paths
- Shell extension modifications

---

### Device connection and disconnection patterns

**Windows Event Logs:**

- Event ID 6416 (External device recognized) - New USB device connected
- Event ID 20001 (Plug and Play device install) - Device driver installation
- Event ID 20003 (Plug and Play device driver install failed) - Installation issues
- Event ID 400 (Device Manager) - Device insertion
- Event ID 410 (Device Manager) - Device removal

**Device installation logs:**

- `%SystemRoot%\inf\setupapi.dev.log` - Detailed device installation information
- Review for USB storage device installations

**Focus on:**

- Devices connected during off-hours
- Rapid connect/disconnect patterns (quick data transfer)
- Unknown or unregistered USB devices
- Devices connected to sensitive workstations (domain controllers, file servers)

**USBStor tracking:**

- First connection timestamp
- Last connection timestamp
- Device serial numbers and vendor IDs

---

### Lateral movement patterns originating from removable media execution

**Windows Event Logs:**

- Event ID 4624 (Successful logon) - Logons shortly after USB insertion
- Event ID 4648 (Logon with explicit credentials) - Credential use after USB execution
- Event ID 5140 (Network share access) - Share access following removable media activity

**Sysmon:**

- Event ID 3 (Network connection) - Outbound connections from processes launched from removable media
- Event ID 1 (Process creation) - Child processes spawned after initial execution from USB

**Correlation patterns:**

- USB insertion → Process execution → Network activity → Lateral movement
- File copy from USB → Scheduled task creation → Persistence
- Autorun execution → Credential dumping → Network enumeration

---

### Worm-like behavior and self-replication

**File system monitoring:**

- Identical files appearing across multiple systems
- Same hash values of executables on different removable media
- Rapid propagation to other connected USB devices

**Sysmon:**

- Event ID 11 (File creation) - Same filename/hash written to multiple USB devices
- Event ID 15 (FileStream creation - NTFS ADS) - Alternate data streams on USB files

**Behavioral indicators:**

- Malware copying itself to newly inserted removable media
- Automatic file replication when USB devices are inserted
- Network shares being used to distribute USB-borne malware

---

### Execution via LNK files or shortcuts

**Sysmon:**

- Event ID 11 (File creation) - `.lnk` file creation on removable media

**Windows Event Logs:**

- Event ID 4663 (Object access) - LNK file writes to removable drives

**LNK file analysis:**

- Shortcuts pointing to executables on same removable media
- LNK files with hidden target executables
- Shortcut arguments containing PowerShell or script execution
- LNK files with misleading names (appearing as folders or documents)

**Registry:**

- Recent LNK file access: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.lnk`

---

### Antivirus and security software detections

**Windows Defender Logs:**

- Event ID 1116 (Malware detected) - Threats found on removable media
- Event ID 1117 (Malware action taken) - Remediation on USB drives
- Event ID 5007 (Configuration changed) - Real-time protection disabled before USB use

**Third-party AV Logs:**

- Quarantine logs showing threats from removable drive letters
- Real-time protection alerts when USB inserted
- Heuristic/behavioral detection on USB execution

**Application Event Logs:**

- Application crashes or errors correlating with USB insertion
- Security software tampering attempts

---

### Data exfiltration to removable media

**Sysmon:**

- Event ID 11 (File creation) - Sensitive file types copied to removable drives

**Windows Event Logs:**

- Event ID 4663 (Object access) - Access to sensitive files followed by writes to USB
- Event ID 5145 (Network share accessed) - Share access followed by USB writes

**Data Loss Prevention (DLP) Logs:**

- Policy violations for USB writes
- Sensitive document detection on removable media
- Encryption policy enforcement logs

**File types to monitor:**

- Documents: `.docx`, `.xlsx`, `.pdf`, `.txt`
- Databases: `.mdb`, `.accdb`, `.sqlite`, `.db`
- Archives: `.zip`, `.rar`, `.7z`
- Source code: `.py`, `.java`, `.cpp`, various development files

---

## Additional Investigation Areas

**Device Control Policies:**

- Group Policy logs - USB device restrictions and policies
- BitLocker To Go enforcement logs
- Device authorization lists (whitelisted USB devices)

**Forensic Artifacts:**

- Windows Registry: `HKLM\SYSTEM\MountedDevices` - Drive letter assignments
- Volume shadow copies - Historical USB file content
- `$MFT` (Master File Table) analysis - Deleted files from USB
- Link files in user profile `Recent` folder

**PowerShell Logs:**

- Event ID 4103/4104 (Script block logging) - PowerShell scripts executing from USB
- Execution of encoded commands from removable media

**Network Logs:**

- SMB traffic originating after USB insertion
- C2 callbacks initiated from USB-launched processes
- Internal reconnaissance following removable media execution

**Correlation Opportunities:**

- Timeline USB insertion with process creation and network activity
- Cross-reference USB device serial numbers with multiple systems
- Correlate file hashes found on USB with known malware IOCs
- Link USB activity with user behavior analytics (authorized vs. unauthorized users)

# Removable Media Attack Investigation Checklist

## 1. Executable Files on Removable Media

- [ ]  Check Sysmon Event ID 11 for .exe, .dll, .bat, .ps1, .vbs files on drives D:\ through H:\
- [ ]  Review Event ID 4663 for file writes to removable drive letters
- [ ]  Search for double extensions: .pdf.exe, .jpg.scr, .doc.exe
- [ ]  Check for files with system/hidden attributes on USB drives
- [ ]  Verify digital signatures on executables found on removable media

## 2. Autorun Files

- [ ]  Search Sysmon Event ID 11 for autorun.inf creation on any drive
- [ ]  Check for desktop.ini files on removable media
- [ ]  Review autorun.inf contents for open=, shellexecute=, or action= directives
- [ ]  Verify if files referenced in autorun.inf exist on the same media

## 3. Process Execution from Removable Media

- [ ]  Review Event ID 4688/Sysmon Event ID 1 for Image paths starting with D:, E:, F:, G:, H:\
- [ ]  Check CurrentDirectory field pointing to removable drives
- [ ]  Identify scripts (PowerShell, VBScript) executing from USB locations
- [ ]  Verify legitimacy of processes by checking digital signatures

## 4. High Volume File Operations

- [ ]  Count Sysmon Event ID 11 file creation events to removable drives in short timeframes
- [ ]  Check for hundreds of files written within minutes
- [ ]  Review large file transfers from sensitive directories to USB
- [ ]  Identify entire directory structure copies to removable media

## 5. Suspicious File Naming

- [ ]  Search for system file names on removable drives: svchost.exe, explorer.exe, lsass.exe
- [ ]  Check for misspellings: svchast.exe, exploren.exe, isass.exe
- [ ]  Review generic suspicious names: update.exe, readme.exe, install.exe
- [ ]  Check Event ID 1116/1117 for malware detections on USB drives

## 6. AutoRun Registry Modifications

- [ ]  Check Event ID 4657/Sysmon Event ID 13 for changes to NoDriveTypeAutoRun keys
- [ ]  Review modifications to HKLM\SYSTEM\CurrentControlSet\Services\cdrom\AutoRun
- [ ]  Monitor for disabled AutoRun protections
- [ ]  Check for run keys referencing removable media paths

## 7. Device Connection Patterns

- [ ]  Review Event ID 6416 for external device recognition
- [ ]  Check Event ID 20001 for USB device driver installations
- [ ]  Identify connections during off-hours or from sensitive workstations
- [ ]  Check HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR for device history
- [ ]  Look for rapid connect/disconnect patterns

## 8. Lateral Movement After USB Insertion

- [ ]  Correlate Event ID 4624 (logons) occurring after USB insertion
- [ ]  Check Sysmon Event ID 3 for network connections from USB-launched processes
- [ ]  Review Event ID 5140 for network share access following removable media activity
- [ ]  Timeline: USB insertion → Process execution → Network activity → Lateral movement

## 9. LNK File Execution

- [ ]  Search Sysmon Event ID 11 for .lnk file creation on removable drives
- [ ]  Analyze LNK files pointing to executables on same removable media
- [ ]  Check for shortcuts with PowerShell or script execution in arguments
- [ ]  Review HKCU...\Explorer\RecentDocs.lnk for recent LNK access

## 10. Data Exfiltration to USB

- [ ]  Monitor Sysmon Event ID 11 for sensitive file types (.docx, .xlsx, .pdf, .zip) to USB
- [ ]  Check Event ID 4663 for access to sensitive files followed by USB writes
- [ ]  Review DLP logs for policy violations on USB writes
- [ ]  Identify database files (.mdb, .sqlite, .db) or source code copied to removable media